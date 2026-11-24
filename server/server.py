"""Official MCP SDK 2.x stdio server backed by the CE named pipe."""
import json
import struct
import time
from typing import Literal

import pywintypes
import win32con
import win32event
import win32file
import win32pipe
from mcp.server import MCPServer
from mcp.server.mcpserver.exceptions import ToolError

PIPE = r"\\.\pipe\ce_mcp"
MAX_FRAME = 1024 * 1024
TIMEOUT = 20.0
mcp = MCPServer("cheat_engine")


def _io(handle, data_or_size, *, write, deadline):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise ToolError("CE pipe request timed out")
    overlapped = pywintypes.OVERLAPPED()
    overlapped.hEvent = win32event.CreateEvent(None, True, False, None)
    buffer = data_or_size if write else win32file.AllocateReadBuffer(data_or_size)
    try:
        operation = win32file.WriteFile if write else win32file.ReadFile
        operation(handle, buffer, overlapped)
        if win32event.WaitForSingleObject(overlapped.hEvent, max(1, int(remaining * 1000))) != win32event.WAIT_OBJECT_0:
            win32file.CancelIoEx(handle, overlapped)
            win32event.WaitForSingleObject(overlapped.hEvent, win32event.INFINITE)
            raise ToolError("CE pipe request timed out")
        count = win32file.GetOverlappedResult(handle, overlapped, False)
        return count if write else bytes(buffer[:count])
    finally:
        win32file.CloseHandle(overlapped.hEvent)


def _read_exact(handle, size, deadline):
    chunks = bytearray()
    while len(chunks) < size:
        chunk = _io(handle, size - len(chunks), write=False, deadline=deadline)
        if not chunk:
            raise ConnectionError("CE disconnected during response")
        chunks.extend(chunk)
    return bytes(chunks)


def request(method, **params):
    """One independent pipe connection per request; no shared attachment cache."""
    payload = json.dumps({"method": method, "params": params}, ensure_ascii=False).encode("utf-8")
    if len(payload) > MAX_FRAME:
        raise ValueError("Request too large")
    deadline = time.monotonic() + (150.0 if method in {"scan_first", "scan_next"} else TIMEOUT)
    try:
        while True:
            try:
                handle = win32file.CreateFile(PIPE, win32con.GENERIC_READ | win32con.GENERIC_WRITE,
                    0, None, win32con.OPEN_EXISTING, win32con.FILE_FLAG_OVERLAPPED, None)
                break
            except pywintypes.error as exc:
                if exc.winerror != 231:
                    raise
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise ToolError("CE pipe is busy") from exc
                win32pipe.WaitNamedPipe(PIPE, max(1, int(remaining * 1000)))
        try:
            frame = struct.pack("<I", len(payload)) + payload
            offset = 0
            while offset < len(frame):
                count = _io(handle, frame[offset:], write=True, deadline=deadline)
                if not count:
                    raise ConnectionError("CE disconnected during request")
                offset += count
            size, = struct.unpack("<I", _read_exact(handle, 4, deadline))
            if not 0 < size <= MAX_FRAME:
                raise ValueError("Invalid CE response length")
            response = json.loads(_read_exact(handle, size, deadline).decode("utf-8"))
        finally:
            win32file.CloseHandle(handle)
    except pywintypes.error as exc:
        raise ToolError(f"CE pipe unavailable: {exc}. Start CE with ce_mcp autorun installed.") from exc
    if not response.get("ok"):
        raise ToolError(response.get("error", "Unknown CE error"))
    return response["result"]


@mcp.tool()
def ce_status() -> dict:
    """Return CE version and the currently attached process PID/name."""
    return request("ce_status")


@mcp.tool()
def list_processes(filter: str | None = None) -> dict:
    """List running processes, optionally filtering names by case-insensitive substring."""
    return request("list_processes", filter=filter)


@mcp.tool()
def attach(name: str | None = None, pid: int | None = None) -> dict:
    """Attach CE using exactly one of exact executable name or PID. Duplicate names require PID."""
    if (name is None) == (pid is None):
        raise ToolError("Provide exactly one of name or pid")
    return request("attach", **({"name": name} if name is not None else {"pid": pid}))


@mcp.tool()
def read_memory(address: str, size: int) -> dict:
    """Read 1..65536 bytes from a CE address expression; return hex and printable ASCII (others '.')."""
    if not 1 <= size <= 65536:
        raise ToolError("size must be 1..65536")
    return request("read_memory", address=address, size=size)


ValueType = Literal['byte', '2bytes', '4bytes', '8bytes', 'float', 'double', 'string']
FirstScanType = Literal['exact', 'bigger', 'smaller', 'between', 'unknown']
NextScanType = Literal['exact', 'bigger', 'smaller', 'between', 'increased',
    'decreased', 'changed', 'unchanged', 'increased_by', 'decreased_by']


@mcp.tool()
def scan_first(value_type: ValueType, scan_type: FirstScanType,
               value: str | None = None, value2: str | None = None,
               start_address: str = '0', stop_address: str | None = None) -> dict:
    """Replace the CE-owned scan. Decimal values are strings; float exact uses CE rtRounded.

    between uses value and value2; unknown takes no value. Strings support exact UTF-8 only.
    Optional address bounds use CE's scan range rules. Returns total and first 20 results.
    """
    params = dict(value_type=value_type, scan_type=scan_type, start_address=start_address)
    for key, item in [('value',value), ('value2',value2), ('stop_address',stop_address)]:
        if item is not None:
            params[key] = item
    return request('scan_first', **params)


@mcp.tool()
def scan_next(scan_type: NextScanType, value: str | None = None,
              value2: str | None = None) -> dict:
    """Filter the previous CE scan, retaining its value type. Compare changes with previous scan.

    increased_by/decreased_by take a decimal delta. unknown is valid only for scan_first.
    Returns total and first 20 addresses/current values.
    """
    params = dict(scan_type=scan_type)
    if value is not None:
        params['value'] = value
    if value2 is not None:
        params['value2'] = value2
    return request('scan_next', **params)


@mcp.tool()
def scan_results(start: int = 0, count: int = 20) -> dict:
    """Page through current CE results, using a zero-based start and count 1..200."""
    return request('scan_results', start=start, count=count)


@mcp.tool()
def read_value(address: str, value_type: ValueType, length: int = 256) -> dict:
    """Read a typed value as a string to preserve integer precision. Integers display unsigned.

    string reads NUL-terminated UTF-8 up to length bytes (1..4096).
    """
    return request('read_value', address=address, value_type=value_type, length=length)


@mcp.tool()
def write_value(address: str, value_type: ValueType, value: str) -> dict:
    """Write a typed decimal value (pass as string); return its actual value read back.

    Integers accept unsigned or signed two's-complement ranges. Strings write UTF-8 plus NUL,
    up to 4096 bytes; the caller must ensure the destination buffer is large enough.
    """
    return request('write_value', address=address, value_type=value_type, value=value)


@mcp.tool()
def add_to_table(address: str, value_type: ValueType, description: str = '',
                 frozen: bool = False, frozen_value: str | None = None,
                 length: int = 256) -> dict:
    """Add an address to CE's visible address table and return its stable record ID.

    frozen=true locks frozen_value, or the current value if omitted. length sets string bytes.
    An MCP attachment change unfreezes bridge records while preserving them in CE's table.
    """
    params = dict(address=address,value_type=value_type,description=description,
                  frozen=frozen,length=length)
    if frozen_value is not None:
        params['frozen_value'] = frozen_value
    return request('add_to_table', **params)


@mcp.tool()
def set_frozen(id: int, frozen: bool, value: str | None = None) -> dict:
    """Toggle freezing of a bridge-created memory record by ID, optionally setting a new value."""
    params = dict(id=id,frozen=frozen)
    if value is not None:
        params['value'] = value
    return request('set_frozen', **params)


if __name__ == "__main__":
    mcp.run(transport="stdio")
