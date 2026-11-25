"""Official MCP SDK 2.x stdio server backed by the CE named pipe."""
import json
import os
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

PIPE = "\\\\.\\pipe\\" + os.environ.get("CE_MCP_PIPE_NAME", "ce_mcp")
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
    if method in {'find_what_writes','find_what_accesses'}:
        seconds=params.get('seconds',5)
        if not isinstance(seconds,(int,float)) or not 0.1 <= seconds <= 120:
            raise ToolError('seconds must be 0.1..120')
        timeout=seconds+30
    elif method == 'run_lua':
        timeout=float(params.get('timeout',3))+20
    elif method == 'mono':
        timeout=120.0
    else:
        timeout=150.0 if method in {'scan_first','scan_next'} else TIMEOUT
    deadline = time.monotonic() + timeout
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


@mcp.tool()
def find_what_writes(address: str, seconds: float = 5, size: int = 1) -> dict:
    """Watch target CPU writes with a hardware breakpoint for 0.1..120 seconds.

    size is 1,2,4 or 8 on x64 and the address must be aligned to it. Returns instruction
    module+offset (when module-backed), disassembly, hit count and first-hit hex registers.
    Hardware data breakpoints stop after execution: attribution uses CE's previous-opcode
    estimate with an instruction-end check; stopped_ip is retained. Removes the owned
    breakpoint on expiry, even if this client disconnects. One concurrent watch is allowed.
    """
    return request('find_what_writes',address=address,seconds=seconds,size=size)


@mcp.tool()
def find_what_accesses(address: str, seconds: float = 5, size: int = 1) -> dict:
    """Like find_what_writes, but collect both reads and writes to the watched range."""
    return request('find_what_accesses',address=address,seconds=seconds,size=size)


@mcp.tool()
def disassemble(address: str, count: int = 10) -> dict:
    """Decode 1..200 x86/x64 instructions, returning addresses, module offsets, bytes and text."""
    return request('disassemble',address=address,count=count)


@mcp.tool()
def nop_instruction(address: str) -> dict:
    """Replace one complete instruction with the same number of 0x90 bytes; save its original.

    Temporarily pauses a running target and verifies the write. Backups live in the CE Lua
    session and are scoped to PID/address; restore patches before restarting CE.
    """
    return request('nop_instruction',address=address)


@mcp.tool()
def restore_instruction(address: str) -> dict:
    """Restore the CE-session NOP backup for this process/address and verify original bytes.

    Refuses to overwrite bytes changed by another editor after the NOP patch.
    """
    return request('restore_instruction',address=address)


@mcp.tool()
def read_pointer(base: str, offsets: list[int | str], value_type: ValueType = '4bytes',
                 length: int = 256) -> dict:
    """Trace a pointer chain and read the final typed value. base accepts module+hex-offset.

    offsets are in BASE-TO-LEAF order: address = dereference(address) + offset at each layer.
    Integer offsets are decimal; string offsets are hexadecimal, optionally signed/0x-prefixed.
    This order is the reverse of CE's top-to-bottom pointer-record offsets. Returns every
    dereference address, pointer value and next address. Uses 8-byte pointers on x64, 4 on x86.
    Empty offsets means no dereference (read base directly). Up to 64 signed 32-bit offsets.
    """
    return request('read_pointer',base=base,offsets=offsets,value_type=value_type,length=length)


@mcp.tool()
def write_pointer(base: str, offsets: list[int | str], value_type: ValueType, value: str) -> dict:
    """Resolve base-to-leaf offsets as in read_pointer, write only the final value and read back.

    Value is a decimal string (or UTF-8 text for string). Intermediate pointers are not modified.
    """
    return request('write_pointer',base=base,offsets=offsets,value_type=value_type,value=value)


@mcp.tool()
def add_pointer_to_table(base: str, offsets: list[int | str], value_type: ValueType,
                         description: str = '', value: str | None = None,
                         frozen: bool = False, length: int = 256) -> dict:
    """Create a native CE pointer record that follows pointer changes, with optional value/freeze.

    Offsets use base-to-leaf order as in read_pointer; CE native/UI order is reversed internally.
    The base module expression is preserved. At least one offset is required. Returns record ID,
    resolved address, both offset orders and actual CE offset texts. Use set_frozen on its ID.
    """
    params=dict(base=base,offsets=offsets,value_type=value_type,description=description,
                frozen=frozen,length=length)
    if value is not None:
        params['value']=value
    return request('add_pointer_to_table',**params)


@mcp.tool()
def address_info(address: str) -> dict:
    """Classify an address and return module+offset and its Windows memory-region attributes.

    Distinguishes static module, dynamic private, mapped, reserved and free memory. MEM_PRIVATE
    alone does not prove heap ownership. Includes protection/read/write/execute/guard properties.
    """
    return request('address_info',address=address)


@mcp.tool()
def auto_assemble(name: str, script: str | None = None, enable: bool = True) -> dict:
    """Enable a named CE Auto Assembler [ENABLE]/[DISABLE] script, or disable it by name.

    When enable=true, supply the full script. CE retains its disableInfo, allocations and
    symbols in this session. With enable=false, omit script; the original DISABLE section
    runs against the same process instance. Disable active scripts before switching targets.
    """
    params=dict(name=name,enable=enable)
    if script is not None:
        params['script']=script
    return request('auto_assemble',**params)


@mcp.tool()
def aob_scan(pattern: str, module: str | None = None) -> dict:
    """Find every match for space-separated hex bytes and ?? wildcards.

    When module is specified, only complete matches within that module are returned.
    Otherwise scans all readable process memory. Results include module+offset where known.
    """
    return request('aob_scan',pattern=pattern,module=module)


@mcp.tool()
def injection_template(address: str, name: str = 'ce_mcp_inject') -> dict:
    """Generate a module-unique AOB injection script for a complete 5-byte near jump.

    Returns the [ENABLE]/[DISABLE] script, original bytes, overwrite size, jump-back
    address and unique pattern. On x64, alloc requests a cave within ±2 GiB. Review
    and edit the custom-code placeholder before calling auto_assemble.
    """
    return request('injection_template',address=address,name=name)


@mcp.tool()
def compare_structures(addresses: list[str], length: int, stride: int = 1,
                       types: list[str] | None = None) -> dict:
    """Compare 2..16 memory blocks by offset as integer, float and pointer fields.

    Samples up to 4096 bytes per address; stride controls offset spacing. types can
    contain byte, 2bytes, 4bytes, 8bytes, float, double and pointer. Each row reports
    values and raw-byte differences to help identify distinguishing fields.
    """
    params=dict(addresses=addresses,length=length,stride=stride)
    if types is not None:
        params['types']=types
    return request('compare_structures',**params)


@mcp.tool()
def run_lua(code: str, timeout: float = 3) -> dict:
    """Run CE Lua, capturing print output, return values, errors and elapsed time.

    timeout is 0.05..30 seconds. Lua instruction loops are interrupted by a VM hook;
    a blocking native CE function cannot be preempted until it returns.
    """
    return request('run_lua',code=code,timeout=timeout)


@mcp.tool()
def speedhack(enabled: bool, speed: float = 1) -> dict:
    """Set CE's process speedhack and report its current multiplier.

    enabled=false restores the normal 1x speed. speed must be >0 and <=100.
    """
    return request('speedhack',enabled=enabled,speed=speed)


@mcp.tool()
def inject_dll(path: str) -> dict:
    """Load an absolute local DLL into the attached process via CE injectDLL.

    Returns CE's module name, path and base address after injection.
    """
    return request('inject_dll',path=path)


@mcp.tool()
def mono(action: Literal['status','assemblies','class','methods','fields'] = 'status',
         namespace: str = '', class_name: str | None = None,
         method_name: str | None = None, instance_address: str | None = None) -> dict:
    """Inspect an attached Mono/IL2CPP process using CE's Mono data collector.

    status reports detection; assemblies lists loaded assemblies; class finds one class;
    methods optionally filters by exact name; fields lists field metadata and reads
    primitive values when an instance_address is supplied (or a static address exists).
    A native target returns is_mono=false with a reason.
    """
    params=dict(action=action,namespace=namespace)
    if class_name is not None: params['class_name']=class_name
    if method_name is not None: params['method_name']=method_name
    if instance_address is not None: params['instance_address']=instance_address
    return request('mono',**params)


if __name__ == "__main__":
    mcp.run(transport="stdio")
