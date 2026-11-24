"""Real CE/Tutorial integration. Run with the project .venv Python."""
import asyncio
import concurrent.futures
import json
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'server'))
from server import request, PIPE
import win32file
import win32con
from mcp import ClientSession, StdioServerParameters, stdio_client
from mcp.server.mcpserver.exceptions import ToolError


def pipe_tests():
    assert request('ce_status')['version'] == 7.7
    processes = request('list_processes', filter='tutorial')['processes']
    target = next(p for p in processes if p['name'].lower() == 'tutorial-x86_64.exe')
    assert request('attach', name=target['name'])['pid'] == target['pid']
    assert request('attach', pid=target['pid'])['pid'] == target['pid']
    header = request('read_memory', address=target['name'], size=64)
    assert header['hex'].startswith('4D 5A') and header['characters'].startswith('MZ')
    assert request('read_memory', address=header['address'], size=64) == header
    assert len(request('read_memory', address=target['name'], size=65536)['characters']) == 65536
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
        results = list(executor.map(lambda _: request('ce_status'), range(32)))
    assert all(r['pid'] == target['pid'] for r in results)
    for method, params in [
        ('attach', {'name':'__ce_mcp_missing__.exe'}),
        ('attach', {'pid':-1}),
        ('read_memory', {'address':'0', 'size':16}),
        ('read_memory', {'address':target['name'], 'size':65537}),
        ('unknown', {}),
    ]:
        try:
            request(method, **params)
        except ToolError:
            pass
        else:
            raise AssertionError((method, params))
    # A held idle client must not block other connections.
    idle = win32file.CreateFile(PIPE, win32con.GENERIC_READ | win32con.GENERIC_WRITE,
        0, None, win32con.OPEN_EXISTING, 0, None)
    try:
        assert request('ce_status')['pid'] == target['pid']
        body = json.dumps({'method':'ce_status'}).encode()
        frame = struct.pack('<I',len(body)) + body
        for fragment in (frame[:2], frame[2:7], frame[7:]):
            win32file.WriteFile(idle, fragment)
        _, raw = win32file.ReadFile(idle, 4)
        size, = struct.unpack('<I', raw)
        _, raw = win32file.ReadFile(idle, size)
        assert json.loads(raw)['ok']
    finally:
        win32file.CloseHandle(idle)
    print('PASS pipe: 4 methods, PID/name attach, numeric/symbol address, 64KiB, 8 concurrent clients/32 requests, idle client, fragmented frame, errors')
    return target


async def mcp_tests(target):
    parameters = StdioServerParameters(command=str(ROOT / '.venv/Scripts/python.exe'),
        args=['-B', str(ROOT / 'server/server.py')])
    async with stdio_client(parameters) as streams:
        async with ClientSession(*streams) as client:
            await client.initialize()
            tools = await client.list_tools()
            assert {t.name for t in tools.tools} >= {'ce_status','list_processes','attach','read_memory'}
            for name, arguments in [
                ('ce_status', {}), ('list_processes', {'filter':'tutorial'}),
                ('attach', {'pid':target['pid']}),
                ('read_memory', {'address':target['name'], 'size':64}),
            ]:
                result = await client.call_tool(name, arguments)
                assert not result.is_error, result
                data = json.loads(result.content[0].text)
                if name == 'ce_status' or name == 'attach':
                    assert data['pid'] == target['pid']
                elif name == 'list_processes':
                    assert target in data['processes']
                else:
                    assert data['hex'].startswith('4D 5A') and data['characters'].startswith('MZ')
                print(f'PASS MCP {name}: verified response contents')
            result = await client.call_tool('read_memory', {'address':'0','size':16})
            assert result.is_error
            assert 'Memory unreadable' in result.content[0].text
            assert not (await client.call_tool('ce_status', {})).is_error
            print('PASS MCP error isolation and subsequent recovery')


if __name__ == '__main__':
    asyncio.run(mcp_tests(pipe_tests()))
