"""Verify run_lua captures its print without replacing CE's Lua Engine print."""
import os
from pathlib import Path
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[1]
assert os.environ.get('CE_MCP_PIPE_NAME','').startswith('ce_mcp_printfix')
sys.path.insert(0,str(ROOT/'server'))
from server import request
from mcp.server.mcpserver.exceptions import ToolError

probe=ROOT/'work/print_probe.lua'
report=ROOT/'work/print_probe.txt'
probe.write_text('''
local info=debug.getinfo(_G.print,'S')
local f=assert(io.open([[E:/workspace/ce-mcp/work/print_probe.txt]],'w'))
local alias=debug.getinfo(_G.Print,'S')
f:write(info.what,'|',info.source,'|',tostring(_G.print),
  '|',alias.what,'|',tostring(_G.Print==_G.print))
f:close()
return 1
''',encoding='utf-8')

target=subprocess.Popen([str(ROOT/'work/step6-fixture/step6_target.exe')],
                        stdin=subprocess.PIPE,stdout=subprocess.PIPE,text=True)
try:
    pid=int(target.stdout.readline())
    request('attach',pid=pid)
    def identity():
        try:
            request('scan_first',value_type='4bytes',scan_type='exact',value='1',
                    start_address="$dofile('E:/workspace/ce-mcp/work/print_probe.lua')",
                    stop_address='0')
        except ToolError as exc:
            assert 'Invalid scan range' in str(exc),str(exc)
        return report.read_text(encoding='utf-8')
    before=identity()
    result=request('run_lua',code="print('MCP capture'); return 42")
    after=identity()
    print('before',before)
    print('after',after)
    print('capture',result)
    assert result['ok'] and result['output']==['MCP capture'] and result['returns']==[42]
    assert before==after,'run_lua replaced CE global print'
    runtime_error=request('run_lua',code="error('expected')")
    assert not runtime_error['ok'] and 'expected' in runtime_error['error']
    syntax_error=request('run_lua',code='return )')
    assert not syntax_error['ok'] and syntax_error['error']
    timeout=request('run_lua',code='while true do end',timeout=.1)
    assert timeout['timed_out']
    assert identity()==before,'error or timeout replaced CE global print'
finally:
    if target.poll() is None:
        target.stdin.write('exit\n');target.stdin.flush();target.wait(5)
