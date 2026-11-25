"""CE step 5 integration against a disposable native process and isolated CE pipe."""
import asyncio
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'server'))
from server import request
from mcp import ClientSession,StdioServerParameters,stdio_client
from mcp.server.mcpserver.exceptions import ToolError

class Target:
    def __init__(self):
        self.p=subprocess.Popen([str(ROOT/'work/injection-fixture/ce_mcp_injection_target.exe')],
                                stdin=subprocess.PIPE,stdout=subprocess.PIPE,text=True)
        self.info=json.loads(self.p.stdout.readline())
        for key in ('site','watched','first','second'):
            self.info[key]=int(self.info[key],16)
    def run(self,n):
        self.p.stdin.write(f'run {n}\n');self.p.stdin.flush()
        return json.loads(self.p.stdout.readline())['value']
    def close(self):
        if self.p.poll() is None:
            self.p.stdin.write('exit\n');self.p.stdin.flush();self.p.wait(5)

def error(method,expected,**kw):
    try:request(method,**kw)
    except ToolError as exc:
        assert expected in str(exc),str(exc)
    else:raise AssertionError(f'{method} unexpectedly succeeded')

def native_tests(t):
    i=t.info
    request('attach',pid=i['pid'])
    code=request('disassemble',address=hex(i['site']),count=3)['instructions']
    assert [x['bytes'] for x in code]==['8B C2','05 78 56 34 12','89 01']
    original='8B C2 05 78 56 34 12'
    assert t.run(1)==0x12345679
    pattern='8B C2 05 ?? 56 34 12 89 01'
    bymodule=request('aob_scan',pattern=pattern,module=i['module'])
    assert bymodule['total']==1 and int(bymodule['results'][0]['address'],16)==i['site']
    assert bymodule['results'][0]['symbol'].endswith('+1230')
    whole=request('aob_scan',pattern=pattern)
    assert any(int(x['address'],16)==i['site'] for x in whole['results'])
    common=request('aob_scan',pattern='4D 00 00 00',module=i['module'])
    hits={int(x['address'],16) for x in common['results']}
    assert i['first']+16 in hits and i['second']+16 in hits
    error('aob_scan','Use space-separated',pattern='1234')
    error('aob_scan','Module not found',pattern=pattern,module='not-a-module.exe')
    compare=request('compare_structures',addresses=[hex(i['first']),hex(i['second'])],length=24,stride=4)
    assert compare['pointer_size']==8 and compare['different_offsets']==[0,4,8]
    fields={r['offset']:r for r in compare['rows']}
    assert fields[4]['interpretations'][1]['values'][0]['value']=='1.5'
    assert fields[4]['interpretations'][1]['values'][1]['value']=='2.5'
    assert fields[8]['interpretations'][2]['values'][0]['value']=='0x1234'
    assert fields[16]['different'] is False
    bytewise=request('compare_structures',addresses=[hex(i['first']),hex(i['second'])],length=24)
    assert bytewise['stride']==1 and bytewise['rows'][1]['offset']==1
    custom=request('compare_structures',addresses=[hex(i['first']),hex(i['second'])],
                   length=12,stride=1,types=['byte','float'])
    assert custom['rows'][0]['interpretations'][0]['different']
    error('compare_structures','Provide 2..16',addresses=[hex(i['first'])],length=24)
    generated=request('injection_template',address=hex(i['site']),name='test_inject')
    assert generated['pattern_unique'] and generated['jump_size']==5
    assert generated['overwrite_size']==7 and generated['original_bytes']==original
    assert int(generated['return_address'],16)==i['site']+7
    assert 'alloc(newmem,1000,test_inject)' in generated['script']
    assert '[ENABLE]' in generated['script'] and '[DISABLE]' in generated['script']
    script=generated['script'].replace('  // Put your custom code here. Preserve registers/flags that your code changes.',
                                      '  add edx,2 // test-only injected behavior')
    enabled=request('auto_assemble',name='测试注入',script=script)
    assert enabled['enabled'] and len(enabled['allocations'])==1
    cave=int(enabled['allocations'][0]['address'],16)
    assert abs(cave-i['site'])<2**31
    patch=request('read_memory',address=hex(i['site']),size=7)['hex']
    assert patch.startswith('E9 ') and patch.endswith('90 90'),patch
    cave_bytes=request('read_memory',address=hex(cave),size=15)['hex'].split()
    assert cave_bytes[:10]==['83','C2','02','8B','C2','05','78','56','34','12']
    assert cave_bytes[10]=='E9',cave_bytes # Return jump is also rel32/5 bytes.
    assert t.run(1)==0x1234567B
    error('auto_assemble','already enabled',name='测试注入',script=script)
    other=Target()
    try:
        error('attach','Disable injection',pid=other.info['pid'])
        assert request('ce_status')['pid']==i['pid']
    finally:other.close()
    disabled=request('auto_assemble',name='测试注入',enable=False)
    assert disabled=={'name':'测试注入','pid':i['pid'],'enabled':False}
    assert request('read_memory',address=hex(i['site']),size=7)['hex']==original
    assert t.run(1)==0x12345679
    error('auto_assemble','No enabled script',name='测试注入',enable=False)
    print('PASS native CE: all-match wildcard AOB, module offsets, structure differences, unique 7-byte template, 5-byte near jump, +2 behavior, exact DISABLE restoration, process-switch guard')

async def sdk_tests(t):
    params=StdioServerParameters(command=sys.executable,args=['-B',str(ROOT/'server/server.py')],env={**os.environ})
    async with stdio_client(params) as streams:
        async with ClientSession(*streams) as client:
            await client.initialize()
            names={x.name for x in (await client.list_tools()).tools}
            assert len(names)>=24 and {'auto_assemble','aob_scan','injection_template','compare_structures'}<=names
            async def call(method,**kw):
                r=await client.call_tool(method,kw)
                assert not r.is_error,(method,r)
                return json.loads(r.content[0].text)
            i=t.info
            assert (await call('aob_scan',pattern='8B C2 05 ?? 56 34 12 89 01',module=i['module']))['total']==1
            assert (await call('compare_structures',addresses=[hex(i['first']),hex(i['second'])],length=24,stride=4))['different_offsets']==[0,4,8]
            g=await call('injection_template',address=hex(i['site']))
            assert g['overwrite_size']==7
            assert (await call('auto_assemble',name='sdk_test',script=g['script']))['enabled']
            assert t.run(3)==0x1234567B
            assert not (await call('auto_assemble',name='sdk_test',enable=False))['enabled']
            assert t.run(3)==0x1234567B
            print('PASS official MCP SDK stdio: 24 tools and all four new tools')

if __name__=='__main__':
    assert os.environ.get('CE_MCP_PIPE_NAME')=='ce_mcp_step5','Run only against isolated CE pipe'
    t=Target()
    try:
        native_tests(t)
        asyncio.run(sdk_tests(t))
    finally:t.close()
