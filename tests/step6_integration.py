"""All target actions are confined to an isolated CE and self-authored native process."""
import asyncio
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[1]
assert os.environ.get('CE_MCP_PIPE_NAME')=='ce_mcp_step6'
sys.path.insert(0,str(ROOT/'server'))
from server import request
from mcp import ClientSession,StdioServerParameters,stdio_client

def test():
    target=subprocess.Popen([str(ROOT/'work/step6-fixture/step6_target.exe')],
                            stdin=subprocess.PIPE,stdout=subprocess.PIPE,text=True)
    try:
        pid=int(target.stdout.readline())
        assert request('attach',pid=pid)['pid']==pid
        def tick():
            target.stdin.write('tick\n');target.stdin.flush()
            return int(target.stdout.readline())
        normal=tick()
        assert 850<=normal<=1250,normal
        on=request('speedhack',enabled=True,speed=3)
        assert on['enabled'] and abs(on['speed']-3)<.01,on
        assert request('run_lua',code='return getMainForm().cbSpeedhack.Checked')['returns']==[True]
        fast=tick()
        assert fast>normal*1.8,(normal,fast)
        off=request('speedhack',enabled=False)
        assert off['speed']==1,off
        assert request('run_lua',code='return getMainForm().cbSpeedhack.Checked')['returns']==[False]
        restored=tick()
        assert 850<=restored<=1250,(normal,fast,restored)
        print('speed',normal,fast,restored)
        log=ROOT/'work/step6-fixture/dll-loaded.log'
        if log.exists(): log.unlink()
        dll=ROOT/'work/step6-fixture/step6_log.dll'
        inj=request('inject_dll',path=str(dll))
        assert inj['module']=='step6_log.dll' and int(inj['base'],16)>0,inj
        assert log.read_text().strip()=='DLL_PROCESS_ATTACH'
        print('injection',inj)
        nonmono=request('mono',action='status')
        assert nonmono['is_mono'] is False and 'runtime' in nonmono['reason'],nonmono
        print('nonmono',nonmono)
        good=request('run_lua',code="print('capture',42);return 9,nil,{x='ok'}")
        assert good['ok'] and good['output']==['capture\t42'] and good['returns'][0]==9
        assert good['returns'][1]=={'type':'nil'}
        bad=request('run_lua',code="error('test failure')")
        assert not bad['ok'] and 'test failure' in bad['error'] and bad['traceback']
        timeout=request('run_lua',code='while true do end',timeout=.15)
        assert timeout['timed_out'] and not timeout['ok']
        assert request('ce_status')['pid']==pid
        print('lua output/error/timeout verified')
        asyncio.run(sdk_test())
    finally:
        if target.poll() is None:
            target.stdin.write('exit\n');target.stdin.flush();target.wait(5)

async def sdk_test():
    params=StdioServerParameters(command=sys.executable,args=['-B',str(ROOT/'server/server.py')],env={**os.environ})
    async with stdio_client(params) as streams:
        async with ClientSession(*streams) as client:
            await client.initialize()
            names={t.name for t in (await client.list_tools()).tools}
            assert {'run_lua','speedhack','inject_dll','mono'}<=names and len(names)>=28,names
            result=await client.call_tool('run_lua',{'code':'return 123'})
            assert not result.is_error and json.loads(result.content[0].text)['returns']==[123]
            print('MCP SDK: 28 tools')

if __name__=='__main__': test()
