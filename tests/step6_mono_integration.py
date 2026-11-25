"""Positive Mono collector test against a self-authored C# fixture and isolated CE."""
import os
from pathlib import Path
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[1]
assert os.environ.get('CE_MCP_PIPE_NAME')=='ce_mcp_step6'
sys.path.insert(0,str(ROOT/'server'))
from server import request

mono=ROOT/'work/mono-extract/Mono/bin/mono.exe'
fixture=ROOT/'work/step6-fixture/mono_fixture.exe'
p=subprocess.Popen([str(mono),str(fixture)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,
                   stderr=subprocess.PIPE,text=True,encoding='utf-8-sig')
try:
    pid=int(p.stdout.readline())
    print('attach',request('attach',pid=pid),flush=True)
    print('status',request('mono',action='status'),flush=True)
    assemblies=request('mono',action='assemblies')
    print('assemblies',assemblies,flush=True)
    assert assemblies['is_mono'] and any('mono_fixture' in (a['name'] or '') for a in assemblies['assemblies'])
    klass=request('mono',action='class',namespace='CeMcpFixture',class_name='Sample')
    print('class',klass,flush=True)
    assert klass['found']
    methods=request('mono',action='methods',namespace='CeMcpFixture',class_name='Sample',method_name='Add')
    print('methods',methods,flush=True)
    assert methods['total']==1 and methods['methods'][0]['name']=='Add'
    fields=request('mono',action='fields',namespace='CeMcpFixture',class_name='Sample')
    print('fields',fields,flush=True)
    assert {'Counter','Health','Ratio'} <= {f['name'] for f in fields['fields']}
    assert next(f for f in fields['fields'] if f['name']=='Counter')['value']==123
    instances=request('run_lua',code="return mono_class_findInstancesOfClassListOnly(mono_findClass('CeMcpFixture','Sample'))")
    print('instances',instances,flush=True)
    if instances['ok'] and instances['returns'] and isinstance(instances['returns'][0],list):
        candidates=instances['returns'][0]
        found=False
        for candidate in candidates:
            if not isinstance(candidate,str) or not candidate.startswith('0x'): continue
            values=request('mono',action='fields',namespace='CeMcpFixture',class_name='Sample',instance_address=candidate)
            health=next(f for f in values['fields'] if f['name']=='Health').get('value')
            if health==456:
                ratio=next(f for f in values['fields'] if f['name']=='Ratio').get('value')
                print('instance fields',candidate,health,ratio,flush=True)
                assert abs(ratio-1.5)<.001
                found=True;break
        assert found,'Sample instance was not found among collector candidates'
finally:
    if p.poll() is None:
        p.stdin.write('exit\n');p.stdin.flush()
        try: p.wait(3)
        except subprocess.TimeoutExpired: p.kill();p.wait(5)
