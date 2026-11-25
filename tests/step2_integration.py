"""Real CE + real MCP tests. Never writes or sends UI input to Tutorial."""
import asyncio
import concurrent.futures
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT / 'server'))
from server import request
from mcp import ClientSession, StdioServerParameters, stdio_client
from mcp.server.mcpserver.exceptions import ToolError


def error(method, **params):
    try:
        request(method, **params)
    except ToolError:
        return
    raise AssertionError(f'Expected error: {method} {params}')


class Target:
    def __init__(self):
        self.process = subprocess.Popen([sys.executable,'-B',str(ROOT / 'tests/target.py')],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
        info = json.loads(self.process.stdout.readline())
        self.pid, self.base = info['pid'], int(info['base'],16)

    def command(self, op, offset, **kwargs):
        self.process.stdin.write(json.dumps(dict(op=op,offset=offset,**kwargs))+'\n')
        self.process.stdin.flush()
        return json.loads(self.process.stdout.readline())

    def poke(self, offset, data):
        self.command('write',offset,hex=data.hex())

    def peek(self, offset, size):
        return bytes.fromhex(self.command('read',offset,size=size)['hex'])

    def addr(self, offset=0):
        return hex(self.base+offset)

    def close(self):
        self.process.terminate()
        self.process.wait(timeout=5)


def scan(target, t, mode='exact', value=None, value2=None, offset=0, size=64):
    params = dict(value_type=t,scan_type=mode,start_address=target.addr(offset),
        stop_address=target.addr(offset+size-1))
    if value is not None:
        params['value'] = value
    if value2 is not None:
        params['value2'] = value2
    return request('scan_first', **params)


def includes(page, address):
    return any(int(r['address'],16) == int(address,16) for r in page['results'])


def direct_tests(target):
    request('attach',pid=target.pid)
    error('scan_next',scan_type='exact',value='1')
    cases = [
        ('byte', '171', '<B', 171), ('2bytes','54321','<H',54321),
        ('4bytes','123456789','<I',123456789),
        ('8bytes','18446744073709551615','<Q',18446744073709551615),
        ('float','100','<f',100.0), ('double','100','<d',100.0),
        ('string','CE_MCP_STEP2_TEST',None,None),
    ]
    for i,(t,value,fmt,number) in enumerate(cases):
        off = i*128
        raw = struct.pack(fmt,number) if fmt else value.encode()+b'\0'
        target.poke(off,raw)
        got=request('read_value',address=target.addr(off),value_type=t)['value']
        assert got==value, (t,got,value)
        page=scan(target,t,value=value,offset=off,size=64)
        assert includes(page,target.addr(off)), (t,page)
        next_page=request('scan_next',scan_type='exact',value=value)
        assert includes(next_page,target.addr(off)), (t,next_page)
        request('write_value',address=target.addr(off),value_type=t,value=value)
        assert target.peek(off,len(raw))==raw
    # Signed writes, range rejection, and full precision 64-bit roundtrip.
    for t,width in [('byte',1),('2bytes',2),('4bytes',4),('8bytes',8)]:
        request('write_value',address=target.addr(1024),value_type=t,value='-1')
        assert target.peek(1024,width)==b'\xff'*width
        error('write_value',address=target.addr(1024),value_type=t,value=str(1 << (width*8)))
    # Float rounding: integer input 100 includes CE's rounded range, not bitwise equality.
    for t,fmt in [('float','<f'),('double','<d')]:
        target.poke(1100,struct.pack(fmt,100.25))
        assert includes(scan(target,t,value='100',offset=1100,size=32),target.addr(1100))
        assert not includes(scan(target,t,value='100.0',offset=1100,size=32),target.addr(1100))
    # Paging and live result values.
    target.poke(2048, struct.pack('<32I', *([7654321]*32)))
    result=scan(target,'4bytes',value='7654321',offset=2048,size=132)
    assert result['total']==32 and len(result['results'])==20, result
    assert len(request('scan_results',start=20,count=20)['results'])==12
    assert request('scan_results',start=32,count=20)['results']==[]
    target.poke(2048,struct.pack('<I',7654322))
    assert request('scan_results',start=0,count=1)['results'][0]['value']=='7654322'
    error('scan_results',start=-1,count=1)
    # Every supported numeric first and next comparison, including unknown snapshots.
    for mode,v,v2 in [('bigger','99',None),('smaller','101',None),('between','99','101')]:
        target.poke(2304,struct.pack('<I',100))
        assert includes(scan(target,'4bytes',mode,v,v2,2304,16),target.addr(2304))
    for mode,after,delta in [('increased',101,None),('decreased',99,None),
        ('changed',102,None),('unchanged',100,None),('increased_by',105,'5'),
        ('decreased_by',95,'5'),('exact',105,'105'),('bigger',105,'104'),
        ('smaller',95,'96'),('between',100,'99')]:
        target.poke(2304,struct.pack('<I',100))
        initial=scan(target,'4bytes','unknown',offset=2304,size=16)
        assert initial['snapshot'] and initial['scanned_bytes']>0 and initial['total']>0 and initial['total_kind']=='bytes'
        target.poke(2304,struct.pack('<I',after))
        params={'scan_type':mode}
        if delta is not None:
            params['value']=delta
        if mode=='between':
            params['value2']='101'
        result=request('scan_next',**params)
        assert includes(result,target.addr(2304)), (mode,result)
    error('scan_next',scan_type='unknown')
    # A new first scan replaces both type and candidate state.
    assert scan(target,'byte',value='199',offset=3000,size=16)['total']==0
    assert request('scan_results')['total']==0
    # Freeze verifies actual writes using independent target-side reads.
    target.poke(3072,struct.pack('<I',11))
    record=request('add_to_table',address=target.addr(3072),value_type='4bytes',
        description='MCP disposable freeze test',frozen=True,frozen_value='777')
    assert record['frozen'] and record['description']=='MCP disposable freeze test'
    time.sleep(.3)
    assert target.peek(3072,4)==struct.pack('<I',777)
    target.poke(3072,struct.pack('<I',12))
    time.sleep(.3)
    assert target.peek(3072,4)==struct.pack('<I',777)
    request('set_frozen',id=record['id'],frozen=True,value='888')
    time.sleep(.3)
    assert target.peek(3072,4)==struct.pack('<I',888)
    request('set_frozen',id=record['id'],frozen=False)
    target.poke(3072,struct.pack('<I',13))
    time.sleep(.3)
    assert target.peek(3072,4)==struct.pack('<I',13)
    request('set_frozen',id=record['id'],frozen=True)
    time.sleep(.3)
    assert target.peek(3072,4)==struct.pack('<I',13)
    request('set_frozen',id=record['id'],frozen=False)
    error('set_frozen',id=-1,frozen=True)
    error('read_value',address='0',value_type='4bytes')
    error('scan_first',value_type='string',scan_type='exact',value='')
    other=Target()
    try:
        request('set_frozen',id=record['id'],frozen=True,value='111')
        request('attach',pid=other.pid)
        error('scan_results')
        error('set_frozen',id=record['id'],frozen=True)
        target.poke(3072,struct.pack('<I',222))
        time.sleep(.3)
        assert target.peek(3072,4)==struct.pack('<I',222)
        request('attach',pid=target.pid)
        request('set_frozen',id=record['id'],frozen=True,value='333')
        time.sleep(.3)
        assert target.peek(3072,4)==struct.pack('<I',333)
        request('set_frozen',id=record['id'],frozen=False)
    finally:
        request('attach',pid=target.pid)
        other.close()
    for i,(t,value,fmt,number) in enumerate(cases):
        off=128*i
        raw=struct.pack(fmt,number) if fmt else value.encode()+b'\0'
        record=request('add_to_table',address=target.addr(off),value_type=t,
            description='MCP freeze '+t,frozen=True,frozen_value=value,length=len(raw)-1 if t=='string' else 256)
        target.poke(off,b'\0'*len(raw))
        time.sleep(.25)
        assert target.peek(off,len(raw))==raw,(t,target.peek(off,len(raw)))
        request('set_frozen',id=record['id'],frozen=False)
    # Default whole-process scan, with no explicit range.
    marker='CE_MCP_WHOLE_PROCESS_739125846'
    target.poke(3584,marker.encode()+b'\0')
    all_memory=request('scan_first',value_type='string',scan_type='exact',value=marker)
    found=includes(all_memory,target.addr(3584))
    for start in range(20,min(all_memory['total'],1000),200):
        found=found or includes(request('scan_results',start=start,count=200),target.addr(3584))
    assert found,all_memory
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        assert all(r['pid']==target.pid for r in pool.map(lambda _:request('ce_status'),range(16)))
    print('PASS real CE: all types/modes, uint64, rounding, paging/live values, replacement, all-type freeze, whole-process scan and errors')


async def mcp_tests(target):
    params=StdioServerParameters(command=sys.executable,args=['-B',str(ROOT/'server/server.py')],
                                 env=dict(os.environ))
    async with stdio_client(params) as streams:
        async with ClientSession(*streams) as client:
            await client.initialize()
            names={tool.name for tool in (await client.list_tools()).tools}
            expected={'ce_status','list_processes','attach','read_memory','scan_first','scan_next',
                'scan_results','read_value','write_value','add_to_table','set_frozen'}
            assert names>=expected,names
            async def call(name,**arguments):
                result=await client.call_tool(name,arguments)
                assert not result.is_error,result
                return json.loads(result.content[0].text)
            assert (await call('ce_status'))['pid']==target.pid
            assert any(p['pid']==target.pid for p in (await call('list_processes',filter='python'))['processes'])
            retained=await call('scan_results')
            await call('attach',pid=target.pid)
            assert await call('scan_results')==retained
            await call('write_value',address=target.addr(3200),value_type='4bytes',value='9876543')
            assert target.peek(3200,4)==struct.pack('<I',9876543)
            assert (await call('read_value',address=target.addr(3200),value_type='4bytes'))['value']=='9876543'
            assert (await call('read_memory',address=target.addr(3200),size=4))['hex']=='3F B4 96 00'
            result=await call('scan_first',value_type='4bytes',scan_type='exact',value='9876543',
                start_address=target.addr(3200),stop_address=target.addr(3263))
            assert includes(result,target.addr(3200))
            target.poke(3200,struct.pack('<I',9876544))
            assert includes(await call('scan_next',scan_type='increased_by',value='1'),target.addr(3200))
            assert includes(await call('scan_results',start=0,count=1),target.addr(3200))
            record=await call('add_to_table',address=target.addr(3200),value_type='4bytes',
                description='MCP stdio test')
            await call('set_frozen',id=record['id'],frozen=True,value='42')
            await asyncio.sleep(.3)
            assert target.peek(3200,4)==struct.pack('<I',42)
            await call('set_frozen',id=record['id'],frozen=False)
            bad=await client.call_tool('scan_next',{'scan_type':'unknown'})
            assert bad.is_error
    print('PASS MCP stdio: 11 schemas and all 11 tools with actual data assertions')


if __name__=='__main__':
    original=request('ce_status')['pid']
    target=Target()
    try:
        direct_tests(target)
        asyncio.run(mcp_tests(target))
    finally:
        # Attaching away clears our scan/unfreezes records before target exit; never write Tutorial.
        try:
            available=request('list_processes')['processes']
            if original and any(p['pid']==original and p['name']!='Tutorial-x86_64.exe' for p in available):
                request('attach',pid=original)
            else:
                request('attach',pid=__import__('os').getpid())
        finally:
            target.close()
