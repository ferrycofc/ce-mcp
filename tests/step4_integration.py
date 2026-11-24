"""Pointer widths/order/retargeting and memory-region tests using native x64 and x86 targets."""
import asyncio
import ctypes
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import time

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'server'))
from server import request
from mcp import ClientSession, StdioServerParameters, stdio_client
from mcp.server.mcpserver.exceptions import ToolError

OFFSETS=['20','-10','38']


class Target:
    def __init__(self,arch):
        self.arch=arch
        self.module=f'ce_mcp_pointer_{arch}.exe'
        self.process=subprocess.Popen([str(ROOT/f'work/pointer-fixture/{arch}/{self.module}')],
            stdin=subprocess.PIPE,stdout=subprocess.PIPE,text=True)
        self.info=json.loads(self.process.stdout.readline())
        self.pid=self.info['pid']
        for name in ['base','root','node_a','node_b','leaf0','leaf1','static_value','code','reserved','guarded','mapped']:
            self.info[name]=int(self.info[name],16)
        self.base=f"{self.module}+{self.info['root']-self.info['base']:X}"
        self.k32=ctypes.WinDLL('kernel32',use_last_error=True)
        self.k32.OpenProcess.restype=ctypes.c_void_p
        self.handle=self.k32.OpenProcess(0x400,False,self.pid)
        assert self.handle

    def command(self,command):
        self.process.stdin.write(command+'\n'); self.process.stdin.flush()
        raw=self.process.stdout.readline()
        assert raw,f'Native fixture exited: {self.process.poll()}'
        result=json.loads(raw)
        assert 'error' not in result,result
        return result

    def put(self,which,data): self.command(f'put {which} {data.hex()}')
    def peek(self,which,size): return bytes.fromhex(self.command(f'bytes {which} {size}')['hex'])

    def region(self,address):
        buffer=ctypes.create_string_buffer(48)
        assert self.k32.VirtualQueryEx(ctypes.c_void_p(self.handle),ctypes.c_void_p(address),buffer,48)==48
        raw=buffer.raw
        return dict(base=struct.unpack_from('<Q',raw)[0],allocation_base=struct.unpack_from('<Q',raw,8)[0],
            size=struct.unpack_from('<Q',raw,24)[0],state=struct.unpack_from('<I',raw,32)[0],
            protect=struct.unpack_from('<I',raw,36)[0],type=struct.unpack_from('<I',raw,40)[0])

    def close(self):
        self.k32.CloseHandle(ctypes.c_void_p(self.handle))
        if self.process.poll() is None:
            self.process.stdin.write('exit\n'); self.process.stdin.flush()
            self.process.wait(timeout=5)


def error(method,contains=None,**params):
    try:
        request(method,**params)
    except ToolError as exc:
        assert contains is None or contains in str(exc),str(exc)
        return
    raise AssertionError((method,params))


def chain(target,method='read_pointer',**kwargs):
    return request(method,base=target.base,offsets=OFFSETS,value_type=kwargs.pop('value_type','4bytes'),**kwargs)


def trace_assertions(t,result,leaf=0):
    i=t.info
    assert result['pointer_size']==i['pointer_size']==(8 if t.arch=='x64' else 4)
    assert int(result['base_address'],16)==i['root']
    assert result['offset_order']=='base_to_leaf' and result['offsets']==['0x20','-0x10','0x38']
    expected=[(i['root'],i['node_a'],i['node_a']+0x20),
        (i['node_a']+0x20,i['node_b']+0x10,i['node_b']),
        (i['node_b'],i[f'leaf{leaf}']-0x38,i[f'leaf{leaf}'])]
    assert len(result['layers'])==3
    for entry,(address,pointer,next_address) in zip(result['layers'],expected):
        assert tuple(int(entry[k],16) for k in ['address','pointer_value','next_address'])==(address,pointer,next_address)
    assert int(result['address'],16)==i[f'leaf{leaf}']


def scan_tests(t):
    i=t.info
    for address,value,is_static in [(i['static_value'],0x53799127,True),(i['leaf0'],0x12345678,False)]:
        result=request('scan_first',value_type='4bytes',scan_type='exact',value=str(value),
            start_address=hex(address),stop_address=hex(address+8))
        assert result['total']==1,result
        for page in [result,request('scan_results',start=0,count=1),request('scan_next',scan_type='unchanged')]:
            entry=page['results'][0]
            assert int(entry['address'],16)==address and entry['is_static']==is_static,entry
            if is_static:
                assert entry['module']==t.module
                assert int(entry['module_offset'],16)==address-i['base']
                assert entry['symbol']==f"{t.module}+{address-i['base']:X}"
            else:
                assert 'symbol' not in entry and 'module' not in entry


def region_tests(t):
    for name,classification in [('root','static_module'),('code','static_module'),
        ('leaf0','dynamic_private'),('reserved','reserved'),('guarded','dynamic_private'),('mapped','mapped')]:
        address=t.info[name]
        result=request('address_info',address=hex(address))
        native=t.region(address); region=result['region']
        assert result['classification']==classification,(name,result)
        assert int(region['base_address'],16)==native['base']
        assert int(region['allocation_base'],16)==native['allocation_base']
        assert int(region['size'])==native['size']
        assert region['state_code']==native['state'] and region['type_code']==native['type']
        assert int(region['protect'],16)==native['protect']
        assert result['is_static']==(name in ['root','code'])
        if name=='code': assert region['executable'] and not region['writable']
        if name=='leaf0': assert region['readable'] and region['writable'] and not region['executable']
        if name=='guarded': assert region['guard'] and not region['readable'] and not region['writable']
        if name=='reserved': assert not region['readable'] and not result['is_dynamic']
    assert request('address_info',address='0')['classification']=='free'
    root=request('address_info',address=t.base)
    assert root['symbol']==t.base and int(root['address'],16)==t.info['root']


def direct_tests(t):
    request('attach',pid=t.pid)
    if t.arch=='x64':
        assert t.info['node_a']>0xffffffff and t.info['node_b']>0xffffffff
    first=chain(t)
    trace_assertions(t,first)
    assert first['value']==str(0x12345678)
    for offsets in [[32,-16,56],['0x20','-0x10','0x38']]:
        assert request('read_pointer',base=t.base,offsets=offsets,value_type='4bytes')==first
    scan_tests(t)
    region_tests(t)
    cases=[('byte','171',b'\xab'),('2bytes','54321',struct.pack('<H',54321)),
        ('4bytes','123456789',struct.pack('<I',123456789)),
        ('8bytes','18446744073709551615',b'\xff'*8),
        ('float','100.25',struct.pack('<f',100.25)),('double','100.25',struct.pack('<d',100.25)),
        ('string','CE指针链','CE指针链'.encode()+b'\0')]
    for value_type,value,raw in cases:
        t.put(0,raw)
        result=chain(t,value_type=value_type)
        trace_assertions(t,result)
        assert result['value']==value,(value_type,result)
        t.put(0,b'\0'*len(raw))
        result=chain(t,'write_pointer',value_type=value_type,value=value)
        assert result['value']==value and t.peek(0,len(raw))==raw
    # Signed final writes retain the same typed-memory semantics.
    chain(t,'write_pointer',value_type='4bytes',value='-1')
    assert t.peek(0,4)==b'\xff'*4
    t.put(0,struct.pack('<I',123))
    record=chain(t,'add_pointer_to_table',description='Native pointer order test',value='777',frozen=True)
    assert record['is_pointer'] and record['offset_count']==3 and record['address']==t.base
    assert record['offsets']==['0x20','-0x10','0x38']
    assert record['ce_offsets']==['0x38','-0x10','0x20'],record
    assert record['ce_offset_texts']==['38','-10','20'],record
    assert int(record['resolved_address'],16)==t.info['leaf0']
    time.sleep(.3)
    assert t.peek(0,4)==struct.pack('<I',777)
    t.put(0,struct.pack('<I',1));time.sleep(.3)
    assert t.peek(0,4)==struct.pack('<I',777)
    # Change a middle pointer only: fixed-address records would fail this test.
    t.command('select 1'); time.sleep(.8)
    t.put(0,struct.pack('<I',5555));t.put(1,struct.pack('<I',1));time.sleep(.4)
    assert t.peek(0,4)==struct.pack('<I',5555)
    assert t.peek(1,4)==struct.pack('<I',777)
    resolved=request('set_frozen',id=record['id'],frozen=False)
    assert int(resolved['resolved_address'],16)==t.info['leaf1']
    trace_assertions(t,chain(t),leaf=1)
    t.put(1,struct.pack('<I',888));time.sleep(.3)
    assert t.peek(1,4)==struct.pack('<I',888)
    request('set_frozen',id=record['id'],frozen=True)
    t.put(1,struct.pack('<I',0));time.sleep(.3)
    assert t.peek(1,4)==struct.pack('<I',888)
    request('set_frozen',id=record['id'],frozen=False)
    t.command('select 0')
    string_record=chain(t,'add_pointer_to_table',value_type='string',value='POINTER_RECORD',length=32)
    assert string_record['value']=='POINTER_RECORD' and not string_record['frozen']
    assert t.peek(0,15)==b'POINTER_RECORD\0'
    direct=request('read_pointer',base=hex(t.info['leaf0']),offsets=[],value_type='string')
    assert direct['layers']==[] and direct['value']=='POINTER_RECORD'
    error('add_pointer_to_table','at least one',base=t.base,offsets=[],value_type='4bytes')
    for bad in [['nothex'],[2**31],['FFFFFFFFFFFFFFFF'],[1.5]]:
        error('read_pointer',base=t.base,offsets=bad,value_type='4bytes')
    error('read_pointer',base='__missing_pointer_module__+10',offsets=OFFSETS,value_type='4bytes')
    old=t.peek(0,16)
    t.command('null 1')
    error('write_pointer','layer 1',base=t.base,offsets=OFFSETS,value_type='4bytes',value='999')
    assert t.peek(0,16)==old
    t.command('null 0');t.command('middle_null')
    error('read_pointer','layer 3',base=t.base,offsets=OFFSETS,value_type='4bytes')
    t.command('select 0')
    print(f'PASS {t.arch}: actual {t.info["pointer_size"]}-byte dereferences, seven final types, native CE offset order, middle-pointer retarget/freeze, region OS checks, static/dynamic scan metadata and errors')


async def mcp_tests(t):
    parameters=StdioServerParameters(command=sys.executable,args=['-B',str(ROOT/'server/server.py')])
    async with stdio_client(parameters) as streams:
        async with ClientSession(*streams) as client:
            await client.initialize()
            names={tool.name for tool in (await client.list_tools()).tools}
            assert len(names)==20 and {'read_pointer','write_pointer','add_pointer_to_table','address_info'}<=names,names
            async def call(method,**params):
                result=await client.call_tool(method,params)
                assert not result.is_error,result
                return json.loads(result.content[0].text)
            await call('write_pointer',base=t.base,offsets=OFFSETS,value_type='4bytes',value='654321')
            assert t.peek(0,4)==struct.pack('<I',654321)
            result=await call('read_pointer',base=t.base,offsets=OFFSETS,value_type='4bytes')
            trace_assertions(t,result)
            assert result['value']=='654321'
            record=await call('add_pointer_to_table',base=t.base,offsets=OFFSETS,value_type='4bytes',
                description='MCP native pointer',value='111',frozen=True)
            assert record['is_pointer'] and record['ce_offset_texts']==['38','-10','20']
            await asyncio.sleep(.3)
            assert t.peek(0,4)==struct.pack('<I',111)
            t.command('select 1');await asyncio.sleep(.8)
            assert t.peek(1,4)==struct.pack('<I',111)
            await call('set_frozen',id=record['id'],frozen=False)
            assert (await call('address_info',address=t.base))['symbol']==t.base
            static=t.info['static_value']
            await call('scan_first',value_type='4bytes',scan_type='exact',value=str(0x53799127),
                start_address=hex(static),stop_address=hex(static+8))
            entry=(await call('scan_results',start=0,count=1))['results'][0]
            assert entry['is_static'] and entry['symbol']==f"{t.module}+{static-t.info['base']:X}"
            bad=await client.call_tool('read_pointer',{'base':t.base,'offsets':['bad-offset'],'value_type':'4bytes'})
            assert bad.is_error
            assert not (await client.call_tool('ce_status',{})).is_error
    print(f'PASS {t.arch} MCP stdio: 20 schemas, all four pointer/address tools, native pointer record and scan metadata')


if __name__=='__main__':
    for arch in ['x64','x86']:
        target=Target(arch)
        try:
            direct_tests(target)
            asyncio.run(mcp_tests(target))
        finally:
            try:
                request('attach',pid=os.getpid()) # Unfreeze every bridge record; never attach Tutorial.
            finally:
                target.close()
