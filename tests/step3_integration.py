"""Real CE debugger tests against an independently compiled native fixture; never attach Tutorial."""
import asyncio
import concurrent.futures
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
from server import request, PIPE
from mcp import ClientSession, StdioServerParameters, stdio_client
from mcp.server.mcpserver.exceptions import ToolError
import win32con
import win32file


class Target:
    def __init__(self):
        self.process=subprocess.Popen([str(ROOT/'work/debug-fixture/ce_mcp_debug_target.exe')],
            stdin=subprocess.PIPE,stdout=subprocess.PIPE,text=True)
        self.info=json.loads(self.process.stdout.readline())
        self.pid=self.info['pid']
        for name in ['base','address','writer_a','writer_b','reader_a']:
            self.info[name]=int(self.info[name],16)
        self.handle=ctypes.windll.kernel32.OpenProcess(0x10|0x400,False,self.pid)
        assert self.handle

    def command(self,command):
        self.process.stdin.write(command+'\n'); self.process.stdin.flush()
        reply=self.process.stdout.readline()
        assert reply, f'Native target exited: {self.process.poll()}'
        return json.loads(reply)

    def read(self,address,size):
        buffer=ctypes.create_string_buffer(size)
        done=ctypes.c_size_t()
        ok=ctypes.windll.kernel32.ReadProcessMemory(self.handle,ctypes.c_void_p(address),
            buffer,size,ctypes.byref(done))
        assert ok and done.value==size
        return buffer.raw

    def close(self):
        ctypes.windll.kernel32.CloseHandle(self.handle)
        if self.process.poll() is None:
            self.process.stdin.write('exit\n'); self.process.stdin.flush()
            self.process.wait(timeout=5)

    def debug_registers(self):
        # Independent OS check: the CE descriptor list includes inactive retired records.
        k32=ctypes.windll.kernel32
        thread=k32.OpenThread(0x4a,False,self.info['tid'])
        assert thread
        suspended=False
        try:
            assert k32.SuspendThread(thread)!=0xffffffff
            suspended=True
            memory=ctypes.create_string_buffer(1248)
            aligned=(ctypes.addressof(memory)+15)&~15
            ctypes.c_uint32.from_address(aligned+48).value=0x100010
            assert k32.GetThreadContext(thread,ctypes.c_void_p(aligned)),ctypes.get_last_error()
            return struct.unpack('<6Q',ctypes.string_at(aligned+72,48))
        finally:
            if suspended:
                k32.ResumeThread(thread)
            k32.CloseHandle(thread)

    def protection(self,address):
        buffer=ctypes.create_string_buffer(48)
        assert ctypes.windll.kernel32.VirtualQueryEx(self.handle,ctypes.c_void_p(address),buffer,48)==48
        return struct.unpack_from('<I',buffer.raw,36)[0]


def expect_error(method,contains=None,**params):
    try:
        request(method,**params)
    except ToolError as exc:
        assert contains is None or contains in str(exc),str(exc)
        return
    raise AssertionError((method,params))


def wait_ready():
    end=time.monotonic()+10
    while time.monotonic()<end:
        state=request('ce_status')['debugger']
        if state['monitoring']:
            return state
        time.sleep(.025)
    raise AssertionError('Hardware watch did not become ready')


def check_watch(result,target,access,count):
    assert result['reason']=='completed',result
    assert result['breakpoint_removed'] and target.debug_registers()[-1]&0xff==0
    assert result['errors']==[] and result['unattributed_hits']==0
    assert result['total_hits']==count*(3 if access else 2),result
    entries={int(i['address'],16):i for i in result['instructions']}
    names=['writer_a','writer_b']+(['reader_a'] if access else [])
    assert set(entries)=={target.info[n] for n in names},entries
    for name in names:
        instruction=entries[target.info[name]]
        assert instruction['hit_count']==count
        assert int(instruction['stopped_ip'],16)==target.info[name]+2
        assert instruction['bytes']==('8B 01' if name=='reader_a' else '89 11')
        assert instruction['instruction'].lower().startswith('mov ')
        assert instruction['module']=='ce_mcp_debug_target.exe',instruction
        assert instruction['symbol']==f"ce_mcp_debug_target.exe+{target.info[name]-target.info['base']:X}"
        regs=instruction['registers']
        assert int(regs['RCX'],16)==target.info['address'],regs
        assert int(regs['RIP'],16)==target.info[name]+2
        if name=='writer_a':
            assert int(regs['RDX'],16)==0x11223344
        elif name=='writer_b':
            assert int(regs['RDX'],16)==0x55667700
        else:
            assert int(regs['RAX'],16)==0x55667700
    assert not request('ce_status')['debugger']['monitoring']
    print(f"PASS {result['mode']}: {len(entries)} exact instruction addresses, {result['total_hits']} hits, first registers, hardware registers cleared")


def direct_tests(target):
    request('attach',pid=target.pid)
    a=hex(target.info['address']); code=hex(target.info['writer_a'])
    decoded=request('disassemble',address=code,count=2)['instructions']
    assert [(i['bytes'],i['size']) for i in decoded]==[('89 11',2),('C3',1)],decoded
    assert target.read(target.info['writer_a'],3)==bytes.fromhex('89 11 C3')
    expect_error('find_what_writes',address=a,seconds=0)
    expect_error('find_what_accesses',address=hex(target.info['address']+1),seconds=.1,size=4)
    expect_error('disassemble',address='0',count=1)
    expect_error('restore_instruction',address=code)
    for access in [False,True,False]:
        method='find_what_accesses' if access else 'find_what_writes'
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            future=pool.submit(request,method,address=a,seconds=1.5,size=4)
            wait_ready()
            registers=target.debug_registers()
            assert registers[-1]&0xff and target.info['address'] in registers[:4],registers
            expect_error('find_what_writes','already active',address=a,seconds=.1)
            expect_error('attach','hardware watch',pid=os.getpid())
            expect_error('nop_instruction','hardware watch',address=code)
            assert target.command('run 7')=={'done':7}
            result=future.result(timeout=10)
        check_watch(result,target,access,7)
    empty=request('find_what_writes',address=a,seconds=.15,size=4)
    assert empty['total_hits']==0 and empty['instructions']==[] and empty['breakpoint_removed']
    # Client goes away before the watch ends; CE timer must still remove it.
    handle=win32file.CreateFile(PIPE,win32con.GENERIC_READ|win32con.GENERIC_WRITE,
        0,None,win32con.OPEN_EXISTING,0,None)
    payload=json.dumps({'method':'find_what_writes','params':{'address':a,'seconds':.4,'size':4}}).encode()
    win32file.WriteFile(handle,struct.pack('<I',len(payload))+payload)
    wait_ready()
    win32file.CloseHandle(handle)
    time.sleep(.7)
    state=request('ce_status')['debugger']
    assert not state['monitoring'] and target.debug_registers()[-1]&0xff==0
    assert target.command('run 1')=={'done':1}
    # Patch a genuine RX module .text instruction; verify bytes independently.
    original_protection=target.protection(target.info['writer_a'])
    assert original_protection==0x20,hex(original_protection)
    patch=request('nop_instruction',address=code)
    assert patch['size']==2 and patch['original_bytes']=='89 11' and patch['patched_bytes']=='90 90'
    assert target.read(target.info['writer_a'],3)==bytes.fromhex('90 90 C3')
    assert target.protection(target.info['writer_a'])==original_protection
    assert request('ce_status')['debugger']['saved_patches']==1
    expect_error('nop_instruction','overlaps',address=code)
    expect_error('nop_instruction','overlaps',address=hex(target.info['writer_a']+1))
    # With writer_a NOPed only writer_b is observed; restoring re-enables both.
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        future=pool.submit(request,'find_what_writes',address=a,seconds=1,size=4)
        wait_ready(); target.command('run 3'); watched=future.result(timeout=10)
    assert len(watched['instructions'])==1 and watched['instructions'][0]['hit_count']==3
    assert int(watched['instructions'][0]['address'],16)==target.info['writer_b']
    # Another edit is preserved rather than overwritten by restore.
    request('write_value',address=code,value_type='byte',value='204')
    expect_error('restore_instruction','differ',address=code)
    assert target.read(target.info['writer_a'],1)==b'\xcc'
    request('write_value',address=code,value_type='byte',value='144')
    restored=request('restore_instruction',address=code)
    assert restored['restored'] and target.read(target.info['writer_a'],3)==bytes.fromhex('89 11 C3')
    assert target.protection(target.info['writer_a'])==original_protection
    assert request('ce_status')['debugger']['saved_patches']==0
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        future=pool.submit(request,'find_what_writes',address=a,seconds=1,size=4)
        wait_ready(); target.command('run 2'); check_watch(future.result(timeout=10),target,False,2)
    print('PASS native debugger: exact addresses/counts/first registers, post-IP, zero/repeat/disconnected-client cleanup, module disassembly, RX NOP/restore/conflict and code behavior')


async def mcp_tests(target):
    parameters=StdioServerParameters(command=sys.executable,args=['-B',str(ROOT/'server/server.py')])
    async with stdio_client(parameters) as streams:
        async with ClientSession(*streams) as client:
            await client.initialize()
            names={t.name for t in (await client.list_tools()).tools}
            assert len(names)>=16 and {'find_what_writes','find_what_accesses','disassemble',
                'nop_instruction','restore_instruction'}<=names,names
            async def call(method,**params):
                result=await client.call_tool(method,params)
                assert not result.is_error,result
                return json.loads(result.content[0].text)
            a=hex(target.info['address']); code=hex(target.info['writer_a'])
            assert (await call('disassemble',address=code,count=2))['instructions'][0]['bytes']=='89 11'
            for access in [False,True]:
                task=asyncio.create_task(call('find_what_accesses' if access else 'find_what_writes',
                    address=a,seconds=1,size=4))
                await asyncio.to_thread(wait_ready)
                await asyncio.to_thread(target.command,'run 2')
                check_watch(await task,target,access,2)
            assert (await call('nop_instruction',address=code))['size']==2
            assert target.read(target.info['writer_a'],2)==b'\x90\x90'
            assert (await call('restore_instruction',address=code))['restored']
            assert target.read(target.info['writer_a'],2)==b'\x89\x11'
            bad=await client.call_tool('disassemble',{'address':'0','count':1})
            assert bad.is_error
            assert not (await client.call_tool('ce_status',{})).is_error
    print('PASS real MCP stdio: 16 tool schemas and all five debugger tools, including live hits and patches')


def process_exit_test():
    target=Target()
    try:
        request('attach',pid=target.pid)
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            future=pool.submit(request,'find_what_writes',address=hex(target.info['address']),seconds=2,size=4)
            wait_ready()
            target.close()
            result=future.result(timeout=10)
        assert result['breakpoint_removed'] and result['reason']=='process_exited',result
        assert not request('ce_status')['debugger']['monitoring']
        print('PASS watched process exits: no stranded watch or hardware resources')
    finally:
        if target.process.poll() is None:
            target.close()


if __name__=='__main__':
    target=Target()
    try:
        direct_tests(target)
        asyncio.run(mcp_tests(target))
    finally:
        target.close()
    process_exit_test()
