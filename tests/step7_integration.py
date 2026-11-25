"""Address-table integration in an isolated CE and self-authored pointer target."""
import asyncio
import json
import os
from pathlib import Path
import subprocess
import sys
import time

ROOT=Path(__file__).resolve().parents[1]
assert os.environ.get('CE_MCP_PIPE_NAME')=='ce_mcp_step7'
sys.path.insert(0,str(ROOT/'server'))
from server import request
from mcp import ClientSession, StdioServerParameters, stdio_client
from mcp.server.mcpserver.exceptions import ToolError


def test():
    target=subprocess.Popen([str(ROOT/'work/pointer-fixture/x64/ce_mcp_pointer_x64.exe')],
        stdin=subprocess.PIPE,stdout=subprocess.PIPE,text=True)
    info=json.loads(target.stdout.readline())
    try:
        assert request('attach',pid=info['pid'])['pid']==info['pid']
        assert request('list_table')['count']==0
        base=f"ce_mcp_pointer_x64.exe+{int(info['root'],16)-int(info['base'],16):X}"
        pointer=request('add_pointer_to_table',base=base,offsets=['20','-10','38'],
            value_type='4bytes',description='Fixture pointer')
        number=request('add_to_table',address=info['static_value'],value_type='4bytes',
            description='Fixture number')
        original='53799127'
        site=info['static_value'][2:].upper()
        script=f'''[ENABLE]
{site}:
dd 11223344
[DISABLE]
{site}:
dd {original}
'''
        aa=request('add_script_record',description='Fixture script',script=script)
        listing=request('list_table')
        assert listing['count']==3,listing
        records={r['id']:r for r in listing['records']}
        assert records[pointer['id']]['is_pointer']
        assert records[pointer['id']]['offsets']==['20','-10','38']
        assert records[number['id']]['value']==str(int(original,16))
        assert records[aa['id']]['is_script'] and not records[aa['id']]['active']
        assert request('set_record_active',id=aa['id'],active=True)['active']
        assert request('read_value',address=info['static_value'],value_type='4bytes')['value']==str(0x11223344)
        assert not request('set_record_active',id=aa['id'],active=False)['active']
        assert request('read_value',address=info['static_value'],value_type='4bytes')['value']==str(int(original,16))
        assert request('set_record_active',id=number['id'],active=True)['active']
        request('write_value',address=info['static_value'],value_type='4bytes',value='7')
        for _ in range(20):
            current=request('read_value',address=info['static_value'],value_type='4bytes')['value']
            if current==str(int(original,16)): break
            time.sleep(.1)
        else: raise AssertionError('CE did not freeze the numeric record')
        assert not request('set_record_active',id=number['id'],active=False)['active']
        assert request('set_record_active',id=pointer['id'],active=True)['active']
        target.stdin.write('put 0 01000000\n');target.stdin.flush()
        assert json.loads(target.stdout.readline())=={}
        for _ in range(20):
            if int.from_bytes(bytes.fromhex(json.loads(command(target,'bytes 0 4'))['hex']),'little')==0x12345678:
                break
            time.sleep(.1)
        else: raise AssertionError('CE did not freeze the pointer record')
        assert not request('set_record_active',id=pointer['id'],active=False)['active']
        target.stdin.write('put 0 02000000\n');target.stdin.flush()
        assert json.loads(target.stdout.readline())=={}
        assert request('read_value',address=info['leaf0'],value_type='4bytes')['value']=='2'
        table_file=ROOT/'work/step7-fixture/table.ct'
        table_file.parent.mkdir(parents=True,exist_ok=True)
        saved=request('save_table',path=str(table_file))
        assert saved['count']==3 and saved['size']>0,saved
        data=table_file.read_text(encoding='utf-8-sig')
        assert '<CheatEntry>' in data and '<AssemblerScript>' in data,data[:500]
        loaded=request('load_table',path=str(table_file))
        assert loaded['count']==3,loaded
        by_description={r['description']:r for r in loaded['records']}
        assert by_description['Fixture pointer']['is_pointer']
        assert by_description['Fixture pointer']['offsets']==['20','-10','38']
        assert by_description['Fixture script']['is_script']
        loaded_script=by_description['Fixture script']['id']
        assert request('set_record_active',id=loaded_script,active=True)['active']
        assert request('read_value',address=info['static_value'],value_type='4bytes')['value']==str(0x11223344)
        assert not request('set_record_active',id=loaded_script,active=False)['active']
        merged=request('load_table',path=str(table_file),merge=True)
        assert merged['count']==6,merged
        try:request('set_record_active',id=99999999,active=True)
        except ToolError as exc: assert 'not found' in str(exc)
        else:raise AssertionError('missing record ID succeeded')
        nested=request('run_lua',code='''
local a=getAddressList()
local g=a.createMemoryRecord();g.Description='Group';g.IsGroupHeader=true
local c=a.createMemoryRecord();c.Description='Child';c.Address='0';c.appendToEntry(g)
return g.ID,c.ID
''')
        assert nested['ok'],nested
        group_id,child_id=nested['returns']
        grouped={r['id']:r for r in request('list_table')['records']}
        assert grouped[group_id]['is_group'] and grouped[child_id]['parent_id']==group_id
        asyncio.run(sdk_test())
        print('table records, AA activation, pointer freeze, CT roundtrip, merge verified')
    finally:
        if target.poll() is None:
            target.stdin.write('exit\n');target.stdin.flush();target.wait(5)


def command(target,text):
    target.stdin.write(text+'\n');target.stdin.flush()
    return target.stdout.readline()


async def sdk_test():
    params=StdioServerParameters(command=sys.executable,args=['-B',str(ROOT/'server/server.py')],env={**os.environ})
    async with stdio_client(params) as streams:
        async with ClientSession(*streams) as client:
            await client.initialize()
            names={tool.name for tool in (await client.list_tools()).tools}
            expected={'list_table','add_script_record','set_record_active','save_table','load_table'}
            assert expected<=names and len(names)==33,names
            result=await client.call_tool('list_table',{})
            assert not result.is_error and json.loads(result.content[0].text)['count']==8
            print('MCP SDK: 33 tools')


if __name__=='__main__': test()
