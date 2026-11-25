-- Address-list and .CT operations use CE 7.7's native MemoryRecord API.
local M = {}

local function integer(v)
  return type(v)=='number' and v==math.floor(v)
end

local function hex(v)
  if type(v)=='number' then return string.format('0x%X',v) end
end

local function record(r)
  local script=r.Type==vtAutoAssembler
  local pointer=r.OffsetCount>0
  local offsets=setmetatable({}, {isArray=true})
  local ce_offsets=setmetatable({}, {isArray=true})
  for i=0,r.OffsetCount-1 do
    local offset=r.OffsetText[i]
    ce_offsets[i+1]=offset
    offsets[r.OffsetCount-i]=offset
  end
  local parent=r.Parent
  local item={id=r.ID, description=r.Description, address=r.Address,
    address_string=r.AddressString, type=r.VarType, type_id=r.Type,
    active=r.Active, is_script=script, is_pointer=pointer,
    is_group=r.IsGroupHeader, parent_id=parent and parent.ID or nil,
    offsets=offsets, ce_offsets=ce_offsets, offset_order='base_to_leaf'}
  if not script and not item.is_group then
    local ok,value=pcall(function() return r.Value end)
    if ok then item.value=value else item.value_error=tostring(value) end
    local resolved,addr=pcall(function() return r.CurrentAddress end)
    if resolved then item.resolved_address=hex(addr) end
  end
  return item
end

local function listing()
  local list=getAddressList()
  local items=setmetatable({}, {isArray=true})
  for i=0,list.Count-1 do items[#items+1]=record(list.MemoryRecord[i]) end
  return {count=#items, records=items}
end

local function table_path(path)
  assert(type(path)=='string' and #path>0 and #path<=32767,
    'path must be a nonempty .CT filename')
  assert(path:lower():match('%.ct$'), 'path must end in .CT')
  assert(path:match('^%a:[/\\]') or path:match('^[/\\][/\\]'),
    'path must be absolute')
  return path
end

function M.dispatch(method,p)
  if method=='list_table' then return true,listing() end
  if method=='add_script_record' then
    assert(type(p.description)=='string' and #p.description>0,
      'description must be nonempty')
    assert(type(p.script)=='string' and #p.script>0 and #p.script<=262144,
      'script must be 1..262144 characters')
    local upper=p.script:upper()
    assert(upper:find('%[ENABLE%]') and upper:find('%[DISABLE%]'),
      'script must contain [ENABLE] and [DISABLE] sections')
    local r=getAddressList().createMemoryRecord()
    local ok,result=pcall(function()
      r.Type=vtAutoAssembler
      r.Description=p.description
      r.Script=p.script
      return record(r)
    end)
    if not ok then r.destroy();error(result) end
    return true,result
  end
  if method=='set_record_active' then
    assert(integer(p.id) and p.id>=0, 'id must be a memory record ID')
    assert(type(p.active)=='boolean', 'active must be boolean')
    local r=getAddressList().getMemoryRecordByID(p.id)
    assert(r,'Memory record not found')
    if r.Active~=p.active then
      r.Active=p.active
      assert(r.Active==p.active, 'CE refused to change record activation state')
    end
    return true,record(r)
  end
  if method=='save_table' then
    local path=table_path(p.path)
    local result=saveTable(path)
    assert(result~=false, 'CE failed to save table')
    local f=io.open(path,'rb')
    assert(f, 'CE did not create the .CT file')
    local size=f:seek('end');f:close()
    return true,{path=path,size=size,count=getAddressList().Count}
  end
  if method=='load_table' then
    local path=table_path(p.path)
    assert(p.merge==nil or type(p.merge)=='boolean', 'merge must be boolean')
    local f=io.open(path,'rb')
    assert(f, 'File does not exist or cannot be read')
    f:close()
    local result=loadTable(path,p.merge or false)
    assert(result~=false, 'CE failed to load table')
    local data=listing()
    data.path=path;data.merge=p.merge or false
    return true,data
  end
  return false
end

return M
