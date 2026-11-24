-- Stateless address/pointer helpers. APIs verified in the installed celua.txt.
local M={}
function M.hex(v) return string.format('0x%X',v) end
local function integer(v) return type(v)=='number' and v==math.floor(v) end
function M.resolve(v)
  assert(type(v)=='string' or integer(v), 'Invalid address')
  local a=type(v)=='string' and getAddressSafe(v) or v
  assert(a and a>=0, 'Address cannot be resolved')
  return a
end
function M.module_info(a,modules)
  for _,m in ipairs(modules or enumModules()) do
    if m.Size and a>=m.Address and a-m.Address<m.Size then
      return {is_static=true,module=m.Name,module_base=M.hex(m.Address),
        module_offset=M.hex(a-m.Address),module_path=m.PathToFile,
        symbol=m.Name..'+'..string.format('%X',a-m.Address)}
    end
  end
  return {is_static=false}
end
function M.offset_text(v)
  return v<0 and ('-'..M.hex(-v)) or M.hex(v)
end
function M.offsets(values)
  assert(type(values)=='table' and #values<=64, 'offsets must be an array of at most 64 entries')
  local count=0
  for k in pairs(values) do
    assert(integer(k) and k>=1 and k<=#values, 'offsets must be a dense array')
    count=count+1
  end
  assert(count==#values, 'offsets must be a dense array')
  local result={}
  for i,v in ipairs(values) do
    local n=v
    if type(v)=='string' then
      local sign=1
      if v:sub(1,1)=='-' then sign=-1; v=v:sub(2)
      elseif v:sub(1,1)=='+' then v=v:sub(2) end
      v=v:gsub('^0[xX]','')
      assert(v:match('^%x+$'), 'Invalid hexadecimal offset at index '..i)
      assert(#v:gsub('^0+','')<=8, 'Hexadecimal offset '..i..' exceeds 32 bits')
      n=tonumber(v,16)
      if n then n=sign*n end
    end
    assert(integer(n) and n>=-2147483648 and n<=2147483647,
      'Offset '..i..' must fit a signed 32-bit CE record offset')
    result[i]=n
  end
  return result
end
function M.trace(base,values)
  local offsets=M.offsets(values)
  local a=M.resolve(base)
  local size=targetIs64Bit() and 8 or 4
  local result={base=tostring(base),base_address=M.hex(a),pointer_size=size,
    offset_order='base_to_leaf',offsets=setmetatable({}, {isArray=true}),
    layers=setmetatable({}, {isArray=true})}
  for i,offset in ipairs(offsets) do
    local pointer
    if size==8 then pointer=readQword(a) else pointer=readInteger(a) end
    assert(integer(pointer) and pointer>0,
      'Pointer layer '..i..' at '..M.hex(a)..' is null, unreadable or outside user address space')
    local next_address=pointer+offset
    assert(next_address>=0 and (size==8 or next_address<=0xffffffff),
      'Pointer address overflow at layer '..i)
    result.offsets[i]=M.offset_text(offset)
    result.layers[i]={index=i,address=M.hex(a),pointer_value=M.hex(pointer),
      offset=M.offset_text(offset),next_address=M.hex(next_address)}
    a=next_address
  end
  result.address=M.hex(a)
  return result,a,offsets
end
local states={[0x1000]='MEM_COMMIT',[0x2000]='MEM_RESERVE',[0x10000]='MEM_FREE'}
local region_types={[0x20000]='MEM_PRIVATE',[0x40000]='MEM_MAPPED',[0x1000000]='MEM_IMAGE'}
local protections={[1]='PAGE_NOACCESS',[2]='PAGE_READONLY',[4]='PAGE_READWRITE',
  [8]='PAGE_WRITECOPY',[0x10]='PAGE_EXECUTE',[0x20]='PAGE_EXECUTE_READ',
  [0x40]='PAGE_EXECUTE_READWRITE',[0x80]='PAGE_EXECUTE_WRITECOPY',[0]='NONE'}
function M.info(a)
  local result=M.module_info(a)
  local r=getMemoryRegionInfo(a)
  assert(r and r.BaseAddress and r.RegionSize, 'Cannot query memory region')
  local p=r.Protect or 0
  local mode=p & 0xff
  local committed=r.State==0x1000
  local guard=(p & 0x100)~=0
  result.address=M.hex(a)
  result.is_dynamic=not result.is_static and committed
  if result.is_static then result.classification='static_module'
  elseif r.State==0x10000 then result.classification='free'
  elseif r.State==0x2000 then result.classification='reserved'
  elseif r.Type==0x20000 then result.classification='dynamic_private'
  elseif r.Type==0x40000 then result.classification='mapped'
  elseif r.Type==0x1000000 then result.classification='unlisted_image'
  else result.classification='unknown' end
  result.region={base_address=M.hex(r.BaseAddress),allocation_base=M.hex(r.AllocationBase or 0),
    size=tostring(r.RegionSize),size_hex=M.hex(r.RegionSize),state=states[r.State] or 'UNKNOWN',
    state_code=r.State,type=region_types[r.Type] or 'NONE',type_code=r.Type,
    protect=M.hex(p),protect_name=protections[mode] or 'UNKNOWN',
    allocation_protect=M.hex(r.AllocationProtect or 0),guard=guard,
    readable=committed and not guard and (mode==2 or mode==4 or mode==8 or mode==0x20 or mode==0x40 or mode==0x80),
    writable=committed and not guard and (mode==4 or mode==8 or mode==0x40 or mode==0x80),
    executable=committed and not guard and (mode==0x10 or mode==0x20 or mode==0x40 or mode==0x80),
    copy_on_write=mode==8 or mode==0x80,no_cache=(p & 0x200)~=0,write_combine=(p & 0x400)~=0,
    extra=r.Extra}
  return result
end
return M
