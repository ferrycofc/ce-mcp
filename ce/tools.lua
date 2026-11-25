-- Scan state and typed values live in CE, not in Python.
local M = {}
local here=assert(debug.getinfo(1,'S').source:match('^@(.+)[/\\][^/\\]+$'),
  'tools.lua must be loaded from a file')
local addressing=dofile(here..'/addressing.lua')
local types = {byte=vtByte, ['2bytes']=vtWord, ['4bytes']=vtDword,
  ['8bytes']=vtQword, float=vtSingle, double=vtDouble, string=vtString}
local widths = {byte=1, ['2bytes']=2, ['4bytes']=4, ['8bytes']=8}
local options = {exact=soExactValue, bigger=soBiggerThan, smaller=soSmallerThan,
  between=soValueBetween, unknown=soUnknownValue, increased=soIncreasedValue,
  decreased=soDecreasedValue, changed=soChanged, unchanged=soUnchanged,
  increased_by=soIncreasedValueBy, decreased_by=soDecreasedValueBy}
local first_modes = {exact=true, bigger=true, smaller=true, between=true, unknown=true}
local needs_value = {exact=true, bigger=true, smaller=true, between=true,
  increased_by=true, decreased_by=true}
local state, records = nil, {}
local function integer(v) return type(v)=='number' and v==math.floor(v) end
local function attached()
  local pid = getOpenedProcessID()
  assert(pid ~= 0, 'No process attached')
  return pid
end
local function address(v)
  assert(type(v)=='string' or integer(v), 'Invalid address')
  local a = type(v)=='string' and getAddressSafe(v) or v
  assert(a and a>=0, 'Address cannot be resolved')
  return a
end
local function check_type(t) assert(types[t], 'Unsupported value_type'); return types[t] end
local function text(v)
  assert(type(v)=='string' or type(v)=='number', 'Value must be a decimal string or number')
  if type(v)=='number' then
    assert(v==v and math.abs(v)~=math.huge, 'Value must be finite')
    assert(math.abs(v)<=9007199254740991, 'Large values must be passed as strings')
  end
  return tostring(v)
end
-- Decimal byte conversion avoids JSON/Lua floating point loss for full uint64 values.
local function integer_bytes(v, width)
  local s = text(v)
  local negative = s:sub(1,1)=='-'
  s = s:gsub('^[+-]', '')
  assert(s:match('^%d+$'), 'Integer value must use decimal digits')
  local bytes = {}
  for i=1,width do bytes[i]=0 end
  for digit in s:gmatch('.') do
    local carry=tonumber(digit)
    for i=1,width do
      local n=bytes[i]*10+carry
      bytes[i]=n%256; carry=math.floor(n/256)
    end
    assert(carry==0, 'Integer out of range')
  end
  if negative then
    assert(bytes[width]<128 or (bytes[width]==128 and (function()
      for i=1,width-1 do if bytes[i]~=0 then return false end end
      return true
    end)()), 'Signed integer out of range')
    local carry=1
    for i=1,width do
      local n=255-bytes[i]+carry; bytes[i]=n%256; carry=math.floor(n/256)
    end
  end
  return bytes
end
local function unsigned_decimal(bytes)
  local s='0'
  for i=#bytes,1,-1 do
    local carry=bytes[i]; local out=''
    for j=#s,1,-1 do
      local n=tonumber(s:sub(j,j))*256+carry
      out=tostring(n%10)..out; carry=math.floor(n/10)
    end
    while carry>0 do out=tostring(carry%10)..out; carry=math.floor(carry/10) end
    s=out:gsub('^0+', ''); if s=='' then s='0' end
  end
  return s
end
local function validated(t,v)
  check_type(t)
  if widths[t] then integer_bytes(v,widths[t]); return text(v) end
  if t=='string' then
    assert(type(v)=='string' and #v<=4096 and not v:find('\0',1,true), 'String must be at most 4096 UTF-8 bytes with no NUL')
    return v
  end
  local s=text(v); local n=tonumber(s)
  assert(n and n==n and math.abs(n)~=math.huge, 'Invalid finite floating point value')
  assert(t~='float' or math.abs(n)<=3.4028234663852886e38, 'float out of range')
  return s
end
local function read(t,a,length)
  check_type(t)
  if widths[t] then
    local b=readBytes(a,widths[t],true)
    assert(b and #b==widths[t], 'Memory unreadable or incomplete')
    return unsigned_decimal(b)
  end
  if t=='string' then
    length=length or 256
    assert(integer(length) and length>=1 and length<=4096, 'length must be 1..4096')
    local value=readString(a,length,false)
    assert(value~=nil, 'Memory unreadable')
    return value
  end
  local n
  if t=='float' then n=readFloat(a) else n=readDouble(a) end
  assert(n~=nil, 'Memory unreadable')
  return string.format('%.17g',n)
end
local function write(t,a,v)
  local s=validated(t,v)
  if widths[t] then
    local bytes=integer_bytes(s,widths[t])
    assert(writeBytes(a,bytes)==#bytes, 'Write failed or incomplete')
  elseif t=='float' then assert(writeFloat(a,tonumber(s)), 'Write failed')
  elseif t=='double' then assert(writeDouble(a,tonumber(s)), 'Write failed')
  else
    -- CE writeString does not append a terminator; include one explicitly.
    assert(writeString(a,s..'\0',false), 'Write failed')
  end
end
local function clear_scan()
  if not state then return end
  assert(not state.busy, 'Scan in progress')
  if state.found then state.found.destroy() end
  state.scan.destroy(); state=nil
end
local function current_scan()
  assert(state, 'No scan; call scan_first')
  assert(state.pid==attached(), 'Attached process changed; call scan_first')
  assert(not state.busy, 'Scan in progress')
  return state
end
function M.before_attach()
  assert(not state or not state.busy, 'Cannot attach during a scan')
  clear_scan()
  for id in pairs(records) do
    local r=getAddressList().getMemoryRecordByID(id)
    if r then r.Active=false end
  end
end
local function page(start,count)
  local s=current_scan()
  start=start or 0; count=count or 20
  assert(integer(start) and start>=0, 'start must be a zero-based nonnegative index')
  assert(integer(count) and count>=1 and count<=200, 'count must be 1..200')
  local results=setmetatable({}, {isArray=true})
  if s.scan.LastScanWasRegionScan then
    local progress=s.scan.getProgress()
    return {total=s.scan.FoundCount, start=start, results=results, value_type=s.value_type,
      snapshot=true, total_kind='bytes', scanned_bytes=progress.TotalAddressesToScan,
      message='CE unknown initial value stores a region snapshot. Filter with scan_next to enumerate addresses.'}
  end
  local modules=enumModules()
  for i=start,math.min(s.found.Count-1,start+count-1) do
    local a='0x'..s.found.Address[i]
    local info=addressing.module_info(address(a),modules)
    local ok,value=pcall(read,s.value_type,address(a),s.string_length)
    results[#results+1]={index=i,address=a,value=ok and value or nil,
      error=not ok and tostring(value) or nil,is_static=info.is_static,
      symbol=info.symbol,module=info.module,module_offset=info.module_offset}
  end
  return {total=s.found.Count, total_kind='addresses', start=start, results=results, value_type=s.value_type}
end
local function scan_inputs(p,t,first)
  local mode=p.scan_type
  assert(options[mode]~=nil, 'Unsupported scan_type')
  if first then assert(first_modes[mode], 'Comparison mode requires scan_next')
  else assert(mode~='unknown', 'unknown is an initial scan only; use scan_first') end
  assert(t~='string' or mode=='exact', 'CE string scans support exact only')
  local v1,v2='',''
  if needs_value[mode] then v1=validated(t,p.value) end
  assert(t~='string' or #v1>0, 'String scan value must not be empty')
  if mode=='between' then
    v2=validated(t,p.value2)
    assert(tonumber(v1)<=tonumber(v2), 'between requires value <= value2')
  end
  return options[mode],v1,v2
end
local function begin_scan(p,first)
  attached()
  assert(not state or not state.busy, 'Scan in progress')
  local t=first and p.value_type or current_scan().value_type
  check_type(t)
  local option,v1,v2=scan_inputs(p,t,first)
  if first then
    local low=address(p.start_address or '0')
    local high=address(p.stop_address or (targetIs64Bit() and '7FFFFFFFFFFFFFFF' or 'FFFFFFFF'))
    assert(low<=high, 'Invalid scan range')
    clear_scan()
    state={scan=createMemScan(),pid=attached(),value_type=t,string_length=t=='string' and math.max(1,#v1) or nil}
    state.scan.firstScan(option,types[t],rtRounded,v1,v2,low,high,'',fsmNotAligned,'1',false,true,false,true)
  else
    state.found.deinitialize()
    state.scan.nextScan(option,rtRounded,v1,v2,false,true,false,true,false)
    if t=='string' then state.string_length=math.max(1,#v1) end
  end
  state.busy=true
  return {__scan=state.scan}
end
function M.finish_scan(ok,err)
  assert(state and state.busy, 'Scan state lost')
  state.busy=false
  if not ok or (state.scan.ErrorString and state.scan.ErrorString~='') then
    local message=err or state.scan.ErrorString
    state.scan.terminateScan(true); clear_scan()
    error('Scan failed: '..tostring(message))
  end
  state.found=state.found or createFoundList(state.scan)
  state.found.initialize()
  return page(0,20)
end
local function record_result(r)
  local value=r.Value -- Refresh native resolution before reading CurrentAddress.
  local offsets=setmetatable({}, {isArray=true})
  local ce_offsets=setmetatable({}, {isArray=true})
  local texts=setmetatable({}, {isArray=true})
  for i=0,r.OffsetCount-1 do
    ce_offsets[i+1]=addressing.offset_text(r.Offset[i])
    texts[i+1]=r.OffsetText[i]
    offsets[r.OffsetCount-i]=ce_offsets[i+1]
  end
  return {id=r.ID, address=r.Address, description=r.Description, value=value, frozen=r.Active,
    is_pointer=r.OffsetCount>0,offset_count=r.OffsetCount,offsets=offsets,offset_order='base_to_leaf',
    ce_offsets=ce_offsets,ce_offset_texts=texts,resolved_address=addressing.hex(r.CurrentAddress)}
end
function M.dispatch(method,p)
  if method=='address_info' then
    attached(); return true,addressing.info(addressing.resolve(p.address))
  end
  if method=='read_pointer' or method=='write_pointer' then
    attached(); check_type(p.value_type)
    local result,a=addressing.trace(p.base,p.offsets)
    if method=='write_pointer' then write(p.value_type,a,p.value) end
    result.value_type=p.value_type
    result.value=read(p.value_type,a,p.length or (p.value_type=='string' and p.value and math.max(1,#p.value) or nil))
    return true,result
  end
  if method=='scan_first' then return true,begin_scan(p,true) end
  if method=='scan_next' then return true,begin_scan(p,false) end
  if method=='scan_results' then return true,page(p.start,p.count) end
  if method=='read_value' or method=='write_value' then
    attached(); local a=address(p.address); check_type(p.value_type)
    if method=='write_value' then write(p.value_type,a,p.value) end
    return true,{address=string.format('0x%X',a),value_type=p.value_type,
      value=read(p.value_type,a,p.length or (p.value_type=='string' and p.value and math.max(1,#p.value) or nil))}
  end
  if method=='add_to_table' or method=='add_pointer_to_table' then
    local pid=attached(); check_type(p.value_type)
    local pointer=method=='add_pointer_to_table'
    local a,offsets
    if pointer then
      local trace
      trace,a,offsets=addressing.trace(p.base,p.offsets)
      assert(#offsets>0, 'A CE pointer record requires at least one offset; use [0] for one dereference')
    else a=address(p.address) end
    assert(p.description==nil or type(p.description)=='string', 'Invalid description')
    assert(p.frozen==nil or type(p.frozen)=='boolean', 'frozen must be boolean')
    local value=p.frozen_value
    if pointer then value=p.value end
    if value~=nil then value=validated(p.value_type,value) end
    local length=p.length or (p.value_type=='string' and value and math.max(1,#value) or 256)
    if p.value_type=='string' then
      assert(integer(length) and length>=1 and length<=4096, 'length must be 1..4096')
      assert(not value or #value<=length, 'Frozen string exceeds record length')
    end
    local actual=read(p.value_type,a,length)
    local r=getAddressList().createMemoryRecord()
    local ok,result=pcall(function()
      r.Type=types[p.value_type]
      if pointer then
        r.Address=type(p.base)=='string' and p.base or string.format('%X',p.base)
        r.OffsetCount=#offsets
        for i=0,#offsets-1 do r.Offset[i]=offsets[#offsets-i] end
        local refreshed=r.Value
        assert(r.CurrentAddress==a, 'Native CE pointer offset order/resolution does not match traced address')
      else r.Address=string.format('%X',a) end
      r.Description=p.description or 'MCP '..r.Address
      if p.value_type=='string' then r.String.Size=length; r.String.Unicode=false end
      if pointer and value~=nil then
        write(p.value_type,a,value)
        actual=read(p.value_type,a,length)
      end
      if p.frozen then
        r.Value=value or actual; r.Active=true
        assert(r.Active, 'Cannot freeze record')
      end
      records[r.ID]={pid=pid,value_type=p.value_type,length=length}
      return record_result(r)
    end)
    if not ok then r.Active=false; r.destroy(); error(result) end
    return true,result
  end
  if method=='set_frozen' then
    local pid=attached()
    assert(integer(p.id), 'id must be a memory record ID')
    assert(type(p.frozen)=='boolean', 'frozen must be boolean')
    local info=records[p.id]
    assert(info and info.pid==pid, 'Record not owned by this bridge/current process')
    local r=getAddressList().getMemoryRecordByID(p.id)
    assert(r, 'Memory record no longer exists')
    if p.value~=nil then
      local value=validated(info.value_type,p.value)
      assert(p.frozen, 'value requires frozen=true')
      assert(info.value_type~='string' or #value<=info.length, 'Frozen string exceeds record length')
      r.Value=value
    end
    r.Active=p.frozen
    assert(r.Active==p.frozen, 'Cannot change frozen state')
    return true,record_result(r)
  end
  return false
end
return M
