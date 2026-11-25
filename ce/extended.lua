-- CE 7.7 APIs: celua.txt and the installed autorun/monoscript.lua.
local M={}
local A=dofile([[E:/workspace/ce-mcp/ce/addressing.lua]])
local function array() return setmetatable({}, {isArray=true}) end
local function attached()
  local pid=getOpenedProcessID()
  assert(pid~=0 and getProcesslist()[pid], 'No live process attached')
  return pid
end
local function finite(n) return type(n)=='number' and n==n and n~=math.huge and n~=-math.huge end
local function safe(v,seen,depth)
  local t=type(v)
  if t=='nil' then return {type='nil'} end
  if t=='boolean' then return v end
  if t=='string' then
    if #v>65536 then return v:sub(1,65536)..'<truncated>' end
    return v
  end
  if t=='number' then
    if not finite(v) or (v==math.floor(v) and math.abs(v)>9007199254740991) then
      return tostring(v)
    end
    return v
  end
  if t~='table' then return {type=t,value=tostring(v)} end
  seen=seen or {};depth=depth or 0
  if seen[v] or depth>=6 then return {type='table',value='<cycle or depth limit>'} end
  seen[v]=true
  local sequence=true
  local length=#v
  for k in pairs(v) do
    if type(k)~='number' or k~=math.floor(k) or k<1 or k>length then
      sequence=false;break
    end
  end
  local out=sequence and array() or {}
  local count=0
  if sequence then
    for i=1,math.min(length,100) do out[i]=safe(v[i],seen,depth+1) end
  else
    for k,x in pairs(v) do
      count=count+1
      if count>100 then out['...']='truncated';break end
      out[type(k)=='number' and ('#'..tostring(k)) or tostring(k)]=safe(x,seen,depth+1)
    end
  end
  seen[v]=nil
  return out
end
local function run_lua(p)
  assert(type(p.code)=='string' and #p.code<=65536,'code must be a string of at most 65536 bytes')
  local seconds=p.timeout or 3
  assert(finite(seconds) and seconds>=0.05 and seconds<=30,'timeout must be 0.05..30 seconds')
  local compile,err=load(p.code,'=ce_mcp_run_lua','t',setmetatable({},{__index=_G,__newindex=_G}))
  if not compile then return {ok=false,error=tostring(err),output=array(),returns=array(),timed_out=false} end
  local output=array()
  local output_bytes=0
  local output_truncated=false
  -- The chunk's environment captures print without changing CE's global print.
  local _,scope=debug.getupvalue(compile,1)
  if scope then scope.print=function(...)
    local parts={}
    for i=1,select('#',...) do parts[i]=tostring(select(i,...)) end
    local line=table.concat(parts,'\t')
    local remaining=262144-output_bytes
    if remaining<=0 or #output>=1000 then output_truncated=true else
      output[#output+1]=line:sub(1,remaining)
      output_bytes=output_bytes+math.min(#line,remaining)
      if #line>remaining then output_truncated=true end
    end
  end end
  local deadline=getTickCount()+math.ceil(seconds*1000)
  local oldhook,oldmask,oldcount=debug.gethook()
  local marker='CE_MCP_LUA_TIMEOUT'
  local function hook()
    if getTickCount()>=deadline then error(marker,0) end
  end
  local packed
  debug.sethook(hook,'',10000)
  local ok,why=xpcall(function() packed=table.pack(compile()) end,function(e)
    return {message=tostring(e),traceback=debug.traceback('',2)}
  end)
  debug.sethook(oldhook,oldmask,oldcount)
  local values=array()
  if ok then for i=1,math.min(packed.n,100) do values[i]=safe(packed[i]) end end
  return {ok=ok,output=output,output_truncated=output_truncated,returns=values,
    error=why and why.message or nil,traceback=why and why.traceback or nil,
    timed_out=not ok and why.message:find(marker,1,true)~=nil,
    elapsed_ms=math.max(0,math.ceil(seconds*1000)-(deadline-getTickCount()))}
end
local function speedhack(p)
  local pid=attached()
  assert(type(p.enabled)=='boolean','enabled must be boolean')
  local speed=p.enabled and (p.speed or 1) or 1
  assert(finite(speed) and speed>0 and speed<=100,'speed must be >0 and <=100')
  -- CE documents setSpeed/getSpeed; its main-form checkbox controls deactivation.
  local ok,err=pcall(speedhack_setSpeed,speed)
  assert(ok,'speedhack_setSpeed failed: '..tostring(err))
  local checkbox=getMainForm().cbSpeedhack
  assert(checkbox,'CE speedhack checkbox is unavailable')
  if not p.enabled then checkbox.Checked=false end
  return {pid=pid,enabled=checkbox.Checked,speed=speedhack_getSpeed()}
end
local function inject_dll(p)
  local pid=attached()
  assert(type(p.path)=='string' and p.path:lower():match('%.dll$') and #p.path<32768,
    'path must be an absolute .dll path')
  assert(p.path:match('^%a:[/\\]') or p.path:match('^\\\\'), 'DLL path must be absolute')
  local f=io.open(p.path,'rb');assert(f,'DLL file does not exist');f:close()
  local name=p.path:match('([^/\\]+)$')
  local ok,result=pcall(injectDLL,p.path)
  assert(ok and result,'injectDLL failed: '..tostring(result))
  local mod
  for _,v in ipairs(enumModules()) do
    if v.Name:lower()==name:lower() then
      if not mod or (v.PathToFile and v.PathToFile:lower()==p.path:lower()) then mod=v end
    end
  end
  assert(mod,'DLL injection succeeded but the module is not visible in CE module list')
  return {pid=pid,module=mod.Name,base=A.hex(mod.Address),path=mod.PathToFile}
end
local function mono_module_present()
  for _,v in ipairs(enumModules()) do
    local name=v.Name:lower()
    if name=='mono.dll' or name:find('mono%-2%.0') or
       name:find('libmono',1,true) or name:find('gameassembly.dll',1,true) or
       name:find('libil2cpp',1,true) then return true end
  end
  return false
end
local function hex_or_nil(v) if v and v~=0 then return A.hex(v) end end
local function mono(p)
  local pid=attached()
  local action=p.action or 'status'
  assert(({status=true,assemblies=true,class=true,methods=true,fields=true})[action],
    'action must be status, assemblies, class, methods or fields')
  if type(LaunchMonoDataCollector)~='function' then
    return {pid=pid,is_mono=false,reason='CE Mono extension is unavailable'}
  end
  -- Avoid CE's collector injection and modal error dialog for native targets.
  if not mono_module_present() then
    return {pid=pid,is_mono=false,reason='No Mono or IL2CPP runtime module is loaded'}
  end
  local ok,launched=pcall(LaunchMonoDataCollector)
  if not ok or not launched or launched==0 or not mono_isValid() then
    return {pid=pid,is_mono=false,reason='Mono collector could not attach: '..tostring(launched)}
  end
  local result={pid=pid,is_mono=true,il2cpp=mono_isil2cpp(),action=action}
  if action=='status' then return result end
  if action=='assemblies' then
    local out=array()
    for _,assembly in ipairs(mono_enumAssemblies() or {}) do
      local image=mono_getImageFromAssembly(assembly)
      out[#out+1]={assembly=A.hex(assembly),image=hex_or_nil(image),
        name=image and mono_image_get_name(image) or nil,
        filename=image and mono_image_get_filename(image) or nil}
    end
    result.assemblies=out;result.total=#out;return result
  end
  assert(type(p.class_name)=='string' and p.class_name~='', 'class_name is required')
  local namespace=p.namespace or ''
  assert(type(namespace)=='string','namespace must be a string')
  local class=mono_findClass(namespace,p.class_name)
  result.class_name=p.class_name;result.namespace=namespace
  result.found=class~=nil and class~=0
  if not result.found then return result end
  result.class=hex_or_nil(class)
  if action=='class' then return result end
  if action=='methods' then
    local out=array()
    for _,method in ipairs(mono_class_enumMethods(class,false) or {}) do
      if not p.method_name or method.name==p.method_name then
        local sig,args,ret=mono_method_getSignature(method.method)
        out[#out+1]={name=method.name,address=A.hex(method.method),
          signature=sig,parameters=args,return_type=ret}
      end
    end
    result.methods=out;result.total=#out;return result
  end
  local out=array()
  local instance
  if p.instance_address then instance=A.resolve(p.instance_address) end
  for _,field in ipairs(mono_class_enumFields(class,false,false) or {}) do
    local row={name=field.name,type=field.typename,offset=A.hex(field.offset),
      is_static=field.isStatic,is_const=field.isConst,field=A.hex(field.field)}
    local a=field.isStatic and field.staticAddress or (instance and instance+field.offset)
    row.address=hex_or_nil(a)
    if a then
      local kind=field.monotype
      local read=({[2]=readByte,[3]=readSmallInteger,[4]=readByte,[5]=readByte,
        [6]=readSmallInteger,[7]=readSmallInteger,[8]=readInteger,[9]=readInteger,
        [10]=readQword,[11]=readQword,[12]=readFloat,[13]=readDouble})[kind]
      if read then row.value=read(a) end
    end
    out[#out+1]=row
  end
  result.fields=out;result.total=#out;return result
end
function M.dispatch(method,p)
  if method=='run_lua' then return true,run_lua(p) end
  if method=='speedhack' then return true,speedhack(p) end
  if method=='inject_dll' then return true,inject_dll(p) end
  if method=='mono' then return true,mono(p) end
  return false
end
return M
