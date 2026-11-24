-- CE 7.7 debugger APIs/constants verified in installed celua.txt/defines.lua.
local M = {}
local active, patches = nil, {}
local retired={}
local decoder=createDisassembler()
local register_names = {'RAX','RBX','RCX','RDX','RSI','RDI','RBP','RSP','RIP',
  'R8','R9','R10','R11','R12','R13','R14','R15','EFLAGS'}
local register_names32 = {'EAX','EBX','ECX','EDX','ESI','EDI','EBP','ESP','EIP','EFLAGS'}
local function array() return setmetatable({}, {isArray=true}) end
local function integer(v) return type(v)=='number' and v==math.floor(v) end
local function hex(v) return string.format('0x%X',v) end
local function attached()
  local pid=getOpenedProcessID()
  assert(pid~=0, 'No process attached')
  return pid
end
local function address(v)
  assert(type(v)=='string' or integer(v), 'Invalid address')
  local a=type(v)=='string' and getAddressSafe(v) or v
  assert(a and a>=0, 'Address cannot be resolved')
  return a
end
local function bytes_at(a,size)
  local b=readBytes(a,size,true)
  assert(b and #b==size, 'Memory unreadable or incomplete')
  return b
end
local function byte_string(b)
  local t={}
  for i,v in ipairs(b) do t[i]=string.format('%02X',v) end
  return table.concat(t,' ')
end
local function equal(a,b)
  if #a~=#b then return false end
  for i,v in ipairs(a) do if v~=b[i] then return false end end
  return true
end
local function location(a,modules)
  for _,m in ipairs(modules or enumModules()) do
    if m.Size and a>=m.Address and a-m.Address<m.Size then
      return m.Name..'+'..string.format('%X',a-m.Address),m.Name,hex(a-m.Address)
    end
  end
  return hex(a),nil,nil -- Dynamically allocated code has no owning module.
end
local function instruction(a,modules)
  local size=getInstructionSize(a)
  assert(integer(size) and size>=1 and size<=15, 'Invalid x86 instruction size')
  local bytes=bytes_at(a,size)
  decoder.disassemble(a)
  local data=decoder.getLastDisassembleData()
  local opcode=(data.prefix~='' and data.prefix..' ' or '')..data.opcode..
    (data.parameters~='' and ' '..data.parameters or '')
  local extra=data.description
  assert(opcode and opcode~='' and not opcode:lower():find('^db '), 'Cannot decode instruction')
  local symbol,module,offset=location(a,modules)
  return {address=hex(a),symbol=symbol,module=module,module_offset=offset,
    bytes=byte_string(bytes),instruction=opcode,comment=extra,size=size},bytes
end
local function finish(job,reason)
  if job.done then return end
  job.accepting=false
  if job.timer then job.timer.Enabled=false; job.timer.destroy(); job.timer=nil end
  local ok,err=pcall(function()
    -- CE returns the identity object {PID,DTID,ID}. Retired descriptors remain
    -- in debug_getBreakpointList even after their hardware registers are cleared.
    if getProcesslist()[job.pid] then
      local removed,remove_error=debug_removeBreakpointByID(job.breakpoint_id)
      assert(removed==true, 'Cannot remove owned breakpoint: '..tostring(remove_error))
      local key=tostring(job.pid)..':'..hex(job.address)
      retired[key]=(retired[key] or 0)+1
    end -- Process exit destroys its threads and debug-register state.
  end)
  job.cleanup_error=not ok and tostring(err) or nil
  job.removed=ok
  job.reason=reason
  job.elapsed=((getTickCount()-job.started)%4294967296)/1000
  job.done=true
  if active==job then active=nil end
end
local function on_hit(job)
  -- The context belongs to the stopped thread. Do not modify its registers.
  local ok,err=pcall(function()
    if not job.accepting then return end
    if (getTickCount()-job.started)%4294967296>=job.seconds*1000 then return end
    job.total_hits=job.total_hits+1
    local ip=job.is64 and RIP or EIP
    assert(integer(ip), 'Breakpoint context has no instruction pointer')
    local previous=getPreviousOpcode(ip)
    assert(previous and previous<ip and ip-previous<=15, 'Cannot resolve previous instruction')
    local decoded=instruction(previous,job.modules)
    assert(previous+decoded.size==ip, 'Previous instruction does not end at stopped IP')
    local key=decoded.address
    local entry=job.by_address[key]
    if not entry then
      entry=decoded; entry.hit_count=0; entry.stopped_ip=hex(ip)
      entry.attribution='ce_previous_opcode'
      entry.registers={}
      for _,name in ipairs(job.is64 and register_names or register_names32) do
        if type(_G[name])=='number' then entry.registers[name]=hex(_G[name]) end
      end
      job.by_address[key]=entry; job.entries[#job.entries+1]=entry
    end
    entry.hit_count=entry.hit_count+1
  end)
  if not ok then
    job.unattributed_hits=job.unattributed_hits+1
    if #job.errors<20 then job.errors[#job.errors+1]=tostring(err) end
  end
  -- Continue even when decoding/context capture failed. Never strand the target.
  local continued,why=pcall(debug_continueFromBreakpoint,co_run)
  if not continued then
    job.errors[#job.errors+1]='Cannot continue breakpoint: '..tostring(why)
    finish(job,'callback_error')
  end
  return 1
end
local function begin_watch(p,access)
  local pid=attached()
  assert(not active, 'A hardware watch is already active')
  assert(not isPaused(), 'Target is paused; continue it before monitoring')
  local a=address(p.address)
  local size=p.size or 1
  assert(size==1 or size==2 or size==4 or (size==8 and targetIs64Bit()), 'Hardware size must be 1,2,4 (or 8 on x64)')
  assert(a%size==0, 'Hardware watch address must be aligned to size')
  local seconds=p.seconds or 5
  assert(type(seconds)=='number' and seconds==seconds and seconds>=0.1 and seconds<=120,
    'seconds must be 0.1..120')
  bytes_at(a,size)
  if not debug_isDebugging() then debugProcess(1) end
  assert(debug_isDebugging(), 'Cannot start the debugger')
  -- Avoid replacing an existing user's breakpoint, including overlapping data ranges.
  local seen={}
  for _,b in pairs(debug_getBreakpointList() or {}) do
    local key=tostring(pid)..':'..hex(b)
    seen[key]=(seen[key] or 0)+1
    assert(b<a-7 or b>=a+size or seen[key]<=(retired[key] or 0), 'Existing breakpoint overlaps this watch')
  end
  local job={pid=pid,address=a,size=size,seconds=seconds,is64=targetIs64Bit(),
    access=access,modules=enumModules(),entries=array(),by_address={},errors=array(),
    total_hits=0,unattributed_hits=0,accepting=true,started=getTickCount()}
  local set,id=debug_setBreakpoint(a,size,access and bptAccess or bptWrite,bpmDebugRegister,
    function() return on_hit(job) end)
  assert(set, 'Cannot set hardware breakpoint (debug-register slots may be full)')
  job.breakpoint_id=id
  assert(type(id)=='table' and id.ID and id.PID==pid and id.DTID,
    'CE did not return the hardware breakpoint identity')
  job.started=getTickCount()
  active=job
  local ok,err=pcall(function()
    job.timer=createTimer(nil,false)
    job.timer.Interval=math.max(10,math.min(100,math.floor(seconds*1000)))
    job.timer.OnTimer=function()
      if getOpenedProcessID()~=job.pid then finish(job,'process_changed')
      elseif not getProcesslist()[job.pid] or not debug_isDebugging() then finish(job,'process_exited')
      elseif (getTickCount()-job.started)%4294967296>=seconds*1000 then finish(job,'completed') end
    end
    job.timer.Enabled=true
  end)
  if not ok then finish(job,'setup_error'); error(err) end
  return {__watch=job}
end
function M.watch_done(job) return job.done==true end
function M.watch_result(job)
  assert(job.done, 'Watch has not finished')
  assert(not job.cleanup_error, 'Breakpoint cleanup failed: '..tostring(job.cleanup_error))
  table.sort(job.entries,function(a,b) return a.hit_count>b.hit_count or
    (a.hit_count==b.hit_count and a.address<b.address) end)
  return {address=hex(job.address),size=job.size,pid=job.pid,
    mode=job.access and 'access' or 'write',seconds=job.seconds,elapsed_seconds=job.elapsed,
    reason=job.reason,total_hits=job.total_hits,instructions=job.entries,
    unattributed_hits=job.unattributed_hits,errors=job.errors,
    breakpoint_removed=job.removed,cleanup_method='debug_removeBreakpointByID'}
end
function M.before_attach() assert(not active, 'Cannot attach during a hardware watch') end
function M.status()
  local count=0; local pid=getOpenedProcessID()
  for _,p in pairs(patches) do if p.pid==pid then count=count+1 end end
  local debugging=debug_isDebugging()
  return {debugging=debugging,paused=isPaused(),monitoring=active~=nil,
    watch_address=active and hex(active.address) or nil,saved_patches=count}
end
local function with_paused(fn)
  local paused=isPaused()
  if not paused then pause() end
  local ok,result=pcall(fn)
  if not paused then unpause() end
  if not ok then error(result) end
  return result
end
local function patch_result(p,restored)
  return {pid=p.pid,address=hex(p.address),symbol=p.symbol,size=#p.original,
    original_bytes=byte_string(p.original),patched_bytes=byte_string(p.nops),restored=restored}
end
local function nop(a)
  local pid=attached()
  assert(not active, 'Cannot patch during a hardware watch')
  return with_paused(function()
    local decoded,original=instruction(a)
    for _,p in pairs(patches) do
      assert(p.pid~=pid or a+#original<=p.address or a>=p.address+#p.original,
        'Instruction overlaps an existing NOP backup; restore it first')
    end
    local p={pid=pid,address=a,symbol=decoded.symbol,original=original,nops={}}
    for i=1,#original do p.nops[i]=0x90 end
    local key=tostring(pid)..':'..hex(a)
    patches[key]=p -- Save original bytes before attempting any write.
    local ok,err=pcall(function()
      assert(writeBytes(a,p.nops)==#p.nops, 'NOP write incomplete')
      assert(equal(bytes_at(a,#p.nops),p.nops), 'NOP verification failed')
    end)
    if not ok then
      local rolled=pcall(function()
        assert(writeBytes(a,original)==#original, 'Rollback write incomplete')
        assert(equal(bytes_at(a,#original),original), 'Rollback verification failed')
      end)
      if rolled then patches[key]=nil end
      error(tostring(err)..(rolled and '; original bytes restored' or '; rollback failed; original backup retained'))
    end
    return patch_result(p,false)
  end)
end
local function restore(a)
  local pid=attached()
  assert(not active, 'Cannot restore during a hardware watch')
  local key=tostring(pid)..':'..hex(a)
  local p=patches[key]
  assert(p, 'No NOP backup for this address and process in this CE session')
  return with_paused(function()
    assert(equal(bytes_at(a,#p.nops),p.nops), 'Current bytes differ from saved NOP patch; refusing to overwrite other edits')
    assert(writeBytes(a,p.original)==#p.original, 'Restore write incomplete; backup retained')
    assert(equal(bytes_at(a,#p.original),p.original), 'Restore verification failed; backup retained')
    patches[key]=nil
    return patch_result(p,true)
  end)
end
function M.dispatch(method,p)
  if method=='find_what_writes' or method=='find_what_accesses' then
    return true,begin_watch(p,method=='find_what_accesses')
  end
  if method=='disassemble' then
    attached(); local a=address(p.address); local count=p.count or 10
    assert(integer(count) and count>=1 and count<=200, 'count must be 1..200')
    local results=array(); local modules=enumModules()
    for i=1,count do
      local decoded=instruction(a,modules)
      results[#results+1]=decoded; a=a+decoded.size
    end
    return true,{instructions=results}
  end
  if method=='nop_instruction' then return true,nop(address(p.address)) end
  if method=='restore_instruction' then return true,restore(address(p.address)) end
  return false
end
return M
