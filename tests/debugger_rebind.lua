-- Isolated lifecycle contract regression, executed inside CE against its Lua runtime.
-- Native tests independently cover actual hardware hits and DR7 cleanup.
-- Evidence before the fix: an exited native VEH fixture leaves the started flag
-- true. Normal openProcess switches happened to detach it, so that path alone
-- did not reproduce zero hits. The isolated stale-owner case below failed on
-- the original module: it installed a watch without starting the new debugger.
-- This rules out address/decoder errors as the cause of that lifecycle failure;
-- native known-instruction/DR7 tests separately verify the real watch machinery.
local here=assert(debug.getinfo(1,'S').source:match('^@(.+)[/\\][^/\\]+$'),
  'debugger_rebind.lua must be loaded from a file')
local path=here..'/../ce/debugger.lua'
local function scenario()
  local current,owner,handle=202,101,2002
  local starts,detaches=0,0
  local env=setmetatable({}, {__index=_G})
  env.getOpenedProcessID=function() return current end
  env.getOpenedProcessHandle=function() return handle end
  env.getProcesslist=function() return {[202]='fixture'} end -- owner 101 exited
  env.debug_isDebugging=function() return owner~=nil end
  env.detachIfPossible=function() detaches=detaches+1;owner=nil end
  env.debugProcess=function(interface) assert(interface==1);starts=starts+1;owner=current end
  env.isPaused=function() return false end
  env.getAddressSafe=function() return 4096 end
  env.readBytes=function(_,size) local t={};for i=1,size do t[i]=0 end;return t end
  env.targetIs64Bit=function() return true end
  env.enumModules=function() return {} end
  env.debug_getBreakpointList=function() return {} end
  env.getTickCount=function() return 100 end
  env.createDisassembler=function() return {} end
  env.createTimer=function() return {destroy=function() end} end
  env.debug_setBreakpoint=function()
    return true,{ID=1,PID=current,DTID=1}
  end
  env.debug_removeBreakpointByID=function() return true end
  local m=assert(loadfile(path,'t',env))()
  local _,r=m.dispatch('find_what_writes',{address=4096,size=4,seconds=1})
  assert(owner==current, 'STALE OWNER: watch installed while debugger still belongs to exited process')
  assert(detaches==1 and starts==1,'Stale debugger must detach before starting current process')
  -- Complete watch without decoding; retain current debugger on repeated watches.
  local job=r.__watch
  env.getTickCount=function() return 1200 end
  job.timer.OnTimer();assert(job.done)
  env.getTickCount=function() return 1300 end
  local _,again=m.dispatch('find_what_accesses',{address=4096,size=4,seconds=1})
  assert(detaches==1 and starts==1,'Same live process should reuse debugger')
  env.getTickCount=function() return 2400 end;again.__watch.timer.OnTimer()
  -- Reopening/reusing a PID with a different handle invalidates ownership too.
  handle=2003
  local _,reopened=m.dispatch('find_what_writes',{address=4096,size=4,seconds=1})
  assert(detaches==2 and starts==2,'Changed handle must invalidate the debugger owner')
  env.getTickCount=function() return 3500 end;reopened.__watch.timer.OnTimer()
  -- Switching while both processes are alive must detach at the attach boundary.
  m.before_attach();assert(owner==nil and detaches==3)
  current=303;handle=3003
  env.getProcesslist=function() return {[303]='fixture'} end
  local _,next_watch=m.dispatch('find_what_writes',{address=4096,size=4,seconds=1})
  assert(owner==303 and starts==3)
  -- A dead target must release a debugger even when its started flag remains true.
  env.getProcesslist=function() return {} end
  next_watch.__watch.timer.OnTimer()
  assert(owner==nil and next_watch.__watch.done and next_watch.__watch.removed)
  return 'PASS stale owner, same process reuse, changed handle, switch, exit cleanup'
end
local ok,result=pcall(scenario)
local f=assert(io.open(here..'/../work/rebind_contract.txt','w'))
f:write(ok and result or tostring(result));f:close()
assert(ok,result)
return 1
