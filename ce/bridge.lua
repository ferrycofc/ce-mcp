-- CE 7.7 APIs verified against the installed celua.txt.
if CE_MCP_BRIDGE then return end
local json = require('json')
local MAX_FRAME = 1024 * 1024
local tools = dofile([[E:\workspace\ce-mcp\ce\tools.lua]])
local debugger = dofile([[E:\workspace\ce-mcp\ce\debugger.lua]])
local injection = dofile([[E:\workspace\ce-mcp\ce\injection.lua]])
local extended = dofile([[E:\workspace\ce-mcp\ce\extended.lua]])
local pipe_name = os.getenv('CE_MCP_PIPE_NAME') or 'ce_mcp'
assert(pipe_name:match('^[%w_]+$'), 'Invalid CE_MCP_PIPE_NAME')
local function invalid_json_path(v,path,seen)
  local kind=type(v)
  if kind=='table' then
    seen=seen or {}; if seen[v] then return path..' (cycle)' end; seen[v]=true
    for k,item in pairs(v) do
      local problem=invalid_json_path(item,path..'.'..tostring(k),seen)
      if problem then return problem end
    end
    seen[v]=nil
  elseif kind~='nil' and kind~='boolean' and kind~='number' and kind~='string' then
    return path..' ('..kind..')'
  end
end
local function integer(v) return type(v) == 'number' and v == math.floor(v) end
local function status()
  local pid = getOpenedProcessID()
  local processes = getProcesslist()
  return {version = getCEVersion(), pid = pid, process_name = processes[pid],debugger=debugger.status()}
end
local function dispatch(req)
  assert(type(req) == 'table' and type(req.method) == 'string', 'Invalid request')
  local p = req.params or {}
  local extended_handled, extended_result = extended.dispatch(req.method,p)
  if extended_handled then return extended_result end
  local injection_handled, injection_result = injection.dispatch(req.method,p)
  if injection_handled then return injection_result end
  local debug_handled, debug_result = debugger.dispatch(req.method,p)
  if debug_handled then return debug_result end
  local handled, result = tools.dispatch(req.method,p)
  if handled then return result end
  if req.method == 'ce_status' then return status() end
  if req.method == 'list_processes' then
    assert(p.filter == nil or type(p.filter) == 'string', 'filter must be a string')
    local result = setmetatable({}, {isArray=true})
    for pid, name in pairs(getProcesslist()) do
      if not p.filter or name:lower():find(p.filter:lower(), 1, true) then
        result[#result+1] = {pid = pid, name = name}
      end
    end
    table.sort(result, function(a,b) return a.pid < b.pid end)
    return {processes = result}
  end
  if req.method == 'attach' then
    assert((p.pid ~= nil) ~= (p.name ~= nil), 'Provide exactly one of pid or name')
    local processes = getProcesslist()
    local pid = p.pid
    if p.name then
      assert(type(p.name) == 'string' and #p.name > 0, 'Invalid name')
      for id, name in pairs(processes) do
        if name:lower() == p.name:lower() then
          assert(pid == nil, 'Multiple matching processes; use PID')
          pid = id
        end
      end
    end
    assert(integer(pid) and pid > 0 and processes[pid], 'Process not found')
    if getOpenedProcessID() ~= pid then
      injection.before_attach()
      debugger.before_attach()
      tools.before_attach()
      openProcess(pid)
    end
    assert(getOpenedProcessID() == pid, 'Failed to attach')
    return status()
  end
  if req.method == 'read_memory' then
    assert(getOpenedProcessID() ~= 0, 'No process attached')
    assert(integer(p.size) and p.size >= 1 and p.size <= 65536, 'size must be 1..65536')
    assert(type(p.address) == 'string' or integer(p.address), 'Invalid address')
    local address = type(p.address) == 'string' and getAddressSafe(p.address) or p.address
    assert(address and address >= 0, 'Address cannot be resolved')
    local bytes = readBytes(address, p.size, true)
    assert(bytes and #bytes == p.size, 'Memory unreadable or incomplete')
    local hex, chars = {}, {}
    for i,b in ipairs(bytes) do
      hex[i] = string.format('%02X', b)
      chars[i] = b >= 32 and b <= 126 and string.char(b) or '.'
    end
    return {address = string.format('0x%X', address), size = #bytes,
      hex = table.concat(hex, ' '), characters = table.concat(chars)}
  end
  error('Unknown method: '..req.method)
end
local function serve(pipe)
  pipe.Timeout = 15
  pcall(function()
    while pipe.Connected do
      local size = pipe.readDword()
      if not size or size < 1 or size > MAX_FRAME then break end
      local body = pipe.readString(size)
      if not body or #body ~= size then break end
      local ok, req = pcall(json.decode, body)
      local result
      if ok then
        ok, result = synchronize(function() return pcall(dispatch, req) end)
        if ok and type(result)=='table' and result.__scan then
          -- Waiting on the pipe worker leaves the CE main thread available.
          local waited, done = pcall(function() return result.__scan.waitTillDone(120000) end)
          ok, result = synchronize(function()
            return pcall(tools.finish_scan, waited and done~=false, waited and 'Scan timed out' or tostring(done))
          end)
        end
        if ok and type(result)=='table' and result.__watch then
          local job=result.__watch
          repeat sleep(25) until synchronize(function() return debugger.watch_done(job) end)
          ok,result=synchronize(function() return pcall(debugger.watch_result,job) end)
        end
      else result = req end
      local encoded,response = pcall(json.encode,ok and {ok=true, result=result} or {ok=false, error=tostring(result)})
      if not encoded then
        response=json.encode({ok=false,error='Response JSON encoding failed at '..
          (invalid_json_path(result,'result') or 'unknown field')..': '..tostring(response)})
      end
      if #response>MAX_FRAME then
        response=json.encode({ok=false,error='Response exceeds 1 MiB; narrow the scan pattern/module or request fewer instructions/watch hits'})
      end
      if pipe.writeDword(#response) ~= 4 then break end
      if pipe.writeString(response) ~= #response then break end
    end
  end)
  pipe.destroy()
end
CE_MCP_BRIDGE = {version = 1, injection = injection, extended = extended, pipe_name = pipe_name}
createThread(function()
  local listener = createPipe(pipe_name, 65536, 65536, 16)
  if not listener or not listener.valid then
    CE_MCP_BRIDGE.error = 'Cannot create '..pipe_name..' pipe'
    return
  end
  CE_MCP_BRIDGE.listener = listener
  while true do
    local client = listener.acceptConnection(true)
    if client then createThread(function() serve(client) end) else break end
  end
  listener.destroy()
end)
