-- CE 7.7 APIs verified against the installed celua.txt.
if CE_MCP_BRIDGE then return end
local json = require('json')
local MAX_FRAME = 1024 * 1024
local function integer(v) return type(v) == 'number' and v == math.floor(v) end
local function status()
  local pid = getOpenedProcessID()
  local processes = getProcesslist()
  return {version = getCEVersion(), pid = pid, process_name = processes[pid]}
end
local function dispatch(req)
  assert(type(req) == 'table' and type(req.method) == 'string', 'Invalid request')
  local p = req.params or {}
  if req.method == 'ce_status' then return status() end
  if req.method == 'list_processes' then
    assert(p.filter == nil or type(p.filter) == 'string', 'filter must be a string')
    local result = {}
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
    openProcess(pid)
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
      else result = req end
      local response = json.encode(ok and {ok=true, result=result} or {ok=false, error=tostring(result)})
      if pipe.writeDword(#response) ~= 4 then break end
      if pipe.writeString(response) ~= #response then break end
    end
  end)
  pipe.destroy()
end
CE_MCP_BRIDGE = {version = 1}
createThread(function()
  local listener = createPipe('ce_mcp', 65536, 65536, 16)
  if not listener or not listener.valid then
    CE_MCP_BRIDGE.error = 'Cannot create ce_mcp pipe'
    return
  end
  CE_MCP_BRIDGE.listener = listener
  while true do
    local client = listener.acceptConnection(true)
    if client then createThread(function() serve(client) end) else break end
  end
  listener.destroy()
end)
