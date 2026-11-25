-- Installed as <CE>/autorun/ce_mcp.lua by install.ps1.
-- The neighboring path file is generated locally and is not part of Git.
local here=assert(debug.getinfo(1,'S').source:match('^@(.+)[/\\][^/\\]+$'),
  'ce_mcp.lua must be loaded from a file')
local path_file=assert(io.open(here..'/ce_mcp_path.txt','r'),
  'ce_mcp_path.txt is missing; run install.ps1 from the repository')
local root=path_file:read('*l')
path_file:close()
assert(root and #root>0, 'ce_mcp_path.txt is empty')
dofile(root..'/ce/bridge.lua')
