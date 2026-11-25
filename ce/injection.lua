-- CE 7.7 celua.txt: autoAssemble/disableInfo, AOBScan, Disassembler and typed reads.
local M={}
local A=dofile([[E:/workspace/ce-mcp/ce/addressing.lua]])
local scripts={}
local function arr() return setmetatable({}, {isArray=true}) end
local function integer(n) return type(n)=='number' and n==math.floor(n) end
local function attached()
  local pid=getOpenedProcessID()
  assert(pid~=0 and getProcesslist()[pid], 'No live process attached')
  return pid
end
local function bytes(a,n)
  local b=readBytes(a,n,true)
  assert(b and #b==n,'Memory unreadable or incomplete at '..A.hex(a))
  return b
end
local function byte_text(b)
  local out={};for i,v in ipairs(b) do out[i]=string.format('%02X',v) end
  return table.concat(out,' ')
end
local function pattern(s)
  assert(type(s)=='string' and #s>0 and #s<=4096,'pattern must be 1..4096 characters')
  local out={};local concrete=false
  for t in s:gmatch('%S+') do
    assert(t=='??' or t:match('^%x%x$'),'Use space-separated hex bytes or ?? wildcards')
    out[#out+1]=t:upper();if t~='??' then concrete=true end
  end
  assert(#out>0 and concrete,'Pattern must contain a concrete byte')
  return table.concat(out,' '),#out
end
local function module_by_name(name,modules)
  if name==nil then return nil end
  assert(type(name)=='string' and #name>0,'Invalid module')
  local found
  for _,m in ipairs(modules) do
    if m.Name:lower()==name:lower() then assert(not found,'Ambiguous module');found=m end
  end
  assert(found and found.Size and found.Size>0,'Module not found')
  return found
end
local function scan(s,mod)
  local normalized,width=pattern(s)
  -- AOBScan owns an independent scan; it never replaces the user's MemScan.
  local list=AOBScan(normalized,'*X*C*W',0,'1')
  local out=arr()
  local ok,err=pcall(function()
    if list then
      for i=0,list.Count-1 do
        local a=tonumber(list[i],16)
        if not mod or (a>=mod.Address and a+width<=mod.Address+mod.Size) then
          out[#out+1]=a
        end
      end
    end
  end)
  if list then list.destroy() end
  if not ok then error(err) end
  table.sort(out)
  return out,normalized
end
local function script_run(p)
  local pid=attached()
  assert(type(p.name)=='string' and p.name:match('%S') and #p.name<=160 and
    not p.name:find('%c'), 'name must be 1..160 bytes of printable text')
  local enable=p.enable~=false
  assert(p.enable==nil or type(p.enable)=='boolean','enable must be boolean')
  local saved=scripts[p.name]
  if not enable then
    assert(saved,'No enabled script with this name')
    assert(saved.pid==pid and saved.handle==getOpenedProcessHandle(),
      'Script belongs to another process instance; reopen its original process/session')
    local ok,info=autoAssemble(saved.script,false,saved.disable_info)
    assert(ok,'DISABLE failed; saved state retained: '..tostring(info))
    scripts[p.name]=nil
    return {name=p.name,pid=pid,enabled=false}
  end
  assert(not saved,'Script name already enabled; disable it before replacing it')
  assert(type(p.script)=='string' and #p.script>0 and #p.script<=262144,'script must be 1..262144 characters')
  local upper=p.script:upper()
  assert(upper:find('[ENABLE]',1,true) and upper:find('[DISABLE]',1,true),
    'Managed scripts require both [ENABLE] and [DISABLE] sections')
  local ok,info=autoAssemble(p.script,false)
  assert(ok,'ENABLE failed: '..tostring(info))
  assert(type(info)=='table','CE did not return disableInfo')
  scripts[p.name]={pid=pid,handle=getOpenedProcessHandle(),script=p.script,disable_info=info}
  local allocs=arr()
  for name,v in pairs(info.allocs or {}) do
    allocs[#allocs+1]={name=name,address=A.hex(v.address),size=v.size}
  end
  table.sort(allocs,function(a,b) return tostring(a.name)<tostring(b.name) end)
  return {name=p.name,pid=pid,enabled=true,allocations=allocs}
end
function M.before_attach()
  for name,s in pairs(scripts) do
    if getProcesslist()[s.pid] then
      error('Disable injection '..name..' before switching processes')
    end
    scripts[name]=nil -- Dead processes have no code or allocations to restore.
  end
end
local function template(p)
  attached()
  local a=A.resolve(p.address)
  local modules=enumModules();local mod
  for _,m in ipairs(modules) do
    if m.Size and a>=m.Address and a<m.Address+m.Size then mod=m;break end
  end
  assert(mod,'AOB injection requires an address inside a module')
  local name=p.name or 'ce_mcp_inject'
  assert(type(name)=='string' and name:match('^[%a_][%w_]*$') and #name<=60,'Invalid template symbol name')
  assert(not mod.Name:find('["\r\n,]'),'Module name cannot be represented in AA')
  local decoder=createDisassembler()
  local instructions=arr();local stolen=0;local wildcard={}
  local ok,result=pcall(function()
    while stolen<5 do
      decoder.disassemble(a+stolen)
      local d=decoder.getLastDisassembleData()
      local n=getInstructionSize(a+stolen)
      assert(integer(n) and n>=1 and n<=15,'Invalid instruction length')
      local b=bytes(a+stolen,n)
      local text=(d.prefix~='' and d.prefix..' ' or '')..d.opcode..
        (d.parameters~='' and ' '..d.parameters or '')
      assert(not text:lower():match('^db '),'Cannot decode instruction')
      instructions[#instructions+1]={address=A.hex(a+stolen),bytes=byte_text(b),instruction=text,size=n}
      stolen=stolen+n
    end
    assert(a+stolen<=mod.Address+mod.Size,'Instructions cross module boundary')
    -- Grow full instructions; CE's wildcard metadata masks relocatable operands.
    local length=0;local unique,chosen
    while length<128 and a+length<mod.Address+mod.Size do
      decoder.disassemble(a+length)
      local d=decoder.getLastDisassembleData();local n=getInstructionSize(a+length)
      assert(integer(n) and n>=1 and n<=15 and a+length+n<=mod.Address+mod.Size,'Cannot extend signature')
      local b=bytes(a+length,n)
      for i,v in ipairs(b) do
        wildcard[#wildcard+1]=(d.wildcard and d.wildcard[i]) and '??' or string.format('%02X',v)
      end
      length=length+n
      if length>=math.max(stolen,8) then
        local masked=table.concat(wildcard,' ')
        local hits=scan(masked,mod)
        if #hits==1 and hits[1]==a then unique=true;chosen=masked;break end
      end
    end
    assert(unique,'No unique relocatable AOB within 128 bytes of this instruction')
    local original=byte_text(bytes(a,stolen))
    local lines={'// '..name..': '..mod.Name..'+'..string.format('%X',a-mod.Address),
      '// Generated from complete instructions; review custom code before enabling.',
      '[ENABLE]',string.format('aobscanmodule(%s,"%s",%s)',name,mod.Name,chosen),
      'assert('..name..','..original..')',
      'alloc(newmem,1000,'..name..') // x64: allocate within +/-2 GiB of injection',
      'label(originalcode)','label(return)','registersymbol('..name..')','',
      'newmem:','  // Put your custom code here. Preserve registers/flags that your code changes.',
      'originalcode:'}
    for _,ins in ipairs(instructions) do
      -- Reassemble resolves RIP-relative and branch operands at the new location;
      -- copying db bytes into the cave would silently change their destinations.
      lines[#lines+1]='  // '..ins.bytes..' : '..ins.instruction
      lines[#lines+1]='  reassemble('..name..'+'..string.format('%X',tonumber(ins.address)-a)..')'
    end
    lines[#lines+1]=targetIs64Bit() and '  jmp long return' or '  jmp return'
    lines[#lines+1]='';lines[#lines+1]=name..':'
    lines[#lines+1]=targetIs64Bit() and '  jmp long newmem // force rel32; fail instead of emitting a 14-byte jump' or '  jmp newmem'
    if stolen>5 then lines[#lines+1]='  db '..string.rep('90 ',stolen-5):sub(1,-2) end
    lines[#lines+1]='return:';lines[#lines+1]='';lines[#lines+1]='[DISABLE]'
    lines[#lines+1]=name..':';lines[#lines+1]='  db '..original
    lines[#lines+1]='unregistersymbol('..name..')';lines[#lines+1]='dealloc(newmem)'
    local info=A.module_info(a,modules)
    return {address=A.hex(a),symbol=info.symbol,module=mod.Name,pattern=chosen,
      pattern_address=A.hex(a),pattern_unique=true,jump_size=5,overwrite_size=stolen,
      return_address=A.hex(a+stolen),original_bytes=original,instructions=instructions,
      relocation='CE reassemble preserves original operand destinations',script=table.concat(lines,'\n')}
  end)
  decoder.destroy()
  if not ok then error(result) end
  return result
end
local formats={byte={1,'<I1'},['2bytes']={2,'<I2'},['4bytes']={4,'<i4'},
  ['8bytes']={8,'<i8'},float={4,'<f'},double={8,'<d'}}
local function compare(p)
  attached()
  assert(type(p.addresses)=='table' and #p.addresses>=2 and #p.addresses<=16,'Provide 2..16 addresses')
  assert(integer(p.length) and p.length>=1 and p.length<=4096,'length must be 1..4096 bytes')
  local stride=p.stride or 1
  assert(integer(stride) and stride>=1 and stride<=64,'stride must be 1..64')
  local types=p.types or {'4bytes','float','pointer'}
  assert(type(types)=='table' and #types>=1 and #types<=8,'Provide 1..8 types')
  local ptr=targetIs64Bit() and 8 or 4
  local layouts={};local used={}
  for _,t in ipairs(types) do
    assert(not used[t],'Duplicate type');used[t]=true
    local layout=t=='pointer' and {ptr,ptr==8 and '<I8' or '<I4'} or formats[t]
    assert(layout,'Unsupported comparison type');layouts[t]=layout
  end
  local samples=arr();local modules=enumModules()
  for _,input in ipairs(p.addresses) do
    local a=A.resolve(input)
    samples[#samples+1]={address=A.hex(a),data=bytes(a,p.length)}
  end
  local rows=arr();local differences=arr()
  for offset=0,p.length-1,stride do
    local row={offset=offset,offset_hex=A.hex(offset),different=false,interpretations=arr()}
    for _,t in ipairs(types) do
      local width,fmt=table.unpack(layouts[t])
      if offset+width<=p.length then
        local entry={value_type=t,width=width,different=false,values=arr()};local first
        for i,s in ipairs(samples) do
          local b={};for j=1,width do b[j]=s.data[offset+j] end
          local raw=byte_text(b)
          if i==1 then first=raw elseif raw~=first then entry.different=true end
          local v=string.unpack(fmt,string.char(table.unpack(b)))
          local text
          if t=='pointer' then text=A.hex(v)
          elseif t=='float' or t=='double' then text=string.format(t=='float' and '%.9g' or '%.17g',v)
          else text=tostring(v) end
          local value={address=A.hex(tonumber(s.address)+offset),value=text,bytes=raw}
          if t=='pointer' then value.target=A.module_info(v,modules) end
          entry.values[#entry.values+1]=value
        end
        row.different=row.different or entry.different
        row.interpretations[#row.interpretations+1]=entry
      end
    end
    if #row.interpretations>0 then
      rows[#rows+1]=row;if row.different then differences[#differences+1]=offset end
    end
  end
  local addresses=arr();for _,s in ipairs(samples) do addresses[#addresses+1]=s.address end
  return {addresses=addresses,length=p.length,stride=stride,pointer_size=ptr,rows=rows,
    different_offsets=differences,comparison='raw bytes; floating NaN/bit differences remain visible',
    snapshot='sequential reads, target is not paused'}
end
function M.dispatch(method,p)
  if method=='auto_assemble' then return true,script_run(p) end
  if method=='aob_scan' then
    attached();local modules=enumModules();local mod=module_by_name(p.module,modules)
    local hits,normalized=scan(p.pattern,mod);local results=arr()
    for _,a in ipairs(hits) do
      local row=A.module_info(a,modules);row.address=A.hex(a);results[#results+1]=row
    end
    return true,{pattern=normalized,module=mod and mod.Name or nil,total=#results,results=results}
  end
  if method=='injection_template' then return true,template(p) end
  if method=='compare_structures' then return true,compare(p) end
  return false
end
return M
