# Findings

- MemScan firstScan/nextScan require input values as strings; rtRounded preserves CE's decimal precision rules.
- FoundList is 0-indexed and needs initialize after scan, deinitialize before next scan.
- waitTillDone must run off the CE main thread; all scan object setup and result access return via synchronize.
- CE documents soUnknownValue only for firstScan, not nextScan. Do not silently substitute comparison modes.
- MemoryRecord Active controls freezing; use stable record ID, not shifting table index.
- Scan state belongs to one PID and must be discarded on attachment change; frozen records created by bridge must be unfrozen before attachment changes to avoid writes into another target.
- Empty scan result test reproduced `{}` instead of `[]`; bundled json.lua encode_table explicitly supports metatable.isArray. Both results and process lists now declare arrays at source (two independent evidence checks: runtime plus serializer source).
- Live-value fixture independently changed target memory after scan and FoundList.Value remained cached. FoundList represents saved results, not a live memory reader. Result pages now use FoundList.Address plus typed reads of current memory; unreadable entries carry an error rather than hiding all results.
- CE unknown snapshot FoundCount/getProgress report captured bytes, while FoundList.Count is 0 until refinement. Responses declare snapshot=true and total_kind=bytes; enumerated results use total_kind=addresses. All 10 next modes successfully refine native unknown snapshots.
- Existing CE registry settings already redirect scanner data to E:\CEBUFFER\ (`Don't use tempdir`=1). Restart environment TEMP/TMP additionally points to E:\workspace\ce-mcp\work\temp. No scanner settings changed.

## Step 3 API checks

- celua.txt lines 876..895: debugProcess, debug_isDebugging, debug_getBreakpointList, debug_setBreakpoint with per-breakpoint callback, debug_removeBreakpointByID (2nd result from setBreakpoint), debug_continueFromBreakpoint(co_run).
- defines.lua: bpmDebugRegister=1, bptWrite=2, bptAccess=1. Use explicit hardware method; do not replace global debugger_onBreakpoint.
- Hardware data watchpoints report post-instruction IP. getPreviousOpcode explicitly returns an estimated guess; verify predecessor length ends at stopped IP and expose attribution status rather than claiming certainty on variable-length x86.
- disassemble/splitDisassembledString/getInstructionSize plus createDisassembler.LastDisassembleData provide bytes/opcode. getNameFromAddress(address,true,false) yields module+offset without preferring user symbols.
- Register globals and debug_getCurrentContextTable are documented; return register values as hex strings to avoid JSON precision loss.
- Startup serialization diagnostic pinpointed `result.debugger.broken` as a function. Focused native diagnostics confirmed debug_isBroken() returns itself (same_function=true, C function), both before and after debugger startup. Use the documented isPaused() as the primary paused-state API, without silently coercing unknown values. Response encoding failures are now visible to clients with the field path.
- Runtime debug_setBreakpoint second result is the identity object {ID,DTID,PID}. Pass the whole object to debug_removeBreakpointByID and require true; a bare ID is rejected. debug_getBreakpointList includes retired/inactive descriptors, so list presence is NOT evidence of an active hardware breakpoint. Local executable inspection confirms getBreakpointAddresses copies every descriptor without an active/deleted filter; removal disables hardware state and marks its descriptor for later retirement. Independent Windows GetThreadContext verified DR7 enable bits were nonzero with the watch active and zero after removal, including repeated watches and a disconnected client. Track counts of bridge-owned retired descriptors only for the overlap check, so repeated watches can reuse their address without masking unrelated pre-existing addresses.
- CE's splitDisassembledString tuple order differs from the installed documentation (the assumed opcode slot contained bytes). Use the documented createDisassembler.getLastDisassembleData fields instead. Native C/MASM instruction bytes and expected MOV text both verify the result.
- Diagnostic helper APIs/timers were removed after isolating the native behavior. Capstone was installed into the E: venv solely to inspect the local CE bindings; it is not a server dependency and no CE binaries were changed.

## Step 4 pointer API checks

- readPointer uses the target pointer width (readQword for x64, readInteger for x86), not CE's host width.
- MemoryRecord.OffsetCount=0 is a direct address; Offset[]/OffsetText[] hold pointer offsets, CurrentAddress/getCurrentAddress resolves the live pointer chain. The installed text does not explicitly establish the array/UI traversal direction, so an asymmetric native fixture and a real native pointer record will verify it.
- API offsets will be documented in base-to-leaf dereference order; native CE offset arrays/UI order are returned separately and verified against CurrentAddress before writing/freezing.
- enumModules supplies Name/Address/Size/PathToFile; getMemoryRegionInfo supplies raw allocation/protection/state/type. MEM_PRIVATE alone cannot prove an address belongs to a heap instead of a stack or VirtualAlloc allocation; classify it as dynamic private memory without inventing heap provenance.
- Real x64 and x86 native pointer records confirmed API offsets [0x20,-0x10,0x38] map to Offset[0..2]=[0x38,-0x10,0x20], with OffsetText[0..2]=["38","-10","20"]. CurrentAddress exactly matched the independent C fixture's leaf address. Retargeting a middle pointer redirected both the record and CE's freezing to the new leaf, leaving the former leaf untouched after resolution updated.
- x64 heap pointers were above 4 GiB and read as full QWORDs; x86 slots carried nonzero poison DWORDs after each 4-byte pointer so accidental 8-byte dereferences would fail. Both architectures passed all seven final value types, including uint64 and UTF-8 strings.
- address_info region base/allocation base/size/state/protect/type matched independent Windows VirtualQueryEx for module data/code, HeapAlloc memory, reserved, guarded and mapped regions; address 0 correctly classified as free. Guard-page inspection did not read or consume the guard.
- Static module+offset metadata was checked on scan_first, scan_results and scan_next; private-memory results are explicitly is_static=false. Actual official SDK stdio clients discovered 20 tools and exercised all four new tools on both architectures.
