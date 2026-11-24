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
