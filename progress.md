# Progress

2026-11-25: skeleton committed (9ada401). Installed celua.txt checked. Implementation in progress. Tutorial PID 64016 will not be written or advanced. Tests will allocate controlled values in a separate Python process.

First runtime run passed seven typed scans/reads/writes and float rounding. Pagination fixture found 31 of 32 values because CE's stop boundary omitted the final complete value. Expanded test bound by one width and clarified API doc to use CE's native range semantics; no scan algorithm change.

All 11 tools passed real CE and MCP stdio. Live values now independently reread target memory. Unknown initial scans successfully refine via all next modes but FoundList.Count is 0 before refinement because CE uses region snapshots. Native FoundCount/getProgress reporting verified: captured byte count, snapshot=true, total_kind=bytes. Enumerated results declare total_kind=addresses.

Final suite passed after CE cold restart: seven types of scan/read/write/freeze, uint64 precision/signed writes, rounding, all supported numeric scan comparisons, paging/empty/live values, default whole-process scan, concurrent status requests, expected errors, process-switch unfreezing with record retention, same-PID scan retention and CE state surviving separate Python clients. Fixture memory was allocated in independent target.py processes. Tutorial PID 64016 remained alive and was not written, clicked, or advanced.

Codex config backed up to D:\CodexData\config.toml.bak-step2-20261125-020651 before raising only cheat_engine.tool_timeout_sec to 180. Config parses successfully. Scanner data follows existing E:\CEBUFFER configuration; CE launched with E: TEMP/TMP. No build or package operation was needed.

Final cleanup: restart CE to discard disposable test records and restore attachment to Tutorial PID 64016. No frozen test entries remain active. Final commit message: ⑮ 扫描和改内存.

## Step 3

Read debugger/disassembler API and constants; implemented timed per-breakpoint watches, instruction-end validation and register capture, NOP backups/readback/conflict checks. Built x64 C/MASM fixture under E:\workspace\ce-mcp\work\debug-fixture with TEMP/TMP on E:. Fixed machine instructions provide independent expected addresses/bytes/counts/registers.

First startup probe raced autorun; later list_processes works but new ce_status closes its pipe instead of returning JSON. Added explicit response-encoding diagnostics to trace this before changing debugger behavior. Competing hypotheses: unencodable debugger status result vs debugger API call error vs bridge not loaded. Working list_processes rules out a missing listener; pcall dispatch would return API errors, so serialization is the leading hypothesis.

Native diagnostics isolated debug_isBroken returning its own C function instead of a boolean (with and without debugger, and in a main-state timer). Local binding inspection confirms it computes the flag without pushing it to Lua. Use documented isPaused as primary state API. Typed memory/process APIs were unaffected. SplitDisassembledString also differed from documented tuple order, so disassembly now uses explicit LastDisassembleData fields.

Cleanup investigation: scalar breakpoint ID is rejected; complete {PID,DTID,ID} identity is accepted and disables hardware state. The CE list intentionally includes retired descriptors; local binding inspection confirmed it copies all descriptors without checking active/deleted flags. Consequently, comparing that list to an empty list was an invalid test. Independent Windows thread-context reads now assert DR7 is enabled during a watch and cleared afterward. Repeated same-address watches distinguish bridge-owned retired records from pre-existing addresses. Temporary diagnostics/probe timer removed. No CE binary changed.

Native and real SDK stdio tests passed: writers A/B each 7 hits; access monitor includes reader A for 21 hits; exact instruction bytes/module offsets/first RCX/RDX/RAX and RIP+2 checked against C/MASM fixture. Zero-hit, repeated watches, pipe-client disconnect, process-exit cleanup passed. Patching RX .text replaces 89 11 with 90 90, disables only writer A, restoration re-enables it, external edits block restoration, and original page protection stays PAGE_EXECUTE_READ. All five debugger tools work through MCP; total tools=16. Tutorial was never attached, debugged, written, or clicked during this step.

Final cold-start rerun passed the debugger suite and the full original 11-tool scan/memory regression. Removed the arbitrary unique-instruction cap; oversized protocol responses now fail explicitly rather than truncating data. All native fixtures exited; NOP byte backups are empty after successful restores. Final CE restart clears test-only memory records and retired descriptors and leaves CE unattached, with no active watch or saved patch. Tutorial remained PID 64016 with the same start time. No Codex config change was needed (existing 180-second tool timeout already covers watches). Ready for commit ⑯ 调试器.

## Step 4

Checked installed celua.txt pointer and memory-region APIs before implementation. Added shared addressing.lua helpers; reused typed values, record ownership and freezing in tools.lua. API offsets run from base to leaf and are reversed for native CE records. Native CurrentAddress is checked before the optional value/freeze operation. Record responses include actual native OffsetText order.

Built independent x64 and x86 C fixtures with all objects/executables/TEMP/TMP under E:\workspace\ce-mcp\work. Three-level asymmetric chain [20,-10,38] resolves from a module-root slot through HeapAlloc slots to a leaf; an intermediate slot can be retargeted to a second leaf. x86 slots include poison after their 4-byte pointer; x64 actual pointer values exceed 4 GiB.

Both architectures passed real CE and real SDK stdio: 20 schemas; seven typed pointer reads/writes; negative offsets; module expressions; native offset arrays/text; explicit initial value, freezing, intermediate retargeting, unlocking/refreezing; string records; direct empty chains; null roots/later links; invalid offsets/base; static/dynamic metadata on first/next/paged scans. Module/private/reserved/guard/mapped/free region metadata matched independent VirtualQueryEx. No failures required a speculative fix. Tutorial has not been attached, debugged or modified.

Full scan/memory regression (all original 11 tools, including native records/freezing) and debugger regression (five tools with real hit/context/DR7/NOP checks) passed with the new pointer helpers loaded. No additional source changes were needed after validation. All native fixture processes exited, freezes were disabled on attachment change, and debugger patches/watches were restored/removed. Final CE restart clears test-only records and leaves PID 0, no active debugger/watch or saved patches. No Codex config change required. Final commit: ⑰ 指针.

## Step 5

Added named Auto Assembler enable/disable, wildcard AOB matches, module-unique injection templates and structure comparison. A separate CE instance on `ce_mcp_step5` ran the native fixture and official MCP SDK client; all four new tools passed, with 24 tool schemas. Existing scan and debugger regressions passed on the isolated instance. The active CE bridge was hot-loaded without changing its Tutorial attachment or debugger state. Build and temporary files stayed on E:.
