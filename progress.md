# Progress

2026-11-25: skeleton committed (9ada401). Installed celua.txt checked. Implementation in progress. Tutorial PID 64016 will not be written or advanced. Tests will allocate controlled values in a separate Python process.

First runtime run passed seven typed scans/reads/writes and float rounding. Pagination fixture found 31 of 32 values because CE's stop boundary omitted the final complete value. Expanded test bound by one width and clarified API doc to use CE's native range semantics; no scan algorithm change.

All 11 tools passed real CE and MCP stdio. Live values now independently reread target memory. Unknown initial scans successfully refine via all next modes but FoundList.Count is 0 before refinement because CE uses region snapshots. Native FoundCount/getProgress reporting verified: captured byte count, snapshot=true, total_kind=bytes. Enumerated results declare total_kind=addresses.

Final suite passed after CE cold restart: seven types of scan/read/write/freeze, uint64 precision/signed writes, rounding, all supported numeric scan comparisons, paging/empty/live values, default whole-process scan, concurrent status requests, expected errors, process-switch unfreezing with record retention, same-PID scan retention and CE state surviving separate Python clients. Fixture memory was allocated in independent target.py processes. Tutorial PID 64016 remained alive and was not written, clicked, or advanced.

Codex config backed up to D:\CodexData\config.toml.bak-step2-20261125-020651 before raising only cheat_engine.tool_timeout_sec to 180. Config parses successfully. Scanner data follows existing E:\CEBUFFER configuration; CE launched with E: TEMP/TMP. No build or package operation was needed.

Final cleanup: restart CE to discard disposable test records and restore attachment to Tutorial PID 64016. No frozen test entries remain active. Final commit message: ⑮ 扫描和改内存.
