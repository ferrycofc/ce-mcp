# Step 2: scanning and typed memory tools

- [x] Commit skeleton as ⑭ 骨架：管道桥和四个工具 (9ada401).
- [x] Read installed celua.txt scan, FoundList, typed memory, memory record APIs.
- [x] Implement CE-owned single scan, typed values, address table and freeze lifecycle.
- [x] Exercise through real CE and MCP against a dedicated disposable process; never modify Tutorial.
- [x] Document results and commit as ⑮ 扫描和改内存.

Final validation passed against real CE and official MCP SDK stdio: all 11 tools, seven types, all native scan comparisons, native unknown snapshots, all-type freeze, process switches, same-PID scan retention, cross-Python-client state, whole-process scan, and negative cases. CE will be restarted after fixture cleanup to remove disposable table entries, then reattached to the original Tutorial PID without writing memory.

# Step 3: debugger

- [x] Read installed celua.txt debugger, hardware breakpoint, context and disassembler APIs; verify constants in defines.lua.
- [x] Implement timed write/access watches with per-breakpoint callbacks, post-instruction attribution and cleanup. All unique instructions are retained; protocol overflow reports an explicit error rather than silently truncating.
- [x] Implement disassembly and process-scoped NOP backups/restoration with byte verification.
- [x] Test real native fixture + real MCP, including exact instruction addresses/counts/registers, zero-hit and repeat watches, disconnect cleanup, and unchanged Tutorial.
- [x] Document and commit as ⑯ 调试器.

Final cold-start suite and the complete step-2 regression passed through real CE and official SDK stdio. Native fixture processes exited; all NOPs restored and all monitored hardware slots disabled. Restart CE once after tests to discard test-only address records/debugger descriptors, leaving it unattached. Tutorial PID 64016 stayed unchanged and was not attached during step 3. Commit: ⑯ 调试器.

Constraints: E: temporary/cache storage; restart CE permitted; keep Tutorial alive and unmodified. No unrelated audit.
