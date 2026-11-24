# Step 2: scanning and typed memory tools

- [x] Commit skeleton as ⑭ 骨架：管道桥和四个工具 (9ada401).
- [x] Read installed celua.txt scan, FoundList, typed memory, memory record APIs.
- [x] Implement CE-owned single scan, typed values, address table and freeze lifecycle.
- [x] Exercise through real CE and MCP against a dedicated disposable process; never modify Tutorial.
- [x] Document results and commit as ⑮ 扫描和改内存.

Final validation passed against real CE and official MCP SDK stdio: all 11 tools, seven types, all native scan comparisons, native unknown snapshots, all-type freeze, process switches, same-PID scan retention, cross-Python-client state, whole-process scan, and negative cases. CE will be restarted after fixture cleanup to remove disposable table entries, then reattached to the original Tutorial PID without writing memory.

Constraints: E: temporary/cache storage; restart CE permitted; keep Tutorial alive and unmodified. No unrelated audit.
