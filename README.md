# Cheat Engine MCP

Windows / Cheat Engine 7.7 / official Python MCP SDK 2.3.0.

## Installed layout

- `ce/bridge.lua`: CE bridge. Background listener at `\\.\pipe\ce_mcp`, up to 16 pipe instances; each accepted client gets a worker thread. CE calls execute through `synchronize` on the main thread. `CE_MCP_PIPE_NAME` selects a separate pipe for isolated test instances.
- `ce/autorun.lua`: installed as `C:\Program Files\Cheat Engine\autorun\ce_mcp.lua`; loads the bridge from this project. New CE starts load the current bridge. Loading twice is guarded; the active session can be hot-loaded without restarting CE.
- `server/server.py`: MCP stdio server. Each tool call creates its own pipe connection. CE attachment is global to CE, so another client can change the currently attached process.
- `.venv`: dedicated Python environment.

## Tools

| Tool | Arguments | Result |
| --- | --- | --- |
| `ce_status` | none | CE version, attached PID and process name (name omitted when unattached) |
| `list_processes` | optional `filter` | PID/name list, case-insensitive substring match |
| `attach` | exactly one of `name`, `pid` | Attached process status; exact executable name, case-insensitive; duplicate matches require PID |
| `read_memory` | `address` string, `size` 1..65536 | Resolved hex address, size, space-separated hex bytes, printable ASCII; nonprintable bytes become `.` |
| `auto_assemble` | `name`, full `script` on enable; `enable=false` to disable | Runs named `[ENABLE]`/`[DISABLE]` scripts and retains CE's disable state for restoration |
| `aob_scan` | hex-byte/`??` `pattern`, optional `module` | All matching addresses with module+offset metadata |
| `injection_template` | `address`, optional symbol `name` | Module-unique AOB script, complete stolen instructions, 5-byte near jump, return address and exact DISABLE bytes |
| `compare_structures` | 2..16 `addresses`, `length`, optional `stride`/`types` | Per-offset integer, float and pointer interpretations with differing fields |

Addresses accept CE expressions, for example `Tutorial-x86_64.exe`, `Tutorial-x86_64.exe+100`, or `0x100000000`. An unreadable or incomplete range returns an error instead of partial data.

## Protocol

Little-endian unsigned 32-bit UTF-8 byte length, followed by JSON (maximum 1 MiB). Requests: `{"method":"ce_status","params":{}}`. Responses: `{"ok":true,"result":{...}}` or `{"ok":false,"error":"..."}`. Connections support repeated requests. Idle CE client connections expire after 15 seconds; Python calls have a 20-second I/O deadline. `auto_assemble` executes trusted CE Auto Assembler scripts, including embedded Lua. This local pipe assumes trusted clients. Broad AOB results can exceed 1 MiB; narrow the module or use a longer pattern.

## Run and test

```powershell
& E:\workspace\ce-mcp\.venv\Scripts\python.exe -B E:\workspace\ce-mcp\server\server.py
# With CE and Tutorial-x86_64.exe running:
& E:\workspace\ce-mcp\.venv\Scripts\python.exe -B E:\workspace\ce-mcp\tests\integration.py
```

Dependencies are pinned in `requirements.txt`. When reinstalling, set TEMP/TMP and package caches to E: before running package tools. Do not run builds or packaging on C:.

## Step 2: scans, typed values and address table

`ce/tools.lua` implements the following seven additional tools:

| Tool | Main arguments | Behavior |
| --- | --- | --- |
| `scan_first` | `value_type`, `scan_type`, optional `value`, `value2`, `start_address`, `stop_address` | Replaces the previous scan; default range is the whole target process |
| `scan_next` | `scan_type`, optional `value`, `value2` | Refines the CE-owned previous scan and retains its value type |
| `scan_results` | `start=0`, `count=20` | Pages current results; count is 1..200 |
| `read_value` | `address`, `value_type`, optional string `length=256` | Returns a typed value as a string |
| `write_value` | `address`, `value_type`, `value` | Writes and reads back the typed value |
| `add_to_table` | `address`, `value_type`, `description`, `frozen=false`, optional `frozen_value`, `length=256` | Creates a visible CE memory record and returns its stable `id` |
| `set_frozen` | `id`, `frozen`, optional `value` | Changes the freeze state/value of a bridge-created record |

Types: `byte`, `2bytes`, `4bytes`, `8bytes`, `float`, `double`, `string`. Pass decimal values as strings, particularly 64-bit integers and floating point scan inputs where `100` and `100.0` have different CE rounding precision. Integer reads return unsigned decimal strings; writes also accept negative numbers within the corresponding signed range. Strings use UTF-8 and NUL termination, at most 4096 bytes. String writes require enough space for the value plus its NUL; address-table string length is the maximum byte length.

First scan modes: `exact`, `bigger`, `smaller`, `between` (value/value2), `unknown`. Next modes: `exact`, `bigger`, `smaller`, `between`, `increased`, `decreased`, `changed`, `unchanged`, `increased_by`, `decreased_by`. Changes compare against the immediately preceding scan. Float and double scans use CE's `rtRounded`, so `100` matches `100.0` and `100.25`, while `100.0` uses a narrower range. Scan address bounds follow CE's native range rules.

CE API boundaries are explicit: **unknown is an initial scan only**; it captures regions rather than enumerating matches. Its response has `snapshot=true`, `total_kind="bytes"`, captured byte count in `total`, and an empty address list. Use `scan_next` to obtain matching addresses. String scanning supports `exact` only; other string scan modes return an error. These restrictions come from the installed CE scan API, rather than silently substituting other comparisons.

Ordinary scan responses contain `total` (all matches), `total_kind="addresses"`, `start` (zero-based), `value_type`, and `results` (first 20 for scan operations). Each result contains `index`, hex `address`, and current `value` reread from the target. If an address becomes unreadable it carries an `error`. Pagination does not cache old values.

One scan exists per CE bridge. Concurrent scan mutations are rejected while scanning; the CE main thread remains available while a pipe worker waits for completion. Scan timeout is 120 seconds; Python allows 150 seconds for scan requests, and the Codex MCP timeout is 180 seconds. A new MCP attachment clears the previous scan and unfreezes bridge-created memory records, preserving the records in CE's table. Bridge records can only be frozen when their original PID is attached. Attaching the already attached PID retains the scan. Other CE table entries are untouched. `frozen_value` is applied when `frozen=true`; omitting it freezes the current value. `set_frozen(..., frozen=true, value=...)` changes the locked value.

### Step 2 validation — 2026-11-25

```powershell
& E:\workspace\ce-mcp\.venv\Scripts\python.exe -B E:\workspace\ce-mcp\tests\step2_integration.py
```

The fixture starts `tests/target.py` as an independent process with its own allocated page. It verifies all seven scan/read/write types, all supported numeric first/next modes, unknown snapshots and refinements, full uint64 precision, signed writes and range errors, CE float rounding precision, first-20/paged/empty/live results, scan replacement, all seven types of freezing with target-side overwrite/read verification, unlocking, whole-process scanning without bounds, concurrency of status calls, and expected errors. A real official SDK client initializes the stdio server, verifies all 11 tool schemas, and calls all 11 tools with content assertions. All memory writes go exclusively to the disposable target, not Tutorial. CE was restarted to prove autorun loads both modules. The original Tutorial process remained alive; no tutorial controls, values, or stage transitions were changed. Scanner storage uses the user's existing E:\CEBUFFER setting.

## Step 3: debugger

`ce/debugger.lua` adds five tools (16 tools in total):

| Tool | Arguments | Result |
| --- | --- | --- |
| `find_what_writes` | `address`, `seconds=5`, `size=1` | Hardware write watch with per-instruction hit counts and first-hit registers |
| `find_what_accesses` | same | Hardware read/write watch |
| `disassemble` | `address`, `count=10` (1..200) | Sequential instruction addresses, raw bytes, instruction text, module offsets and sizes |
| `nop_instruction` | `address` at an instruction start | Replaces exactly one instruction with same-length `90` bytes and saves its original bytes |
| `restore_instruction` | original `address` | Verifies the NOP bytes and restores the saved original bytes |

Watches accept 0.1..120 seconds and hardware sizes 1/2/4, plus 8 for x64; the address must be aligned to size. The bridge starts the Windows debugger if none is active, otherwise uses the current CE debugger. It explicitly requests `bpmDebugRegister` with `bptWrite` or `bptAccess`; no software/exception-breakpoint fallback. One watch runs at a time. Requests reject overlapping pre-existing breakpoints, attaching another process, and NOP edits during a watch. Status includes a `debugger` object with `debugging`, `paused`, `monitoring`, `watch_address` (when active) and `saved_patches` for the current PID. A completed watch removes its own full breakpoint identity and leaves other callbacks intact; an independent CE timer performs expiry cleanup even if the pipe client disconnects. Callback errors are recorded and execution is continued. Debugger attachment remains active after a watch.

Watch responses contain `instructions`, `total_hits`, `unattributed_hits`, `errors`, elapsed time, completion `reason` and `breakpoint_removed`. Each instruction has a hexadecimal `address`, `symbol` (`module+offset`), `module`, `module_offset`, `bytes`, `instruction`, `size`, `hit_count`, first-hit hexadecimal `registers`, and `stopped_ip`. Dynamically allocated/JIT code without a containing module uses a raw address rather than inventing a module name. All unique instruction addresses are collected; responses beyond the pipe's 1 MiB limit return an explicit error recommending a shorter watch.

**Post-instruction attribution:** x86/x64 hardware data breakpoints report IP after the memory instruction. The bridge uses CE's documented `getPreviousOpcode(stopped_ip)`, decodes that candidate and checks `candidate + size == stopped_ip`. The saved register context is the first hit's **post-execution** context; IP is retained separately from the inferred writer/accessor address. CE documents backwards decoding as an estimate: ambiguous x86 encodings and control-flow/string instructions can defeat this heuristic. Responses label it `attribution="ce_previous_opcode"`; failed attribution increments `unattributed_hits` and records an error rather than reporting the next instruction as a proven writer.

NOP operations pause a running target for the patch and readback, then resume it; an already paused target stays paused. Saved originals are keyed by PID/address in the current CE Lua session. Overlapping patches are rejected. Restore refuses to clobber a subsequent external edit. Restore patches **before restarting CE**, because the session's backups are in memory. Return values include original/patched hex bytes, size, process and restored state. The tested native RX code page retained its original protection.

### Debugger test fixture

```powershell
& E:\workspace\ce-mcp\tests\build_debug_fixture.ps1
& E:\workspace\ce-mcp\.venv\Scripts\python.exe -B E:\workspace\ce-mcp\tests\step3_integration.py
```

The build requires the installed Visual Studio 2022 Community x64 C/MASM tools. All build intermediates, executable, TEMP/TMP and compiler outputs are under `E:\workspace\ce-mcp\work`; no builds run on C:. `debug_target.c` + `debug_target.asm` provide independent known writers/readers in a real PE module: `89 11` (`mov [rcx],edx`) and `8B 01` (`mov eax,[rcx]`), each followed by `ret`. Tests check exact module offsets, stopped-IP correction (+2), first registers, write/access counts, zero/repeated watches, client disconnect, process exit, active-watch rejection of conflicting operations, NOP execution behavior, original-byte restoration and edit conflicts. Independent Windows `GetThreadContext` checks hardware debug-register enable bits during and after monitoring; this matters because CE's `debug_getBreakpointList` includes inactive retired descriptors. The official SDK stdio client verifies 16 schemas and all five debugger tools with actual hits/patches. These tests never attach, debug or modify Tutorial.

## Step 4: pointers and address information

Four additional tools bring the total to 20:

| Tool | Arguments | Result |
| --- | --- | --- |
| `read_pointer` | `base`, `offsets`, `value_type="4bytes"`, string `length=256` | Each dereference and the final typed value |
| `write_pointer` | `base`, `offsets`, `value_type`, `value` | Same trace, with a write/readback at the final address |
| `add_pointer_to_table` | `base`, `offsets`, `value_type`, `description=""`, optional `value`, `frozen=false`, string `length=256` | A native CE pointer record, with stable ID and live resolved address |
| `address_info` | `address` | Static module information plus Windows region attributes/classification |

`base` accepts CE expressions such as `game.exe+1234`. Offsets are **base-to-leaf**: for each offset, read a pointer at the current address, then add that offset. Integer inputs are decimal; string inputs are hexadecimal with optional sign and `0x` prefix. For example, `offsets=["20","-10","38"]` means:

```text
a1 = pointer_at(base) + 0x20
a2 = pointer_at(a1)   - 0x10
final = pointer_at(a2) + 0x38
value = typed_read(final)
```

The API accepts up to 64 signed 32-bit offsets. `offsets=[]` performs no dereference and reads/writes `base` directly; `[0]` dereferences once. A native pointer record requires at least one offset. A null/unreadable link returns an error identifying its layer and pointer-slot address, without writing through the failed chain. Pointer reads use QWORDs for a 64-bit target and DWORDs for a 32-bit target, independently of CE/Python host width and the final value's type.

Trace results contain `base`, `base_address`, `pointer_size`, `offset_order="base_to_leaf"`, normalized `offsets`, `layers`, final `address`, `value_type` and `value`. Each layer provides `index` (1-based), `address` (pointer slot), `pointer_value`, `offset` and `next_address`. Values retain the existing typed-memory string representation and precision rules. The chain is a sequential runtime observation, not a frozen snapshot of concurrently changing target memory.

**CE record/UI order is reversed:** the example above becomes native `Offset[0..2] = [0x38,-0x10,0x20]`, with actual `OffsetText = ["38","-10","20"]`. The bridge preserves the original base expression in `MemoryRecord.Address`, sets `OffsetCount` and native `Offset[]`, and verifies `CurrentAddress` against the trace before applying an optional value or freeze. It never substitutes a fixed leaf address. Records return `is_pointer`, `offset_count`, API `offsets`, `ce_offsets`, actual `ce_offset_texts`, and `resolved_address`. Existing `set_frozen` works on their returned IDs. With `value` omitted, `frozen=true` freezes the current value; with `value` supplied, it is written even when not frozen. Strings use the supplied record length. Attachment changes unfreeze pointer records through the same lifecycle as ordinary records.

`address_info` returns `is_static`, `is_dynamic`, `classification` and `region`. A module address also includes `symbol` (`module+hex-offset`), `module`, `module_base`, `module_offset`, and `module_path`. Classifications distinguish `static_module`, `dynamic_private`, `mapped`, `unlisted_image`, `reserved`, and `free`. MEM_PRIVATE may be heap, stack or VirtualAlloc memory; region metadata alone cannot establish heap provenance. Region details include base/allocation base, size as decimal and hex strings, raw state/type codes and names, protection codes/names, allocation protection, readable/writable/executable, guard, copy-on-write, no-cache and write-combine flags. Guarded regions are not reported as immediately readable/writable.

Every enumerated scan result now includes `is_static`; module-backed results additionally have `symbol`, `module`, and `module_offset`. This applies to the first 20 results of scan_first/scan_next and to scan_results pages, using a fresh module list per page. Unknown-initial snapshots still have no address entries until refinement.

### Pointer validation — 2026-11-25

```powershell
& E:\workspace\ce-mcp\tests\build_pointer_fixture.ps1
& E:\workspace\ce-mcp\.venv\Scripts\python.exe -B E:\workspace\ce-mcp\tests\step4_integration.py
```

The helper builds x64 and x86 versions of `pointer_target.c` using installed Visual Studio tools, exclusively under `E:\workspace\ce-mcp\work\pointer-fixture`. The native fixture supplies an independently known three-layer chain with asymmetric/negative offsets, high x64 heap addresses and poisoned DWORDs after x86 pointer slots. Both versions verify all seven final types, exact trace addresses/values, native CE offset order and texts, optional initial setting, lock/unlock, and retargeting a middle link while a native pointer record follows/freezes the new leaf. Module, heap/private, reserved, guarded, mapped and free-region reports are checked against an independent OS VirtualQueryEx call. Static and dynamic scan metadata are checked for first, next and paged results. Real SDK clients discover 20 schemas and exercise all four new tools for each architecture. Fixtures never attach, write, debug or send input to Tutorial.

## Step 5: code injection

`auto_assemble(name, script)` enables a CE script with both `[ENABLE]` and `[DISABLE]` sections. CE's returned `disableInfo` stays in the Lua bridge under that name; call `auto_assemble(name, enable=false)` to run DISABLE and release its allocations. The bridge refuses an MCP process switch while a live process has an enabled script. An exited process has no bytes to restore, so its saved script is discarded on the next switch.

`aob_scan` accepts space-separated hex bytes and `??` wildcards. With `module`, it keeps only complete matches inside that module; without it, it returns matches from the process. Results include `symbol` and `module_offset` when the address belongs to a module.

`injection_template` requires a module instruction address. It extends whole instructions until at least 5 bytes are available, then extends a wildcard-aware AOB until it is unique in that module. The generated script allocates `newmem` near the site, forces a 5-byte `jmp long` on x64, reassembles original instructions in the cave (so relative operands keep their destinations), jumps back after the overwritten span, and restores the exact original bytes in DISABLE. Edit the marked custom-code line before enabling it. The `assert` in the script rejects changed original bytes.

`compare_structures` reads 2..16 blocks and compares every byte offset by default (`stride=1`); set `stride=4` to inspect 4-byte boundaries. Each row includes 4-byte integer, float and pointer interpretations by default, raw bytes, and a `different` marker. These are sequential reads of a running process, not a frozen snapshot.

The isolated step 5 test uses `CE_MCP_PIPE_NAME=ce_mcp_step5` for both a separate CE instance and the MCP server. Its native fixture demonstrates a 7-byte overwrite with an actual 5-byte near jump, changes a function result by +2 while enabled, and checks byte-for-byte restoration after disabling. The older scan and debugger suites also pass against that isolated instance. No test attaches to Tutorial.

## Codex registration

`D:\CodexData\config.toml` contains `[mcp_servers.cheat_engine]` launching the dedicated Python interpreter with the absolute server path. Restart Codex to load the newly registered server. CE must be running; the MCP server can start without CE and returns a clear connection error until CE is available.

## Validation — 2026-11-25

Verified installed CE APIs in `C:\Program Files\Cheat Engine\celua.txt`: `createPipe`, `acceptConnection(true)`, pipe framing methods, `createThread`, `synchronize`, `getCEVersion`, `getProcesslist`, `getOpenedProcessID`, `openProcess`, `getAddressSafe`, `readBytes`. JSON uses CE's bundled `require('json')`.

Real CE restart successfully loaded autorun; initial status reported 7.7/PID 0. Attached existing Tutorial PID 64016 by name and PID, read DOS header at `0x100000000` with `4D 5A` / `MZ`, verified symbol and numeric addresses and 64 KiB read. Passed 32 requests across 8 concurrent clients, idle-client isolation, fragmented framing, expected error cases, and real MCP stdio initialization/tool discovery/all four tool calls with content assertions. Expected unreadable-memory errors reach the MCP client, and subsequent calls succeed. Tutorial remains attached. Codex's reload of the new registration requires restarting the app and was not performed during this chat.
