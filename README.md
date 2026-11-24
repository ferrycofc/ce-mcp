# Cheat Engine MCP

Windows / Cheat Engine 7.7 / official Python MCP SDK 2.3.0.

## Installed layout

- `ce/bridge.lua`: CE bridge. Background listener at `\\.\pipe\ce_mcp`, up to 16 pipe instances; each accepted client gets a worker thread. CE calls execute through `synchronize` on the main thread.
- `ce/autorun.lua`: installed as `C:\Program Files\Cheat Engine\autorun\ce_mcp.lua`; loads the bridge from this project. Restart CE after editing the bridge. Loading twice is guarded.
- `server/server.py`: MCP stdio server. Each tool call creates its own pipe connection. CE attachment is global to CE, so another client can change the currently attached process.
- `.venv`: dedicated Python environment.

## Tools

| Tool | Arguments | Result |
| --- | --- | --- |
| `ce_status` | none | CE version, attached PID and process name (name omitted when unattached) |
| `list_processes` | optional `filter` | PID/name list, case-insensitive substring match |
| `attach` | exactly one of `name`, `pid` | Attached process status; exact executable name, case-insensitive; duplicate matches require PID |
| `read_memory` | `address` string, `size` 1..65536 | Resolved hex address, size, space-separated hex bytes, printable ASCII; nonprintable bytes become `.` |

Addresses accept CE expressions, for example `Tutorial-x86_64.exe`, `Tutorial-x86_64.exe+100`, or `0x100000000`. An unreadable or incomplete range returns an error instead of partial data.

## Protocol

Little-endian unsigned 32-bit UTF-8 byte length, followed by JSON (maximum 1 MiB). Requests: `{"method":"ce_status","params":{}}`. Responses: `{"ok":true,"result":{...}}` or `{"ok":false,"error":"..."}`. Connections support repeated requests. Idle CE client connections expire after 15 seconds; Python calls have a 20-second I/O deadline. No arbitrary Lua execution tool is exposed. This local pipe assumes trusted local clients.

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

## Codex registration

`D:\CodexData\config.toml` contains `[mcp_servers.cheat_engine]` launching the dedicated Python interpreter with the absolute server path. Restart Codex to load the newly registered server. CE must be running; the MCP server can start without CE and returns a clear connection error until CE is available.

## Validation — 2026-11-25

Verified installed CE APIs in `C:\Program Files\Cheat Engine\celua.txt`: `createPipe`, `acceptConnection(true)`, pipe framing methods, `createThread`, `synchronize`, `getCEVersion`, `getProcesslist`, `getOpenedProcessID`, `openProcess`, `getAddressSafe`, `readBytes`. JSON uses CE's bundled `require('json')`.

Real CE restart successfully loaded autorun; initial status reported 7.7/PID 0. Attached existing Tutorial PID 64016 by name and PID, read DOS header at `0x100000000` with `4D 5A` / `MZ`, verified symbol and numeric addresses and 64 KiB read. Passed 32 requests across 8 concurrent clients, idle-client isolation, fragmented framing, expected error cases, and real MCP stdio initialization/tool discovery/all four tool calls with content assertions. Expected unreadable-memory errors reach the MCP client, and subsequent calls succeed. Tutorial remains attached. Codex's reload of the new registration requires restarting the app and was not performed during this chat.
