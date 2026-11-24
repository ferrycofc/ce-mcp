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

## Codex registration

`D:\CodexData\config.toml` contains `[mcp_servers.cheat_engine]` launching the dedicated Python interpreter with the absolute server path. Restart Codex to load the newly registered server. CE must be running; the MCP server can start without CE and returns a clear connection error until CE is available.

## Validation — 2026-11-25

Verified installed CE APIs in `C:\Program Files\Cheat Engine\celua.txt`: `createPipe`, `acceptConnection(true)`, pipe framing methods, `createThread`, `synchronize`, `getCEVersion`, `getProcesslist`, `getOpenedProcessID`, `openProcess`, `getAddressSafe`, `readBytes`. JSON uses CE's bundled `require('json')`.

Real CE restart successfully loaded autorun; initial status reported 7.7/PID 0. Attached existing Tutorial PID 64016 by name and PID, read DOS header at `0x100000000` with `4D 5A` / `MZ`, verified symbol and numeric addresses and 64 KiB read. Passed 32 requests across 8 concurrent clients, idle-client isolation, fragmented framing, expected error cases, and real MCP stdio initialization/tool discovery/all four tool calls with content assertions. Expected unreadable-memory errors reach the MCP client, and subsequent calls succeed. Tutorial remains attached. Codex's reload of the new registration requires restarting the app and was not performed during this chat.
