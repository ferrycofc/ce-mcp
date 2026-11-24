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

## Codex registration

`D:\CodexData\config.toml` contains `[mcp_servers.cheat_engine]` launching the dedicated Python interpreter with the absolute server path. Restart Codex to load the newly registered server. CE must be running; the MCP server can start without CE and returns a clear connection error until CE is available.

## Validation — 2026-11-25

Verified installed CE APIs in `C:\Program Files\Cheat Engine\celua.txt`: `createPipe`, `acceptConnection(true)`, pipe framing methods, `createThread`, `synchronize`, `getCEVersion`, `getProcesslist`, `getOpenedProcessID`, `openProcess`, `getAddressSafe`, `readBytes`. JSON uses CE's bundled `require('json')`.

Real CE restart successfully loaded autorun; initial status reported 7.7/PID 0. Attached existing Tutorial PID 64016 by name and PID, read DOS header at `0x100000000` with `4D 5A` / `MZ`, verified symbol and numeric addresses and 64 KiB read. Passed 32 requests across 8 concurrent clients, idle-client isolation, fragmented framing, expected error cases, and real MCP stdio initialization/tool discovery/all four tool calls with content assertions. Expected unreadable-memory errors reach the MCP client, and subsequent calls succeed. Tutorial remains attached. Codex's reload of the new registration requires restarting the app and was not performed during this chat.
