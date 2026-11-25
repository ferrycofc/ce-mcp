# ce-mcp

把 Cheat Engine 7.7 的 Lua 功能接到本机 MCP 客户端。CE 内的 Lua 桥通过 Windows 命名管道 `\\.\pipe\ce_mcp` 接收请求；Python 服务以 stdio 向 MCP 客户端提供 33 个工具。地址、扫描结果、调试器和地址表都由 CE 管理。这个项目只在本机运行，不提供网络服务。

项目用 CE 自带的 Tutorial、gtutorial 和自写测试程序开发。使用前请确认你有权操作目标进程；`run_lua`、内存写入、代码注入和脚本记录会在 CE 当前附加的进程中执行。

## 需要什么

- Windows、Cheat Engine 7.7（含 `celua.txt` 和 Lua autorun）、Python 3.12。当前依赖版本见 `requirements.txt`。
- 一个支持**本地 stdio MCP** 的客户端。下面给出 Codex 配置示例。
- 只有运行原生测试夹具时才需要 Visual Studio C++ 构建工具（含 x86/x64 编译器和 MASM）；Mono 测试另需下载 Mono 安装包。

## 三步安装

1. **安装 Python 依赖。** 在 PowerShell 里进入克隆后的仓库目录：

   ```powershell
   py -3.12 -m venv .venv
   .\.venv\Scripts\python.exe -m pip install -r requirements.txt
   ```

2. **安装 CE 启动脚本。** 把参数换成你自己的 CE 安装目录；若目录在 Program Files，PowerShell 需要相应写入权限。

   ```powershell
   .\install.ps1 -CheatEngineDir '<你的 CE 安装目录>'
   ```

   安装器把 `ce/autorun.lua` 复制成 CE 的 `autorun/ce_mcp.lua`，并在同一目录写入只含本机仓库路径的 `ce_mcp_path.txt`。启动 CE 时，加载器读这个文件找到仓库的 `ce/bridge.lua`；其它 Lua 模块按自身文件位置加载。移动仓库后重新运行安装器。安装后启动 CE，Lua 桥会自动加载；已有 CE 进程要重新加载启动脚本时，可在 CE 的 Lua Engine 执行 `dofile([[<CE 安装目录>/autorun/ce_mcp.lua]])`，前提是该进程里尚未加载桥。

3. **在本地 MCP 客户端配置 Python 服务。** 例如在 [Codex 的 MCP 配置](https://developers.openai.com/learn/docs-mcp)中加入下面的 TOML，把示例路径全部换成仓库的实际绝对路径（TOML 单引号保留 Windows 反斜杠）：

   ```toml
   [mcp_servers.cheat_engine]
   command = 'X:\path\to\ce-mcp\.venv\Scripts\python.exe'
   args = ['-B', 'X:\path\to\ce-mcp\server\server.py']
   startup_timeout_sec = 30
   tool_timeout_sec = 180
   ```

   重新连接客户端后调用 `ce_status`，应看到 CE 版本和当前附加的进程。Python 服务可以先启动，CE 未运行时会返回管道不可用错误。

**ChatGPT 网页版：** 当前仓库只有本地 stdio 服务，不能直接把 Python 文件或 `\\.\pipe\ce_mcp` 填成 ChatGPT 的 Server URL。官方的 [自定义 MCP 连接](https://developers.openai.com/api/docs/guides/custom-mcp-server)使用远程 SSE/streaming HTTP URL，或者具备相应权限的 [Secure MCP Tunnel](https://developers.openai.com/api/docs/guides/secure-mcp-tunnels)。仓库尚未实现这两种部署方式，也不是已发布的 ChatGPT 插件。

## 工具清单（33 个）

| 分组 | 工具 | 用途 |
| --- | --- | --- |
| 进程和内存（4） | `ce_status`, `list_processes`, `attach`, `read_memory` | 查看状态、列进程、附加、读原始字节 |
| 扫描和值（7） | `scan_first`, `scan_next`, `scan_results`, `read_value`, `write_value`, `add_to_table`, `set_frozen` | 首次/后续扫描、翻页、按类型读写、添加和锁定记录 |
| 调试器（5） | `find_what_writes`, `find_what_accesses`, `disassemble`, `nop_instruction`, `restore_instruction` | 硬件断点、反汇编、NOP 与恢复 |
| 指针（4） | `read_pointer`, `write_pointer`, `add_pointer_to_table`, `address_info` | 指针链读写与内存区域信息 |
| 注入和分析（4） | `auto_assemble`, `aob_scan`, `injection_template`, `compare_structures` | AA 脚本、特征码、注入模板、结构对比 |
| CE 扩展（4） | `run_lua`, `speedhack`, `inject_dll`, `mono` | Lua、变速、DLL 注入、Mono 信息 |
| 地址表（5） | `list_table`, `add_script_record`, `set_record_active`, `save_table`, `load_table` | 查看/激活记录，保存或载入 `.CT` |

`scan_first` 会替换上一轮扫描，`scan_next` 接着当前扫描结果筛选。指针工具的偏移输入顺序是基址到最终地址；`list_table` 同时返回这个顺序和 CE 界面顺序。地址表记录 ID 以当前表为准，载入 `.CT` 后应重新查询。`load_table(..., merge=False)` 替换地址表；`merge=True` 追加。CE 会按自身规则处理 `.CT` 中的表脚本。

## 跑测试

测试使用独立 CE 实例和仓库自带的目标程序。先从仓库根目录编译原生夹具（所有输出在 `work/`）；`vswhere` 会定位 Visual Studio，不依赖固定安装路径：

```powershell
.\tests\build_native_fixtures.ps1
```

在一个 PowerShell 窗口启动**独立** CE，给它指定测试管道。例如测试第七步：

```powershell
$env:CE_MCP_PIPE_NAME = 'ce_mcp_step7'
Start-Process -FilePath '<CE 安装目录>\cheatengine-x86_64.exe'
.\.venv\Scripts\python.exe -B .\tests\step7_integration.py
```

其它测试脚本位于 `tests/`。`step5_integration.py` 要求 `ce_mcp_step5`，`step6_integration.py` 和 `step6_mono_integration.py` 要求 `ce_mcp_step6`，`step6_print_regression.py` 要求以 `ce_mcp_printfix` 开头的管道；切换管道时为该测试启动另一份 CE。`step2_integration.py`、`step3_integration.py` 和 `step4_integration.py` 使用各自的自写目标。`integration.py` 会附加 CE 官方 Tutorial，默认测试流程无需运行。Mono 夹具可用 `tests/build_step6_mono_fixture.ps1` 另行构建，它会下载 Mono 安装包到 `work/`。

## 已知限制

- 仅验证了 Windows 上的 CE 7.7 和 Python 3.12。CE 的 Lua API 以安装包中的 `celua.txt` 为准；其它版本可能有差异。
- 一个 CE 实例同一时间只保留一轮扫描、一个硬件监视任务。硬件断点数量受 CPU/调试器限制；写入指令地址由停住位置向前解码推断，极少数不明确的指令不会被当成确定命中。
- `run_lua` 的超时可以中断 Lua 指令循环，但不能强行中断正在阻塞的 CE 原生调用。管道单条响应上限为 1 MiB。
- 命名管道和 MCP 服务没有用户认证；仅在可信的本机环境运行，不要把管道或未加防护的桥直接暴露到公网。
- `save_table` 和 `load_table` 使用 CE 原生 `.CT` 语义；载入来自别人的表前应先检查其中的 Lua/AA 脚本。

MIT 许可证见 [LICENSE](LICENSE)。
