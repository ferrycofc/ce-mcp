@echo off
set "TEMP=E:\workspace\ce-mcp\work\temp"
set "TMP=%TEMP%"
if not exist "%TEMP%" mkdir "%TEMP%"
if not exist "E:\workspace\ce-mcp\work\injection-fixture" mkdir "E:\workspace\ce-mcp\work\injection-fixture"
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
if errorlevel 1 exit /b 1
cl /nologo /O2 /c /Fo"E:\workspace\ce-mcp\work\injection-fixture\target.obj" "E:\workspace\ce-mcp\tests\injection_target.c"
if errorlevel 1 exit /b 1
ml64 /nologo /c /Fo"E:\workspace\ce-mcp\work\injection-fixture\code.obj" "E:\workspace\ce-mcp\tests\injection_target.asm"
if errorlevel 1 exit /b 1
link /nologo /SUBSYSTEM:CONSOLE /INCREMENTAL:NO /OPT:NOICF /OUT:"E:\workspace\ce-mcp\work\injection-fixture\ce_mcp_injection_target.exe" "E:\workspace\ce-mcp\work\injection-fixture\target.obj" "E:\workspace\ce-mcp\work\injection-fixture\code.obj" kernel32.lib
exit /b %errorlevel%
