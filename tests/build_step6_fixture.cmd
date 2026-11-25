@echo off
set "TEMP=E:\workspace\ce-mcp\work\temp"
set "TMP=%TEMP%"
if not exist "%TEMP%" mkdir "%TEMP%"
if not exist "E:\workspace\ce-mcp\work\step6-fixture" mkdir "E:\workspace\ce-mcp\work\step6-fixture"
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
if errorlevel 1 exit /b 1
cl /nologo /O2 /Fe"E:\workspace\ce-mcp\work\step6-fixture\step6_target.exe" /Fo"E:\workspace\ce-mcp\work\step6-fixture\target.obj" "E:\workspace\ce-mcp\tests\step6_target.c" /link /INCREMENTAL:NO /PDB:"E:\workspace\ce-mcp\work\step6-fixture\target.pdb"
if errorlevel 1 exit /b 1
cl /nologo /LD /O2 /Fe"E:\workspace\ce-mcp\work\step6-fixture\step6_log.dll" /Fo"E:\workspace\ce-mcp\work\step6-fixture\dll.obj" "E:\workspace\ce-mcp\tests\step6_log_dll.c" /link /INCREMENTAL:NO /PDB:"E:\workspace\ce-mcp\work\step6-fixture\dll.pdb"
exit /b %errorlevel%
