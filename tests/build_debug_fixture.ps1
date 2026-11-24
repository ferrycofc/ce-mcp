$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path $PSScriptRoot -Parent
if (-not $projectRoot.StartsWith('E:\', [StringComparison]::OrdinalIgnoreCase)) {
    throw 'Fixture builds must run in the E: workspace.'
}
$buildPath = Join-Path $projectRoot 'work\debug-fixture'
$tempPath = Join-Path $projectRoot 'work\temp'
New-Item -ItemType Directory -Force $buildPath, $tempPath | Out-Null
$env:TEMP = $tempPath
$env:TMP = $tempPath
$env:VSCMD_SKIP_SENDTELEMETRY = '1'
$vcvars = 'C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat'
if (-not (Test-Path -LiteralPath $vcvars)) { throw 'Visual Studio x64 build tools are required.' }
$script = @"
@echo off
call "$vcvars"
if errorlevel 1 exit /b 1
cl /nologo /O2 /c /Fo"$buildPath\target.obj" "$PSScriptRoot\debug_target.c"
if errorlevel 1 exit /b 1
ml64 /nologo /c /Fo"$buildPath\code.obj" "$PSScriptRoot\debug_target.asm"
if errorlevel 1 exit /b 1
link /nologo /SUBSYSTEM:CONSOLE /INCREMENTAL:NO /OPT:NOICF /OUT:"$buildPath\ce_mcp_debug_target.exe" "$buildPath\target.obj" "$buildPath\code.obj" kernel32.lib
exit /b %errorlevel%
"@
$scriptPath = Join-Path $buildPath 'build.cmd'
[IO.File]::WriteAllText($scriptPath, $script, [Text.Encoding]::ASCII)
Push-Location $buildPath
try {
    & $env:ComSpec /d /c $scriptPath
    if ($LASTEXITCODE -ne 0) { throw "Native fixture build failed: $LASTEXITCODE" }
} finally { Pop-Location }
