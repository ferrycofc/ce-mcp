param([ValidateSet('x64','x86','all')][string]$Architecture = 'all')
$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path $PSScriptRoot -Parent
if (-not $projectRoot.StartsWith('E:\', [StringComparison]::OrdinalIgnoreCase)) {
    throw 'Fixture builds must run in the E: workspace.'
}
$tempPath = Join-Path $projectRoot 'work\temp'
New-Item -ItemType Directory -Force $tempPath | Out-Null
$env:TEMP=$tempPath
$env:TMP=$tempPath
$env:VSCMD_SKIP_SENDTELEMETRY='1'
$vcvars='C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvarsall.bat'
if (-not (Test-Path -LiteralPath $vcvars)) { throw 'Visual Studio C build tools are required.' }
$architectures = if ($Architecture -eq 'all') { @('x64','x86') } else { @($Architecture) }
foreach ($fixtureArch in $architectures) {
    $buildPath=Join-Path $projectRoot "work\pointer-fixture\$fixtureArch"
    New-Item -ItemType Directory -Force $buildPath | Out-Null
    $script=@"
@echo off
call "$vcvars" $fixtureArch
if errorlevel 1 exit /b 1
cl /nologo /O2 /Fo"$buildPath\target.obj" /Fe"$buildPath\ce_mcp_pointer_$fixtureArch.exe" "$PSScriptRoot\pointer_target.c" /link /INCREMENTAL:NO kernel32.lib
exit /b %errorlevel%
"@
    $scriptPath=Join-Path $buildPath 'build.cmd'
    [IO.File]::WriteAllText($scriptPath,$script,[Text.Encoding]::ASCII)
    Push-Location $buildPath
    try {
        & $env:ComSpec /d /c $scriptPath
        if ($LASTEXITCODE -ne 0) { throw "Pointer fixture build failed ($fixtureArch): $LASTEXITCODE" }
    } finally { Pop-Location }
}
