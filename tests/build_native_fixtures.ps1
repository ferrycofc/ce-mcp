param(
    [ValidateSet('all','debug','injection','pointer','step6')][string]$Fixture='all',
    [ValidateSet('all','x64','x86')][string]$Architecture='all'
)
$ErrorActionPreference='Stop'
$root=Split-Path $PSScriptRoot -Parent
$work=Join-Path $root 'work'
$temp=Join-Path $work 'temp'
New-Item -ItemType Directory -Force $temp | Out-Null
$env:TEMP=$temp
$env:TMP=$temp
$env:VSCMD_SKIP_SENDTELEMETRY='1'
$vcvars=& (Join-Path $PSScriptRoot 'find_vcvars.ps1')

function Invoke-NativeBuild([string]$folder,[string]$arch,[string[]]$commands) {
    $build=Join-Path $work $folder
    New-Item -ItemType Directory -Force $build | Out-Null
    $lines=@('@echo off',"call `"$vcvars`" $arch",'if errorlevel 1 exit /b 1')
    foreach ($command in $commands) {
        $lines+=@($command,'if errorlevel 1 exit /b 1')
    }
    $lines+='exit /b 0'
    $batch=Join-Path $build 'build.cmd'
    [IO.File]::WriteAllLines($batch,$lines,[Text.Encoding]::ASCII)
    Push-Location $build
    try {
        & $env:ComSpec /d /c $batch
        if ($LASTEXITCODE -ne 0) { throw "$folder build failed: $LASTEXITCODE" }
    } finally { Pop-Location }
}

if ($Fixture -in @('all','debug')) {
    $build=Join-Path $work 'debug-fixture'
    Invoke-NativeBuild 'debug-fixture' 'x64' @(
        "cl /nologo /O2 /c /Fo`"$build\target.obj`" `"$PSScriptRoot\debug_target.c`"",
        "ml64 /nologo /c /Fo`"$build\code.obj`" `"$PSScriptRoot\debug_target.asm`"",
        "link /nologo /SUBSYSTEM:CONSOLE /INCREMENTAL:NO /OPT:NOICF /OUT:`"$build\ce_mcp_debug_target.exe`" `"$build\target.obj`" `"$build\code.obj`" kernel32.lib"
    )
}
if ($Fixture -in @('all','injection')) {
    $build=Join-Path $work 'injection-fixture'
    Invoke-NativeBuild 'injection-fixture' 'x64' @(
        "cl /nologo /O2 /c /Fo`"$build\target.obj`" `"$PSScriptRoot\injection_target.c`"",
        "ml64 /nologo /c /Fo`"$build\code.obj`" `"$PSScriptRoot\injection_target.asm`"",
        "link /nologo /SUBSYSTEM:CONSOLE /INCREMENTAL:NO /OPT:NOICF /OUT:`"$build\ce_mcp_injection_target.exe`" `"$build\target.obj`" `"$build\code.obj`" kernel32.lib"
    )
}
if ($Fixture -in @('all','pointer')) {
    $architectures=if ($Architecture -eq 'all') { @('x64','x86') } else { @($Architecture) }
    foreach ($arch in $architectures) {
        $build=Join-Path $work "pointer-fixture\$arch"
        Invoke-NativeBuild "pointer-fixture\$arch" $arch @(
            "cl /nologo /O2 /Fo`"$build\target.obj`" /Fe`"$build\ce_mcp_pointer_$arch.exe`" `"$PSScriptRoot\pointer_target.c`" /link /INCREMENTAL:NO kernel32.lib"
        )
    }
}
if ($Fixture -in @('all','step6')) {
    $build=Join-Path $work 'step6-fixture'
    Invoke-NativeBuild 'step6-fixture' 'x64' @(
        "cl /nologo /O2 /Fe`"$build\step6_target.exe`" /Fo`"$build\target.obj`" `"$PSScriptRoot\step6_target.c`" /link /INCREMENTAL:NO /PDB:`"$build\target.pdb`"",
        "cl /nologo /LD /O2 /Fe`"$build\step6_log.dll`" /Fo`"$build\dll.obj`" `"$PSScriptRoot\step6_log_dll.c`" /link /INCREMENTAL:NO /PDB:`"$build\dll.pdb`""
    )
}
