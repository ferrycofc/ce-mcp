param(
    [Parameter(Mandatory=$true)]
    [string]$CheatEngineDir
)
$ErrorActionPreference='Stop'
$repo=(Resolve-Path -LiteralPath $PSScriptRoot).Path
$ce=(Resolve-Path -LiteralPath $CheatEngineDir).Path
$executables=@('cheatengine-x86_64.exe','cheatengine-x86_64-SSE4-AVX2.exe','cheatengine-i386.exe')
if (-not ($executables | Where-Object { Test-Path -LiteralPath (Join-Path $ce $_) })) {
    throw "Cheat Engine executable not found in $ce"
}
$autorun=Join-Path $ce 'autorun'
if (-not (Test-Path -LiteralPath $autorun -PathType Container)) {
    throw "Cheat Engine autorun folder not found: $autorun"
}
if (-not (Test-Path -LiteralPath (Join-Path $repo 'ce\bridge.lua'))) {
    throw "Bridge not found in repository: $repo"
}
Copy-Item -LiteralPath (Join-Path $repo 'ce\autorun.lua') -Destination (Join-Path $autorun 'ce_mcp.lua') -Force
$utf8=New-Object System.Text.UTF8Encoding($false)
[IO.File]::WriteAllText((Join-Path $autorun 'ce_mcp_path.txt'),$repo.Replace('\','/')+"`n",$utf8)
Write-Output "Installed CE autorun loader for $repo"
Write-Output 'Start Cheat Engine to load the bridge.'
