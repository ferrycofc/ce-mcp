$ErrorActionPreference='Stop'
if ($env:VSINSTALLDIR) {
    $candidate=Join-Path $env:VSINSTALLDIR 'VC\Auxiliary\Build\vcvarsall.bat'
    if (Test-Path -LiteralPath $candidate) { return $candidate }
}
$vswhere=Get-Command vswhere.exe -ErrorAction SilentlyContinue
if ($vswhere) { $vswhere=$vswhere.Source }
elseif (${env:ProgramFiles(x86)}) {
    $candidate=Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
    if (Test-Path -LiteralPath $candidate) { $vswhere=$candidate }
}
if (-not $vswhere) { throw 'Visual Studio C++ build tools (vswhere.exe) not found' }
$installation=& $vswhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if (-not $installation) { throw 'Visual Studio C++ build tools not found' }
$vcvars=Join-Path $installation 'VC\Auxiliary\Build\vcvarsall.bat'
if (-not (Test-Path -LiteralPath $vcvars)) { throw "vcvarsall.bat not found: $vcvars" }
return $vcvars
