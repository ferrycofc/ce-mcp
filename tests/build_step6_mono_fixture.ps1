$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$work = Join-Path $root 'work'
$env:TEMP = Join-Path $work 'temp'
$env:TMP = $env:TEMP
New-Item -ItemType Directory -Force $env:TEMP, (Join-Path $work 'step6-fixture') | Out-Null
$msi = Join-Path $work 'mono-6.12.0.206-x64-0.msi'
$extract = Join-Path $work 'mono-extract'
$mono = Join-Path $extract 'Mono\bin\mono.exe'
if (-not (Test-Path $mono)) {
    if (-not (Test-Path $msi)) {
        Invoke-WebRequest 'https://download.mono-project.com/archive/6.12.0/windows-installer/mono-6.12.0.206-x64-0.msi' -OutFile $msi
    }
    $args = @('/a', $msi, '/qn', "TARGETDIR=$extract", '/L*v', (Join-Path $work 'mono-extract.log'))
    $p = Start-Process msiexec.exe -ArgumentList $args -Wait -PassThru -WindowStyle Hidden
    if ($p.ExitCode -ne 0) { throw "Mono MSI extraction failed: $($p.ExitCode)" }
}
$mcs = Join-Path $extract 'Mono\lib\mono\4.5\mcs.exe'
$output = Join-Path $work 'step6-fixture\mono_fixture.exe'
& $mono $mcs "/out:$output" (Join-Path $root 'tests\step6_mono_fixture.cs')
if ($LASTEXITCODE -ne 0) { throw 'Mono fixture build failed' }
Write-Output $output
