$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$exe = Join-Path $root 'build\Release\tinyDub.exe'
if (!(Test-Path $exe)) { & (Join-Path $PSScriptRoot 'build.ps1') }
if (!(Test-Path $exe)) { throw "Executable not found: $exe" }
Start-Process $exe
