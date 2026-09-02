$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$buildScript = Join-Path $PSScriptRoot 'build.ps1'
& $buildScript
if ($LASTEXITCODE -ne 0) { throw "Build failed." }

$exe = Join-Path $root 'build\Release\tinyDub.exe'
if (!(Test-Path $exe)) { throw "Executable not found: $exe" }

$installRoot = Join-Path $env:LOCALAPPDATA 'tinyDub'
New-Item -ItemType Directory -Force -Path $installRoot | Out-Null
Copy-Item $exe (Join-Path $installRoot 'tinyDub.exe') -Force

$shortcut = Join-Path ([Environment]::GetFolderPath('Desktop')) 'tinyDub.lnk'
$ws = New-Object -ComObject WScript.Shell
$sc = $ws.CreateShortcut($shortcut)
$sc.TargetPath = Join-Path $installRoot 'tinyDub.exe'
$sc.WorkingDirectory = $installRoot
$sc.Save()

Write-Host "Installed to $installRoot"
