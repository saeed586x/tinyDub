$ErrorActionPreference = 'Stop'

$root = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$exe = Join-Path $root 'build\Release\tinyDub.exe'
$source = Join-Path $root 'src\tinydub_app.cpp'

if (-not (Test-Path $exe)) { throw "Executable not found: $exe" }
if (-not (Test-Path $source)) { throw "UI source not found: $source" }

$uiText = Get-Content -Raw -LiteralPath $source
$requiredUiContract = @(
    'Gemini API key',
    'Show',
    'Target language',
    'Save key',
    'Forget key',
    'Current routing',
    'Overlay mode',
    'SOURCE AUDIO',
    'GEMINI',
    'OUTPUT AUDIO',
    'Start translation',
    'Stop translation',
    'Waiting for translated audio'
)
foreach ($item in $requiredUiContract) {
    if (-not $uiText.Contains($item)) {
        throw "UI contract text missing from source: $item"
    }
}

$p = Start-Process -FilePath $exe -PassThru
try {
    Start-Sleep -Milliseconds 1200
    if ($p.HasExited) {
        throw "tinyDub exited during GUI startup with exit code $($p.ExitCode)."
    }
    Write-Host "UI startup smoke test passed."
    Write-Host "UI contract smoke test passed ($($requiredUiContract.Count) required strings found)."
}
finally {
    if ($p -and -not $p.HasExited) {
        Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
        $p.WaitForExit(2000)
    }
}
