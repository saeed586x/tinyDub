$ErrorActionPreference = 'Stop'

$root = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$exe = Join-Path $root 'build\Release\tinyDub.exe'
$source = Join-Path $root 'src\ui_main.cpp'

if (-not (Test-Path $exe)) { throw "Executable not found: $exe" }
if (-not (Test-Path $source)) { throw "UI source not found: $source" }

# The GitHub-hosted Windows runner is non-interactive/headless, so a visible
# HWND cannot be used as a reliable CI assertion. We validate the UI contract
# statically and also verify that the GUI executable can start and remain alive.
$requiredUiContract = @(
    'Gemini API key',
    'Show',
    'Target language',
    'Save key',
    'Forget key',
    'Routing mode',
    'Overlay mode',
    'Original audio stays at system volume',
    'Start translation',
    'Stop translation',
    'Close'
)

$uiText = Get-Content -Raw -LiteralPath $source
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
    Write-Host "UI startup smoke test passed (GUI process alive)."
    Write-Host "UI contract smoke test passed ($($requiredUiContract.Count) required labels/states found)."
}
finally {
    if ($p -and -not $p.HasExited) {
        Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
        $p.WaitForExit(2000)
    }
}
