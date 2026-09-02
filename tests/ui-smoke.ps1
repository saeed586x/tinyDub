$ErrorActionPreference = 'Stop'

$exe = Join-Path $PSScriptRoot '..\build\Release\tinyDub.exe'
$exe = [System.IO.Path]::GetFullPath($exe)
if (-not (Test-Path $exe)) { throw "Executable not found: $exe" }

Add-Type @"
using System;
using System.Text;
using System.Collections.Generic;
using System.Runtime.InteropServices;
public static class Win32 {
    public delegate bool EnumChildProc(IntPtr hWnd, IntPtr lParam);
    [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern IntPtr FindWindow(string lpClassName, string lpWindowName);
    [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetWindowText(IntPtr hWnd, StringBuilder lpString, int nMaxCount);
    [DllImport("user32.dll")] public static extern bool EnumChildWindows(IntPtr hWndParent, EnumChildProc lpEnumFunc, IntPtr lParam);
    [DllImport("user32.dll")] public static extern bool IsWindow(IntPtr hWnd);
}
"@

$p = Start-Process -FilePath $exe -PassThru
try {
    $window = [IntPtr]::Zero
    for ($i = 0; $i -lt 50; $i++) {
        Start-Sleep -Milliseconds 100
        $window = [Win32]::FindWindow($null, 'tinyDub — Real-time translation')
        if ($window -ne [IntPtr]::Zero) { break }
    }
    if ($window -eq [IntPtr]::Zero -or -not [Win32]::IsWindow($window)) { throw 'tinyDub main window did not appear.' }

    $texts = New-Object System.Collections.Generic.List[string]
    $callback = [Win32+EnumChildProc]{ param($hwnd, $lparam)
        $sb = New-Object System.Text.StringBuilder 256
        [void][Win32]::GetWindowText($hwnd, $sb, $sb.Capacity)
        if ($sb.Length -gt 0) { $texts.Add($sb.ToString()) }
        return $true
    }
    [void][Win32]::EnumChildWindows($window, $callback, [IntPtr]::Zero)

    $required = @(
        'Gemini API key',
        'Show',
        'Target language',
        'Save key',
        'Forget key',
        'Overlay mode',
        'Start translation',
        'Close'
    )
    foreach ($item in $required) {
        if (-not $texts.Contains($item)) { throw "UI control not found: $item" }
    }

    Write-Host "UI smoke test passed. Found $($texts.Count) child controls/texts."
}
finally {
    if ($p -and -not $p.HasExited) { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue }
}
