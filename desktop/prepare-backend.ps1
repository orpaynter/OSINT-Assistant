param(
    [string]$Source = "..\\dist\\OSINT-Assistant.exe"
)

$ErrorActionPreference = "Stop"
$targetDir = Join-Path $PSScriptRoot "backend"
$sourcePath = if ([System.IO.Path]::IsPathRooted($Source)) {
    [System.IO.Path]::GetFullPath($Source)
} else {
    [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot $Source))
}

if (-not (Test-Path $sourcePath)) {
    throw "Source executable not found at $sourcePath. Run packaging/pyinstaller-win.ps1 first."
}

New-Item -ItemType Directory -Force -Path $targetDir | Out-Null
$target = Join-Path $targetDir "osint_web_app.exe"
Copy-Item $sourcePath $target -Force
Write-Host "Copied backend to $target for Electron packaging."
