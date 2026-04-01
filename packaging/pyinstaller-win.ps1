<#
Build Windows executables for the web UI (Flask) and CLI using PyInstaller.
Prereqs: Python 3.11+, pip, and an .ico at packaging\assets\icon.ico (or override -IconPath).
Outputs: dist/OSINT-Assistant.exe (windowed Flask UI) and dist/OSINT-Assistant-CLI.exe (console CLI).
#>
param(
    [string]$IconPath = "packaging\\assets\\icon.ico",
    [switch]$Console
)

$ErrorActionPreference = "Stop"
$repoRoot = Split-Path -Parent $PSScriptRoot
Set-Location $repoRoot

if (-not (Test-Path $IconPath)) {
    throw "Icon not found at $IconPath. Provide a .ico (convert from PNG via 'magick icon.png -define icon:auto-resize=256,128,64,48,32,16 packaging\\assets\\icon.ico')."
}

$venv = Join-Path $repoRoot ".venv-pyinstaller"
if (-not (Test-Path $venv)) {
    python -m venv $venv
}

$python = Join-Path $venv "Scripts\\python.exe"
$pyinstaller = Join-Path $venv "Scripts\\pyinstaller.exe"

& $python -m pip install --upgrade pip
& $python -m pip install -r requirements.txt pyinstaller

$commonArgs = @("--onefile", "--icon", $IconPath)
$uiArgs = @($commonArgs)
if (-not $Console) { $uiArgs += "--windowed" }

# Flask web app bundle
& $pyinstaller @($uiArgs + @("--name", "OSINT-Assistant", "osint_web_app.py"))

# CLI bundle (always console)
& $pyinstaller @($commonArgs + @("--name", "OSINT-Assistant-CLI", "osint_assistant.py"))

Write-Host "Built executables in dist/. Copy your .env (with PERPLEXITY_API_KEY) beside the exe before running."
