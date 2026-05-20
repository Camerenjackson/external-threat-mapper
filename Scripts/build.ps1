# Build ExternalThreatMapper.exe (Windows) - same flow as ZodiacSignFinder
# Requires: Python 3.10+ with pip, PowerShell installed on target machines for the .exe to launch the UI

$ErrorActionPreference = "Stop"
$root = Split-Path $PSScriptRoot -Parent
Set-Location $root

Write-Host "Installing PyInstaller..." -ForegroundColor Cyan
python -m pip install -r (Join-Path $PSScriptRoot "requirements-build.txt")

Write-Host "Building executable (bundles PowerShell modules + UI)..." -ForegroundColor Cyan
$iconArg = @()
$iconIco = Join-Path $root "assets\etm-icon.ico"
$iconPng = Join-Path $root "assets\etm-icon.png"
if (Test-Path $iconIco) {
    $iconArg = @("--icon", $iconIco)
}
elseif (Test-Path $iconPng) {
    $iconArg = @("--icon", $iconPng)
}

python -m PyInstaller `
    --noconfirm `
    --clean `
    --windowed `
    --onefile `
    --name "ExternalThreatMapper" `
    @iconArg `
    --add-data "Modules;Modules" `
    --add-data "UI;UI" `
    --add-data "config;config" `
    --add-data "samples;samples" `
    --add-data "scopes;scopes" `
    --add-data "ExternalThreatMapper.psm1;." `
    --add-data "Scripts/Start-ExternalThreatMapper.ps1;Scripts" `
    --add-data "SECURITY.md;." `
    --add-data "assets;assets" `
    launcher/main.py

Write-Host ""
Write-Host "Done! Your app is here:" -ForegroundColor Green
Write-Host "  $(Join-Path $root 'dist\ExternalThreatMapper.exe')"
Write-Host ""
Write-Host "Note: The .exe extracts app files and launches PowerShell (WPF). Target PC needs PowerShell 5.1+."
Write-Host "Upload dist\ExternalThreatMapper.exe via GitHub Releases (do not commit dist/ to git)."
