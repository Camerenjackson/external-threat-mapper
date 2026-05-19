# Build ExternalThreatMapper.exe (Windows) - same flow as ZodiacSignFinder
# Requires: Python 3.10+ with pip, PowerShell installed on target machines for the .exe to launch the UI

$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

Write-Host "Installing PyInstaller..." -ForegroundColor Cyan
python -m pip install -r requirements-build.txt

Write-Host "Building executable (bundles PowerShell modules + UI)..." -ForegroundColor Cyan
$iconArg = @()
if (Test-Path "$PSScriptRoot\assets\etm-icon.ico") {
    $iconArg = @('--icon', "$PSScriptRoot\assets\etm-icon.ico")
}
elseif (Test-Path "$PSScriptRoot\assets\etm-icon.png") {
    $iconArg = @('--icon', "$PSScriptRoot\assets\etm-icon.png")
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
    --add-data "Start-ExternalThreatMapper.ps1;." `
    --add-data "SECURITY.md;." `
    --add-data "assets;assets" `
    main.py

Write-Host ""
Write-Host "Done! Your app is here:" -ForegroundColor Green
Write-Host "  $PSScriptRoot\dist\ExternalThreatMapper.exe"
Write-Host ""
Write-Host "Note: The .exe extracts app files and launches PowerShell (WPF). Target PC needs PowerShell 5.1+."
Write-Host "Upload dist\ExternalThreatMapper.exe via GitHub Releases (do not commit dist/ to git)."
