# Quick smoke test for demo import, normalize, and scan (no GUI).
$ErrorActionPreference = 'Stop'
$root = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
if (-not (Test-Path (Join-Path $root 'ExternalThreatMapper.psm1'))) {
    $root = Split-Path $PSScriptRoot -Parent
}
Set-Location $root
Import-Module (Join-Path $root 'ExternalThreatMapper.psm1') -Force

Write-Host '1. Demo JSON import...'
$demo = Import-ETMScanResultJson -Path (Join-Path $root 'samples\demo-result.json')
$fc = (ConvertTo-ETMObjectList $demo.findings).Count
$ic = (ConvertTo-ETMObjectList $demo.threatIntel).Count
Write-Host "   OK - findings=$fc intel=$ic score=$($demo.score.TotalScore)"

Write-Host '2. Passive scan (example.com)...'
& (Join-Path $root 'Start-ExternalThreatMapper.ps1') -Domain example.com -ScanMode PassiveOnly | Out-Host
Write-Host '   OK'

Write-Host 'All core tests passed.'
