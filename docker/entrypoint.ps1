# Docker entrypoint - HTTP API + optional one-shot scan

param(
    [string]$Domain = $env:ETM_SCAN_DOMAIN,
    [string]$Mode = $(if ($env:ETM_SCAN_MODE) { $env:ETM_SCAN_MODE } else { 'PassiveOnly' })
)

$ErrorActionPreference = 'Stop'
$root = '/app'
Import-Module (Join-Path $root 'ExternalThreatMapper.psm1') -Force

if ($Domain) {
    Write-Host "Running headless scan for $Domain ..."
    $scope = New-ETMScopeObject -PrimaryDomain $Domain -ScanMode $Mode -AuthorizationAcknowledged $true
    $config = Get-ETMAppConfig
    $cb = { param($p, $m) Write-Host "[$p%] $m" }
    $cancel = [ref]$false
    $result = Start-ETMExternalScan -Scope $scope -Config $config -ProgressCallback $cb -CancelFlag $cancel
    $out = Join-Path $root "reports/scan-$(Get-Date -Format 'yyyyMMdd-HHmmss').json"
    Export-ETMFindingsJson -ScanResult $result -OutputPath $out
    Write-Host "Report: $out"
    exit 0
}

. (Join-Path $root 'Scripts/Start-ETMHttpService.ps1')
Start-ETMHttpService -Port 8080 -Root $root
