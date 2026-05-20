#Requires -Version 5.1
<#
.SYNOPSIS
  External Threat Mapper - GUI (default) or command-line mode.

.EXAMPLE
  .\Start-ExternalThreatMapper.ps1
  Opens the WPF dashboard.

.EXAMPLE
  .\Start-ExternalThreatMapper.ps1 -Domain example.com -ScanMode PassiveOnly
  Runs a headless scan and writes JSON to reports\

.EXAMPLE
  .\Start-ExternalThreatMapper.ps1 -TestApis
  Tests all configured API integrations (no GUI).

.EXAMPLE
  .\Start-ExternalThreatMapper.ps1 -Help
#>
param(
    [string]$Domain,
    [ValidateSet('PassiveOnly', 'CorporateSafe', 'FullAuthorized')]
    [string]$ScanMode = 'PassiveOnly',
    [switch]$TestApis,
    [switch]$Help
)

$ErrorActionPreference = 'Continue'
$root = if ($env:ETM_APP_ROOT -and (Test-Path $env:ETM_APP_ROOT)) {
    $env:ETM_APP_ROOT
} else {
    Split-Path $PSScriptRoot -Parent
}
$env:ETM_APP_ROOT = $root
Set-Location $root
$configPath = Join-Path $root 'config\config.json'
$examplePath = Join-Path $root 'config\config.example.json'
if (-not (Test-Path $configPath) -and (Test-Path $examplePath)) {
    Copy-Item $examplePath $configPath
}

function Show-ETMHelp {
    @"
External Threat Mapper

GUI (default):
  powershell -STA -File .\Scripts\Start-ExternalThreatMapper.ps1
  Or double-click Launch-ETM.cmd

Command-line scan:
  powershell -File .\Scripts\Start-ExternalThreatMapper.ps1 -Domain example.com -ScanMode PassiveOnly

Test API keys:
  powershell -File .\Scripts\Start-ExternalThreatMapper.ps1 -TestApis

Authorized targets only. No exploitation.
"@ | Write-Host
}

if ($Help) {
    Show-ETMHelp
    exit 0
}

$cliMode = ($Domain -or $TestApis.IsPresent)

if (-not $cliMode) {
    if ([System.Threading.Thread]::CurrentThread.ApartmentState -ne 'STA') {
        $exe = if (Get-Command pwsh -ErrorAction SilentlyContinue) { 'pwsh' } else { 'powershell' }
        & $exe -NoProfile -ExecutionPolicy Bypass -STA -File $PSCommandPath
        exit $LASTEXITCODE
    }
    try {
        Import-Module (Join-Path $root 'ExternalThreatMapper.psm1') -Force
        Show-ETMMainWindow
        exit 0
    }
    catch {
        $msg = $_.Exception.Message
        Write-Host "External Threat Mapper failed to start: $msg" -ForegroundColor Red
        try {
            Add-Type -AssemblyName System.Windows.Forms
            [System.Windows.Forms.MessageBox]::Show(
                "Could not start External Threat Mapper:`n`n$msg",
                'Startup error', 'OK', 'Error') | Out-Null
        }
        catch { }
        exit 1
    }
}

# --- CLI mode (no STA / no WPF required) ---
try {
    Import-Module (Join-Path $root 'ExternalThreatMapper.psm1') -Force

    if ($TestApis) {
        Write-Host 'Testing API integrations...' -ForegroundColor Cyan
        $results = @(Test-ETMAllApiConnections)
        foreach ($r in $results) {
            $color = if ($r.ok) { 'Green' } else { 'Yellow' }
            Write-Host ("[{0}] {1}: {2}" -f $(if ($r.ok) { 'OK' } else { '--' }), $r.id, $r.message) -ForegroundColor $color
        }
        $ok = @($results | Where-Object { $_.ok -eq $true }).Count
        Write-Host "`n$ok / $($results.Count) providers connected." -ForegroundColor Cyan
        exit 0
    }

    if ([string]::IsNullOrWhiteSpace($Domain)) {
        Write-Host 'Specify -Domain for CLI scan, -TestApis, or run without flags for GUI.' -ForegroundColor Yellow
        Show-ETMHelp
        exit 1
    }

    Write-Host "Starting scan: $Domain [$ScanMode]" -ForegroundColor Cyan
    $scope = New-ETMScopeObject -PrimaryDomain $Domain.Trim() -ScanMode $ScanMode -AuthorizationAcknowledged $true
    $config = Get-ETMAppConfig
    $cancel = [ref]$false
    $progress = {
        param($pct, $msg)
        Write-Host ("  [{0,3}%] {1}" -f $pct, $msg)
    }
    $result = Start-ETMExternalScan -Scope $scope -Config $config -ProgressCallback $progress -CancelFlag $cancel

    $reportsDir = Join-Path $root 'reports'
    if (-not (Test-Path $reportsDir)) { New-Item -ItemType Directory -Path $reportsDir -Force | Out-Null }
    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $jsonPath = Join-Path $reportsDir "etm-cli-$stamp.json"
    Export-ETMFindingsJson -ScanResult $result -OutputPath $jsonPath

    $score = $result.score
    Write-Host ''
    Write-Host 'Scan complete.' -ForegroundColor Green
    if ($score) {
        Write-Host ("  Protection score: {0}/100 ({1})" -f $score.TotalScore, $score.Grade)
    }
    $fc = (ConvertTo-ETMObjectList $result.findings).Count
    $ic = (ConvertTo-ETMObjectList $result.threatIntel).Count
    Write-Host "  Findings: $fc  |  Intel rows: $ic"
    Write-Host "  Report:   $jsonPath"
    exit 0
}
catch {
    Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}
