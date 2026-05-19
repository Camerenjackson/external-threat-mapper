# ExternalThreatMapper.psm1 — root module loader

$script:ETMRoot = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }

$moduleOrder = @(
    'ConfigManager.psm1',
    'Logging.psm1',
    'Database.psm1',
    'HistoryStore.psm1',
    'RiskScoring.psm1',
    'MitreMapping.psm1',
    'DnsResolution.psm1',
    'SubdomainDiscovery.psm1',
    'WebProbe.psm1',
    'TlsCheck.psm1',
    'TyposquatCheck.psm1',
    'CloudExposure.psm1',
    'BreachExposure.psm1',
    'ApiManager.psm1',
    'ThreatIntel.psm1',
    'GitHubExposure.psm1',
    'ReportGenerator.psm1',
    'ScanOrchestrator.psm1'
)

foreach ($name in $moduleOrder) {
    $path = Join-Path $script:ETMRoot "Modules\$name"
    if (Test-Path $path) {
        Import-Module $path -Force -Global
    }
}

. (Join-Path $script:ETMRoot 'UI\UiSafe.ps1')
. (Join-Path $script:ETMRoot 'UI\MainWindow.ps1')

Export-ModuleMember -Function 'Show-ETMMainWindow', 'Start-ETMExternalScan', 'Get-ETMAppConfig', 'Import-ETMScopeFile'
