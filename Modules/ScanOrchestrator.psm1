# ScanOrchestrator.psm1 — coordinates passive/safe scan pipeline

function Test-ETMScanCancelled {
    param($CancelFlag)
    if ($null -eq $CancelFlag) { return $false }
    if ($CancelFlag -is [hashtable]) { return [bool]$CancelFlag.Cancel }
    if ($CancelFlag -is [ref]) { return $CancelFlag.Value }
    return $false
}

function Start-ETMExternalScan {
    param(
        [Parameter(Mandatory)][psobject]$Scope,
        [Parameter(Mandatory)][psobject]$Config,
        [scriptblock]$ProgressCallback,
        $CancelFlag
    )

    $scanId = [guid]::NewGuid().ToString()
    Write-ETMLog -Level AUDIT -Message 'Scan started' -Data @{ scanId = $scanId; domain = $Scope.primaryDomain; mode = $Scope.scanMode }
    Add-ETMScanRecord -ScanId $scanId -Scope $Scope -Status 'Running'

    $findings = [System.Collections.Generic.List[object]]::new()

    & $ProgressCallback 5 'Discovering subdomains (passive, no API key required)...'
    if (Test-ETMScanCancelled $CancelFlag) { return $null }
    $subs = @(Invoke-ETMSubdomainDiscovery -Scope $Scope -Config $Config -CancelFlag $CancelFlag)
    Add-ETMSubdomainRecords -ScanId $scanId -Records $subs

    foreach ($s in $subs | Where-Object { $_.riskScore -ge 50 }) {
        $findings.Add([pscustomobject]@{
                title                = "Risky hostname: $($s.hostname)"
                severity             = if ($s.riskScore -ge 70) { 'High' } else { 'Medium' }
                category             = 'subdomain'
                evidence             = "Source: $($s.source); IP: $($s.ip)"
                businessExplanation  = 'An internet-discoverable hostname may expose sensitive services to attackers.'
                technicalExplanation = 'Hostname matches external attack surface risk keywords.'
                remediation          = 'Restrict public DNS, use private endpoints, and review whether the service must be internet-facing.'
                confidence           = 'Medium'
                status               = 'Open'
            })
    }

    & $ProgressCallback 35 'Checking typosquat candidates...'
    if (Test-ETMScanCancelled $CancelFlag) { return $null }
    if (-not (Test-ETMScanCancelled $CancelFlag)) {
        $typos = @(Invoke-ETMTyposquatCheck -Domain $Scope.primaryDomain)
        foreach ($t in $typos) {
            $findings.Add([pscustomobject]@{
                    title = "Resolvable typosquat candidate: $($t.candidate)"
                    severity = 'Medium'
                    category = 'typosquat-brand'
                    evidence = "DNS resolves; HTTP hint: $($t.httpHint)"
                    businessExplanation = 'Lookalike domains can enable phishing and brand impersonation.'
                    technicalExplanation = 'Passive DNS/HTTP title check only - no authentication attempted.'
                    remediation = 'Monitor brand abuse, register defensive domains, and enforce email/auth protections.'
                    confidence = 'Medium'
                    status = 'Open'
                })
        }
    }

    & $ProgressCallback 55 'Cloud exposure indicators...'
    if (Test-ETMScanCancelled $CancelFlag) { return $null }
    if (-not (Test-ETMScanCancelled $CancelFlag) -and $Scope.scanMode -ne 'PassiveOnly') {
        $cloud = @(Invoke-ETMCloudExposureScan -Domain $Scope.primaryDomain)
        foreach ($c in $cloud) {
            $findings.Add([pscustomobject]@{
                    title = "Cloud exposure indicator: $($c.url)"
                    severity = if ($c.riskScore -ge 80) { 'High' } else { 'Medium' }
                    category = 'cloud'
                    evidence = "HTTP $($c.statusCode) - $($c.indicator)"
                    businessExplanation = 'Public cloud storage responses can expose sensitive organizational data.'
                    technicalExplanation = 'HEAD request only; no object download performed.'
                    remediation = 'Verify bucket policies, block public access, and enable logging/alerts.'
                    confidence = 'Low'
                    status = 'Open'
                })
        }
    }

    & $ProgressCallback 65 'Threat intel (skipped if no API keys)...'
    $intelRows = @()
    if (Test-ETMScanCancelled $CancelFlag) { return $null }
    if (-not (Test-ETMScanCancelled $CancelFlag)) {
        $ips = @($subs | ForEach-Object { $_.ip } | Where-Object { $_ })
        $intelRows = @(Invoke-ETMThreatIntelEnrichment -Domain $Scope.primaryDomain -Ips $ips)
        if ($intelRows -and $intelRows.Count -gt 0) {
            $intelFindings = @(Convert-ETMThreatIntelToFindings -IntelRows @($intelRows))
            foreach ($f in $intelFindings) { $findings.Add($f) }
        }
    }

    & $ProgressCallback 75 'GitHub metadata search...'
    if (Test-ETMScanCancelled $CancelFlag) { return $null }
    if (-not (Test-ETMScanCancelled $CancelFlag)) {
        $ghToken = Get-ETMApiSecret -Name 'GitHub'
        $gh = @(Invoke-ETMGitHubExposureSearch -Domain $Scope.primaryDomain -Token $ghToken)
        foreach ($g in $gh) {
            $findings.Add([pscustomobject]@{
                    title = "GitHub code reference: $($g.repository)"
                    severity = 'Medium'
                    category = 'github-code'
                    evidence = "Path: $($g.path) (redacted)"
                    businessExplanation = 'Public repositories may leak domain references or sensitive patterns.'
                    technicalExplanation = 'GitHub Search API metadata; secrets redacted and not validated.'
                    remediation = 'Review repository visibility, secret scanning, and developer training.'
                    confidence = 'Medium'
                    status = 'Open'
                })
        }
    }

    & $ProgressCallback 85 'Safe web probing...'
    $web = @()
    if (Test-ETMScanCancelled $CancelFlag) { return $null }
    if (-not (Test-ETMScanCancelled $CancelFlag)) {
        $web = @(Invoke-ETMWebProbeBatch -Hostnames ($subs.hostname | Select-Object -First 15) -ScanMode $Scope.scanMode)
    }

    & $ProgressCallback 95 'Scoring and MITRE mapping...'
    Add-ETMFindingRecords -ScanId $scanId -Findings $findings

    $score = Measure-ETMProtectionScore -Findings @($findings) -Subdomains @($subs) -WebServices @($web)
    foreach ($f in $findings) {
        $f | Add-Member -NotePropertyName mitre -NotePropertyValue (Get-ETMMitreMappingForFinding -Finding $f) -Force
    }

    & $ProgressCallback 100 'Complete'
    Write-ETMLog -Level AUDIT -Message 'Scan completed' -Data @{ scanId = $scanId; findings = $findings.Count }

    $scanResult = Normalize-ETMScanResult ([pscustomobject]@{
            scanId      = $scanId
            subdomains  = $subs
            webServices = $web
            threatIntel = $intelRows
            findings    = $findings
            score       = $score
        })
    try {
        Save-ETMScanHistory -Result $scanResult -Scope $Scope
    }
    catch {
        Write-ETMLog -Level WARN -Message 'Could not save scan history' -Data @{ error = $_.Exception.Message }
    }
    return $scanResult
}

Export-ModuleMember -Function 'Start-ETMExternalScan', 'Test-ETMScanCancelled'
