# ThreatIntel.psm1 - Passive enrichment via external security APIs

function Get-ETMThreatIntelHeaders {
    param(
        [string]$ApiKey,
        [hashtable]$Extra = @{}
    )
    $h = @{ 'User-Agent' = 'ExternalThreatMapper-Defensive/1.0' }
    foreach ($k in $Extra.Keys) { $h[$k] = $Extra[$k] }
    return $h
}

function Invoke-ETMShodanDomainIntel {
    param([Parameter(Mandatory)][string]$Domain, [string]$ApiKey)
    if (-not $ApiKey) { return @() }
    $uri = "https://api.shodan.io/dns/domain/$Domain?key=$([uri]::EscapeDataString($ApiKey))"
    try {
        $r = Invoke-RestMethod -Uri $uri -TimeoutSec 25 -ErrorAction Stop
        $rows = [System.Collections.Generic.List[object]]::new()
        foreach ($sub in @($r.subdomains)) {
            $fqdn = if ($sub -match '\.') { $sub } else { "$sub.$Domain" }
            $rows.Add([pscustomobject]@{
                    provider   = 'Shodan'
                    asset      = $fqdn
                    assetType  = 'hostname'
                    severity   = 'Info'
                    summary    = 'Subdomain observed in Shodan DNS data'
                    detail     = "Tags: $(@($r.tags) -join ', ')"
                    source     = 'shodan.io'
                })
        }
        if ($rows.Count -eq 0) {
            $rows.Add([pscustomobject]@{
                    provider = 'Shodan'; asset = $Domain; assetType = 'domain'
                    severity = 'Info'; summary = 'Shodan DNS lookup returned no subdomains'
                    detail = "Data: $($r.data.Count) records"; source = 'shodan.io'
                })
        }
        return $rows
    }
    catch {
        Write-ETMLog -Level WARN -Message 'Shodan API error' -Data @{ error = $_.Exception.Message }
        return @()
    }
}

function Invoke-ETMVirusTotalDomainIntel {
    param([Parameter(Mandatory)][string]$Domain, [string]$ApiKey)
    if (-not $ApiKey) { return @() }
    $uri = "https://www.virustotal.com/api/v3/domains/$([uri]::EscapeDataString($Domain))"
    $h = Get-ETMThreatIntelHeaders -ApiKey $ApiKey -Extra @{ 'x-apikey' = $ApiKey }
    try {
        $r = Invoke-RestMethod -Uri $uri -Headers $h -TimeoutSec 25 -ErrorAction Stop
        $stats = $r.data.attributes.last_analysis_stats
        $mal = [int]$stats.malicious
        $sus = [int]$stats.suspicious
        $sev = if ($mal -gt 2) { 'High' } elseif ($mal -gt 0 -or $sus -gt 2) { 'Medium' } else { 'Low' }
        return @([pscustomobject]@{
                provider  = 'VirusTotal'
                asset     = $Domain
                assetType = 'domain'
                severity  = $sev
                summary   = "VT detections: $mal malicious, $sus suspicious"
                detail    = "Harmless: $($stats.harmless), Undetected: $($stats.undetected)"
                source    = 'virustotal.com'
            })
    }
    catch {
        Write-ETMLog -Level WARN -Message 'VirusTotal API error' -Data @{ error = $_.Exception.Message }
        return @()
    }
}

function Invoke-ETMSecurityTrailsDomainIntel {
    param([Parameter(Mandatory)][string]$Domain, [string]$ApiKey)
    if (-not $ApiKey) { return @() }
    $uri = "https://api.securitytrails.com/v1/domain/$Domain"
    $h = Get-ETMThreatIntelHeaders -Extra @{ APIKEY = $ApiKey }
    try {
        $r = Invoke-RestMethod -Uri $uri -Headers $h -TimeoutSec 25 -ErrorAction Stop
        $count = @($r.subdomains).Count
        return @([pscustomobject]@{
                provider  = 'SecurityTrails'
                asset     = $Domain
                assetType = 'domain'
                severity  = if ($count -gt 50) { 'Medium' } else { 'Info' }
                summary   = "SecurityTrails reports $count subdomains"
                detail    = "Alexa rank: $($r.alexa_rank); Current DNS: $($r.current_dns)"
                source    = 'securitytrails.com'
            })
    }
    catch {
        Write-ETMLog -Level WARN -Message 'SecurityTrails API error' -Data @{ error = $_.Exception.Message }
        return @()
    }
}

function Invoke-ETMCensysDomainIntel {
    param([Parameter(Mandatory)][string]$Domain, [string]$ApiId, [string]$ApiSecret)
    if (-not $ApiId -or -not $ApiSecret) { return @() }
    $uri = 'https://search.censys.io/api/v2/hosts/search'
    $body = @{ q = "dns.names: $Domain"; per_page = 5 } | ConvertTo-Json
    $pair = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("${ApiId}:${ApiSecret}"))
    $h = Get-ETMThreatIntelHeaders -Extra @{ Authorization = "Basic $pair" }
    try {
        $r = Invoke-RestMethod -Uri $uri -Method Post -Headers $h -Body $body -ContentType 'application/json' -TimeoutSec 30
        $total = [int]$r.result.total
        return @([pscustomobject]@{
                provider  = 'Censys'
                asset     = $Domain
                assetType = 'domain'
                severity  = if ($total -gt 10) { 'Medium' } else { 'Info' }
                summary   = "Censys hosts matching domain: $total"
                detail    = "Sample hits: $(@($r.result.hits.ip | Select-Object -First 3) -join ', ')"
                source    = 'censys.io'
            })
    }
    catch {
        Write-ETMLog -Level WARN -Message 'Censys API error' -Data @{ error = $_.Exception.Message }
        return @()
    }
}

function Invoke-ETMUrlscanDomainIntel {
    param([Parameter(Mandatory)][string]$Domain, [string]$ApiKey)
    if (-not $ApiKey) { return @() }
    $q = [uri]::EscapeDataString("domain:$Domain")
    $uri = "https://urlscan.io/api/v1/search/?q=$q&size=5"
    $h = Get-ETMThreatIntelHeaders -Extra @{ 'API-Key' = $ApiKey }
    try {
        $r = Invoke-RestMethod -Uri $uri -Headers $h -TimeoutSec 25 -ErrorAction Stop
        $total = [int]$r.total
        $rows = [System.Collections.Generic.List[object]]::new()
        $rows.Add([pscustomobject]@{
                provider  = 'urlscan.io'
                asset     = $Domain
                assetType = 'domain'
                severity  = if ($total -gt 20) { 'Medium' } else { 'Info' }
                summary   = "urlscan.io has $total historical scans"
                detail    = 'Review for phishing clones and exposed admin panels.'
                source    = 'urlscan.io'
            })
        return $rows
    }
    catch {
        Write-ETMLog -Level WARN -Message 'urlscan API error' -Data @{ error = $_.Exception.Message }
        return @()
    }
}

function Invoke-ETMAbuseIPDBIntel {
    param([Parameter(Mandatory)][string]$Ip, [string]$ApiKey)
    if (-not $ApiKey -or -not $Ip) { return @() }
    $uri = "https://api.abuseipdb.com/api/v2/check?ipAddress=$([uri]::EscapeDataString($Ip))&maxAgeInDays=90"
    $h = Get-ETMThreatIntelHeaders -Extra @{ Key = $ApiKey }
    try {
        $r = Invoke-RestMethod -Uri $uri -Headers $h -TimeoutSec 20 -ErrorAction Stop
        $score = [int]$r.data.abuseConfidenceScore
        $sev = if ($score -ge 75) { 'High' } elseif ($score -ge 25) { 'Medium' } else { 'Low' }
        return @([pscustomobject]@{
                provider  = 'AbuseIPDB'
                asset     = $Ip
                assetType = 'ip'
                severity  = $sev
                summary   = "Abuse confidence score: $score%"
                detail    = "Reports: $($r.data.totalReports); Country: $($r.data.countryCode)"
                source    = 'abuseipdb.com'
            })
    }
    catch { return @() }
}

function Invoke-ETMGreyNoiseIpIntel {
    param([Parameter(Mandatory)][string]$Ip, [string]$ApiKey)
    if (-not $ApiKey -or -not $Ip) { return @() }
    $uri = "https://api.greynoise.io/v3/community/$Ip"
    $h = Get-ETMThreatIntelHeaders -Extra @{ key = $ApiKey }
    try {
        $r = Invoke-RestMethod -Uri $uri -Headers $h -TimeoutSec 20 -ErrorAction Stop
        $noise = [bool]$r.noise
        return @([pscustomobject]@{
                provider  = 'GreyNoise'
                asset     = $Ip
                assetType = 'ip'
                severity  = if ($noise) { 'Medium' } else { 'Info' }
                summary   = if ($noise) { 'IP classified as internet noise/scanner' } else { 'IP not in GreyNoise noise dataset' }
                detail    = "Classification: $($r.classification); Name: $($r.name)"
                source    = 'greynoise.io'
            })
    }
    catch { return @() }
}

function Invoke-ETMOtxDomainIntel {
    param([Parameter(Mandatory)][string]$Domain, [string]$ApiKey)
    $uri = "https://otx.alienvault.com/api/v1/indicators/domain/$Domain/general"
    $h = Get-ETMThreatIntelHeaders -Extra @{}
    if ($ApiKey) { $h['X-OTX-API-KEY'] = $ApiKey }
    try {
        $r = Invoke-RestMethod -Uri $uri -Headers $h -TimeoutSec 25 -ErrorAction Stop
        $pulses = [int]$r.pulse_info.count
        $sev = if ($pulses -gt 5) { 'High' } elseif ($pulses -gt 0) { 'Medium' } else { 'Info' }
        return @([pscustomobject]@{
                provider  = 'AlienVault OTX'
                asset     = $Domain
                assetType = 'domain'
                severity  = $sev
                summary   = "Linked to $pulses OTX threat pulses"
                detail    = "Alexa: $($r.alexa); Validation: $($r.validation)"
                source    = 'otx.alienvault.com'
            })
    }
    catch {
        Write-ETMLog -Level WARN -Message 'OTX API error' -Data @{ error = $_.Exception.Message }
        return @()
    }
}

function Invoke-ETMThreatIntelEnrichment {
    param(
        [Parameter(Mandatory)][string]$Domain,
        [string[]]$Ips = @(),
        [int]$MaxIpLookups = 3
    )
    $all = [System.Collections.Generic.List[object]]::new()

    $shodan = Get-ETMApiSecret -Name 'Shodan'
    $all.AddRange(@(Invoke-ETMShodanDomainIntel -Domain $Domain -ApiKey $shodan))

    $vt = Get-ETMApiSecret -Name 'VirusTotal'
    $all.AddRange(@(Invoke-ETMVirusTotalDomainIntel -Domain $Domain -ApiKey $vt))

    $st = Get-ETMApiSecret -Name 'SecurityTrails'
    $all.AddRange(@(Invoke-ETMSecurityTrailsDomainIntel -Domain $Domain -ApiKey $st))

    $cId = Get-ETMApiSecret -Name 'Censys'
    $cSec = Get-ETMApiSecret -Name 'CensysSecret'
    $all.AddRange(@(Invoke-ETMCensysDomainIntel -Domain $Domain -ApiId $cId -ApiSecret $cSec))

    $urlscan = Get-ETMApiSecret -Name 'Urlscan'
    $all.AddRange(@(Invoke-ETMUrlscanDomainIntel -Domain $Domain -ApiKey $urlscan))

    $otx = Get-ETMApiSecret -Name 'AlienVaultOTX'
    $all.AddRange(@(Invoke-ETMOtxDomainIntel -Domain $Domain -ApiKey $otx))

    $abuse = Get-ETMApiSecret -Name 'AbuseIPDB'
    $grey = Get-ETMApiSecret -Name 'GreyNoise'
    $ipList = @($Ips | Where-Object { $_ -match '^\d+\.\d+\.\d+\.\d+$' } | Select-Object -Unique -First $MaxIpLookups)
    foreach ($ip in $ipList) {
        Start-Sleep -Milliseconds 400
        $all.AddRange(@(Invoke-ETMAbuseIPDBIntel -Ip $ip -ApiKey $abuse))
        Start-Sleep -Milliseconds 400
        $all.AddRange(@(Invoke-ETMGreyNoiseIpIntel -Ip $ip -ApiKey $grey))
    }

    return $all.ToArray()
}

function Convert-ETMThreatIntelToFindings {
    param([Parameter(Mandatory)][array]$IntelRows)
    $findings = [System.Collections.Generic.List[object]]::new()
    foreach ($row in $IntelRows) {
        $findings.Add([pscustomobject]@{
                title                = "[$($row.provider)] $($row.summary)"
                severity             = $row.severity
                category             = 'threat-intel'
                evidence             = "$($row.asset) ($($row.assetType)) via $($row.source): $($row.detail)"
                businessExplanation  = 'Third-party threat intelligence indicates external visibility or reputation risk.'
                technicalExplanation = "Passive API enrichment from $($row.provider)."
                remediation          = 'Validate findings, tune detections, and reduce unintended exposure.'
                confidence           = 'Medium'
                status               = 'Open'
                intelProvider        = $row.provider
            })
    }
    return $findings.ToArray()
}

Export-ModuleMember -Function @(
    'Invoke-ETMThreatIntelEnrichment', 'Convert-ETMThreatIntelToFindings',
    'Invoke-ETMShodanDomainIntel', 'Invoke-ETMVirusTotalDomainIntel'
)
