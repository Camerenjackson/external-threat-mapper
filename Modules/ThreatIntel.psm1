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

function Get-ETMThreatIntelSettings {
    param($Config)
    $ti = $null
    if ($Config -and $Config.threatIntel) { $ti = $Config.threatIntel }
    $baseDelay = 400
    if ($Config -and $Config.application -and $Config.application.rateLimitMs) {
        $baseDelay = [int]$Config.application.rateLimitMs
    }
    return [pscustomobject]@{
        maxIpLookups       = if ($ti -and $ti.maxIpLookups) { [int]$ti.maxIpLookups } else { 8 }
        maxHostnameLookups = if ($ti -and $ti.maxHostnameLookups) { [int]$ti.maxHostnameLookups } else { 6 }
        maxShodanHostLookups = if ($ti -and $ti.maxShodanHostLookups) { [int]$ti.maxShodanHostLookups } else { 5 }
        apiDelayMs         = if ($ti -and $ti.apiDelayMs) { [int]$ti.apiDelayMs } else { $baseDelay }
    }
}

function New-ETMIntelRow {
    param(
        [string]$Provider,
        [string]$Asset,
        [string]$AssetType,
        [string]$Severity,
        [string]$Summary,
        [string]$Detail,
        [string]$Source
    )
    return [pscustomobject]@{
        provider  = $Provider
        asset     = $Asset
        assetType = $AssetType
        severity  = $Severity
        summary   = $Summary
        detail    = $Detail
        source    = $Source
    }
}

function Get-ETMCollectedScanIndicators {
    param(
        [Parameter(Mandatory)][string]$Domain,
        [array]$Subdomains = @(),
        [array]$WebServices = @(),
        [array]$IntelRows = @()
    )
    $ips = [System.Collections.Generic.List[string]]::new()
    $hosts = [System.Collections.Generic.List[string]]::new()
    $domain = $Domain.Trim().ToLower()

    foreach ($s in @($Subdomains)) {
        if ($s.hostname) { [void]$hosts.Add([string]$s.hostname.Trim().ToLower()) }
        if ($s.ip) {
            foreach ($ip in ($s.ip -split '[,;\s]+')) {
                $ip = $ip.Trim()
                if ($ip -match '^\d{1,3}(\.\d{1,3}){3}$') { [void]$ips.Add($ip) }
            }
        }
    }
    foreach ($w in @($WebServices)) {
        if ($w.hostname) { [void]$hosts.Add([string]$w.hostname.Trim().ToLower()) }
    }
    foreach ($row in @($IntelRows)) {
        if ($row.assetType -eq 'ip' -and $row.asset -match '^\d{1,3}(\.\d{1,3}){3}$') {
            [void]$ips.Add([string]$row.asset)
        }
        if ($row.assetType -eq 'hostname' -and $row.asset) {
            [void]$hosts.Add([string]$row.asset.Trim().ToLower())
        }
        if ($row.detail) {
            foreach ($m in [regex]::Matches([string]$row.detail, '\b\d{1,3}(?:\.\d{1,3}){3}\b')) {
                [void]$ips.Add($m.Value)
            }
        }
    }

    $hostFiltered = @($hosts | Where-Object {
            $_ -and ($_ -eq $domain -or $_ -like "*.$domain")
        } | Select-Object -Unique)

    return [pscustomobject]@{
        Ips       = @($ips | Select-Object -Unique)
        Hostnames = $hostFiltered
    }
}

function Invoke-ETMThreatIntelThrottle {
    param([int]$DelayMs = 400)
    if ($DelayMs -gt 0) { Start-Sleep -Milliseconds $DelayMs }
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
    $uri = "https://api.securitytrails.com/v1/domain/$([uri]::EscapeDataString($Domain))"
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
    $body = @{ q = "dns.names: $Domain"; per_page = 8 } | ConvertTo-Json
    $pair = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("${ApiId}:${ApiSecret}"))
    $h = Get-ETMThreatIntelHeaders -Extra @{ Authorization = "Basic $pair" }
    try {
        $r = Invoke-RestMethod -Uri $uri -Method Post -Headers $h -Body $body -ContentType 'application/json' -TimeoutSec 30
        $total = [int]$r.result.total
        $rows = [System.Collections.Generic.List[object]]::new()
        $rows.Add((New-ETMIntelRow -Provider 'Censys' -Asset $Domain -AssetType 'domain' `
                -Severity $(if ($total -gt 10) { 'Medium' } else { 'Info' }) `
                -Summary "Censys hosts matching domain: $total" `
                -Detail 'Internet-wide host index (certificate/DNS visibility).' `
                -Source 'censys.io'))
        foreach ($hit in @($r.result.hits | Select-Object -First 5)) {
            $ip = if ($hit.ip) { [string]$hit.ip } else { '' }
            if (-not $ip) { continue }
            $svc = ''
            if ($hit.services) {
                $svc = (@($hit.services | ForEach-Object { $_.service_name } | Where-Object { $_ } | Select-Object -First 3)) -join ', '
            }
            $rows.Add((New-ETMIntelRow -Provider 'Censys' -Asset $ip -AssetType 'ip' `
                    -Severity 'Info' -Summary "Censys host on $Domain" `
                    -Detail "Services: $(if ($svc) { $svc } else { 'unknown' })" -Source 'censys.io'))
        }
        return $rows
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
        $rows.Add((New-ETMIntelRow -Provider 'urlscan.io' -Asset $Domain -AssetType 'domain' `
                -Severity $(if ($total -gt 20) { 'Medium' } else { 'Info' }) `
                -Summary "urlscan.io has $total historical scans" `
                -Detail 'Review for phishing clones and exposed admin panels.' -Source 'urlscan.io'))
        foreach ($hit in @($r.results | Select-Object -First 3)) {
            $page = $hit.page
            $url = if ($page -and $page.url) { [string]$page.url } else { '' }
            if (-not $url) { continue }
            $rows.Add((New-ETMIntelRow -Provider 'urlscan.io' -Asset $url -AssetType 'url' `
                    -Severity 'Info' -Summary 'Historical urlscan capture' `
                    -Detail "Task: $($hit.task.uuid)" -Source 'urlscan.io'))
        }
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
    $h = Get-ETMThreatIntelHeaders -Extra @{ key = $ApiKey; Accept = 'application/json' }
    foreach ($uri in @(
            "https://api.greynoise.io/v3/ip/$Ip",
            "https://api.greynoise.io/v3/community/$Ip"
        )) {
        try {
            $r = Invoke-RestMethod -Uri $uri -Headers $h -TimeoutSec 20 -ErrorAction Stop
            $noise = [bool]$r.noise
            $riot = [bool]$r.riot
            $sev = if ($noise -and -not $riot) { 'Medium' } else { 'Info' }
            $summary = if ($riot) { 'Known benign service (RIOT)' } elseif ($noise) { 'Internet noise / scanner activity' } else { 'Not observed as noise' }
            return @((New-ETMIntelRow -Provider 'GreyNoise' -Asset $Ip -AssetType 'ip' -Severity $sev `
                    -Summary $summary -Detail "Classification: $($r.classification); Name: $($r.name)" -Source 'greynoise.io'))
        }
        catch {
            if ($uri -like '*community*') { return @() }
        }
    }
    return @()
}

function Invoke-ETMVirusTotalIpIntel {
    param([Parameter(Mandatory)][string]$Ip, [string]$ApiKey)
    if (-not $ApiKey -or -not $Ip) { return @() }
    $uri = "https://www.virustotal.com/api/v3/ip_addresses/$([uri]::EscapeDataString($Ip))"
    $h = Get-ETMThreatIntelHeaders -ApiKey $ApiKey -Extra @{ 'x-apikey' = $ApiKey }
    try {
        $r = Invoke-RestMethod -Uri $uri -Headers $h -TimeoutSec 25 -ErrorAction Stop
        $stats = $r.data.attributes.last_analysis_stats
        $mal = [int]$stats.malicious
        $sus = [int]$stats.suspicious
        $asn = $r.data.attributes.asn
        $country = $r.data.attributes.country
        $sev = if ($mal -gt 2) { 'High' } elseif ($mal -gt 0 -or $sus -gt 2) { 'Medium' } else { 'Low' }
        return @((New-ETMIntelRow -Provider 'VirusTotal' -Asset $Ip -AssetType 'ip' -Severity $sev `
                -Summary "VT IP reputation: $mal malicious, $sus suspicious" `
                -Detail "ASN: $asn; Country: $country" -Source 'virustotal.com'))
    }
    catch {
        Write-ETMLog -Level WARN -Message 'VirusTotal IP lookup error' -Data @{ ip = $Ip; error = $_.Exception.Message }
        return @()
    }
}

function Invoke-ETMVirusTotalHostnameIntel {
    param([Parameter(Mandatory)][string]$Hostname, [string]$ApiKey)
    if (-not $ApiKey -or -not $Hostname) { return @() }
    return @(Invoke-ETMVirusTotalDomainIntel -Domain $Hostname -ApiKey $ApiKey | ForEach-Object {
            $_.asset = $Hostname
            $_.assetType = 'hostname'
            $_.summary = "VT hostname: $($_.summary)"
            $_
        })
}

function Invoke-ETMShodanHostIntel {
    param([Parameter(Mandatory)][string]$Ip, [string]$ApiKey)
    if (-not $ApiKey -or -not $Ip) { return @() }
    $uri = "https://api.shodan.io/shodan/host/$([uri]::EscapeDataString($Ip))?key=$([uri]::EscapeDataString($ApiKey))"
    try {
        $r = Invoke-RestMethod -Uri $uri -TimeoutSec 25 -ErrorAction Stop
        $ports = @($r.ports | Select-Object -First 12) -join ','
        $hostnames = @($r.hostnames | Select-Object -First 5) -join ', '
        $vulns = @($r.vulns | Select-Object -First 5) -join ', '
        $sev = if ($r.vulns -and $r.vulns.Count -gt 0) { 'High' } elseif ($r.ports -and $r.ports.Count -gt 5) { 'Medium' } else { 'Info' }
        $detail = "Ports: $ports; Hostnames: $hostnames"
        if ($vulns) { $detail += "; Vulns: $vulns" }
        return @((New-ETMIntelRow -Provider 'Shodan' -Asset $Ip -AssetType 'ip' -Severity $sev `
                -Summary 'Shodan internet exposure on discovered IP' -Detail $detail -Source 'shodan.io'))
    }
    catch {
        Write-ETMLog -Level WARN -Message 'Shodan host lookup error' -Data @{ ip = $Ip; error = $_.Exception.Message }
        return @()
    }
}

function Invoke-ETMOtxIpIntel {
    param([Parameter(Mandatory)][string]$Ip, [string]$ApiKey)
    if (-not $Ip) { return @() }
    $uri = "https://otx.alienvault.com/api/v1/indicators/IPv4/$Ip/general"
    $h = Get-ETMThreatIntelHeaders -Extra @{}
    if ($ApiKey) { $h['X-OTX-API-KEY'] = $ApiKey }
    try {
        $r = Invoke-RestMethod -Uri $uri -Headers $h -TimeoutSec 20 -ErrorAction Stop
        $pulses = [int]$r.pulse_info.count
        $sev = if ($pulses -gt 5) { 'High' } elseif ($pulses -gt 0) { 'Medium' } else { 'Info' }
        return @((New-ETMIntelRow -Provider 'AlienVault OTX' -Asset $Ip -AssetType 'ip' -Severity $sev `
                -Summary "OTX pulses for IP: $pulses" -Detail "Reputation: $($r.reputation)" -Source 'otx.alienvault.com'))
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

function Invoke-ETMApiSubdomainDiscovery {
    <#
    .SYNOPSIS
    Uses Shodan + SecurityTrails to find corporate assets in the wild and merge into discovery.
    #>
    param(
        [Parameter(Mandatory)][string]$Domain,
        $Config
    )
    $settings = Get-ETMThreatIntelSettings -Config $Config
    $records = [System.Collections.Generic.List[object]]::new()
    $today = (Get-Date).ToString('yyyy-MM-dd')

    if (Test-ETMApiConfigured -Provider 'Shodan') {
        $key = Get-ETMApiSecret -Name 'Shodan'
        $uri = "https://api.shodan.io/dns/domain/$([uri]::EscapeDataString($Domain))?key=$([uri]::EscapeDataString($key))"
        try {
            $r = Invoke-RestMethod -Uri $uri -TimeoutSec 25 -ErrorAction Stop
            foreach ($sub in @($r.subdomains | Select-Object -First 120)) {
                $fqdn = ([string]$sub).Trim().ToLower()
                if ($fqdn -notmatch '\.') { $fqdn = "$fqdn.$Domain" }
                if ($fqdn -like "*.$Domain" -or $fqdn -eq $Domain) {
                    [void]$records.Add([pscustomobject]@{
                            hostname  = $fqdn; source = 'Shodan-DNS'; ip = ''
                            riskScore = 0; tags = @('api-discovery')
                            firstSeen = $today; lastSeen = $today
                        })
                }
            }
            Write-ETMLog -Level INFO -Message 'Shodan DNS discovery' -Data @{ domain = $Domain; count = $records.Count }
        }
        catch {
            Write-ETMLog -Level WARN -Message 'Shodan DNS discovery failed' -Data @{ error = $_.Exception.Message }
        }
        Invoke-ETMThreatIntelThrottle -DelayMs $settings.apiDelayMs
    }

    if (Test-ETMApiConfigured -Provider 'SecurityTrails') {
        $key = Get-ETMApiSecret -Name 'SecurityTrails'
        $uri = "https://api.securitytrails.com/v1/domain/$([uri]::EscapeDataString($Domain))/subdomains"
        $h = Get-ETMThreatIntelHeaders -Extra @{ APIKEY = $key }
        try {
            $r = Invoke-RestMethod -Uri $uri -Headers $h -TimeoutSec 25 -ErrorAction Stop
            $items = @($r.subdomains)
            if ($items.Count -eq 0 -and $r.hostname) { $items = @($r.hostname) }
            foreach ($sub in $items | Select-Object -First 120) {
                $fqdn = if ($sub -is [string]) {
                    $s = $sub.Trim().ToLower()
                    if ($s -like '*.*') { $s } else { "$s.$Domain" }
                }
                elseif ($sub.hostname) { [string]$sub.hostname.Trim().ToLower() }
                else { continue }
                [void]$records.Add([pscustomobject]@{
                        hostname  = $fqdn; source = 'SecurityTrails'; ip = ''
                        riskScore = 0; tags = @('api-discovery')
                        firstSeen = $today; lastSeen = $today
                    })
            }
            Write-ETMLog -Level INFO -Message 'SecurityTrails subdomain discovery' -Data @{ domain = $Domain; added = $items.Count }
        }
        catch {
            Write-ETMLog -Level WARN -Message 'SecurityTrails subdomain discovery failed' -Data @{ error = $_.Exception.Message }
        }
    }

    return ,@($records.ToArray())
}

function Invoke-ETMThreatIntelEnrichment {
    <#
    .SYNOPSIS
    Two-pass enrichment: domain reputation APIs, then cascade discovered IPs/hostnames across VT/Shodan/OTX/AbuseIPDB/GreyNoise.
    #>
    param(
        [Parameter(Mandatory)][string]$Domain,
        [array]$Subdomains = @(),
        [array]$WebServices = @(),
        [array]$ExistingIntel = @(),
        $Config,
        [ValidateSet('PassiveOnly', 'CorporateSafe', 'FullAuthorized')]
        [string]$ScanMode = 'PassiveOnly',
        [switch]$FollowUpOnly
    )
    $all = [System.Collections.Generic.List[object]]::new()
    $configured = @(Get-ETMConfiguredApiProviders -ProviderIds $(
        'Shodan', 'VirusTotal', 'SecurityTrails', 'Censys', 'Urlscan',
        'AlienVaultOTX', 'AbuseIPDB', 'GreyNoise'))

    if ($configured.Count -eq 0) {
        Write-ETMLog -Level INFO -Message 'Threat intel skipped' -Data @{
            domain = $Domain; scanMode = $ScanMode; reason = 'No API keys configured'
        }
        return ,@()
    }

    $settings = Get-ETMThreatIntelSettings -Config $Config
    $seen = @{}

    function Add-IntelRows {
        param($Rows)
        foreach ($row in @($Rows)) {
            if (-not $row) { continue }
            $key = "$($row.provider)|$($row.assetType)|$($row.asset)|$($row.summary)"
            if ($seen.ContainsKey($key)) { continue }
            $seen[$key] = $true
            [void]$all.Add($row)
        }
    }

    if (-not $FollowUpOnly) {
        Write-ETMLog -Level INFO -Message 'Threat intel domain pass' -Data @{
            domain = $Domain; providers = ($configured -join ',')
        }

        if ($configured -contains 'Shodan') {
            Add-IntelRows (Invoke-ETMShodanDomainIntel -Domain $Domain -ApiKey (Get-ETMApiSecret -Name 'Shodan'))
            Invoke-ETMThreatIntelThrottle -DelayMs $settings.apiDelayMs
        }
        if ($configured -contains 'VirusTotal') {
            Add-IntelRows (Invoke-ETMVirusTotalDomainIntel -Domain $Domain -ApiKey (Get-ETMApiSecret -Name 'VirusTotal'))
            Invoke-ETMThreatIntelThrottle -DelayMs $settings.apiDelayMs
        }
        if ($configured -contains 'SecurityTrails') {
            Add-IntelRows (Invoke-ETMSecurityTrailsDomainIntel -Domain $Domain -ApiKey (Get-ETMApiSecret -Name 'SecurityTrails'))
            Invoke-ETMThreatIntelThrottle -DelayMs $settings.apiDelayMs
        }
        if ($configured -contains 'Censys') {
            Add-IntelRows (Invoke-ETMCensysDomainIntel -Domain $Domain `
                    -ApiId (Get-ETMApiSecret -Name 'Censys') -ApiSecret (Get-ETMApiSecret -Name 'CensysSecret'))
            Invoke-ETMThreatIntelThrottle -DelayMs $settings.apiDelayMs
        }
        if ($configured -contains 'Urlscan') {
            Add-IntelRows (Invoke-ETMUrlscanDomainIntel -Domain $Domain -ApiKey (Get-ETMApiSecret -Name 'Urlscan'))
            Invoke-ETMThreatIntelThrottle -DelayMs $settings.apiDelayMs
        }
        if ($configured -contains 'AlienVaultOTX') {
            Add-IntelRows (Invoke-ETMOtxDomainIntel -Domain $Domain -ApiKey (Get-ETMApiSecret -Name 'AlienVaultOTX'))
            Invoke-ETMThreatIntelThrottle -DelayMs $settings.apiDelayMs
        }
    }

    $indicators = Get-ETMCollectedScanIndicators -Domain $Domain -Subdomains $Subdomains `
        -WebServices $WebServices -IntelRows @($all.ToArray() + @($ExistingIntel))

    $ipList = @($indicators.Ips | Select-Object -First $settings.maxIpLookups)
    $hostList = @($indicators.Hostnames | Select-Object -First $settings.maxHostnameLookups)

    if ($ipList.Count -gt 0) {
        Write-ETMLog -Level INFO -Message 'Threat intel IP cascade' -Data @{
            count = $ipList.Count; ips = ($ipList -join ', ')
            pass  = if ($FollowUpOnly) { 'follow-up' } else { 'primary' }
        }
        $shodanHosts = 0
        foreach ($ip in $ipList) {
            if ($configured -contains 'VirusTotal') {
                Add-IntelRows (Invoke-ETMVirusTotalIpIntel -Ip $ip -ApiKey (Get-ETMApiSecret -Name 'VirusTotal'))
                Invoke-ETMThreatIntelThrottle -DelayMs $settings.apiDelayMs
            }
            if ($configured -contains 'Shodan' -and $shodanHosts -lt $settings.maxShodanHostLookups) {
                Add-IntelRows (Invoke-ETMShodanHostIntel -Ip $ip -ApiKey (Get-ETMApiSecret -Name 'Shodan'))
                $shodanHosts++
                Invoke-ETMThreatIntelThrottle -DelayMs $settings.apiDelayMs
            }
            if ($configured -contains 'AbuseIPDB') {
                Add-IntelRows (Invoke-ETMAbuseIPDBIntel -Ip $ip -ApiKey (Get-ETMApiSecret -Name 'AbuseIPDB'))
                Invoke-ETMThreatIntelThrottle -DelayMs $settings.apiDelayMs
            }
            if ($configured -contains 'GreyNoise') {
                Add-IntelRows (Invoke-ETMGreyNoiseIpIntel -Ip $ip -ApiKey (Get-ETMApiSecret -Name 'GreyNoise'))
                Invoke-ETMThreatIntelThrottle -DelayMs $settings.apiDelayMs
            }
            if ($configured -contains 'AlienVaultOTX') {
                Add-IntelRows (Invoke-ETMOtxIpIntel -Ip $ip -ApiKey (Get-ETMApiSecret -Name 'AlienVaultOTX'))
                Invoke-ETMThreatIntelThrottle -DelayMs $settings.apiDelayMs
            }
        }
    }

    if ($hostList.Count -gt 0 -and $configured -contains 'VirusTotal') {
        Write-ETMLog -Level INFO -Message 'Threat intel hostname cascade' -Data @{ count = $hostList.Count }
        foreach ($host in $hostList) {
            Add-IntelRows (Invoke-ETMVirusTotalHostnameIntel -Hostname $host -ApiKey (Get-ETMApiSecret -Name 'VirusTotal'))
            Invoke-ETMThreatIntelThrottle -DelayMs $settings.apiDelayMs
        }
    }

    return ,@($all.ToArray())
}

function Convert-ETMThreatIntelToFindings {
    param($IntelRows)
    $rows = ConvertTo-ETMObjectList $IntelRows
    if ($rows.Count -eq 0) { return @() }
    $findings = [System.Collections.Generic.List[object]]::new()
    foreach ($row in $rows) {
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
    return ,@($findings.ToArray())
}

Export-ModuleMember -Function @(
    'Invoke-ETMApiSubdomainDiscovery', 'Invoke-ETMThreatIntelEnrichment', 'Convert-ETMThreatIntelToFindings',
    'Get-ETMCollectedScanIndicators', 'Invoke-ETMShodanDomainIntel', 'Invoke-ETMShodanHostIntel',
    'Invoke-ETMVirusTotalDomainIntel', 'Invoke-ETMVirusTotalIpIntel'
)
