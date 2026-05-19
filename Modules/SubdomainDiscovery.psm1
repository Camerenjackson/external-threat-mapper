# SubdomainDiscovery.psm1 — passive subdomain enumeration

function Get-ETMSubdomainsFromCertificateTransparency {
    param(
        [Parameter(Mandatory)][string]$Domain,
        [int]$TimeoutSec = 30
    )
    $results = [System.Collections.Generic.List[object]]::new()
    try {
        $uri = "https://crt.sh/?q=%25.$([uri]::EscapeDataString($Domain))&output=json"
        $resp = Invoke-RestMethod -Uri $uri -TimeoutSec $TimeoutSec -ErrorAction Stop
        $names = $resp | ForEach-Object { $_.name_value } | ForEach-Object { $_ -split "`n" } | ForEach-Object { $_.Trim().ToLower() } |
            Where-Object { $_ -and $_ -like "*.$Domain" } | Select-Object -Unique
        foreach ($n in $names) {
            $results.Add([pscustomobject]@{
                    hostname   = $n
                    source     = 'CertificateTransparency'
                    ip         = ''
                    riskScore  = 0
                    tags       = @()
                    firstSeen  = (Get-Date).ToString('yyyy-MM-dd')
                    lastSeen   = (Get-Date).ToString('yyyy-MM-dd')
                })
        }
    }
    catch {
        Write-Verbose "CT lookup skipped or failed: $($_.Exception.Message)"
    }
    return $results
}

function Get-ETMSubdomainsFromDnsBruteforceLite {
    param(
        [Parameter(Mandatory)][string]$Domain,
        [string[]]$Prefixes,
        [int]$RateLimitMs = 300
    )
    if (-not $Prefixes) {
        $Prefixes = @('www', 'mail', 'vpn', 'admin', 'portal', 'dev', 'test', 'staging', 'api', 'sso', 'remote', 'citrix')
    }
    $results = [System.Collections.Generic.List[object]]::new()
    foreach ($p in $Prefixes) {
        $host = "$p.$Domain"
        try {
            $dns = Resolve-DnsName -Name $host -Type A -ErrorAction Stop | Select-Object -First 1
            if ($dns) {
                $results.Add([pscustomobject]@{
                        hostname  = $host
                        source    = 'DNS-Passive'
                        ip        = ($dns.IPAddress -join ',')
                        riskScore = 0
                        tags      = @($p)
                        firstSeen = (Get-Date).ToString('yyyy-MM-dd')
                        lastSeen  = (Get-Date).ToString('yyyy-MM-dd')
                    })
            }
        }
        catch { }
        Start-Sleep -Milliseconds $RateLimitMs
    }
    return $results
}

function Invoke-ETMSubdomainDiscovery {
    param(
        [Parameter(Mandatory)][psobject]$Scope,
        [psobject]$Config
    )
    $domain = $Scope.primaryDomain
    $all = [System.Collections.Generic.List[object]]::new()
    $rate = if ($Config.application.rateLimitMs) { [int]$Config.application.rateLimitMs } else { 500 }

    $all.AddRange((Get-ETMSubdomainsFromCertificateTransparency -Domain $domain))
    if ($Scope.scanMode -ne 'PassiveOnly') {
        # Still DNS-only — not intrusive port scan
        $all.AddRange((Get-ETMSubdomainsFromDnsBruteforceLite -Domain $domain -RateLimitMs $rate))
    }

    $keywords = $Config.riskKeywords.subdomains
    foreach ($item in $all) {
        $score = 10
        foreach ($kw in $keywords) {
            if ($item.hostname -like "*$kw*") { $score += 15 }
        }
        if ($score -gt 100) { $score = 100 }
        $item.riskScore = $score
        if ($score -ge 40) { $item.tags = @($item.tags + 'risky-keyword') | Select-Object -Unique }
    }

    return $all | Sort-Object hostname -Unique
}

Export-ModuleMember -Function @(
    'Get-ETMSubdomainsFromCertificateTransparency',
    'Get-ETMSubdomainsFromDnsBruteforceLite',
    'Invoke-ETMSubdomainDiscovery'
)
