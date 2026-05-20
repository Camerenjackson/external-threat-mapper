# BreachExposure.psm1 — Have I Been Pwned (domain + optional seed emails)

function Get-ETMHibpHeaders {
    param([Parameter(Mandatory)][string]$ApiKey)
    return @{
        'hibp-api-key' = $ApiKey
        'User-Agent'   = 'ExternalThreatMapper-Defensive/1.0'
    }
}

function Invoke-ETMHibpApi {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$ApiKey,
        [int]$TimeoutSec = 30
    )
    $uri = "https://haveibeenpwned.com/api/v3/$($Path.TrimStart('/'))"
    $headers = Get-ETMHibpHeaders -ApiKey $ApiKey
    try {
        $r = Invoke-WebRequest -Uri $uri -Headers $headers -Method Get -TimeoutSec $TimeoutSec -UseBasicParsing -ErrorAction Stop
        return [pscustomobject]@{
            Ok         = $true
            StatusCode = [int]$r.StatusCode
            Body       = $r.Content
            Json       = if ($r.Content) { $r.Content | ConvertFrom-Json } else { $null }
        }
    }
    catch {
        $resp = $_.Exception.Response
        $code = if ($resp) { [int]$resp.StatusCode } else { 0 }
        $body = ''
        try {
            $stream = $resp.GetResponseStream()
            if ($stream) {
                $reader = New-Object System.IO.StreamReader($stream)
                $body = $reader.ReadToEnd()
                $reader.Close()
            }
        }
        catch { }
        $msg = $_.Exception.Message
        if ($body) {
            try {
                $errJson = $body | ConvertFrom-Json
                if ($errJson.message) { $msg = [string]$errJson.message }
            }
            catch { }
        }
        return [pscustomobject]@{
            Ok         = $false
            StatusCode = $code
            Body       = $body
            Json       = $null
            Message    = $msg
        }
    }
}

function Get-ETMHibpDomainVerificationMessage {
    return @'
HIBP domain search requires you to verify ownership of the domain in your HIBP subscription dashboard first.
Add and verify the domain at https://haveibeenpwned.com/Dashboard (DNS TXT, email approval, or meta tag).
Until verified, breachedDomain and stealer log domain APIs return HTTP 403.
'@
}

function ConvertFrom-ETMHibpDomainBreachMap {
    param(
        [Parameter(Mandatory)][string]$Domain,
        $Json
    )
    $rows = [System.Collections.Generic.List[object]]::new()
    if (-not $Json) { return ,@($rows.ToArray()) }

    if ($Json -is [System.Collections.IDictionary]) {
        foreach ($alias in $Json.Keys) {
            $breaches = @($Json[$alias])
            $rows.Add([pscustomobject]@{
                    alias    = [string]$alias
                    domain   = $Domain
                    breaches = $breaches
                    breachCount = $breaches.Count
                })
        }
        return ,@($rows.ToArray())
    }

    $props = $Json.PSObject.Properties
    foreach ($p in $props) {
        $breaches = @($p.Value)
        $rows.Add([pscustomobject]@{
                alias       = [string]$p.Name
                domain      = $Domain
                breaches    = $breaches
                breachCount = $breaches.Count
            })
    }
    return ,@($rows.ToArray())
}

function Invoke-ETMHibpDomainBreachSearch {
    param(
        [Parameter(Mandatory)][string]$Domain,
        [Parameter(Mandatory)][string]$ApiKey
    )
    $encoded = [uri]::EscapeDataString($Domain)
    $r = Invoke-ETMHibpApi -Path "breacheddomain/$encoded" -ApiKey $ApiKey
    if ($r.Ok) {
        $aliases = @(ConvertFrom-ETMHibpDomainBreachMap -Domain $Domain -Json $r.Json)
        return [pscustomobject]@{
            Ok          = $true
            Domain      = $Domain
            SearchType  = 'breachedDomain'
            AliasCount  = $aliases.Count
            Aliases     = $aliases
            Message     = if ($aliases.Count -gt 0) {
                "$($aliases.Count) mailbox alias(es) appear in known data breaches."
            } else {
                'No breached mailbox aliases returned for this domain.'
            }
            Verified    = $true
        }
    }
    if ($r.StatusCode -eq 404) {
        return [pscustomobject]@{
            Ok         = $true
            Domain     = $Domain
            SearchType = 'breachedDomain'
            AliasCount = 0
            Aliases    = @()
            Message    = 'No breached organizational mailboxes found in HIBP for this domain.'
            Verified   = $true
        }
    }
    if ($r.StatusCode -eq 403) {
        return [pscustomobject]@{
            Ok         = $false
            Domain     = $Domain
            SearchType = 'breachedDomain'
            AliasCount = 0
            Aliases    = @()
            Message    = 'Domain not verified in HIBP (HTTP 403). Verify the domain in your HIBP dashboard before scanning.'
            Verified   = $false
            NeedsVerification = $true
        }
    }
    return [pscustomobject]@{
        Ok         = $false
        Domain     = $Domain
        SearchType = 'breachedDomain'
        AliasCount = 0
        Aliases    = @()
        Message    = if ($r.Message) { $r.Message } else { "HIBP request failed (HTTP $($r.StatusCode))." }
        Verified   = $false
    }
}

function Invoke-ETMHibpStealerLogEmailDomainSearch {
    param(
        [Parameter(Mandatory)][string]$Domain,
        [Parameter(Mandatory)][string]$ApiKey
    )
    $encoded = [uri]::EscapeDataString($Domain)
    $r = Invoke-ETMHibpApi -Path "stealerLogsByEmailDomain/$encoded" -ApiKey $ApiKey
    if ($r.Ok) {
        $entries = [System.Collections.Generic.List[object]]::new()
        if ($r.Json) {
            foreach ($p in $r.Json.PSObject.Properties) {
                $sites = @($p.Value)
                $entries.Add([pscustomobject]@{
                        alias          = [string]$p.Name
                        domain         = $Domain
                        exposedSites   = $sites
                        exposedSiteCount = $sites.Count
                    })
            }
        }
        return [pscustomobject]@{
            Ok          = $true
            Domain      = $Domain
            SearchType  = 'stealerLogsByEmailDomain'
            AliasCount  = $entries.Count
            Entries     = $entries.ToArray()
            Message     = if ($entries.Count -gt 0) {
                "$($entries.Count) alias(es) appear in stealer logs for this email domain."
            } else {
                'No stealer log aliases returned for this email domain.'
            }
        }
    }
    if ($r.StatusCode -eq 404) {
        return [pscustomobject]@{
            Ok         = $true
            Domain     = $Domain
            SearchType = 'stealerLogsByEmailDomain'
            AliasCount = 0
            Entries    = @()
            Message    = 'No stealer log exposure found for this email domain.'
        }
    }
    if ($r.StatusCode -eq 403) {
        return [pscustomobject]@{
            Ok         = $false
            Domain     = $Domain
            SearchType = 'stealerLogsByEmailDomain'
            AliasCount = 0
            Entries    = @()
            Message    = 'Stealer log domain search unavailable (domain not verified or subscription tier).'
        }
    }
    return [pscustomobject]@{
        Ok         = $false
        Domain     = $Domain
        SearchType = 'stealerLogsByEmailDomain'
        Message    = if ($r.Message) { $r.Message } else { "Stealer log API failed (HTTP $($r.StatusCode))." }
    }
}

function Invoke-ETMHibpAccountBreachSearch {
    param(
        [Parameter(Mandatory)][string]$Email,
        [Parameter(Mandatory)][string]$ApiKey
    )
    $encoded = [uri]::EscapeDataString($Email.Trim())
    $r = Invoke-ETMHibpApi -Path "breachedaccount/$encoded" -ApiKey $ApiKey
    if ($r.Ok) {
        $breaches = @($r.Json)
        $names = @($breaches | ForEach-Object {
                if ($_.Name) { $_.Name } elseif ($_.Title) { $_.Title } else { [string]$_ }
            })
        return [pscustomobject]@{
            Ok           = $true
            Email        = $Email
            SearchType   = 'breachedAccount'
            BreachCount  = $names.Count
            BreachNames  = $names
            Message      = if ($names.Count -gt 0) { "Found in $($names.Count) breach(es)." } else { 'No breaches for this address.' }
        }
    }
    if ($r.StatusCode -eq 404) {
        return [pscustomobject]@{
            Ok          = $true
            Email       = $Email
            SearchType  = 'breachedAccount'
            BreachCount = 0
            BreachNames = @()
            Message     = 'No breaches found for this authorized seed email.'
        }
    }
    return [pscustomobject]@{
        Ok         = $false
        Email      = $Email
        SearchType = 'breachedAccount'
        Message    = if ($r.Message) { $r.Message } else { "Account search failed (HTTP $($r.StatusCode))." }
    }
}

function New-ETMBreachFinding {
    param(
        [string]$Title,
        [string]$Severity,
        [string]$Evidence,
        [string]$Business,
        [string]$Technical,
        [string]$Remediation
    )
    return [pscustomobject]@{
        title                = $Title
        severity             = $Severity
        category             = 'credential-breach'
        evidence             = $Evidence
        businessExplanation  = $Business
        technicalExplanation = $Technical
        remediation          = $Remediation
        confidence           = 'High'
        status               = 'Open'
        intelProvider        = 'Have I Been Pwned'
    }
}

function Convert-ETMHibpResultsToFindings {
    param(
        [Parameter(Mandatory)][string]$PrimaryDomain,
        $DomainResults,
        $StealerResult,
        $SeedResults
    )
    $findings = [System.Collections.Generic.List[object]]::new()
    $intel = [System.Collections.Generic.List[object]]::new()

    foreach ($dr in @($DomainResults)) {
        if (-not $dr) { continue }
        if ($dr.NeedsVerification) {
            [void]$findings.Add((New-ETMBreachFinding `
                    -Title 'HIBP domain search blocked: domain not verified' `
                    -Severity 'Medium' `
                    -Evidence $dr.Message `
                    -Business 'You cannot assess organizational breach exposure until the target domain is verified in your HIBP subscription.' `
                    -Technical (Get-ETMHibpDomainVerificationMessage) `
                    -Remediation 'Verify the domain at haveibeenpwned.com Dashboard, then re-run the scan.'))
            continue
        }
        if ($dr.AliasCount -gt 0) {
            $totalBreaches = ($dr.Aliases | ForEach-Object { $_.breachCount } | Measure-Object -Sum).Sum
            [void]$findings.Add((New-ETMBreachFinding `
                    -Title "HIBP: $($dr.AliasCount) organizational mailbox alias(es) in data breaches" `
                    -Severity $(if ($dr.AliasCount -ge 25) { 'High' } elseif ($dr.AliasCount -ge 5) { 'Medium' } else { 'Low' }) `
                    -Evidence "Domain: $($dr.Domain); distinct aliases: $($dr.AliasCount); breach references: $totalBreaches" `
                    -Business 'Compromised corporate mailboxes increase phishing, credential stuffing, and account takeover risk.' `
                    -Technical 'HIBP breachedDomain API (aliases only, not full messages). Domain must be verified in HIBP.' `
                    -Remediation 'Force password resets, review MFA coverage, and monitor for suspicious sign-ins.'))
            [void]$intel.Add([pscustomobject]@{
                    provider  = 'Have I Been Pwned'
                    asset     = $dr.Domain
                    assetType = 'email-domain'
                    severity  = $(if ($dr.AliasCount -ge 25) { 'High' } elseif ($dr.AliasCount -ge 5) { 'Medium' } else { 'Low' })
                    summary   = "$($dr.AliasCount) breached mailbox alias(es)"
                    detail    = $dr.Message
                    source    = 'haveibeenpwned.com'
                })
            $cap = 30
            $n = 0
            foreach ($a in $dr.Aliases) {
                if ($n -ge $cap) { break }
                $aliasLabel = if ($a.alias -match '@') { $a.alias } else { "$($a.alias)@$($dr.Domain)" }
                $breachList = (@($a.breaches) | Select-Object -First 8) -join ', '
                [void]$findings.Add((New-ETMBreachFinding `
                        -Title "Breached mailbox: $aliasLabel" `
                        -Severity $(if ($a.breachCount -ge 3) { 'High' } elseif ($a.breachCount -ge 1) { 'Medium' } else { 'Low' }) `
                        -Evidence "Breaches: $breachList" `
                        -Business 'This alias has appeared in public breach corpora.' `
                        -Technical 'Discovered via HIBP domain search (authorized, domain-verified).' `
                        -Remediation 'Reset credentials, enable MFA, and check for reuse on corporate SSO.'))
                $n++
            }
            if ($dr.Aliases.Count -gt $cap) {
                [void]$findings.Add((New-ETMBreachFinding `
                        -Title "HIBP: $($dr.Aliases.Count - $cap) additional breached aliases not shown" `
                        -Severity 'Info' `
                        -Evidence "Listing capped at $cap rows. Export JSON report for full data." `
                        -Business 'Large breach footprint may indicate widespread credential exposure.' `
                        -Technical 'UI cap to keep dashboard readable.' `
                        -Remediation 'Review full HIBP dashboard export for complete alias list.'))
            }
        }
        elseif ($dr.Ok) {
            [void]$intel.Add([pscustomobject]@{
                    provider  = 'Have I Been Pwned'
                    asset     = $dr.Domain
                    assetType = 'email-domain'
                    severity  = 'Info'
                    summary   = 'No breached aliases on domain'
                    detail    = $dr.Message
                    source    = 'haveibeenpwned.com'
                })
        }
    }

    if ($StealerResult -and $StealerResult.Ok -and $StealerResult.AliasCount -gt 0) {
        [void]$findings.Add((New-ETMBreachFinding `
                -Title "HIBP stealer logs: $($StealerResult.AliasCount) alias(es) with captured credentials" `
                -Severity 'High' `
                -Evidence $StealerResult.Message `
                -Business 'Infostealer malware exposure often precedes account takeover.' `
                -Technical 'HIBP stealerLogsByEmailDomain API (Pro subscription).' `
                -Remediation 'Isolate affected endpoints, reset passwords, and review conditional access.'))
        $n = 0
        foreach ($e in @($StealerResult.Entries)) {
            if ($n -ge 20) { break }
            $aliasLabel = if ($e.alias -match '@') { $e.alias } else { "$($e.alias)@$($e.domain)" }
            $sites = (@($e.exposedSites) | Select-Object -First 6) -join ', '
            [void]$findings.Add((New-ETMBreachFinding `
                    -Title "Stealer log exposure: $aliasLabel" `
                    -Severity 'High' `
                    -Evidence "Sites in logs: $sites" `
                    -Business 'Credentials for these services were captured by infostealers.' `
                    -Technical 'HIBP stealer log index (domain-verified).' `
                    -Remediation 'Assume compromise; rotate secrets and revoke active sessions.'))
            $n++
        }
    }

    foreach ($sr in @($SeedResults)) {
        if (-not $sr -or -not $sr.Ok) { continue }
        $email = $sr.Email
        if ($sr.BreachCount -gt 0) {
            $names = (@($sr.BreachNames) | Select-Object -First 10) -join ', '
            [void]$findings.Add((New-ETMBreachFinding `
                    -Title "HIBP seed check: breaches for authorized mailbox" `
                    -Severity $(if ($sr.BreachCount -ge 3) { 'High' } else { 'Medium' }) `
                    -Evidence "Address on file; breaches: $names" `
                    -Business 'Explicitly authorized seed email shows prior third-party breach exposure.' `
                    -Technical 'HIBP breachedaccount API (single mailbox).' `
                    -Remediation 'Ensure password is unique and MFA is enabled for this account.'))
        }
        else {
            [void]$intel.Add([pscustomobject]@{
                    provider  = 'Have I Been Pwned'
                    asset     = 'authorized-seed'
                    assetType = 'email'
                    severity  = 'Info'
                    summary   = 'Seed email: no breaches'
                    detail    = $sr.Message
                    source    = 'haveibeenpwned.com'
                })
        }
    }

    return @{
        findings = $findings.ToArray()
        intel    = $intel.ToArray()
    }
}

function Get-ETMBreachExposure {
    <#
    .SYNOPSIS
    Corporate breach assessment via HIBP domain search (primary) and optional authorized seed emails.
    Domain search returns mailbox aliases only; full addresses are not stored in logs.
    #>
    param(
        [Parameter(Mandatory)][psobject]$Scope,
        [string]$ApiKey,
        [int]$MaxSeedEmails = 5,
        [int]$DelayMs = 1600
    )
    $domain = [string]$Scope.primaryDomain
    if ([string]::IsNullOrWhiteSpace($domain)) {
        return [pscustomobject]@{
            checked  = $false
            message  = 'No primary domain in scope.'
            findings = @()
            intel    = @()
        }
    }
    if (-not $ApiKey) {
        return [pscustomobject]@{
            checked  = $false
            message  = 'HIBP API key not configured.'
            findings = @()
            intel    = @()
        }
    }

    $domainsToSearch = [System.Collections.Generic.List[string]]::new()
    [void]$domainsToSearch.Add($domain.Trim().ToLower())
    foreach ($d in @($Scope.additionalDomains)) {
        if ($d -and $domainsToSearch -notcontains $d.Trim().ToLower()) {
            [void]$domainsToSearch.Add($d.Trim().ToLower())
        }
    }

    $domainResults = [System.Collections.Generic.List[object]]::new()
    $stealerResult = $null
    foreach ($d in $domainsToSearch) {
        Write-ETMLog -Level INFO -Message 'HIBP domain breach search' -Data @{ domain = $d }
        [void]$domainResults.Add((Invoke-ETMHibpDomainBreachSearch -Domain $d -ApiKey $ApiKey))
        Start-Sleep -Milliseconds $DelayMs
    }

    # Stealer logs for primary domain only (separate rate limit)
    Write-ETMLog -Level INFO -Message 'HIBP stealer log domain search' -Data @{ domain = $domain }
    $stealerResult = Invoke-ETMHibpStealerLogEmailDomainSearch -Domain $domain -ApiKey $ApiKey
    Start-Sleep -Milliseconds $DelayMs

    $seedResults = [System.Collections.Generic.List[object]]::new()
    $seeds = @()
    if ($Scope.PSObject.Properties['breachCheckEmails'] -and $Scope.breachCheckEmails) {
        $seeds = @($Scope.breachCheckEmails | Where-Object { $_ -match '@' })
    }
    $seeds = @($seeds | Select-Object -First $MaxSeedEmails)
    foreach ($email in $seeds) {
        Write-ETMLog -Level INFO -Message 'HIBP seed email breach check' -Data @{ emailDomain = ($email -split '@')[-1] }
        [void]$seedResults.Add((Invoke-ETMHibpAccountBreachSearch -Email $email -ApiKey $ApiKey))
        Start-Sleep -Milliseconds $DelayMs
    }

    $converted = Convert-ETMHibpResultsToFindings -PrimaryDomain $domain `
        -DomainResults $domainResults.ToArray() `
        -StealerResult $stealerResult `
        -SeedResults $seedResults.ToArray()

    $verified = @($domainResults | Where-Object { $_.Ok -and -not $_.NeedsVerification }).Count -gt 0
    $aliasTotal = ($domainResults | ForEach-Object { $_.AliasCount } | Measure-Object -Sum).Sum

    return [pscustomobject]@{
        checked      = $true
        domain       = $domain
        domainsSearched = $domainsToSearch.ToArray()
        aliasTotal   = $aliasTotal
        domainVerified = $verified
        message      = "HIBP complete: $aliasTotal breached alias(es) across $($domainsToSearch.Count) domain(s); $($seeds.Count) seed email(s) checked."
        findings     = $converted.findings
        intel        = $converted.intel
        domainResults = $domainResults.ToArray()
        stealerResult = $stealerResult
        seedResults  = $seedResults.ToArray()
    }
}

Export-ModuleMember -Function @(
    'Get-ETMBreachExposure', 'Invoke-ETMHibpApi', 'Invoke-ETMHibpDomainBreachSearch', 'Invoke-ETMHibpAccountBreachSearch',
    'Get-ETMHibpDomainVerificationMessage'
)
