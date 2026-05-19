# ApiManager.psm1 - Multi-provider API keys (DPAPI / env / container JSON)

function Test-ETMContainerMode {
    return [bool]($env:ETM_CONTAINER -eq '1' -or $env:ETM_USE_PLAIN_CREDENTIALS -eq '1')
}

function Get-ETMPlainCredentialPath {
    Join-Path (Get-ETMProjectRoot) 'data\credentials.json'
}

function Get-ETMIntegrationCatalog {
    $path = Join-Path (Get-ETMProjectRoot) 'config\integrations.json'
    if (-not (Test-Path $path)) { return @() }
    $raw = Get-Content $path -Raw | ConvertFrom-Json
    return @($raw.providers | Where-Object { -not $_.hidden })
}

function Get-ETMProviderEnvVars {
    param([Parameter(Mandatory)][string]$Name)
    if ($Name -eq 'SqlPassword') { return @('ETM_SQL_PASSWORD', 'ETM_SQL_CONNECTION_PASSWORD') }
    $catalog = Get-ETMIntegrationCatalog
    $entry = $catalog | Where-Object { $_.id -eq $Name } | Select-Object -First 1
    if ($entry -and $entry.envVars) { return @($entry.envVars) }
    return @("ETM_${Name}_API_KEY", "${Name}_API_KEY")
}

function Protect-ETMSecret {
    param([Parameter(Mandatory)][string]$PlainText)
    if (Test-ETMContainerMode) { return $PlainText }
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($PlainText)
    $enc = [System.Security.Cryptography.ProtectedData]::Protect(
        $bytes, $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser
    )
    return [Convert]::ToBase64String($enc)
}

function Unprotect-ETMSecret {
    param([Parameter(Mandatory)][string]$ProtectedBase64)
    if ([string]::IsNullOrWhiteSpace($ProtectedBase64)) { return '' }
    if (Test-ETMContainerMode) { return $ProtectedBase64 }
    try {
        $enc = [Convert]::FromBase64String($ProtectedBase64)
        $bytes = [System.Security.Cryptography.ProtectedData]::Unprotect(
            $enc, $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser
        )
        return [System.Text.Encoding]::UTF8.GetString($bytes)
    }
    catch { return $ProtectedBase64 }
}

function Get-ETMApiCredentialPath {
    if (Test-ETMContainerMode) { return Get-ETMPlainCredentialPath }
    Join-Path (Get-ETMProjectRoot) 'credentials\api-keys.dpapi.json'
}

function Get-ETMPlainCredentials {
    $path = Get-ETMPlainCredentialPath
    if (-not (Test-Path $path)) { return @{} }
    $raw = Get-Content $path -Raw | ConvertFrom-Json
    $out = @{}
    $raw.PSObject.Properties | ForEach-Object { $out[$_.Name] = [string]$_.Value }
    return $out
}

function Get-ETMApiCredentials {
    $path = Get-ETMApiCredentialPath
    if (-not (Test-Path $path)) { return @{} }
    $raw = Get-Content $path -Raw | ConvertFrom-Json
    $out = @{}
    $raw.PSObject.Properties | ForEach-Object { $out[$_.Name] = $_.Value }
    return $out
}

function Set-ETMApiCredential {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$Value
    )
    if (Test-ETMContainerMode) {
        $dir = Split-Path (Get-ETMPlainCredentialPath) -Parent
        if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
        $all = Get-ETMPlainCredentials
        if ($all -isnot [hashtable]) { $all = @{} }
        $all[$Name] = $Value
        ($all | ConvertTo-Json) | Set-Content -Path (Get-ETMPlainCredentialPath) -Encoding UTF8
        Write-ETMLog -Level AUDIT -Message 'API credential updated (container)' -Data @{ name = $Name }
        return
    }
    $dir = Split-Path (Get-ETMApiCredentialPath) -Parent
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    $all = Get-ETMApiCredentials
    if ($all -isnot [hashtable]) {
        $ht = @{}
        $all.PSObject.Properties | ForEach-Object { $ht[$_.Name] = $_.Value }
        $all = $ht
    }
    $all[$Name] = if ($Value) { Protect-ETMSecret -PlainText $Value } else { '' }
    ($all | ConvertTo-Json) | Set-Content -Path (Get-ETMApiCredentialPath) -Encoding UTF8
    Write-ETMLog -Level AUDIT -Message 'API credential updated' -Data @{ name = $Name }
}

function Get-ETMApiSecret {
    param([Parameter(Mandatory)][string]$Name)
    foreach ($en in (Get-ETMProviderEnvVars -Name $Name)) {
        $v = [Environment]::GetEnvironmentVariable($en)
        if ($v) { return $v }
    }
    if (Test-ETMContainerMode) {
        $plain = Get-ETMPlainCredentials
        if ($plain -is [hashtable] -and $plain.ContainsKey($Name)) { return $plain[$Name] }
    }
    $all = Get-ETMApiCredentials
    if ($all -is [hashtable]) {
        if (-not $all.ContainsKey($Name)) { return '' }
        return Unprotect-ETMSecret -ProtectedBase64 $all[$Name]
    }
    $prop = $all.PSObject.Properties[$Name]
    if (-not $prop) { return '' }
    return Unprotect-ETMSecret -ProtectedBase64 $prop.Value
}

function Invoke-ETMGitHubApi {
    param(
        [Parameter(Mandatory)][string]$Uri,
        [Parameter(Mandatory)][string]$Token
    )
    $baseHeaders = @{
        Accept       = 'application/vnd.github+json'
        'User-Agent' = 'ExternalThreatMapper-Defensive/1.0'
    }
    $last = $null
    foreach ($auth in @("Bearer $Token", "token $Token")) {
        try {
            $h = $baseHeaders.Clone()
            $h['Authorization'] = $auth
            return Invoke-RestMethod -Uri $Uri -Headers $h -TimeoutSec 20 -ErrorAction Stop
        }
        catch {
            $last = $_
            if ($_.Exception.Response.StatusCode.value__ -ne 401) { throw }
        }
    }
    throw $last
}

function Test-ETMApiConnection {
    param(
        [Parameter(Mandatory)][string]$Provider
    )
    $key = Get-ETMApiSecret -Name $Provider
    $needsKey = $Provider -notin @('AlienVaultOTX')

    if ($needsKey -and -not $key) {
        return [pscustomobject]@{
            Ok      = $false
            Message = 'No API key saved. Enter a key below or set an environment variable.'
        }
    }

    try {
        switch ($Provider) {
            'GitHub' {
                $r = Invoke-ETMGitHubApi -Uri 'https://api.github.com/rate_limit' -Token $key
                return [pscustomobject]@{ Ok = $true; Message = "Connected. Rate limit remaining: $($r.resources.core.remaining)" }
            }
            'Shodan' {
                Invoke-RestMethod -Uri "https://api.shodan.io/api-info?key=$key" -TimeoutSec 15 | Out-Null
                return [pscustomobject]@{ Ok = $true; Message = 'Shodan API key is valid.' }
            }
            'VirusTotal' {
                $h = @{ 'x-apikey' = $key }
                Invoke-RestMethod -Uri 'https://www.virustotal.com/api/v3/domains/google.com' -Headers $h -TimeoutSec 20 | Out-Null
                return [pscustomobject]@{ Ok = $true; Message = 'VirusTotal API key is valid.' }
            }
            'SecurityTrails' {
                $h = @{ APIKEY = $key; 'User-Agent' = 'ETM' }
                Invoke-RestMethod -Uri 'https://api.securitytrails.com/v1/ping' -Headers $h -TimeoutSec 15 | Out-Null
                return [pscustomobject]@{ Ok = $true; Message = 'SecurityTrails API key is valid.' }
            }
            'Censys' {
                $sec = Get-ETMApiSecret -Name 'CensysSecret'
                if (-not $sec) { return [pscustomobject]@{ Ok = $false; Message = 'Save Censys API Secret as well.' } }
                $pair = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("${key}:${sec}"))
                $h = @{ Authorization = "Basic $pair" }
                Invoke-RestMethod -Uri 'https://search.censys.io/api/v1/account' -Headers $h -TimeoutSec 20 | Out-Null
                return [pscustomobject]@{ Ok = $true; Message = 'Censys credentials are valid.' }
            }
            'CensysSecret' {
                return [pscustomobject]@{ Ok = $true; Message = 'Secret stored. Test Censys (ID) to verify the pair.' }
            }
            'Urlscan' {
                $h = @{ 'API-Key' = $key; 'User-Agent' = 'ETM' }
                Invoke-RestMethod -Uri 'https://urlscan.io/api/v1/quotas' -Headers $h -TimeoutSec 15 | Out-Null
                return [pscustomobject]@{ Ok = $true; Message = 'urlscan.io API key is valid.' }
            }
            'AbuseIPDB' {
                $h = @{ Key = $key }
                Invoke-RestMethod -Uri 'https://api.abuseipdb.com/api/v2/check-block?network=1.1.1.0/24' -Headers $h -TimeoutSec 15 | Out-Null
                return [pscustomobject]@{ Ok = $true; Message = 'AbuseIPDB API key is valid.' }
            }
            'GreyNoise' {
                $h = @{ key = $key; 'User-Agent' = 'ETM' }
                Invoke-RestMethod -Uri 'https://api.greynoise.io/v3/meta/metadata' -Headers $h -TimeoutSec 15 | Out-Null
                return [pscustomobject]@{ Ok = $true; Message = 'GreyNoise API key is valid.' }
            }
            'AlienVaultOTX' {
                $h = @{ 'User-Agent' = 'ETM' }
                if ($key) { $h['X-OTX-API-KEY'] = $key }
                Invoke-RestMethod -Uri 'https://otx.alienvault.com/api/v1/pulses/subscribed' -Headers $h -TimeoutSec 20 | Out-Null
                return [pscustomobject]@{ Ok = $true; Message = 'OTX API reachable (key optional for low volume).' }
            }
            'HIBP' {
                $h = @{ 'hibp-api-key' = $key; 'User-Agent' = 'ExternalThreatMapper-Defensive' }
                $breaches = Invoke-RestMethod -Uri 'https://haveibeenpwned.com/api/v3/breaches' -Headers $h -TimeoutSec 20
                $n = @($breaches).Count
                return [pscustomobject]@{ Ok = $true; Message = "HIBP connected ($n breaches in catalog)." }
            }
            default {
                return [pscustomobject]@{ Ok = $false; Message = "Unknown provider: $Provider" }
            }
        }
    }
    catch {
        $msg = $_.Exception.Message
        if ($_.ErrorDetails.Message) { $msg = $_.ErrorDetails.Message }
        return [pscustomobject]@{ Ok = $false; Message = $msg }
    }
}

function Test-ETMAllApiConnections {
    $results = [System.Collections.Generic.List[object]]::new()
    foreach ($p in Get-ETMIntegrationCatalog) {
        if ($p.id -eq 'CensysSecret') { continue }
        try {
            $t = Test-ETMApiConnection -Provider $p.id
            $msg = $t.Message
            $ok = $t.Ok
        }
        catch {
            $ok = $false
            $msg = $_.Exception.Message
        }
        [void]$results.Add([pscustomobject]@{
                provider = $p.displayName
                id       = $p.id
                ok       = $ok
                message  = $msg
            })
        Start-Sleep -Milliseconds 250
    }
    return $results.ToArray()
}

Export-ModuleMember -Function @(
    'Protect-ETMSecret', 'Unprotect-ETMSecret', 'Get-ETMApiCredentials', 'Set-ETMApiCredential',
    'Get-ETMApiSecret', 'Test-ETMApiConnection', 'Test-ETMAllApiConnections', 'Invoke-ETMGitHubApi',
    'Test-ETMContainerMode', 'Get-ETMIntegrationCatalog', 'Get-ETMProviderEnvVars'
)
