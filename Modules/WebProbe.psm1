# WebProbe.psm1 — safe HTTP probing (Corporate Safe / Full Authorized only)

function Invoke-ETMSafeWebProbe {
    param(
        [Parameter(Mandatory)][string]$Url,
        [int]$TimeoutSec = 15
    )
    try {
        $resp = Invoke-WebRequest -Uri $Url -Method Head -TimeoutSec $TimeoutSec -UseBasicParsing -MaximumRedirection 2 -ErrorAction Stop
        return [pscustomobject]@{
            url         = $Url
            statusCode  = [int]$resp.StatusCode
            title       = ''
            headers     = ($resp.Headers | ConvertTo-Json -Compress)
            loginDetected = ($resp.Headers.Server -match 'login|auth' -or $Url -match 'login|signin|sso')
            riskScore   = 0
        }
    }
    catch {
        if ($_.Exception.Response) {
            return [pscustomobject]@{
                url        = $Url
                statusCode = [int]$_.Exception.Response.StatusCode.value__
                title      = ''
                headers    = ''
                loginDetected = ($Url -match 'login|signin|admin|portal')
                riskScore  = 0
            }
        }
    }
    return $null
}

function Invoke-ETMWebProbeBatch {
    param(
        [Parameter(Mandatory)][array]$Hostnames,
        [ValidateSet('PassiveOnly', 'CorporateSafe', 'FullAuthorized')]
        [string]$ScanMode = 'CorporateSafe',
        [int]$RateLimitMs = 500
    )
    if ($ScanMode -eq 'PassiveOnly') { return @() }

    $services = [System.Collections.Generic.List[object]]::new()
    foreach ($h in $Hostnames | Select-Object -First 25) {
        foreach ($scheme in @('https', 'http')) {
            $url = "${scheme}://${h}"
            $r = Invoke-ETMSafeWebProbe -Url $url
            if ($r) {
                if ($r.loginDetected) { $r.riskScore = 75 }
                [void]$services.Add($r)
            }
            Start-Sleep -Milliseconds $RateLimitMs
        }
    }
    return $services
}

Export-ModuleMember -Function 'Invoke-ETMSafeWebProbe', 'Invoke-ETMWebProbeBatch'
