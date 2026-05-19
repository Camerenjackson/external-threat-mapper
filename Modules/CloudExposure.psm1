# CloudExposure.psm1 — public cloud bucket indicator checks (no auth, no download)

function Get-ETMCloudNameCandidates {
    param([Parameter(Mandatory)][string]$Domain)
    $label = ($Domain -replace '\.', '-').ToLower()
    @(
        "$label",
        "$label-backup",
        "$label-assets",
        "com-$label",
        "${label}.s3.amazonaws.com"
    )
}

function Test-ETMCloudExposureIndicator {
    param([Parameter(Mandatory)][string]$Name)
    $urls = @(
        "https://$Name.s3.amazonaws.com",
        "https://$Name.blob.core.windows.net",
        "https://storage.googleapis.com/$Name"
    )
    foreach ($u in $urls) {
        try {
            $r = Invoke-WebRequest -Uri $u -Method Head -TimeoutSec 8 -UseBasicParsing -ErrorAction Stop
            if ($r.StatusCode -in 200, 403) {
                return [pscustomobject]@{
                    name       = $Name
                    url        = $u
                    statusCode = [int]$r.StatusCode
                    indicator  = if ($r.StatusCode -eq 200) { 'PublicResponse' } else { 'ExistsDeniedListing' }
                    riskScore  = if ($r.StatusCode -eq 200) { 85 } else { 40 }
                }
            }
        }
        catch { }
    }
    return $null
}

function Invoke-ETMCloudExposureScan {
    param(
        [Parameter(Mandatory)][string]$Domain,
        [int]$RateLimitMs = 500
    )
    $hits = [System.Collections.Generic.List[object]]::new()
    foreach ($n in (Get-ETMCloudNameCandidates -Domain $Domain)) {
        $hit = Test-ETMCloudExposureIndicator -Name ($n -replace '\.s3\.amazonaws\.com$', '')
        if ($hit) { [void]$hits.Add($hit) }
        Start-Sleep -Milliseconds $RateLimitMs
    }
    return $hits
}

Export-ModuleMember -Function 'Invoke-ETMCloudExposureScan', 'Get-ETMCloudNameCandidates'
