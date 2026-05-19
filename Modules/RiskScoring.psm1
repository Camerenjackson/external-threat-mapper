# RiskScoring.psm1 — protection score (0-100) and category breakdown

function Get-ETMGrade {
    param([int]$Score)
    if ($Score -ge 90) { return 'A - Strong' }
    if ($Score -ge 75) { return 'B - Good' }
    if ($Score -ge 50) { return 'C - Moderate' }
    if ($Score -ge 25) { return 'D - Weak' }
    return 'F - Critical Exposure'
}

function Measure-ETMProtectionScore {
    param(
        [Parameter(Mandatory)][array]$Findings,
        [Parameter(Mandatory)][array]$Subdomains,
        [Parameter(Mandatory)][array]$WebServices
    )

    $categories = [ordered]@{
        ExternalAssetHygiene   = @{ Weight = 20; Score = 20; Notes = @() }
        WebExposureRisk      = @{ Weight = 15; Score = 15; Notes = @() }
        CredentialExposure   = @{ Weight = 15; Score = 15; Notes = @() }
        CloudExposureRisk    = @{ Weight = 15; Score = 15; Notes = @() }
        BrandAbuseRisk       = @{ Weight = 10; Score = 10; Notes = @() }
        CertificateDnsHygiene = @{ Weight = 10; Score = 10; Notes = @() }
        ThreatReputation     = @{ Weight = 10; Score = 10; Notes = @() }
        DetectionReadiness   = @{ Weight = 5; Score = 5; Notes = @() }
    }

    $high = @($Findings | Where-Object { $_.severity -in @('Critical', 'High') })
    $loginFindings = @($Findings | Where-Object { $_.category -match 'login|credential|portal' })
    $cloudFindings = @($Findings | Where-Object { $_.category -match 'cloud' })
    $typoFindings = @($Findings | Where-Object { $_.category -match 'typosquat|brand' })
    $certFindings = @($Findings | Where-Object { $_.category -match 'certificate|tls' })
    $riskyHosts = @($Subdomains | Where-Object { $_.riskScore -ge 70 })

    if ($riskyHosts.Count -gt 5) {
        $categories.ExternalAssetHygiene.Score -= [Math]::Min(12, $riskyHosts.Count)
        $categories.ExternalAssetHygiene.Notes += "Multiple high-risk hostnames discovered ($($riskyHosts.Count))."
    }

    if ($loginFindings.Count -gt 0) {
        $ded = [Math]::Min(15, $loginFindings.Count * 3)
        $categories.WebExposureRisk.Score -= $ded
        $categories.CredentialExposure.Score -= [Math]::Min(15, $loginFindings.Count * 4)
        $categories.WebExposureRisk.Notes += 'Internet-visible login or admin surfaces detected.'
    }

    if ($cloudFindings.Count -gt 0) {
        $categories.CloudExposureRisk.Score -= [Math]::Min(15, $cloudFindings.Count * 5)
        $categories.CloudExposureRisk.Notes += 'Cloud storage exposure indicators present.'
    }

    if ($typoFindings.Count -gt 0) {
        $categories.BrandAbuseRisk.Score -= [Math]::Min(10, $typoFindings.Count * 2)
        $categories.BrandAbuseRisk.Notes += 'Suspicious lookalike domains may indicate brand abuse risk.'
    }

    if ($certFindings.Count -gt 0) {
        $categories.CertificateDnsHygiene.Score -= [Math]::Min(10, $certFindings.Count * 3)
        $categories.CertificateDnsHygiene.Notes += 'Certificate or TLS hygiene issues identified.'
    }

    if ($high.Count -gt 3) {
        $categories.ThreatReputation.Score -= 4
        $categories.DetectionReadiness.Score -= 2
        $categories.ThreatReputation.Notes += 'Elevated high-severity external findings.'
    }

    foreach ($key in @($categories.Keys)) {
        if ($categories[$key].Score -lt 0) { $categories[$key].Score = 0 }
    }

    $total = 0
    foreach ($key in @($categories.Keys)) { $total += $categories[$key].Score }

    [pscustomobject]@{
        TotalScore   = $total
        Grade        = Get-ETMGrade -Score $total
        Categories   = $categories
        Summary      = "Protection score $total/100 based on passive external visibility indicators."
        TopRisks     = @($high | Select-Object -First 5 title, severity, businessExplanation)
    }
}

Export-ModuleMember -Function 'Get-ETMGrade', 'Measure-ETMProtectionScore'
