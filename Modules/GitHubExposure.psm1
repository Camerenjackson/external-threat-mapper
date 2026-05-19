# GitHubExposure.psm1 - GitHub code search metadata (secrets redacted)

function Invoke-ETMGitHubExposureSearch {
    param(
        [Parameter(Mandatory)][string]$Domain,
        [string]$Token,
        [int]$RateLimitMs = 800
    )
    $hits = [System.Collections.Generic.List[object]]::new()
    if (-not $Token) { return $hits }

    $q = [uri]::EscapeDataString("""$Domain"" in:file")
    $uri = "https://api.github.com/search/code?q=$q&per_page=5"
    try {
        $resp = Invoke-ETMGitHubApi -Uri $uri -Token $Token
        foreach ($item in @($resp.items)) {
            $hits.Add([pscustomobject]@{
                    repository = $item.repository.full_name
                    path       = $item.path
                    category   = 'domain-reference'
                    riskScore  = 50
                    summary    = 'Public code reference to in-scope domain (metadata only).'
                    redacted   = $true
                })
        }
    }
    catch {
        Write-ETMLog -Level WARN -Message 'GitHub search skipped' -Data @{
            error  = $_.Exception.Message
            domain = $Domain
        }
    }
    Start-Sleep -Milliseconds $RateLimitMs
    return $hits
}

Export-ModuleMember -Function 'Invoke-ETMGitHubExposureSearch'
