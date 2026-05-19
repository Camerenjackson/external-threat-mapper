# TyposquatCheck.psm1 — passive typosquat / lookalike checks

function Get-ETMTyposquatCandidates {
    param([Parameter(Mandatory)][string]$Domain)
    $parts = $Domain.Split('.')
    if ($parts.Count -lt 2) { return @() }
    $label = $parts[0]
    $tld = $parts[-1]
    $base = ($parts[0..($parts.Count - 2)] -join '.')
    $candidates = [System.Collections.Generic.HashSet[string]]::new()
    [void]$candidates.Add("$base.co")
    [void]$candidates.Add("$base.net")
    [void]$candidates.Add("$base.org")
    if ($label.Length -gt 3) {
        [void]$candidates.Add("$($label.Substring(0,$label.Length-1)).$tld")
        [void]$candidates.Add("${label}s.$tld")
    }
    if ($label.Length -ge 2) {
        $swapped = $label.ToCharArray()
        $tmp = $swapped[0]; $swapped[0] = $swapped[1]; $swapped[1] = $tmp
        [void]$candidates.Add(("$(-join $swapped).$tld"))
    }
    return @($candidates)
}

function Invoke-ETMTyposquatCheck {
    param(
        [Parameter(Mandatory)][string]$Domain,
        [int]$RateLimitMs = 400
    )
    $out = [System.Collections.Generic.List[object]]::new()
    foreach ($c in (Get-ETMTyposquatCandidates -Domain $Domain)) {
        $resolved = $false
        $title = ''
        try {
            $dns = Resolve-DnsName -Name $c -Type A -ErrorAction Stop
            $resolved = $true
        }
        catch { }
        if ($resolved) {
            try {
                $r = Invoke-WebRequest -Uri "http://$c" -Method Head -TimeoutSec 8 -UseBasicParsing -ErrorAction Stop
                $title = $r.Headers['Content-Type']
            }
            catch { }
        }
        if ($resolved) {
            $out.Add([pscustomobject]@{
                    candidate = $c
                    resolves  = $true
                    httpHint  = $title
                    riskScore = 60
                })
        }
        Start-Sleep -Milliseconds $RateLimitMs
    }
    return $out
}

Export-ModuleMember -Function 'Get-ETMTyposquatCandidates', 'Invoke-ETMTyposquatCheck'
