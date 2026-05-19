# TlsCheck.psm1 — certificate expiration checks (safe)

function Test-ETMTlsCertificate {
    param(
        [Parameter(Mandatory)][string]$Hostname,
        [int]$Port = 443
    )
    try {
        $tcp = New-Object System.Net.Sockets.TcpClient($Hostname, $Port)
        $ssl = New-Object System.Net.Security.SslStream($tcp.GetStream(), $false, ({ $true }))
        $ssl.AuthenticateAsClient($Hostname)
        $cert = $ssl.RemoteCertificate
        $ssl.Close(); $tcp.Close()
        if (-not $cert) { return $null }
        $exp = [DateTime]::Parse($cert.GetExpirationDateString())
        $days = ($exp - (Get-Date)).Days
        return [pscustomobject]@{
            hostname = $Hostname
            expires  = $exp.ToString('yyyy-MM-dd')
            daysLeft = $days
            expired  = ($days -lt 0)
        }
    }
    catch {
        return $null
    }
}

Export-ModuleMember -Function 'Test-ETMTlsCertificate'
