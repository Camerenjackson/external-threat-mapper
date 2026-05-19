# Simple HTTP API for Docker / headless use

function Start-ETMHttpService {
    param(
        [int]$Port = 8080,
        [string]$Root = (Get-ETMProjectRoot)
    )

    $listener = [System.Net.HttpListener]::new()
    $listener.Prefixes.Add("http://+:$Port/")
    $listener.Start()
    Write-Host "ETM API listening on http://0.0.0.0:$Port"

    while ($listener.IsListening) {
        $ctx = $listener.GetContext()
        $req = $ctx.Request
        $res = $ctx.Response
        $path = $req.Url.LocalPath.TrimEnd('/')
        $body = ''
        $code = 200

        try {
            if ($path -eq '/health') {
                $body = '{"status":"ok"}'
            }
            elseif ($path -eq '/api/test' -and $req.HttpMethod -eq 'GET') {
                $results = Test-ETMAllApiConnections
                $body = ($results | ConvertTo-Json -Compress)
            }
            elseif ($path -eq '/api/scan' -and $req.HttpMethod -eq 'POST') {
                $reader = New-Object IO.StreamReader($req.InputStream)
                $json = $reader.ReadToEnd() | ConvertFrom-Json
                $domain = $json.domain
                $mode = if ($json.mode) { $json.mode } else { 'PassiveOnly' }
                $scope = New-ETMScopeObject -PrimaryDomain $domain -ScanMode $mode -AuthorizationAcknowledged $true
                $config = Get-ETMAppConfig
                $cb = { param($p, $m) }
                $cancel = [ref]$false
                $result = Start-ETMExternalScan -Scope $scope -Config $config -ProgressCallback $cb -CancelFlag $cancel
                $body = ($result | ConvertTo-Json -Depth 8 -Compress)
            }
            else {
                $code = 404
                $body = '{"error":"not found"}'
            }
        }
        catch {
            $code = 500
            $body = (@{ error = $_.Exception.Message } | ConvertTo-Json -Compress)
        }

        $bytes = [Text.Encoding]::UTF8.GetBytes($body)
        $res.StatusCode = $code
        $res.ContentType = 'application/json'
        $res.OutputStream.Write($bytes, 0, $bytes.Length)
        $res.Close()
    }
}
