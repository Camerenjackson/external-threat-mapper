# ReportGenerator.psm1 — HTML / CSV / JSON exports

function Export-ETMHtmlReport {
    param(
        [Parameter(Mandatory)][psobject]$ScanResult,
        [Parameter(Mandatory)][string]$OutputPath,
        [ValidateSet('Executive', 'Technical')]
        [string]$ReportType = 'Executive'
    )
    $score = $ScanResult.score
    $findings = @($ScanResult.findings)
    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.AppendLine('<!DOCTYPE html><html><head><meta charset="utf-8">')
    [void]$sb.AppendLine("<title>ETM $ReportType Report</title>")
    [void]$sb.AppendLine('<style>body{font-family:Segoe UI,sans-serif;background:#0f1419;color:#e6edf3;margin:2rem}')
    [void]$sb.AppendLine('.card{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:1.5rem;margin-bottom:1rem}')
    [void]$sb.AppendLine('h1{color:#58a6ff}.score{font-size:2.5rem;font-weight:bold}')
    [void]$sb.AppendLine('table{width:100%;border-collapse:collapse}th,td{border:1px solid #30363d;padding:8px}')
    [void]$sb.AppendLine('</style></head><body>')
    [void]$sb.AppendLine("<h1>External Threat Mapper - $ReportType</h1>")
    [void]$sb.AppendLine("<p>Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm')</p>")
    [void]$sb.AppendLine('<div class="card">')
    [void]$sb.AppendLine("<p class=""score"">$($score.TotalScore) / 100</p><p>$($score.Grade)</p><p>$($score.Summary)</p>")
    [void]$sb.AppendLine('</div><div class="card"><h2>Findings</h2><table><tr><th>Severity</th><th>Title</th><th>Category</th></tr>')
    foreach ($f in $findings) {
        $t = [System.Security.SecurityElement]::Escape([string]$f.title)
        [void]$sb.AppendLine("<tr><td>$($f.severity)</td><td>$t</td><td>$($f.category)</td></tr>")
    }
    [void]$sb.AppendLine('</table></div><p><em>Authorized defensive assessment only.</em></p></body></html>')
    $html = $sb.ToString()
    $dir = Split-Path $OutputPath -Parent
    if ($dir -and -not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    Set-Content -Path $OutputPath -Value $html -Encoding UTF8
}

function Export-ETMFindingsCsv {
    param(
        [Parameter(Mandatory)][array]$Findings,
        [Parameter(Mandatory)][string]$OutputPath
    )
    $Findings | Select-Object title, severity, category, evidence, businessExplanation, remediation, confidence, status |
        Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
}

function Export-ETMFindingsJson {
    param(
        [Parameter(Mandatory)]$ScanResult,
        [Parameter(Mandatory)][string]$OutputPath
    )
    $ScanResult | ConvertTo-Json -Depth 12 | Set-Content -Path $OutputPath -Encoding UTF8
}

Export-ModuleMember -Function 'Export-ETMHtmlReport', 'Export-ETMFindingsCsv', 'Export-ETMFindingsJson'
