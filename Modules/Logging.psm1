# Logging.psm1 — structured file logging (no secrets)

$script:ETMLogPath = $null

function Initialize-ETMLogging {
    param([string]$LogDirectory)
    if (-not $LogDirectory) {
        $proj = if (Get-Command Get-ETMProjectRoot -ErrorAction SilentlyContinue) {
            Get-ETMProjectRoot
        } else { Split-Path (Split-Path $PSScriptRoot -Parent) -Parent }
        $LogDirectory = Join-Path $proj 'logs'
    }
    if (-not (Test-Path $LogDirectory)) {
        New-Item -ItemType Directory -Path $LogDirectory -Force | Out-Null
    }
    $script:ETMLogPath = Join-Path $LogDirectory ("etm_{0:yyyyMMdd}.log" -f (Get-Date))
}

function Write-ETMLog {
    param(
        [ValidateSet('INFO', 'WARN', 'ERROR', 'DEBUG', 'AUDIT')]
        [string]$Level = 'INFO',
        [Parameter(Mandatory)][string]$Message,
        [hashtable]$Data
    )
    if (-not $script:ETMLogPath) { Initialize-ETMLogging }
    $line = "[{0:yyyy-MM-dd HH:mm:ss}] [{1}] {2}" -f (Get-Date), $Level, $Message
    if ($Data) {
        $safe = $Data.Clone()
        foreach ($k in @('apiKey', 'token', 'secret', 'password')) {
            if ($safe.ContainsKey($k)) { $safe[$k] = '***REDACTED***' }
        }
        $line += " | " + ($safe | ConvertTo-Json -Compress)
    }
    Add-Content -Path $script:ETMLogPath -Value $line -Encoding UTF8
}

Export-ModuleMember -Function 'Initialize-ETMLogging', 'Write-ETMLog'
