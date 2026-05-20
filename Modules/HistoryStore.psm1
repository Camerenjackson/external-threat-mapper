# HistoryStore.psm1 - Local scan history (data/history) + optional SQL Server sync

function Get-ETMHistoryDirectory {
    $cfg = Get-ETMAppConfig
    $dirName = if ($cfg.storage.historyDirectory) { $cfg.storage.historyDirectory } else { 'data\history' }
    $path = Join-Path (Get-ETMProjectRoot) $dirName
    if (-not (Test-Path $path)) { New-Item -ItemType Directory -Path $path -Force | Out-Null }
    return $path
}

function Get-ETMHistoryIndexPath {
    Join-Path (Get-ETMHistoryDirectory) 'index.json'
}

function Get-ETMHistoryIndex {
    $path = Get-ETMHistoryIndexPath
    if (-not (Test-Path $path)) {
        return [pscustomobject]@{ scans = @() }
    }
    $raw = Get-Content $path -Raw -Encoding UTF8 | ConvertFrom-Json
    if (-not $raw.scans) { $raw | Add-Member -NotePropertyName scans -NotePropertyValue @() -Force }
    return $raw
}

function Save-ETMHistoryIndex {
    param([Parameter(Mandatory)][psobject]$Index)
    $Index | ConvertTo-Json -Depth 6 | Set-Content -Path (Get-ETMHistoryIndexPath) -Encoding UTF8
}

function Get-ETMSqlSettings {
    $cfg = Get-ETMAppConfig
    $sql = $null
    if ($cfg.storage) { $sql = $cfg.storage.sql }
    if (-not $sql) {
        return [pscustomobject]@{
            enabled = $false; server = 'localhost'; database = 'ExternalThreatMapper'
            integratedSecurity = $true; userId = ''; trustServerCertificate = $true
        }
    }
    return $sql
}

function Get-ETMSqlConnectionString {
    $sql = Get-ETMSqlSettings
    if (-not $sql.enabled) { return $null }
    $builder = New-Object System.Data.SqlClient.SqlConnectionStringBuilder
    $builder['Data Source'] = [string]$sql.server
    $builder['Initial Catalog'] = [string]$sql.database
    $builder['TrustServerCertificate'] = [bool]($sql.trustServerCertificate -ne $false)
    if ($sql.integratedSecurity) {
        $builder['Integrated Security'] = $true
    }
    else {
        $builder['Integrated Security'] = $false
        $builder['User ID'] = [string]$sql.userId
        $pwd = Get-ETMApiSecret -Name 'SqlPassword'
        if (-not $pwd) { throw 'SQL password not configured. Enter it on the SQL Database tab and click Connect.' }
        $builder['Password'] = $pwd
    }
    return $builder.ConnectionString
}

function Initialize-ETMSqlSchema {
    param([Parameter(Mandatory)][string]$ConnectionString)
    $ddl = @"
IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'ETM_Scans')
CREATE TABLE ETM_Scans (
    ScanId NVARCHAR(36) NOT NULL PRIMARY KEY,
    StartedUtc DATETIME2 NOT NULL,
    CompletedUtc DATETIME2 NULL,
    Domain NVARCHAR(255) NULL,
    Organization NVARCHAR(255) NULL,
    ScanMode NVARCHAR(50) NULL,
    Status NVARCHAR(50) NULL,
    TotalScore INT NULL,
    FindingCount INT NULL,
    ResultJson NVARCHAR(MAX) NULL
);
"@
    $conn = New-Object System.Data.SqlClient.SqlConnection($ConnectionString)
    $conn.Open()
    try {
        $cmd = $conn.CreateCommand()
        $cmd.CommandText = $ddl
        [void]$cmd.ExecuteNonQuery()
    }
    finally { $conn.Close() }
}

function Build-ETMSqlConnectionString {
    param(
        [Parameter(Mandatory)][string]$Server,
        [Parameter(Mandatory)][string]$Database,
        [bool]$IntegratedSecurity = $true,
        [string]$UserId = '',
        [string]$PlainPassword = '',
        [bool]$TrustServerCertificate = $true
    )
    $builder = New-Object System.Data.SqlClient.SqlConnectionStringBuilder
    $builder['Data Source'] = $Server
    $builder['Initial Catalog'] = $Database
    $builder['TrustServerCertificate'] = $TrustServerCertificate
    if ($IntegratedSecurity) {
        $builder['Integrated Security'] = $true
    }
    else {
        $builder['Integrated Security'] = $false
        $builder['User ID'] = $UserId
        if (-not $PlainPassword) {
            $PlainPassword = Get-ETMApiSecret -Name 'SqlPassword'
        }
        if (-not $PlainPassword) { throw 'SQL password is required for SQL authentication.' }
        $builder['Password'] = $PlainPassword
    }
    return $builder.ConnectionString
}

function Test-ETMSqlConnectionString {
    param([Parameter(Mandatory)][string]$ConnectionString)
    try {
        $conn = New-Object System.Data.SqlClient.SqlConnection($ConnectionString)
        $conn.Open()
        $conn.Close()
        return [pscustomobject]@{ Ok = $true; Message = 'SQL Server connection successful.' }
    }
    catch {
        return [pscustomobject]@{ Ok = $false; Message = $_.Exception.Message }
    }
}

function Test-ETMSqlConnection {
    try {
        $cs = Get-ETMSqlConnectionString
        if (-not $cs) {
            return [pscustomobject]@{ Ok = $false; Message = 'SQL sync is not enabled. Connect from the SQL Database tab.' }
        }
        return Test-ETMSqlConnectionString -ConnectionString $cs
    }
    catch {
        return [pscustomobject]@{ Ok = $false; Message = $_.Exception.Message }
    }
}

function Connect-ETMSqlServer {
    param(
        [Parameter(Mandatory)][string]$Server,
        [Parameter(Mandatory)][string]$Database,
        [bool]$IntegratedSecurity = $true,
        [string]$UserId = '',
        [string]$PlainPassword = ''
    )
    if ([string]::IsNullOrWhiteSpace($Server) -or [string]::IsNullOrWhiteSpace($Database)) {
        return [pscustomobject]@{ Ok = $false; Message = 'Enter server and database name.' }
    }
    Save-ETMSqlSettings -Enabled $true -Server $Server.Trim() -Database $Database.Trim() `
        -IntegratedSecurity $IntegratedSecurity -UserId $UserId.Trim() -PlainPassword $PlainPassword
    try {
        $cs = Build-ETMSqlConnectionString -Server $Server -Database $Database `
            -IntegratedSecurity $IntegratedSecurity -UserId $UserId -PlainPassword $PlainPassword
    }
    catch {
        return [pscustomobject]@{ Ok = $false; Message = $_.Exception.Message }
    }
    $test = Test-ETMSqlConnectionString -ConnectionString $cs
    if (-not $test.Ok) { return $test }
    try {
        Initialize-ETMSqlSchema -ConnectionString $cs
        return [pscustomobject]@{
            Ok      = $true
            Message = "Connected to $Server / $Database. Database tools are now available."
        }
    }
    catch {
        return [pscustomobject]@{ Ok = $false; Message = "Connected but schema setup failed: $($_.Exception.Message)" }
    }
}

function Get-ETMSqlScanSummaries {
    $cs = Get-ETMSqlConnectionString
    if (-not $cs) { return @() }
    $rows = [System.Collections.Generic.List[object]]::new()
    $conn = New-Object System.Data.SqlClient.SqlConnection($cs)
    $conn.Open()
    try {
        $cmd = $conn.CreateCommand()
        $cmd.CommandText = @"
SELECT TOP 50 ScanId, Domain, Organization, ScanMode, Status, TotalScore, FindingCount, CompletedUtc
FROM ETM_Scans
ORDER BY CompletedUtc DESC;
"@
        $reader = $cmd.ExecuteReader()
        while ($reader.Read()) {
            $rows.Add([pscustomobject]@{
                    scanId       = [string]$reader['ScanId']
                    domain       = [string]$reader['Domain']
                    organization = [string]$reader['Organization']
                    scanMode     = [string]$reader['ScanMode']
                    status       = [string]$reader['Status']
                    totalScore   = if ($reader['TotalScore'] -is [DBNull]) { 0 } else { [int]$reader['TotalScore'] }
                    findingCount = if ($reader['FindingCount'] -is [DBNull]) { 0 } else { [int]$reader['FindingCount'] }
                    completedUtc = if ($reader['CompletedUtc'] -is [DBNull]) { '' } else { ([datetime]$reader['CompletedUtc']).ToString('o') }
                })
        }
        $reader.Close()
    }
    finally { $conn.Close() }
    return ,@($rows.ToArray())
}

function Save-ETMScanToSql {
    param(
        [Parameter(Mandatory)][psobject]$Result,
        [Parameter(Mandatory)][psobject]$Scope
    )
    $cs = Get-ETMSqlConnectionString
    if (-not $cs) { return }
    Initialize-ETMSqlSchema -ConnectionString $cs
    $findings = ConvertTo-ETMObjectList $Result.findings
    $score = $Result.score
    $json = $Result | ConvertTo-Json -Depth 12 -Compress
    $conn = New-Object System.Data.SqlClient.SqlConnection($cs)
    $conn.Open()
    try {
        $cmd = $conn.CreateCommand()
        $cmd.CommandText = @"
MERGE ETM_Scans AS t
USING (SELECT @id AS ScanId) AS s ON t.ScanId = s.ScanId
WHEN MATCHED THEN UPDATE SET CompletedUtc=@done, Status=@st, TotalScore=@sc, FindingCount=@fc, ResultJson=@js
WHEN NOT MATCHED THEN INSERT (ScanId, StartedUtc, CompletedUtc, Domain, Organization, ScanMode, Status, TotalScore, FindingCount, ResultJson)
VALUES (@id, @start, @done, @dom, @org, @mode, @st, @sc, @fc, @js);
"@
        [void]$cmd.Parameters.AddWithValue('@id', [string]$Result.scanId)
        [void]$cmd.Parameters.AddWithValue('@start', (Get-Date).ToUniversalTime())
        [void]$cmd.Parameters.AddWithValue('@done', (Get-Date).ToUniversalTime())
        [void]$cmd.Parameters.AddWithValue('@dom', [string]$Scope.primaryDomain)
        [void]$cmd.Parameters.AddWithValue('@org', [string]$Scope.organizationName)
        [void]$cmd.Parameters.AddWithValue('@mode', [string]$Scope.scanMode)
        [void]$cmd.Parameters.AddWithValue('@st', 'Completed')
        [void]$cmd.Parameters.AddWithValue('@sc', [int]($score.TotalScore))
        [void]$cmd.Parameters.AddWithValue('@fc', [int]$findings.Count)
        [void]$cmd.Parameters.AddWithValue('@js', $json)
        [void]$cmd.ExecuteNonQuery()
    }
    finally { $conn.Close() }
}

function Save-ETMScanHistory {
    param(
        [Parameter(Mandatory)][psobject]$Result,
        [Parameter(Mandatory)][psobject]$Scope
    )
    $histDir = Get-ETMHistoryDirectory
    $scanId = [string]$Result.scanId
    if ([string]::IsNullOrWhiteSpace($scanId)) { $scanId = [guid]::NewGuid().ToString() }

    $findings = ConvertTo-ETMObjectList $Result.findings
    $intel = ConvertTo-ETMObjectList $Result.threatIntel
    $score = $Result.score
    $payload = [pscustomobject]@{
        scanId      = $scanId
        savedUtc    = (Get-Date).ToUniversalTime().ToString('o')
        scope       = $Scope
        score       = $score
        findings    = $findings
        subdomains  = (ConvertTo-ETMObjectList $Result.subdomains)
        webServices = (ConvertTo-ETMObjectList $Result.webServices)
        threatIntel = $intel
    }
    $file = Join-Path $histDir "$scanId.json"
    $payload | ConvertTo-Json -Depth 14 | Set-Content -Path $file -Encoding UTF8

    $index = Get-ETMHistoryIndex
    $list = [System.Collections.ArrayList]@()
    foreach ($s in @($index.scans)) {
        if ($s.scanId -ne $scanId) { [void]$list.Add($s) }
    }
    [void]$list.Insert(0, [pscustomobject]@{
            scanId       = $scanId
            domain       = $Scope.primaryDomain
            organization = $Scope.organizationName
            scanMode     = $Scope.scanMode
            startedUtc   = $payload.savedUtc
            totalScore   = if ($score) { $score.TotalScore } else { 0 }
            findingCount = $findings.Count
            file         = "$scanId.json"
        })
    $index.scans = $list
    Save-ETMHistoryIndex -Index $index

    try {
        Save-ETMScanToSql -Result $Result -Scope $Scope
        Write-ETMLog -Level AUDIT -Message 'Scan synced to SQL' -Data @{ scanId = $scanId }
    }
    catch {
        Write-ETMLog -Level WARN -Message 'SQL sync skipped' -Data @{ error = $_.Exception.Message }
    }

    return $scanId
}

function Get-ETMScanHistoryList {
    $index = Get-ETMHistoryIndex
    $rows = @($index.scans)
    return $rows | Sort-Object { $_.startedUtc } -Descending
}

function Import-ETMScanFromHistory {
    param([Parameter(Mandatory)][string]$ScanId)
    $path = Join-Path (Get-ETMHistoryDirectory) "$ScanId.json"
    if (-not (Test-Path $path)) { throw "History file not found: $ScanId" }
    return Import-ETMScanResultJson -Path $path
}

function Clear-ETMScanHistory {
    param([switch]$KeepSql)
    $histDir = Get-ETMHistoryDirectory
    Get-ChildItem -Path $histDir -Filter '*.json' | Remove-Item -Force -ErrorAction SilentlyContinue
    Save-ETMHistoryIndex -Index ([pscustomobject]@{ scans = @() })
    if (-not $KeepSql) {
        try {
            $cs = Get-ETMSqlConnectionString
            if ($cs) {
                $conn = New-Object System.Data.SqlClient.SqlConnection($cs)
                $conn.Open()
                try {
                    $cmd = $conn.CreateCommand()
                    $cmd.CommandText = 'DELETE FROM ETM_Scans'
                    [void]$cmd.ExecuteNonQuery()
                }
                finally { $conn.Close() }
            }
        }
        catch { }
    }
    Write-ETMLog -Level AUDIT -Message 'Local scan history cleared'
}

function Save-ETMSqlSettings {
    param(
        [bool]$Enabled,
        [string]$Server,
        [string]$Database,
        [bool]$IntegratedSecurity,
        [string]$UserId,
        [string]$PlainPassword
    )
    $cfg = Get-ETMAppConfig
    if (-not $cfg.storage) { $cfg | Add-Member -NotePropertyName storage -NotePropertyValue (@{}) -Force }
    if (-not $cfg.storage.sql) {
        $cfg.storage | Add-Member -NotePropertyName sql -NotePropertyValue (@{}) -Force
    }
    $cfg.storage.sql.enabled = $Enabled
    $cfg.storage.sql.server = $Server
    $cfg.storage.sql.database = $Database
    $cfg.storage.sql.integratedSecurity = $IntegratedSecurity
    $cfg.storage.sql.userId = $UserId
    $cfg.storage.sql.trustServerCertificate = $true
    if ($PlainPassword) {
        Set-ETMApiCredential -Name 'SqlPassword' -Value $PlainPassword
    }
    Save-ETMAppConfig -Config $cfg
}

Export-ModuleMember -Function @(
    'Get-ETMHistoryDirectory', 'Save-ETMScanHistory', 'Get-ETMScanHistoryList',
    'Import-ETMScanFromHistory', 'Clear-ETMScanHistory', 'Test-ETMSqlConnection',
    'Test-ETMSqlConnectionString', 'Connect-ETMSqlServer', 'Build-ETMSqlConnectionString',
    'Save-ETMSqlSettings', 'Get-ETMSqlSettings', 'Initialize-ETMSqlSchema', 'Get-ETMSqlScanSummaries'
)
