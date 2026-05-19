# Database.psm1 — SQLite with JSON fallback storage

function Initialize-ETMDatabase {
    $root = Get-ETMProjectRoot
    $dataDir = Join-Path $root 'data'
    if (-not (Test-Path $dataDir)) { New-Item -ItemType Directory -Path $dataDir -Force | Out-Null }

    $dbPath = Join-Path $dataDir 'etm.db'
    $jsonPath = Join-Path $dataDir 'etm-store.json'

    if (Get-Command Initialize-ETMSqlite -ErrorAction SilentlyContinue) {
        return Initialize-ETMSqlite -DbPath $dbPath
    }

    if (-not (Test-Path $jsonPath)) {
        $empty = @{
            scans     = @()
            subdomains = @()
            webServices = @()
            findings  = @()
            typosquats = @()
            githubHits = @()
            cloudHits  = @()
        }
        $empty | ConvertTo-Json -Depth 6 | Set-Content -Path $jsonPath -Encoding UTF8
    }
    return [pscustomobject]@{ Engine = 'Json'; Path = $jsonPath }
}

function Get-ETMJsonStore {
    $root = Get-ETMProjectRoot
    $jsonPath = Join-Path $root 'data\etm-store.json'
    if (-not (Test-Path $jsonPath)) { Initialize-ETMDatabase | Out-Null }
    return Get-Content $jsonPath -Raw -Encoding UTF8 | ConvertFrom-Json
}

function Save-ETMJsonStore {
    param([Parameter(Mandatory)][psobject]$Store)
    $root = Get-ETMProjectRoot
    $jsonPath = Join-Path $root 'data\etm-store.json'
    $Store | ConvertTo-Json -Depth 12 | Set-Content -Path $jsonPath -Encoding UTF8
}

function Add-ETMScanRecord {
    param(
        [Parameter(Mandatory)][string]$ScanId,
        [Parameter(Mandatory)][psobject]$Scope,
        [string]$Status = 'Completed'
    )
    $store = Get-ETMJsonStore
    $record = [pscustomobject]@{
        scanId     = $ScanId
        startedUtc = (Get-Date).ToUniversalTime().ToString('o')
        status     = $Status
        scope      = $Scope
    }
    $list = [System.Collections.ArrayList]@()
    if ($store.scans) { $store.scans | ForEach-Object { [void]$list.Add($_) } }
    [void]$list.Add($record)
    $store.scans = $list
    Save-ETMJsonStore -Store $store
}

function Add-ETMSubdomainRecords {
    param(
        [Parameter(Mandatory)][string]$ScanId,
        [array]$Records = @()
    )
    if (-not $Records -or $Records.Count -eq 0) { return }
    $store = Get-ETMJsonStore
    $list = [System.Collections.ArrayList]@()
    if ($store.subdomains) { $store.subdomains | ForEach-Object { [void]$list.Add($_) } }
    foreach ($r in $Records) {
        $r | Add-Member -NotePropertyName scanId -NotePropertyValue $ScanId -Force
        [void]$list.Add($r)
    }
    $store.subdomains = $list
    Save-ETMJsonStore -Store $store
}

function Add-ETMFindingRecords {
    param(
        [Parameter(Mandatory)][string]$ScanId,
        [array]$Findings = @()
    )
    if (-not $Findings -or $Findings.Count -eq 0) { return }
    $store = Get-ETMJsonStore
    $list = [System.Collections.ArrayList]@()
    if ($store.findings) { $store.findings | ForEach-Object { [void]$list.Add($_) } }
    foreach ($f in $Findings) {
        $f | Add-Member -NotePropertyName scanId -NotePropertyValue $ScanId -Force
        [void]$list.Add($f)
    }
    $store.findings = $list
    Save-ETMJsonStore -Store $store
}

function Get-ETMFindingsForScan {
    param([Parameter(Mandatory)][string]$ScanId)
    $store = Get-ETMJsonStore
    @($store.findings | Where-Object { $_.scanId -eq $ScanId })
}

function Get-ETMSubdomainsForScan {
    param([Parameter(Mandatory)][string]$ScanId)
    $store = Get-ETMJsonStore
    @($store.subdomains | Where-Object { $_.scanId -eq $ScanId })
}

Export-ModuleMember -Function @(
    'Initialize-ETMDatabase', 'Get-ETMJsonStore', 'Save-ETMJsonStore',
    'Add-ETMScanRecord', 'Add-ETMSubdomainRecords', 'Add-ETMFindingRecords',
    'Get-ETMFindingsForScan', 'Get-ETMSubdomainsForScan'
)
