# ConfigManager.psm1 — application and scope configuration

function Get-ETMProjectRoot {
    if ($script:ETMRoot) { return $script:ETMRoot }
    if ($env:ETM_APP_ROOT -and (Test-Path $env:ETM_APP_ROOT)) {
        $script:ETMRoot = $env:ETM_APP_ROOT
        return $script:ETMRoot
    }
    $script:ETMRoot = Split-Path $PSScriptRoot -Parent
    return $script:ETMRoot
}

function Get-ETMConfigPath {
    $root = Get-ETMProjectRoot
    $user = Join-Path $root 'config\config.json'
    if (Test-Path $user) { return $user }
    return Join-Path $root 'config\config.example.json'
}

function Get-ETMAppConfig {
    $path = Get-ETMConfigPath
    if (-not (Test-Path $path)) {
        throw "Configuration not found: $path"
    }
    $raw = Get-Content -Path $path -Raw -Encoding UTF8 | ConvertFrom-Json
    return $raw
}

function Save-ETMAppConfig {
    param([Parameter(Mandatory)][psobject]$Config)
    $root = Get-ETMProjectRoot
    $dir = Join-Path $root 'config'
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    $path = Join-Path $dir 'config.json'
    $Config | ConvertTo-Json -Depth 10 | Set-Content -Path $path -Encoding UTF8
}

function Import-ETMScopeFile {
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path $Path)) { throw "Scope file not found: $Path" }
    return Get-Content -Path $Path -Raw -Encoding UTF8 | ConvertFrom-Json
}

function Export-ETMScopeFile {
    param(
        [Parameter(Mandatory)][psobject]$Scope,
        [Parameter(Mandatory)][string]$Path
    )
    $Scope | ConvertTo-Json -Depth 8 | Set-Content -Path $Path -Encoding UTF8
}

function New-ETMScopeObject {
    param(
        [string]$OrganizationName = '',
        [string]$PrimaryDomain = '',
        [string[]]$AdditionalDomains = @(),
        [string[]]$ApprovedCidrs = @(),
        [string[]]$ExcludedDomains = @(),
        [string[]]$ExcludedIps = @(),
        [ValidateSet('PassiveOnly', 'CorporateSafe', 'FullAuthorized')]
        [string]$ScanMode = 'PassiveOnly',
        [bool]$AuthorizationAcknowledged = $false,
        [string[]]$BreachCheckEmails = @()
    )
    [pscustomobject]@{
        organizationName          = $OrganizationName
        primaryDomain             = $PrimaryDomain
        additionalDomains         = @($AdditionalDomains)
        breachCheckEmails         = @($BreachCheckEmails | Where-Object { $_ -match '@' })
        approvedCidrs             = @($ApprovedCidrs)
        excludedDomains           = @($ExcludedDomains)
        excludedIps               = @($ExcludedIps)
        scanMode                  = $ScanMode
        authorizationAcknowledged = $AuthorizationAcknowledged
        createdUtc                = (Get-Date).ToUniversalTime().ToString('o')
    }
}

function Test-ETMTargetAuthorized {
    param(
        [Parameter(Mandatory)][psobject]$Scope
    )
    if (-not $Scope.authorizationAcknowledged) {
        return [pscustomobject]@{ Ok = $false; Message = 'Authorization acknowledgment is required.' }
    }
    if ([string]::IsNullOrWhiteSpace($Scope.primaryDomain) -and [string]::IsNullOrWhiteSpace($Scope.organizationName)) {
        return [pscustomobject]@{ Ok = $false; Message = 'Provide an organization name and/or primary domain.' }
    }
    return [pscustomobject]@{ Ok = $true; Message = 'Scope validated.' }
}

function ConvertTo-ETMObjectList {
    <#
    .SYNOPSIS
    Ensures collections are real lists. PSCustomObject implements IEnumerable but must stay one row.
    #>
    param($InputObject)
    $list = [System.Collections.Generic.List[object]]::new()
    if ($null -eq $InputObject) { return $list }

    if ($InputObject -is [string]) {
        [void]$list.Add($InputObject)
        return $list
    }

  # Never enumerate a scan row object (fixes threat-intel / history load ItemsSource errors).
    if ($InputObject -is [System.Management.Automation.PSCustomObject]) {
        [void]$list.Add($InputObject)
        return $list
    }

    if ($InputObject -is [System.Array]) {
        foreach ($item in $InputObject) { if ($null -ne $item) { [void]$list.Add($item) } }
        return $list
    }

    if ($InputObject -is [System.Collections.IList]) {
        foreach ($item in $InputObject) { if ($null -ne $item) { [void]$list.Add($item) } }
        return $list
    }

    if ($InputObject -is [System.Collections.Generic.List[object]]) {
        foreach ($item in $InputObject) { if ($null -ne $item) { [void]$list.Add($item) } }
        return $list
    }

    if ($InputObject -is [System.Collections.IEnumerable]) {
        foreach ($item in $InputObject) { if ($null -ne $item) { [void]$list.Add($item) } }
        if ($list.Count -gt 0) { return $list }
    }

    [void]$list.Add($InputObject)
    return $list
}

function Register-ETMDataGridColumnFilter {
    param([Parameter(Mandatory)]$Grid)
    if ($Grid.Tag -eq 'ETMColumnFilter') { return }
    $Grid.Tag = 'ETMColumnFilter'
    $Grid.Add_AutoGeneratingColumn({
        param($sender, $e)
        if ($e.PropertyName -match '^_') { $e.Cancel = $true }
    })
}

function Set-ETMDataGridSource {
    <#
    .SYNOPSIS
    Binds rows to a WPF DataGrid (always a list, never a single PSCustomObject).
    #>
    param(
        [Parameter(Mandatory)]$Grid,
        $Items
    )
    Register-ETMDataGridColumnFilter -Grid $Grid
    $list = ConvertTo-ETMObjectList $Items
    $Grid.ItemsSource = $null
    $bound = New-Object System.Collections.ArrayList
    foreach ($item in $list) { [void]$bound.Add($item) }
    $Grid.ItemsSource = $bound
}

function ConvertTo-ETMObjectArray {
    <#
    .SYNOPSIS
    Returns a PowerShell array safe on 5.1 (do not use New-Object object[] - it throws).
    #>
    param($InputObject)
    $list = ConvertTo-ETMObjectList $InputObject
    if ($list.Count -eq 0) { return @() }
    return @($list.ToArray())
}

function Normalize-ETMScanResult {
    <#
    .SYNOPSIS
    Normalizes scan payloads for UI/history. Collections stored as ArrayList to avoid single-item unwrap.
    #>
    param($Result)
    if (-not $Result) { return $null }

    $findings = New-Object System.Collections.ArrayList
    foreach ($x in (ConvertTo-ETMObjectList $Result.findings)) { [void]$findings.Add($x) }
    $subs = New-Object System.Collections.ArrayList
    foreach ($x in (ConvertTo-ETMObjectList $Result.subdomains)) { [void]$subs.Add($x) }
    $web = New-Object System.Collections.ArrayList
    foreach ($x in (ConvertTo-ETMObjectList $Result.webServices)) { [void]$web.Add($x) }
    $intel = New-Object System.Collections.ArrayList
    foreach ($x in (ConvertTo-ETMObjectList $Result.threatIntel)) { [void]$intel.Add($x) }

    return [pscustomobject]@{
        scanId      = $Result.scanId
        score       = $Result.score
        scope       = $Result.scope
        savedUtc    = $Result.savedUtc
        findings    = $findings
        subdomains  = $subs
        webServices = $web
        threatIntel = $intel
    }
}

function Import-ETMScanResultJson {
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path $Path)) { throw "File not found: $Path" }
    $raw = Get-Content -Path $Path -Raw -Encoding UTF8 | ConvertFrom-Json
    return Normalize-ETMScanResult $raw
}

Export-ModuleMember -Function @(
    'Get-ETMProjectRoot', 'Get-ETMConfigPath', 'Get-ETMAppConfig', 'Save-ETMAppConfig',
    'Import-ETMScopeFile', 'Export-ETMScopeFile', 'New-ETMScopeObject', 'Test-ETMTargetAuthorized',
    'ConvertTo-ETMObjectList', 'ConvertTo-ETMObjectArray', 'Register-ETMDataGridColumnFilter', 'Set-ETMDataGridSource', 'Normalize-ETMScanResult', 'Import-ETMScanResultJson'
)
