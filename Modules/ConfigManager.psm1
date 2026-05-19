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
        [bool]$AuthorizationAcknowledged = $false
    )
    [pscustomobject]@{
        organizationName          = $OrganizationName
        primaryDomain             = $PrimaryDomain
        additionalDomains         = @($AdditionalDomains)
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
    Ensures WPF ItemsSource always gets a list. Fixes ConvertFrom-Json single-element array unwrap.
    #>
    param($InputObject)
    $list = [System.Collections.Generic.List[object]]::new()
    if ($null -eq $InputObject) { return $list }
    if ($InputObject -is [System.Array]) {
        foreach ($item in $InputObject) { if ($null -ne $item) { [void]$list.Add($item) } }
        return $list
    }
    if ($InputObject -is [System.Collections.IList] -and $InputObject -isnot [string]) {
        foreach ($item in $InputObject) { if ($null -ne $item) { [void]$list.Add($item) } }
        return $list
    }
    if ($InputObject -is [System.Collections.IEnumerable] -and $InputObject -isnot [string]) {
        foreach ($item in $InputObject) { if ($null -ne $item) { [void]$list.Add($item) } }
        if ($list.Count -gt 0) { return $list }
    }
    [void]$list.Add($InputObject)
    return $list
}

function Import-ETMScanResultJson {
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path $Path)) { throw "File not found: $Path" }
    $raw = Get-Content -Path $Path -Raw -Encoding UTF8 | ConvertFrom-Json
    foreach ($name in @('findings', 'subdomains', 'webServices', 'threatIntel')) {
        if ($null -ne $raw.PSObject.Properties[$name]) {
            $list = ConvertTo-ETMObjectList $raw.$name
            $raw.PSObject.Properties.Remove($name)
            $raw | Add-Member -NotePropertyName $name -NotePropertyValue $list -Force
        }
    }
    return $raw
}

Export-ModuleMember -Function @(
    'Get-ETMProjectRoot', 'Get-ETMConfigPath', 'Get-ETMAppConfig', 'Save-ETMAppConfig',
    'Import-ETMScopeFile', 'Export-ETMScopeFile', 'New-ETMScopeObject', 'Test-ETMTargetAuthorized',
    'ConvertTo-ETMObjectList', 'Import-ETMScanResultJson'
)
