# MitreMapping.psm1 — defensive MITRE ATT&CK context for findings

$script:ETMTechniqueCatalog = @(
    @{ Id = 'T1590'; Name = 'Gather Victim Network Information'; Tactic = 'Reconnaissance' }
    @{ Id = 'T1590.002'; Name = 'DNS'; Tactic = 'Reconnaissance' }
    @{ Id = 'T1595'; Name = 'Active Scanning'; Tactic = 'Reconnaissance' }
    @{ Id = 'T1595.002'; Name = 'Vulnerability Scanning'; Tactic = 'Reconnaissance' }
    @{ Id = 'T1593'; Name = 'Search Open Websites/Domains'; Tactic = 'Reconnaissance' }
    @{ Id = 'T1596'; Name = 'Search Open Technical Databases'; Tactic = 'Reconnaissance' }
    @{ Id = 'T1580'; Name = 'Cloud Infrastructure Discovery'; Tactic = 'Discovery' }
    @{ Id = 'T1583'; Name = 'Acquire Infrastructure'; Tactic = 'Resource Development' }
    @{ Id = 'T1078'; Name = 'Valid Accounts'; Tactic = 'Initial Access' }
)

function Get-ETMMitreMappingForFinding {
    param([Parameter(Mandatory)][psobject]$Finding)

    $map = switch -Regex ($Finding.category) {
        'subdomain|dns' { 'T1590.002' }
        'typosquat|brand' { 'T1583' }
        'github|code' { 'T1593' }
        'cloud|bucket|storage' { 'T1580' }
        'certificate|tls' { 'T1596' }
        'login|portal|admin' { 'T1078' }
        'web|http' { 'T1593' }
        default { 'T1590' }
    }

    $tech = $script:ETMTechniqueCatalog | Where-Object { $_.Id -eq $map } | Select-Object -First 1
    if (-not $tech) { $tech = $script:ETMTechniqueCatalog[0] }

    [pscustomobject]@{
        techniqueId           = $tech.Id
        techniqueName         = $tech.Name
        tactic                = $tech.Tactic
        explanation           = "External visibility of this finding aligns with $($tech.Name) from an attacker reconnaissance perspective."
        defensiveRecommendation = 'Reduce unnecessary external exposure, monitor DNS/TLS changes, and validate detections for reconnaissance activity.'
        calderaEmulationIdea  = "Safe emulation: passive discovery lab using $($tech.Id) against authorized test agents only - no exploitation."
    }
}

function Get-ETMMitreSummary {
    param([Parameter(Mandatory)][array]$Findings)
    $rows = foreach ($f in $Findings) {
        $m = Get-ETMMitreMappingForFinding -Finding $f
        [pscustomobject]@{
            Finding = $f.title
            $($m.techniqueId) = $m.techniqueName
            Tactic = $m.tactic
        }
    }
    @($rows | Group-Object Tactic | ForEach-Object {
        [pscustomobject]@{ Tactic = $_.Name; Count = $_.Count }
    })
}

Export-ModuleMember -Function 'Get-ETMMitreMappingForFinding', 'Get-ETMMitreSummary', 'Get-ETMTechniqueCatalog'
