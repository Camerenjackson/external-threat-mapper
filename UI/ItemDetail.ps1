# ItemDetail.ps1 — drill-down detail panel for findings and assets

function New-ETMDetailLabel {
    param([string]$Text)
    $tb = New-Object System.Windows.Controls.TextBlock
    $tb.Text = $Text.ToUpper()
    $tb.Foreground = (New-ETMUiBrush '#7D8DA6')
    $tb.FontSize = 10
    $tb.FontWeight = [System.Windows.FontWeights]::SemiBold
    $tb.Margin = '0,14,0,4'
    return $tb
}

function New-ETMDetailValue {
    param([string]$Text, [string]$Color = '#EEF2F8')
    $tb = New-Object System.Windows.Controls.TextBlock
    $tb.Text = if ([string]::IsNullOrWhiteSpace($Text)) { '—' } else { $Text }
    $tb.Foreground = (New-ETMUiBrush $Color)
    $tb.TextWrapping = [System.Windows.TextWrapping]::Wrap
    $tb.FontSize = 13
    $tb.Margin = '0,0,0,2'
    return $tb
}

function Get-ETMFindingPlatformLabel {
    param($Finding)
    switch -Regex ($Finding.category) {
        'typosquat|brand' { return 'Passive DNS + HTTP title check (no login attempts)' }
        'subdomain' { return 'Certificate transparency / passive DNS enumeration' }
        'cloud' { return 'Cloud storage HEAD probe (CorporateSafe+ modes)' }
        'github' { return 'GitHub Search API (metadata only)' }
        'threat-intel' { return 'Third-party threat intelligence API' }
        'credential-breach' { return 'Have I Been Pwned (domain-verified organizational search)' }
        'certificate|tls' { return 'TLS / certificate inspection' }
        default { return 'External Threat Mapper scan engine' }
    }
}

function Get-ETMSeverityBrush {
    param([string]$Severity)
    switch ($Severity) {
        'Critical' { return '#F85149' }
        'High' { return '#F85149' }
        'Medium' { return '#F0B429' }
        'Low' { return '#4C9AFF' }
        default { return '#8B9BB4' }
    }
}

function Add-ETMDetailFields {
    param(
        [Parameter(Mandatory)]$Panel,
        [array]$Fields
    )
    foreach ($f in $Fields) {
        if ($null -eq $f -or [string]::IsNullOrWhiteSpace([string]$f.Value)) { continue }
        [void]$Panel.Children.Add((New-ETMDetailLabel -Text $f.Label))
        $color = if ($f.Color) { $f.Color } else { '#EEF2F8' }
        [void]$Panel.Children.Add((New-ETMDetailValue -Text ([string]$f.Value) -Color $color))
    }
}

function Resolve-ETMDetailItem {
    param($Row)
    if ($Row._kind -and $Row._data) {
        return @{ Kind = [string]$Row._kind; Data = $Row._data }
    }
    if ($Row.title -and $Row.severity) {
        return @{ Kind = 'finding'; Data = $Row }
    }
    if ($Row.provider -and $Row.asset) {
        return @{ Kind = 'intel'; Data = $Row }
    }
    if ($Row.hostname -and $Row.riskScore -ne $null) {
        return @{ Kind = 'subdomain'; Data = $Row }
    }
    if ($Row.url -and $Row.statusCode -ne $null) {
        return @{ Kind = 'web'; Data = $Row }
    }
    if ($Row.type -and $Row.name) {
        return @{ Kind = 'discovery'; Data = $Row }
    }
    return @{ Kind = 'unknown'; Data = $Row }
}

function Show-ETMItemDetail {
    param(
        [Parameter(Mandatory)][scriptblock]$GetControl,
        $Row
    )
    if (-not $Row) { return }
    $resolved = Resolve-ETMDetailItem -Row $Row
    $kind = $resolved.Kind
    $data = $resolved.Data

    $panel = & $GetControl 'DetailFieldsPanel'
    $panel.Children.Clear()

    $title = & $GetControl 'DetailTitle'
    $subtitle = & $GetControl 'DetailSubtitle'
    $fields = [System.Collections.Generic.List[object]]::new()

    switch ($kind) {
        'finding' {
            $f = $data
            $title.Text = [string]$f.title
            $subtitle.Text = "Security finding | $($f.category)"
            $mitre = $null
            if ($f.PSObject.Properties['mitre'] -and $f.mitre) { $mitre = $f.mitre }
            elseif (Get-Command Get-ETMMitreMappingForFinding -ErrorAction SilentlyContinue) {
                $mitre = Get-ETMMitreMappingForFinding -Finding $f
            }
            [void]$fields.Add(@{ Label = 'Risk level'; Value = $f.severity; Color = (Get-ETMSeverityBrush $f.severity) })
            [void]$fields.Add(@{ Label = 'Category'; Value = $f.category })
            [void]$fields.Add(@{ Label = 'How it was found'; Value = (Get-ETMFindingPlatformLabel $f) })
            [void]$fields.Add(@{ Label = 'Evidence'; Value = $f.evidence })
            [void]$fields.Add(@{ Label = 'Business risk'; Value = $f.businessExplanation })
            [void]$fields.Add(@{ Label = 'Technical detail'; Value = $f.technicalExplanation })
            [void]$fields.Add(@{ Label = 'Remediation'; Value = $f.remediation; Color = '#3DD68C' })
            [void]$fields.Add(@{ Label = 'Confidence'; Value = $f.confidence })
            [void]$fields.Add(@{ Label = 'Status'; Value = $f.status })
            if ($mitre) {
                $mitreLine = '{0} - {1}' -f $mitre.techniqueId, $mitre.techniqueName
                [void]$fields.Add(@{ Label = 'MITRE ATT&CK'; Value = $mitreLine })
                [void]$fields.Add(@{ Label = 'Tactic'; Value = $mitre.tactic })
                [void]$fields.Add(@{ Label = 'Defensive note'; Value = $mitre.defensiveRecommendation })
            }
        }
        'subdomain' {
            $s = $data
            $title.Text = [string]$s.hostname
            $subtitle.Text = 'Discovered asset | Subdomain'
            $riskLabel = if ($s.riskScore -ge 70) { 'High' } elseif ($s.riskScore -ge 40) { 'Medium' } else { 'Low' }
            [void]$fields.Add(@{ Label = 'Risk score'; Value = ('{0} / 100' -f $s.riskScore); Color = (Get-ETMSeverityBrush $riskLabel) })
            [void]$fields.Add(@{ Label = 'IP address'; Value = $s.ip })
            [void]$fields.Add(@{ Label = 'Discovery source'; Value = $s.source })
            [void]$fields.Add(@{ Label = 'How it was found'; Value = 'Passive subdomain enumeration (CT logs, DNS hints)' })
            [void]$fields.Add(@{ Label = 'Platform'; Value = 'Certificate Transparency / passive DNS' })
        }
        'web' {
            $w = $data
            $title.Text = [string]$w.hostname
            $subtitle.Text = 'Discovered asset | Web service'
            [void]$fields.Add(@{ Label = 'URL'; Value = $w.url })
            [void]$fields.Add(@{ Label = 'HTTP status'; Value = [string]$w.statusCode })
            [void]$fields.Add(@{ Label = 'Page title'; Value = $w.title })
            [void]$fields.Add(@{ Label = 'How it was found'; Value = 'Safe HTTP probe (GET/HEAD, no auth)' })
            [void]$fields.Add(@{ Label = 'Platform'; Value = 'ETM web probe module' })
        }
        'intel' {
            $i = $data
            $title.Text = '{0} - {1}' -f $i.provider, $i.asset
            $subtitle.Text = "Threat intel | $($i.assetType)"
            [void]$fields.Add(@{ Label = 'Severity'; Value = $i.severity; Color = (Get-ETMSeverityBrush $i.severity) })
            [void]$fields.Add(@{ Label = 'Summary'; Value = $i.summary })
            [void]$fields.Add(@{ Label = 'Detail'; Value = $i.detail })
            [void]$fields.Add(@{ Label = 'Source platform'; Value = $i.source })
            [void]$fields.Add(@{ Label = 'How it was found'; Value = "API enrichment via $($i.provider)" })
        }
        'discovery' {
            $d = $data
            if ($d._kind -and $d._data) {
                Show-ETMItemDetail -GetControl $GetControl -Row $d
                return
            }
            $title.Text = [string]$d.name
            $subtitle.Text = "Asset | $($d.type)"
            [void]$fields.Add(@{ Label = 'Type'; Value = $d.type })
            [void]$fields.Add(@{ Label = 'Detail'; Value = $d.detail })
            [void]$fields.Add(@{ Label = 'Source'; Value = $d.source })
        }
        default {
            $title.Text = 'Item details'
            $subtitle.Text = ''
            $props = $data.PSObject.Properties | ForEach-Object { "$($_.Name): $($_.Value)" }
            [void]$fields.Add(@{ Label = 'Properties'; Value = ($props -join "`n") })
        }
    }

    Add-ETMDetailFields -Panel $panel -Fields $fields
    (& $GetControl 'DetailOverlay').Visibility = 'Visible'
}

function Hide-ETMItemDetail {
    param([Parameter(Mandatory)][scriptblock]$GetControl)
    (& $GetControl 'DetailOverlay').Visibility = 'Collapsed'
}

function Register-ETMDataGridDetailView {
    param(
        [Parameter(Mandatory)][scriptblock]$GetControl,
        [Parameter(Mandatory)]$Grid,
        [scriptblock]$OnLog
    )
    if (-not $Grid) { return }
    $Grid.SelectionMode = [System.Windows.Controls.DataGridSelectionMode]::Single
    $getCtrl = $GetControl
    $Grid.Add_MouseDoubleClick({
        try {
            if ($this.SelectedItem) {
                Show-ETMItemDetail -GetControl $getCtrl -Row $this.SelectedItem
            }
        }
        catch {
            if ($OnLog) { & $OnLog "Detail view: $($_.Exception.Message)" }
        }
    })
}
