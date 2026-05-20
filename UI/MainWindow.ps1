# MainWindow.ps1 - Modern sidebar UI (UiSafe.ps1 provides Register-ETMUiClick error wrappers)
$uiScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
. (Join-Path $uiScriptDir 'UiSafe.ps1')
. (Join-Path $uiScriptDir 'ItemDetail.ps1')

function Show-ETMMainWindow {
    Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase

    $xamlPath = Join-Path (Get-ETMProjectRoot) 'UI\MainWindow.xaml'
    [xml]$xaml = Get-Content -Path $xamlPath -Raw -Encoding UTF8
    $reader = New-Object System.Xml.XmlNodeReader $xaml
    $window = [Windows.Markup.XamlReader]::Load($reader)

    $get = { param($n) $window.FindName($n) }

    $iconPath = Join-Path (Get-ETMProjectRoot) 'assets\etm-icon.png'
    if (Test-Path $iconPath) {
        $uri = [Uri]::new((Resolve-Path $iconPath).Path)
        $frame = [Windows.Media.Imaging.BitmapFrame]::Create($uri)
        $window.Icon = $frame
        $logo = & $get 'ImgSidebarLogo'
        if ($logo) { $logo.Source = $frame }
    }

    $pages = @{
        Dashboard   = $window.FindName('PageDashboard')
        Target      = $window.FindName('PageTarget')
        Discovery   = $window.FindName('PageDiscovery')
        Intel       = $window.FindName('PageIntel')
        Integrations = $window.FindName('PageIntegrations')
        Sql         = $window.FindName('PageSql')
        History     = $window.FindName('PageHistory')
        Reports     = $window.FindName('PageReports')
    }
    $titles = @{
        Dashboard   = 'Dashboard'
        Target      = 'Target scope'
        Discovery   = 'Discovery'
        Intel       = 'Threat intelligence'
        Integrations = 'API integrations'
        Sql         = 'SQL Database'
        History     = 'Local scan history'
        Reports     = 'Reports and activity'
    }

    $state = @{
        config      = Get-ETMAppConfig
        scope       = $null
        lastResult  = $null
        cancelScan  = $false
        scanRunning = $false
        isDemo      = $false
        scanJob     = $null
        scanTimer   = $null
        cancelSync  = $null
        activeScanScope = $null
        activeScanLive  = $null
        sqlConnected = $false
        sqlConnectJob = $null
        sqlConnectTimer = $null
        lastLiveVersion = -1
        discoveryRows = @()
        apiFields   = @{}
    }

    function Show-Page {
        param([string]$Key)
        foreach ($k in $pages.Keys) {
            $pages[$k].Visibility = if ($k -eq $Key) { 'Visible' } else { 'Collapsed' }
        }
        (& $get 'TxtPageTitle').Text = $titles[$Key]
    }

    function Append-LogUi {
        param([string]$Line)
        $tb = & $get 'TxtLogs'
        $tb.AppendText("$(Get-Date -Format 'HH:mm:ss')  $Line`n")
        $tb.ScrollToEnd()
    }

    $uiLog = { param($line) Append-LogUi $line }
    Initialize-ETMUiSafety -Window $window -OnLog $uiLog

    function Get-BreachCheckEmailsFromForm {
        $raw = (& $get 'TxtBreachEmails').Text
        if ([string]::IsNullOrWhiteSpace($raw)) { return @() }
        @($raw -split '[,;\r\n]+' | ForEach-Object { $_.Trim() } | Where-Object { $_ -match '@' })
    }

    function Get-ScopeFromForm {
        $modeItem = & $get 'CmbScanMode'
        $mode = if ($modeItem.SelectedItem) { $modeItem.SelectedItem.Content } else { 'PassiveOnly' }
        New-ETMScopeObject -OrganizationName (& $get 'TxtOrg').Text.Trim() `
            -PrimaryDomain (& $get 'TxtDomain').Text.Trim() `
            -ScanMode $mode `
            -AuthorizationAcknowledged (& $get 'ChkAuthorized').IsChecked `
            -BreachCheckEmails (Get-BreachCheckEmailsFromForm)
    }

    function Set-BreachCheckEmailsOnForm {
        param([string[]]$Emails)
        $tb = & $get 'TxtBreachEmails'
        if (-not $tb) { return }
        $tb.Text = if ($Emails -and $Emails.Count -gt 0) { ($Emails -join ', ') } else { '' }
    }

    function Build-DiscoveryRows {
        param($result)
        $rows = [System.Collections.Generic.List[object]]::new()
        foreach ($s in (ConvertTo-ETMObjectList $result.subdomains)) {
            $rows.Add([pscustomobject]@{
                    type   = 'Subdomain'
                    name   = $s.hostname
                    detail = "IP: $($s.ip); risk: $($s.riskScore)"
                    source = $s.source
                    _kind  = 'subdomain'
                    _data  = $s
                })
        }
        foreach ($w in (ConvertTo-ETMObjectList $result.webServices)) {
            $rows.Add([pscustomobject]@{
                    type   = 'Web'
                    name   = $w.hostname
                    detail = "$($w.url) [$($w.statusCode)]"
                    source = 'http-probe'
                    _kind  = 'web'
                    _data  = $w
                })
        }
        foreach ($f in (ConvertTo-ETMObjectList $result.findings)) {
            if ($f.category -eq 'credential-breach') {
                $rows.Add([pscustomobject]@{
                        type = 'Breach'; name = $f.title; detail = $f.evidence; source = 'hibp'
                        _kind = 'finding'; _data = $f
                    })
            }
            elseif ($f.category -eq 'typosquat-brand') {
                $rows.Add([pscustomobject]@{
                        type = 'Typosquat'; name = $f.title; detail = $f.evidence; source = 'dns'
                        _kind = 'finding'; _data = $f
                    })
            }
            elseif ($f.category -eq 'cloud') {
                $rows.Add([pscustomobject]@{
                        type = 'Cloud'; name = $f.title; detail = $f.evidence; source = 'cloud'
                        _kind = 'finding'; _data = $f
                    })
            }
            elseif ($f.category -eq 'github-code') {
                $rows.Add([pscustomobject]@{
                        type = 'GitHub'; name = $f.title; detail = $f.evidence; source = 'github'
                        _kind = 'finding'; _data = $f
                    })
            }
            elseif ($f.category -eq 'subdomain') {
                $rows.Add([pscustomobject]@{
                        type = 'Subdomain finding'; name = $f.title; detail = $f.evidence; source = 'scan'
                        _kind = 'finding'; _data = $f
                    })
            }
        }
        return $rows.ToArray()
    }

    function Apply-DiscoveryFilter {
        $filter = (& $get 'CmbDiscoveryFilter').SelectedItem.Content
        $rows = $state.discoveryRows
        if ($filter -and $filter -ne 'All assets') {
            $map = @{
                'Subdomains'    = 'Subdomain'
                'Web services'  = 'Web'
                'Typosquatting' = 'Typosquat'
                'Cloud'         = 'Cloud'
                'GitHub'        = 'GitHub'
                'Breaches'      = 'Breach'
            }
            $t = $map[$filter]
            if ($t) {
                $filtered = [System.Collections.Generic.List[object]]::new()
                foreach ($r in $rows) {
                    if ($r.type -eq $t) { [void]$filtered.Add($r) }
                }
                $rows = $filtered
            }
        }
        Set-ETMDataGridSource -Grid (& $get 'GridDiscovery') -Items $rows
    }

    function Update-CategoryGrid {
        param($score)
        # Categories shown via findings on dashboard; intel grid separate
    }

    function Update-Ui {
        param($result)
        $result = Normalize-ETMScanResult $result
        $state.lastResult = $result
        $findings = ConvertTo-ETMObjectList $result.findings
        $subs = ConvertTo-ETMObjectList $result.subdomains
        $web = ConvertTo-ETMObjectList $result.webServices
        $intel = ConvertTo-ETMObjectList $result.threatIntel
        $score = $result.score
        if (-not $score -and $findings.Count -gt 0) {
            $score = Measure-ETMProtectionScore `
                -Findings (ConvertTo-ETMObjectArray $findings) `
                -Subdomains (ConvertTo-ETMObjectArray $subs) `
                -WebServices (ConvertTo-ETMObjectArray $web)
            $result | Add-Member -NotePropertyName score -NotePropertyValue $score -Force
        }
        if ($score) {
            (& $get 'TxtScore').Text = [string]$score.TotalScore
            (& $get 'TxtGrade').Text = "$($score.Grade)"
        }
        (& $get 'TxtFindingCount').Text = [string]$findings.Count
        (& $get 'TxtAssetCount').Text = [string]($subs.Count + $web.Count)
        (& $get 'TxtIntelCount').Text = [string]$intel.Count
        Set-ETMDataGridSource -Grid (& $get 'GridFindings') -Items $findings
        Set-ETMDataGridSource -Grid (& $get 'GridIntel') -Items $intel
        $state.discoveryRows = Build-DiscoveryRows $result
        Set-ETMDataGridSource -Grid (& $get 'GridAssets') -Items $state.discoveryRows
        Apply-DiscoveryFilter
    }

    function Update-UiSafe {
        param(
            $Result,
            [string]$Context = 'Update dashboard'
        )
        try {
            Update-Ui $Result
        }
        catch {
            Show-ETMUiError -Context $Context -Exception $_.Exception -OnLog $uiLog
            return $false
        }
        return $true
    }

    function Update-UiLive {
        param($Snapshot)
        if (-not $Snapshot) { return }
        $partial = Normalize-ETMScanResult $Snapshot
        $findings = ConvertTo-ETMObjectList $partial.findings
        $subs = ConvertTo-ETMObjectList $partial.subdomains
        $web = ConvertTo-ETMObjectList $partial.webServices
        $intel = ConvertTo-ETMObjectList $partial.threatIntel
        $score = $partial.score

        if ($score) {
            (& $get 'TxtScore').Text = [string]$score.TotalScore
            (& $get 'TxtGrade').Text = "$($score.Grade)"
        }
        else {
            (& $get 'TxtScore').Text = '...'
            (& $get 'TxtGrade').Text = 'Updating...'
        }
        (& $get 'TxtFindingCount').Text = [string]$findings.Count
        (& $get 'TxtAssetCount').Text = [string]($subs.Count + $web.Count)
        (& $get 'TxtIntelCount').Text = [string]$intel.Count
        Set-ETMDataGridSource -Grid (& $get 'GridFindings') -Items $findings
        Set-ETMDataGridSource -Grid (& $get 'GridIntel') -Items $intel
        $state.discoveryRows = Build-DiscoveryRows $partial
        Set-ETMDataGridSource -Grid (& $get 'GridAssets') -Items $state.discoveryRows
        Apply-DiscoveryFilter
    }

    function Reset-DashboardUi {
        param([string]$StatusText = 'Dashboard cleared. Set a target and run a scan.')
        $state.lastResult = $null
        $state.isDemo = $false
        (& $get 'TxtScore').Text = '--'
        (& $get 'TxtGrade').Text = ''
        (& $get 'TxtFindingCount').Text = '0'
        (& $get 'TxtAssetCount').Text = '0'
        (& $get 'TxtIntelCount').Text = '0'
        Set-ETMDataGridSource -Grid (& $get 'GridFindings') -Items @()
        Set-ETMDataGridSource -Grid (& $get 'GridAssets') -Items @()
        Set-ETMDataGridSource -Grid (& $get 'GridIntel') -Items @()
        $state.discoveryRows = @()
        Set-ETMDataGridSource -Grid (& $get 'GridDiscovery') -Items @()
        Hide-ETMItemDetail -GetControl $get
        (& $get 'TxtStatus').Text = $StatusText
        (& $get 'ScanProgress').Value = 0
        (& $get 'TxtProgressMsg').Text = ''
    }

    function Complete-ScanUiAfterStop {
        param([switch]$ResetScoreCard)
        $state.scanRunning = $false
        $state.activeScanScope = $null
        $state.activeScanLive = $null
        (& $get 'ScanProgress').Visibility = 'Collapsed'
        (& $get 'ScanProgress').Value = 0
        (& $get 'TxtProgressMsg').Visibility = 'Collapsed'
        (& $get 'BtnCancelScan').Visibility = 'Collapsed'
        if ($ResetScoreCard) {
            (& $get 'TxtScore').Text = '--'
            (& $get 'TxtGrade').Text = ''
        }
    }

    function Invoke-ETMHardStopScan {
        if (-not $state.scanRunning) { return }

        $state.cancelScan = $true
        if ($state.cancelSync) { $state.cancelSync.Cancel = $true }
        (& $get 'TxtProgressMsg').Text = 'Stopping scan immediately...'
        (& $get 'BtnCancelScan').IsEnabled = $false

        if ($state.scanTimer) {
            try { $state.scanTimer.Stop() } catch { }
            $state.scanTimer = $null
        }

        $partialResult = $null
        if ($state.scanJob) {
            try {
                Stop-Job -Job $state.scanJob -Force -ErrorAction SilentlyContinue
                $partialResult = Receive-Job -Job $state.scanJob -ErrorAction SilentlyContinue
            }
            catch { }
            try { Remove-Job -Job $state.scanJob -Force -ErrorAction SilentlyContinue } catch { }
            $state.scanJob = $null
        }

        $scope = $state.activeScanScope
        $live = $state.activeScanLive
        $saved = $false

        if (-not $partialResult -and $live -and $live.snapshot -and $scope) {
            try {
                $partialResult = Normalize-ETMScanResult $live.snapshot
                $partialResult | Add-Member -NotePropertyName scanStatus -NotePropertyValue 'Cancelled' -Force
                if (-not $partialResult.score) {
                    $fa = ConvertTo-ETMObjectArray $partialResult.findings
                    $sa = ConvertTo-ETMObjectArray $partialResult.subdomains
                    $wa = ConvertTo-ETMObjectArray $partialResult.webServices
                    if ($fa.Count -gt 0 -or $sa.Count -gt 0 -or $wa.Count -gt 0) {
                        $partialResult | Add-Member -NotePropertyName score -NotePropertyValue (
                            Measure-ETMProtectionScore -Findings $fa -Subdomains $sa -WebServices $wa) -Force
                    }
                }
            }
            catch { }
        }

        if ($partialResult -and $scope) {
            try {
                if (-not $partialResult.PSObject.Properties['scanStatus']) {
                    $partialResult | Add-Member -NotePropertyName scanStatus -NotePropertyValue 'Cancelled' -Force
                }
                Save-ETMScanHistory -Result $partialResult -Scope $scope
                Update-UiSafe $partialResult -Context 'Save stopped scan'
                $fc = (ConvertTo-ETMObjectList $partialResult.findings).Count
                $sc = if ($partialResult.score) { $partialResult.score.TotalScore } else { '--' }
                (& $get 'TxtStatus').Text = "Stopped - partial scan saved (score $sc, $fc findings)."
                Append-LogUi "Hard stop: partial scan saved to history ($fc findings)."
                Refresh-HistoryGrid
                if ($state.sqlConnected) { Refresh-SqlGrid }
                $saved = $true
            }
            catch {
                Append-LogUi "Hard stop: save failed - $($_.Exception.Message)"
                (& $get 'TxtStatus').Text = 'Scan stopped but could not save partial results.'
            }
        }

        Complete-ScanUiAfterStop -ResetScoreCard:(-not $saved)
        (& $get 'BtnCancelScan').IsEnabled = $true

        if (-not $saved) {
            (& $get 'TxtStatus').Text = 'Scan stopped. No results to save yet (try again after findings appear).'
            Append-LogUi 'Hard stop: job killed (no partial data to save).'
        }
    }

    function Show-AuthorizationPrompt {
        param([switch]$ForScan)
        $msg = @"
External Threat Mapper uses passive and authorized defensive reconnaissance only.

- No exploitation, credential attacks, or brute force
- Use only on targets you are authorized to assess
- Third-party APIs (Shodan, VirusTotal, etc.) require your own API keys

Do you confirm you are authorized to assess your targets?
"@
        $r = [System.Windows.MessageBox]::Show($msg, 'Authorization required', 'YesNo', 'Warning')
        if ($r -eq 'Yes') {
            (& $get 'ChkAuthorized').IsChecked = $true
            $scope = Get-ScopeFromForm
            $scope.authorizationAcknowledged = $true
            try {
                Export-ETMScopeFile -Scope $scope -Path (Join-Path (Get-ETMProjectRoot) 'scopes\current-scope.json')
            }
            catch { }
            return $true
        }
        if ($ForScan) {
            [System.Windows.MessageBox]::Show(
                'A scan cannot run without authorization. Check the box on the Target page when you are permitted to assess that domain.',
                'Authorization required', 'OK', 'Information') | Out-Null
        }
        return $false
    }

    function New-IntegrationCard {
        param($Provider)
        $card = New-Object System.Windows.Controls.Border
        $card.Background = '#121820'
        $card.BorderBrush = '#263041'
        $card.BorderThickness = 1
        $card.CornerRadius = 10
        $card.Padding = 16
        $card.Margin = '0,0,0,10'
        $sp = New-Object System.Windows.Controls.StackPanel
        $title = New-Object System.Windows.Controls.TextBlock
        $title.Text = $Provider.displayName
        $title.FontSize = 15
        $title.FontWeight = 'SemiBold'
        $title.Foreground = '#EEF2F8'
        $desc = New-Object System.Windows.Controls.TextBlock
        $desc.Text = $Provider.description
        $desc.TextWrapping = 'Wrap'
        $desc.Foreground = '#7D8DA6'
        $desc.Margin = '0,6,0,10'
        $desc.FontSize = 12
        $loc = $null
        if ($Provider.keyLocation) {
            $loc = New-Object System.Windows.Controls.TextBlock
            $loc.Text = "Where to find key: $($Provider.keyLocation)"
            $loc.TextWrapping = 'Wrap'
            $loc.Foreground = '#5C6D85'
            $loc.FontSize = 10
            $loc.FontStyle = [System.Windows.FontStyles]::Italic
            $loc.Margin = '0,0,0,10'
        }
        $pwd = New-Object System.Windows.Controls.PasswordBox
        $pwd.Height = 32
        $pwd.Margin = '0,0,0,8'
        $pwd.Background = New-ETMUiBrush '#0A0E14'
        $pwd.Foreground = New-ETMUiBrush '#EEF2F8'
        $pwd.BorderBrush = New-ETMUiBrush '#263041'
        $existing = Get-ETMApiSecret -Name $Provider.id
        if ($existing) { $pwd.Tag = 'configured' }
        $row = New-Object System.Windows.Controls.StackPanel
        $row.Orientation = 'Horizontal'
        $btnSave = New-Object System.Windows.Controls.Button
        $btnSave.Content = 'Save'
        $btnSave.Padding = '14,6'
        $btnSave.Margin = '0,0,8,0'
        $btnSave.Background = '#4C9AFF'
        $btnSave.Foreground = 'White'
        $btnSave.BorderThickness = 0
        $btnTest = New-Object System.Windows.Controls.Button
        $btnTest.Content = 'Test'
        $btnTest.Padding = '14,6'
        $btnTest.Background = '#1A2433'
        $btnTest.Foreground = '#C5D0E0'
        $btnTest.BorderThickness = 0
        $status = New-Object System.Windows.Controls.TextBlock
        $status.Margin = '0,10,0,0'
        $status.TextWrapping = 'Wrap'
        $status.Foreground = '#7D8DA6'
        $status.FontSize = 11
        $providerId = $Provider.id
        if ($providerId -ne 'CensysSecret') {
            if (Test-ETMApiConfigured -Provider $providerId) {
                $status.Text = 'Ready for scans (key on file).'
                $status.Foreground = New-ETMUiBrush '#3DD68C'
            }
            else {
                $status.Text = 'Not configured - this provider is skipped during scans.'
            }
        }
        elseif (Test-ETMApiConfigured -Provider 'Censys') {
            $status.Text = 'Censys ID + secret on file (ready).'
            $status.Foreground = New-ETMUiBrush '#3DD68C'
        }
        else {
            $status.Text = 'Save with Censys API ID to enable Censys.'
        }
        $logFn = { param($line) Append-LogUi $line }
        Register-ETMUiClick -Control $btnSave -Context "Save API $providerId" -OnLog $logFn -Handler {
            $sec = $pwd.SecurePassword
            if ($sec.Length -eq 0) {
                $status.Text = 'Paste an API key first.'
                $status.Foreground = New-ETMUiBrush '#F0B429'
                return
            }
            $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($sec)
            try {
                $plain = [Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
                Set-ETMApiCredential -Name $providerId -Value $plain
                $plain = $null
            }
            finally {
                [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
                $pwd.Clear()
            }
            $status.Text = if (Test-ETMApiConfigured -Provider $providerId) {
                'Saved - ready for scans.'
            } else { 'Saved securely.' }
            $status.Foreground = New-ETMUiBrush '#3DD68C'
            Append-LogUi "API key saved: $providerId"
        }.GetNewClosure()
        Register-ETMUiClick -Control $btnTest -Context "Test API $providerId" -OnLog $logFn -Handler {
            $stored = Get-ETMApiSecret -Name $providerId
            $sec = $pwd.SecurePassword
            if ($sec.Length -gt 0) {
                $plain = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
                    [Runtime.InteropServices.Marshal]::SecureStringToBSTR($sec))
                try { Set-ETMApiCredential -Name $providerId -Value $plain }
                finally { $plain = $null; $pwd.Clear() }
            }
            elseif (-not $stored) {
                $status.Text = 'No API key configured. Enter a key above, then Test or Save.'
                $status.Foreground = New-ETMUiBrush '#F0B429'
                Append-LogUi "[$providerId] Skipped - no key."
                return
            }
            $status.Text = 'Testing connection...'
            $status.Foreground = New-ETMUiBrush '#F0B429'
            $t = Test-ETMApiConnection -Provider $providerId
            $status.Text = $t.Message
            $status.Foreground = if ($t.Ok) { New-ETMUiBrush '#3DD68C' } else { New-ETMUiBrush '#F85149' }
            Append-LogUi "[$providerId] $($t.Message)"
        }.GetNewClosure()
        [void]$row.Children.Add($btnSave)
        [void]$row.Children.Add($btnTest)
        [void]$sp.Children.Add($title)
        [void]$sp.Children.Add($desc)
        if ($loc) { [void]$sp.Children.Add($loc) }
        [void]$sp.Children.Add($pwd)
        [void]$sp.Children.Add($row)
        [void]$sp.Children.Add($status)
        $card.Child = $sp
        $state.apiFields[$Provider.id] = @{ Password = $pwd; Status = $status }
        return $card
    }

    function Build-IntegrationsUi {
        $panel = & $get 'IntegrationsPanel'
        $panel.Children.Clear()
        foreach ($p in Get-ETMIntegrationCatalog) {
            [void]$panel.Children.Add((New-IntegrationCard $p))
        }
    }

    function Refresh-HistoryGrid {
        $items = @(Get-ETMScanHistoryList)
        Set-ETMDataGridSource -Grid (& $get 'GridHistory') -Items $items
    }

    function Get-SqlPasswordFromForm {
        $sec = (& $get 'PwdSql').SecurePassword
        if ($sec.Length -eq 0) { return '' }
        $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($sec)
        try { return [Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr) }
        finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
    }

    function Load-SqlFormFromConfig {
        $sql = Get-ETMSqlSettings
        (& $get 'ChkSqlEnabled').IsChecked = [bool]$sql.enabled
        (& $get 'TxtSqlServer').Text = [string]$sql.server
        (& $get 'TxtSqlDatabase').Text = [string]$sql.database
        (& $get 'ChkSqlIntegrated').IsChecked = [bool]($sql.integratedSecurity -ne $false)
        (& $get 'TxtSqlUser').Text = [string]$sql.userId
        if (Get-ETMApiSecret -Name 'SqlPassword') {
            (& $get 'TxtSqlConnectStatus').Text = 'Saved password on file (re-enter to change).'
        }
    }

    function Update-SqlTabAccess {
        $connected = [bool]$state.sqlConnected
        (& $get 'SqlLockedOverlay').Visibility = if ($connected) { 'Collapsed' } else { 'Visible' }
        (& $get 'SqlWorkspace').Visibility = if ($connected) { 'Visible' } else { 'Collapsed' }
        (& $get 'BtnSqlDisconnect').Visibility = if ($connected) { 'Visible' } else { 'Collapsed' }
        if ($connected) {
            $srv = (& $get 'TxtSqlServer').Text.Trim()
            $db = (& $get 'TxtSqlDatabase').Text.Trim()
            (& $get 'TxtSqlConnectedBanner').Text = "Connected to $srv / $db"
        }
    }

    function Invoke-ETMSqlConnectAsync {
        param(
            [string]$Server,
            [string]$Database,
            [bool]$IntegratedSecurity,
            [string]$UserId,
            [string]$PlainPassword
        )
        if ($state.sqlConnectTimer) {
            try { $state.sqlConnectTimer.Stop() } catch { }
            $state.sqlConnectTimer = $null
        }
        if ($state.sqlConnectJob) {
            try { Remove-Job -Job $state.sqlConnectJob -Force -ErrorAction SilentlyContinue } catch { }
            $state.sqlConnectJob = $null
        }

        $btn = & $get 'BtnSqlConnect'
        $btn.IsEnabled = $false
        (& $get 'TxtSqlConnectStatus').Text = 'Connecting...'

        $root = Get-ETMProjectRoot
        $connectBlock = {
            param($Root, $Server, $Database, $IntegratedSecurity, $UserId, $PlainPassword)
            Import-Module (Join-Path $Root 'ExternalThreatMapper.psm1') -Force
            Connect-ETMSqlServer -Server $Server -Database $Database `
                -IntegratedSecurity $IntegratedSecurity -UserId $UserId -PlainPassword $PlainPassword
        }
        $args = @($root, $Server, $Database, $IntegratedSecurity, $UserId, $PlainPassword)
        if (Get-Command Start-ThreadJob -ErrorAction SilentlyContinue) {
            $state.sqlConnectJob = Start-ThreadJob -ScriptBlock $connectBlock -ArgumentList $args
        }
        else {
            $state.sqlConnectJob = Start-Job -ScriptBlock $connectBlock -ArgumentList $args
        }

        $state.sqlConnectTimer = New-Object System.Windows.Threading.DispatcherTimer
        $state.sqlConnectTimer.Interval = [TimeSpan]::FromMilliseconds(200)
        $state.sqlConnectTimer.Add_Tick({
            $job = $state.sqlConnectJob
            if (-not $job -or $job.State -eq 'Running') { return }
            try {
                $state.sqlConnectTimer.Stop()
                $state.sqlConnectTimer = $null
                $r = Receive-Job -Job $job -ErrorAction Stop
            }
            catch {
                $r = [pscustomobject]@{ Ok = $false; Message = $_.Exception.Message }
            }
            finally {
                try { Remove-Job -Job $job -Force -ErrorAction SilentlyContinue } catch { }
                $state.sqlConnectJob = $null
                (& $get 'BtnSqlConnect').IsEnabled = $true
            }
            if (-not $r) {
                $r = [pscustomobject]@{ Ok = $false; Message = 'Connection ended with no response.' }
            }
            (& $get 'TxtSqlConnectStatus').Text = $r.Message
            if ($r.Ok) {
                $state.sqlConnected = $true
                (& $get 'ChkSqlEnabled').IsChecked = $true
                Update-SqlTabAccess
                Refresh-SqlGrid
                Append-LogUi 'SQL Server connected.'
            }
            else {
                $state.sqlConnected = $false
                Update-SqlTabAccess
                Append-LogUi "SQL connect failed: $($r.Message)"
            }
        })
        $state.sqlConnectTimer.Start()
    }

    function Refresh-SqlGrid {
        if (-not $state.sqlConnected) { return }
        try {
            $rows = @(Get-ETMSqlScanSummaries)
            Set-ETMDataGridSource -Grid (& $get 'GridSqlScans') -Items $rows
            (& $get 'TxtSqlWorkspaceStatus').Text = if ($rows.Count -gt 0) {
                "$($rows.Count) scan(s) in SQL database."
            } else {
                'No scans in database yet. Complete a scan with sync enabled.'
            }
        }
        catch {
            (& $get 'TxtSqlWorkspaceStatus').Text = "Could not read SQL scans: $($_.Exception.Message)"
        }
    }

    function Restore-LastScanIfAny {
        $list = @(Get-ETMScanHistoryList)
        if ($list.Count -eq 0) { return }
        try {
            $last = $list[0]
            $scanId = [string]$last.scanId
            if ([string]::IsNullOrWhiteSpace($scanId)) { return }
            $loaded = Import-ETMScanFromHistory -ScanId $scanId
            Update-UiSafe $loaded -Context 'Restore last scan'
            $state.isDemo = $false
            (& $get 'TxtStatus').Text = "Restored last scan: $($last.domain) ($($last.startedUtc))"
            Append-LogUi "Restored history: $($last.domain)"
        }
        catch {
            Append-LogUi "Could not restore last scan: $($_.Exception.Message)"
        }
    }

    Show-Page 'Dashboard'
    Build-IntegrationsUi
    Load-SqlFormFromConfig
    Update-SqlTabAccess
    $pwdSql = & $get 'PwdSql'
    if ($pwdSql) {
        $pwdSql.Background = New-ETMUiBrush '#0A0E14'
        $pwdSql.Foreground = New-ETMUiBrush '#EEF2F8'
        $pwdSql.BorderBrush = New-ETMUiBrush '#263041'
    }
    Refresh-HistoryGrid

    $scopePath = Join-Path (Get-ETMProjectRoot) 'scopes\current-scope.json'
    if (Test-Path $scopePath) {
        try {
            $savedScope = Import-ETMScopeFile -Path $scopePath
            if ($savedScope.organizationName) { (& $get 'TxtOrg').Text = [string]$savedScope.organizationName }
            if ($savedScope.primaryDomain) { (& $get 'TxtDomain').Text = [string]$savedScope.primaryDomain }
            if ($savedScope.PSObject.Properties['breachCheckEmails']) {
                Set-BreachCheckEmailsOnForm -Emails @($savedScope.breachCheckEmails)
            }
        }
        catch { }
    }

    # Always confirm authorization each time the app opens (saved scope does not skip this).
    (& $get 'ChkAuthorized').IsChecked = $false
    if (-not (Show-AuthorizationPrompt)) {
        [System.Windows.MessageBox]::Show(
            "You chose not to confirm authorization.`n`nExternal Threat Mapper will close. Re-open the app when you are ready to confirm you may assess your targets.",
            'Authorization required',
            'OK',
            'Information') | Out-Null
        return
    }

    Append-LogUi 'Ready. Connect APIs under Integrations, set target, then Run scan.'
    Restore-LastScanIfAny

    (& $get 'NavList').Add_SelectionChanged({
        $item = (& $get 'NavList').SelectedItem
        if ($item -and $item.Tag) {
            $tag = [string]$item.Tag
            if ($tag -eq 'Sql' -and -not $state.sqlConnected) {
                Show-Page 'Sql'
                (& $get 'TxtStatus').Text = 'Enter SQL Server details and click Connect to unlock database tools.'
                return
            }
            Show-Page $tag
            if ($tag -eq 'Sql' -and $state.sqlConnected) { Refresh-SqlGrid }
        }
    })

    (& $get 'CmbDiscoveryFilter').Add_SelectionChanged({ Apply-DiscoveryFilter })

    Register-ETMUiClick -Control (& $get 'BtnLoadDemo') -Context 'Load demo data' -OnLog $uiLog -Handler {
        $demoPath = Join-Path (Get-ETMProjectRoot) 'samples\demo-result.json'
        if (-not (Test-Path $demoPath)) {
            [System.Windows.MessageBox]::Show('Demo file missing.', 'Demo') | Out-Null
            return
        }
        $demo = Import-ETMScanResultJson -Path $demoPath
        $state.isDemo = $true
        if (-not (Update-UiSafe $demo -Context 'Load demo data')) { return }
        (& $get 'TxtOrg').Text = 'Demo Corp'
        (& $get 'TxtDomain').Text = 'demo-corp.example'
        (& $get 'ChkAuthorized').IsChecked = $true
        (& $get 'TxtStatus').Text = 'Demo data loaded (sample only). Run a real scan to replace it.'
        Append-LogUi 'Demo data loaded (not saved to history).'
    }

    Register-ETMUiClick -Control (& $get 'BtnClearDemo') -Context 'Clear dashboard' -OnLog $uiLog -Handler {
        Reset-DashboardUi -StatusText 'Dashboard cleared.'
        Append-LogUi 'Dashboard cleared.'
    }

    Register-ETMUiClick -Control (& $get 'BtnLoadHistory') -Context 'Load history scan' -OnLog $uiLog -Handler {
        $grid = & $get 'GridHistory'
        if (-not $grid.SelectedItem) {
            [System.Windows.MessageBox]::Show('Select a scan in the history table first.', 'History') | Out-Null
            return
        }
        $row = $grid.SelectedItem
        $id = [string]$row.scanId
        if ([string]::IsNullOrWhiteSpace($id)) {
            [System.Windows.MessageBox]::Show('Selected row has no scan ID.', 'History') | Out-Null
            return
        }
        $loaded = Import-ETMScanFromHistory -ScanId $id
        $state.isDemo = $false
        if (-not (Update-UiSafe $loaded -Context 'Load history scan')) { return }
        if ($loaded.scope) {
            if ($loaded.scope.organizationName) { (& $get 'TxtOrg').Text = [string]$loaded.scope.organizationName }
            if ($loaded.scope.primaryDomain) { (& $get 'TxtDomain').Text = [string]$loaded.scope.primaryDomain }
            if ($null -ne $loaded.scope.authorizationAcknowledged) {
                (& $get 'ChkAuthorized').IsChecked = [bool]$loaded.scope.authorizationAcknowledged
            }
        }
        (& $get 'TxtStatus').Text = "Loaded scan $id from history."
        Show-Page 'Dashboard'
        Append-LogUi "Loaded history scan $id ($((ConvertTo-ETMObjectList $loaded.findings).Count) findings)."
    }

    Register-ETMUiClick -Control (& $get 'BtnClearHistory') -Context 'Clear history' -OnLog $uiLog -Handler {
        $ans = [System.Windows.MessageBox]::Show(
            'Clear all local scan history files? SQL data is kept unless you disable SQL and clear separately.',
            'Confirm', 'YesNo', 'Warning')
        if ($ans -ne 'Yes') { return }
        Clear-ETMScanHistory -KeepSql
        Refresh-HistoryGrid
        Append-LogUi 'Local scan history cleared.'
    }

    Register-ETMUiClick -Control (& $get 'BtnSqlConnect') -Context 'Connect SQL' -OnLog $uiLog -Handler {
        $server = (& $get 'TxtSqlServer').Text.Trim()
        $database = (& $get 'TxtSqlDatabase').Text.Trim()
        if ([string]::IsNullOrWhiteSpace($server) -or [string]::IsNullOrWhiteSpace($database)) {
            (& $get 'TxtSqlConnectStatus').Text = 'Enter server and database name before connecting.'
            return
        }
        $integrated = [bool](& $get 'ChkSqlIntegrated').IsChecked
        $pwd = Get-SqlPasswordFromForm
        if (-not $integrated -and -not $pwd -and -not (Get-ETMApiSecret -Name 'SqlPassword')) {
            (& $get 'TxtSqlConnectStatus').Text = 'Enter SQL password, or enable Windows authentication.'
            return
        }
        if ($pwd) { (& $get 'PwdSql').Clear() }
        Invoke-ETMSqlConnectAsync -Server $server -Database $database `
            -IntegratedSecurity $integrated -UserId (& $get 'TxtSqlUser').Text.Trim() -PlainPassword $pwd
    }

    Register-ETMUiClick -Control (& $get 'BtnSqlDisconnect') -Context 'Disconnect SQL' -OnLog $uiLog -Handler {
        $state.sqlConnected = $false
        Save-ETMSqlSettings -Enabled $false `
            -Server (& $get 'TxtSqlServer').Text.Trim() `
            -Database (& $get 'TxtSqlDatabase').Text.Trim() `
            -IntegratedSecurity (& $get 'ChkSqlIntegrated').IsChecked `
            -UserId (& $get 'TxtSqlUser').Text.Trim()
        Update-SqlTabAccess
        Set-ETMDataGridSource -Grid (& $get 'GridSqlScans') -Items @()
        (& $get 'TxtSqlConnectStatus').Text = 'Disconnected. Database tools are locked until you connect again.'
        Append-LogUi 'SQL disconnected.'
    }

    Register-ETMUiClick -Control (& $get 'BtnSqlSaveSync') -Context 'Save SQL sync preference' -OnLog $uiLog -Handler {
        if (-not $state.sqlConnected) {
            [System.Windows.MessageBox]::Show('Connect to SQL Server first.', 'SQL') | Out-Null
            return
        }
        Save-ETMSqlSettings -Enabled (& $get 'ChkSqlEnabled').IsChecked `
            -Server (& $get 'TxtSqlServer').Text.Trim() `
            -Database (& $get 'TxtSqlDatabase').Text.Trim() `
            -IntegratedSecurity (& $get 'ChkSqlIntegrated').IsChecked `
            -UserId (& $get 'TxtSqlUser').Text.Trim()
        (& $get 'TxtSqlWorkspaceStatus').Text = 'Sync preference saved.'
        Append-LogUi "SQL auto-sync: $((& $get 'ChkSqlEnabled').IsChecked)"
    }

    Register-ETMUiClick -Control (& $get 'BtnSqlRefresh') -Context 'Refresh SQL scans' -OnLog $uiLog -Handler {
        if (-not $state.sqlConnected) {
            [System.Windows.MessageBox]::Show('Connect to SQL Server first.', 'SQL') | Out-Null
            return
        }
        Refresh-SqlGrid
        Append-LogUi 'SQL scan list refreshed.'
    }

    Register-ETMUiClick -Control (& $get 'BtnSaveScope') -Context 'Save scope' -OnLog $uiLog -Handler {
        $scope = Get-ScopeFromForm
        if (-not $scope.authorizationAcknowledged) {
            [System.Windows.MessageBox]::Show('Confirm authorization first.', 'Scope') | Out-Null
            return
        }
        Export-ETMScopeFile -Scope $scope -Path (Join-Path (Get-ETMProjectRoot) 'scopes\current-scope.json')
        $state.scope = $scope
        Append-LogUi "Scope saved: $($scope.primaryDomain)"
    }

    Register-ETMUiClick -Control (& $get 'BtnLoadScope') -Context 'Load scope' -OnLog $uiLog -Handler {
        $path = Join-Path (Get-ETMProjectRoot) 'scopes\current-scope.json'
        if (-not (Test-Path $path)) { return }
        $s = Import-ETMScopeFile -Path $path
        (& $get 'TxtOrg').Text = $s.organizationName
        (& $get 'TxtDomain').Text = $s.primaryDomain
        (& $get 'ChkAuthorized').IsChecked = $s.authorizationAcknowledged
        if ($s.PSObject.Properties['breachCheckEmails']) {
            Set-BreachCheckEmailsOnForm -Emails @($s.breachCheckEmails)
        }
        Append-LogUi 'Scope loaded.'
    }

    Register-ETMUiClick -Control (& $get 'BtnTestAllApis') -Context 'Test all API integrations' -OnLog $uiLog -Handler {
        $ready = Get-ETMConfiguredApiLabel
        (& $get 'TxtApiSummary').Text = "Testing providers... (keys on file: $ready)"
        $results = @(Test-ETMAllApiConnections)
        if ($results.Count -eq 0) {
            (& $get 'TxtApiSummary').Text = 'No integrations configured.'
            return
        }
        $ok = @($results | Where-Object { $_.ok -eq $true }).Count
        (& $get 'TxtApiSummary').Text = "$ok / $($results.Count) connected (others need keys or are optional)."
        foreach ($r in $results) {
            if ($state.apiFields.ContainsKey($r.id)) {
                $st = $state.apiFields[$r.id].Status
                $st.Text = $r.message
                $st.Foreground = if ($r.ok) { New-ETMUiBrush '#3DD68C' } else { New-ETMUiBrush '#F85149' }
            }
            Append-LogUi "[$($r.id)] $($r.message)"
        }
    }

    Register-ETMUiClick -Control (& $get 'BtnStartScan') -Context 'Run scan' -OnLog $uiLog -Handler {
        if ($state.scanRunning) { return }
        $scope = Get-ScopeFromForm
        if ([string]::IsNullOrWhiteSpace($scope.primaryDomain)) {
            [System.Windows.MessageBox]::Show('Set primary domain on Target page.', 'Scan')
            Show-Page 'Target'
            return
        }
        if ($scope.primaryDomain -match 'demo-corp\.example') {
            [System.Windows.MessageBox]::Show(
                'Enter your real target domain on the Target page (demo domain is for sample data only).',
                'Scan', 'OK', 'Information') | Out-Null
            Show-Page 'Target'
            return
        }
        if (-not $scope.authorizationAcknowledged) {
            if (-not (Show-AuthorizationPrompt -ForScan)) { return }
            $scope = Get-ScopeFromForm
        }

        if ($state.isDemo -or $state.lastResult) {
            Reset-DashboardUi -StatusText "Starting scan of $($scope.primaryDomain)..."
        }
        $state.isDemo = $false

        $state.scanRunning = $true
        $state.cancelScan = $false
        $state.cancelSync = [hashtable]::Synchronized(@{ Cancel = $false })
        (& $get 'ScanProgress').Visibility = 'Visible'
        (& $get 'TxtProgressMsg').Visibility = 'Visible'
        (& $get 'BtnCancelScan').Visibility = 'Visible'
        (& $get 'ScanProgress').Value = 2
        $apiLabel = Get-ETMConfiguredApiLabel
        $apiHint = if ($apiLabel -eq 'none') {
            'No API keys - DNS/certificate checks only.'
        } else {
            "Using APIs: $apiLabel"
        }
        (& $get 'TxtProgressMsg').Text = "Starting scan - $apiHint"
        (& $get 'TxtStatus').Text = "Scanning $($scope.primaryDomain)..."
        Append-LogUi "Scan started [$($scope.scanMode)]. $apiHint"
        Show-Page 'Dashboard'
        $state.lastLiveVersion = -1
        (& $get 'TxtScore').Text = '...'
        (& $get 'TxtGrade').Text = 'Scanning...'
        Set-ETMDataGridSource -Grid (& $get 'GridFindings') -Items @()
        Set-ETMDataGridSource -Grid (& $get 'GridAssets') -Items @()
        Set-ETMDataGridSource -Grid (& $get 'GridIntel') -Items @()

        $root = Get-ETMProjectRoot
        $prog = [hashtable]::Synchronized(@{ pct = 2; msg = 'Starting...' })
        $live = [hashtable]::Synchronized(@{ version = 0; snapshot = $null; phase = '' })
        $cancelSync = $state.cancelSync
        $state.activeScanScope = $scope
        $state.activeScanLive = $live
        $startJob = {
            param($Root, $Scope, $Config, $Cancel, $Prog, $Live)
            $ErrorActionPreference = 'Stop'
            Import-Module (Join-Path $Root 'ExternalThreatMapper.psm1') -Force
            $cb = {
                param($p, $m)
                $Prog.pct = $p
                $Prog.msg = $m
            }
            Start-ETMExternalScan -Scope $Scope -Config $Config -ProgressCallback $cb -CancelFlag $Cancel -LiveState $Live
        }
        if (Get-Command Start-ThreadJob -ErrorAction SilentlyContinue) {
            $state.scanJob = Start-ThreadJob -ScriptBlock $startJob -ArgumentList $root, $scope, $state.config, $cancelSync, $prog, $live
        }
        else {
            $state.scanJob = Start-Job -ScriptBlock $startJob -ArgumentList $root, $scope, $state.config, $cancelSync, $prog, $live
        }

        $state.scanTimer = New-Object System.Windows.Threading.DispatcherTimer
        $state.scanTimer.Interval = [TimeSpan]::FromMilliseconds(350)
        $state.scanTimer.Add_Tick({
            try {
                if ($prog.msg) {
                    (& $get 'TxtProgressMsg').Text = $prog.msg
                    (& $get 'ScanProgress').Value = [Math]::Min(99, [double]$prog.pct)
                }
                if ($live -and $null -ne $live.version -and $live.version -ne $state.lastLiveVersion) {
                    $state.lastLiveVersion = [int]$live.version
                    try {
                        if ($live.snapshot) {
                            Update-UiLive $live.snapshot
                            $fc = (ConvertTo-ETMObjectList $live.snapshot.findings).Count
                            $phase = if ($live.phase) { $live.phase } else { $prog.msg }
                            (& $get 'TxtStatus').Text = "Scanning $($scope.primaryDomain) - $phase ($fc findings so far)"
                        }
                    }
                    catch {
                        Write-Verbose "Live UI refresh: $($_.Exception.Message)"
                    }
                }
                $job = $state.scanJob
                if (-not $job) { return }

                if ($job.State -eq 'Completed') {
                    $state.scanTimer.Stop()
                    $result = Receive-Job $job -ErrorAction SilentlyContinue
                    Remove-Job $job -Force -ErrorAction SilentlyContinue
                    $state.scanJob = $null
                    $state.scanRunning = $false
                    (& $get 'ScanProgress').Value = 100
                    (& $get 'BtnCancelScan').Visibility = 'Collapsed'
                    $state.activeScanScope = $null
                    $state.activeScanLive = $null
                    if ($result) {
                        Update-UiSafe (Normalize-ETMScanResult $result) -Context 'Apply scan results'
                        $ic = (ConvertTo-ETMObjectList $result.threatIntel).Count
                        $fc = (ConvertTo-ETMObjectList $result.findings).Count
                        $sc = if ($result.score) { $result.score.TotalScore } else { '--' }
                        $statusNote = if ($result.scanStatus -eq 'Cancelled') { 'Stopped (partial saved)' } else { 'Complete' }
                        (& $get 'TxtStatus').Text = "$statusNote - score $sc, $fc findings, $ic intel rows."
                        Append-LogUi 'Scan finished.'
                        Refresh-HistoryGrid
                        if ($state.sqlConnected) { Refresh-SqlGrid }
                        Show-Page 'Dashboard'
                    }
                    else {
                        Complete-ScanUiAfterStop -ResetScoreCard
                        (& $get 'TxtStatus').Text = 'Scan ended with no results (cancelled or no data).'
                        Append-LogUi 'Scan ended with no result payload.'
                    }
                }
                elseif ($job.State -in @('Failed', 'Stopped')) {
                    if ($state.cancelScan) { return }
                    $state.scanTimer.Stop()
                    $err = (Receive-Job $job 2>&1 | Out-String).Trim()
                    Remove-Job $job -Force -ErrorAction SilentlyContinue
                    $state.scanJob = $null
                    Complete-ScanUiAfterStop -ResetScoreCard
                    Append-LogUi "Scan error: $err"
                    (& $get 'TxtStatus').Text = 'Scan failed - see Reports log.'
                    [System.Windows.MessageBox]::Show(
                        "Scan failed.`n`n$err",
                        'Scan', 'OK', 'Warning') | Out-Null
                }
            }
            catch {
                Complete-ScanUiAfterStop
                Show-ETMUiError -Context 'Scan progress' -Exception $_.Exception -OnLog $uiLog
            }
        })
        $state.scanTimer.Start()
    }

    Register-ETMUiClick -Control (& $get 'BtnCancelScan') -Context 'Cancel scan' -OnLog $uiLog -Handler {
        Invoke-ETMHardStopScan
    }

    Register-ETMUiClick -Control (& $get 'BtnExportHtml') -Context 'Export HTML' -OnLog $uiLog -Handler {
        if (-not $state.lastResult) {
            [System.Windows.MessageBox]::Show('Run a scan or load demo first.', 'Export') | Out-Null
            return
        }
        $out = Join-Path (Get-ETMProjectRoot) "reports\etm-$(Get-Date -Format 'yyyyMMdd-HHmmss').html"
        Export-ETMHtmlReport -ScanResult $state.lastResult -OutputPath $out
        [System.Windows.MessageBox]::Show("Saved:`n$out", 'Export') | Out-Null
    }

    Register-ETMUiClick -Control (& $get 'BtnExportCsv') -Context 'Export CSV' -OnLog $uiLog -Handler {
        if (-not $state.lastResult) { return }
        $out = Join-Path (Get-ETMProjectRoot) "reports\etm-$(Get-Date -Format 'yyyyMMdd-HHmmss').csv"
        $findings = ConvertTo-ETMObjectArray $state.lastResult.findings
        Export-ETMFindingsCsv -Findings $findings -OutputPath $out
        [System.Windows.MessageBox]::Show("Saved:`n$out", 'Export') | Out-Null
    }

    Register-ETMUiClick -Control (& $get 'BtnExportJson') -Context 'Export JSON' -OnLog $uiLog -Handler {
        if (-not $state.lastResult) { return }
        $out = Join-Path (Get-ETMProjectRoot) "reports\etm-$(Get-Date -Format 'yyyyMMdd-HHmmss').json"
        Export-ETMFindingsJson -ScanResult $state.lastResult -OutputPath $out
        [System.Windows.MessageBox]::Show("Saved:`n$out", 'Export') | Out-Null
    }

    Register-ETMDataGridDetailView -GetControl $get -Grid (& $get 'GridFindings') -OnLog $uiLog
    Register-ETMDataGridDetailView -GetControl $get -Grid (& $get 'GridAssets') -OnLog $uiLog
    Register-ETMDataGridDetailView -GetControl $get -Grid (& $get 'GridDiscovery') -OnLog $uiLog
    Register-ETMDataGridDetailView -GetControl $get -Grid (& $get 'GridIntel') -OnLog $uiLog

    Register-ETMUiClick -Control (& $get 'BtnDetailClose') -Context 'Close detail' -OnLog $uiLog -Handler {
        Hide-ETMItemDetail -GetControl $get
    }
    $detailOverlay = & $get 'DetailOverlay'
    $detailOverlay.Add_MouseLeftButtonUp({
        if ($_.OriginalSource -eq $detailOverlay) {
            Hide-ETMItemDetail -GetControl $get
        }
    })

    $cardFindings = & $get 'CardFindings'
    $cardFindings.Add_MouseLeftButtonUp({
        Show-Page 'Dashboard'
        $tabs = & $get 'DashResultTabs'
        if ($tabs -and $tabs.Items.Count -gt 0) { $tabs.SelectedIndex = 0 }
        (& $get 'TxtStatus').Text = 'Findings list — double-click a row for full risk detail.'
    })
    $cardAssets = & $get 'CardAssets'
    $cardAssets.Add_MouseLeftButtonUp({
        Show-Page 'Dashboard'
        $tabs = & $get 'DashResultTabs'
        if ($tabs -and $tabs.Items.Count -gt 1) { $tabs.SelectedIndex = 1 }
        (& $get 'TxtStatus').Text = 'Assets list — double-click a row for discovery source and risk.'
    })

    try {
        [void]$window.ShowDialog()
    }
    catch {
        Show-ETMUiError -Context 'Application window' -Exception $_.Exception -OnLog $uiLog
    }
}
