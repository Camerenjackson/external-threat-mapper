# UiSafe.ps1 - UI error handling (loaded at module scope so click handlers always find these commands)

function New-ETMUiBrush {
    param([Parameter(Mandatory)][string]$Hex)
    return [System.Windows.Media.SolidColorBrush]::new(
        ([System.Windows.Media.ColorConverter]::ConvertFromString($Hex)))
}

function Initialize-ETMUiSafety {
    param(
        [Parameter(Mandatory)][System.Windows.Window]$Window,
        [scriptblock]$OnLog
    )
    try {
        if (-not [System.Windows.Application]::Current) {
            $null = New-Object System.Windows.Application
        }
        $app = [System.Windows.Application]::Current
        if ($app) {
            $logBlock = $OnLog
            $handler = {
                param($sender, $e)
                $e.Handled = $true
                Show-ETMUiError -Context 'Unhandled UI error' -Exception $e.Exception -OnLog $logBlock
            }
            $app.add_DispatcherUnhandledException($handler)
        }
    }
    catch {
        Write-Verbose "UI safety hook skipped: $($_.Exception.Message)"
    }
}

function Show-ETMUiError {
    param(
        [string]$Context = 'Operation',
        [Parameter(Mandatory)]$Exception,
        [scriptblock]$OnLog
    )
    $msg = if ($Exception.Message) { $Exception.Message } else { 'Unknown error' }
    if ($msg -match 'api[_-]?key|token|password|secret|bearer') {
        $msg = 'An API or credential error occurred. Check Integrations settings (details not shown for security).'
    }
    try {
        Write-ETMLog -Level ERROR -Message "UI: $Context" -Data @{ error = $Exception.Message } -ErrorAction SilentlyContinue
    }
    catch { }
    if ($OnLog) {
        try { & $OnLog "Error ($Context): $msg" } catch { }
    }
    try {
        [System.Windows.MessageBox]::Show(
            "Something went wrong during: $Context`n`n$msg`n`nThe application will stay open.",
            'External Threat Mapper',
            'OK',
            'Error') | Out-Null
    }
    catch {
        Write-Host "ERROR ($Context): $msg" -ForegroundColor Red
    }
}

function Register-ETMUiClick {
    param(
        [Parameter(Mandatory)]$Control,
        [Parameter(Mandatory)][scriptblock]$Handler,
        [string]$Context = 'Button',
        [scriptblock]$OnLog
    )
    $h = $Handler
    $c = $Context
    $l = $OnLog
    $Control.Add_Click({
        try {
            & $h
        }
        catch {
            $ex = if ($_.Exception) { $_.Exception } else { [System.Exception]::new([string]$_) }
            try {
                Write-ETMLog -Level ERROR -Message "UI: $c" -Data @{ error = $ex.Message } -ErrorAction SilentlyContinue
            }
            catch { }
            if ($l) {
                try { & $l "Error ($c): $($ex.Message)" } catch { }
            }
            $msg = $ex.Message
            if ($msg -match 'api[_-]?key|token|password|secret|bearer') {
                $msg = 'A credential or API error occurred. Check Integrations (details hidden for security).'
            }
            try {
                [System.Windows.MessageBox]::Show(
                    "Something went wrong during: $c`n`n$msg`n`nThe application will stay open.",
                    'External Threat Mapper',
                    'OK',
                    'Error') | Out-Null
            }
            catch {
                Write-Host "ERROR ($c): $msg" -ForegroundColor Red
            }
        }
    }.GetNewClosure())
}
