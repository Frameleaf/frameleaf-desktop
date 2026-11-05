param([Parameter(Mandatory)][string]$Executable, [switch]$InstalledHost)

$ErrorActionPreference = 'Stop'
if ($env:RUNNER_ENVIRONMENT -ne 'github-hosted') { throw 'Requires a disposable Windows runner' }
Add-Type -AssemblyName UIAutomationClient
Add-Type -AssemblyName UIAutomationTypes
$tree = [System.Windows.Automation.TreeScope]::Descendants
$all = [System.Windows.Automation.Condition]::TrueCondition

function Wait-Control([string]$Name, [switch]$Radio, [string]$Type, [int]$Seconds = 45, [switch]$PollOperation) {
    $timer = [Diagnostics.Stopwatch]::StartNew()
    $nextOperationCheck = 0
    do {
        $app.Refresh()
        if ($app.HasExited) { throw "Installed app exited with code $($app.ExitCode)" }
        if ($app.MainWindowHandle -ne [IntPtr]::Zero) {
            $window = [System.Windows.Automation.AutomationElement]::FromHandle($app.MainWindowHandle)
            $controls = $window.FindAll($tree, $all)
            foreach ($control in $controls) {
                $label = $control.Current.Name
                if ($Radio) {
                    if ($control.Current.ControlType -eq [System.Windows.Automation.ControlType]::RadioButton -and
                        $control.Current.IsEnabled -and $label.StartsWith($Name)) { return $control }
                } elseif ($label -ceq $Name -and (!$Type -or ($control.Current.ControlType.ProgrammaticName -eq "ControlType.$Type" -and $control.Current.IsEnabled))) { return $control }
            }
        }
        if ($PollOperation -and $timer.Elapsed.TotalSeconds -ge $nextOperationCheck) {
            $check = $controls | Where-Object { $_.Current.Name -ceq 'Check' -and $_.Current.ControlType.ProgrammaticName -eq 'ControlType.Button' -and $_.Current.IsEnabled } | Select-Object -First 1
            if ($check) {
                $check.GetCurrentPattern([System.Windows.Automation.InvokePattern]::Pattern).Invoke()
                # Leave room for all lifecycle requests in Manager's ten-minute rate limit.
                $nextOperationCheck = $timer.Elapsed.TotalSeconds + 15
            }
        }
        Start-Sleep -Milliseconds 350
    } while ($timer.Elapsed.TotalSeconds -lt $Seconds)
    $labels = @($controls | ForEach-Object { $_.Current.Name } | Where-Object { $_ } | Select-Object -Unique -First 70)
    throw "Missing '$Name' in installed app. Visible controls: $($labels -join ' | ')"
}

function Select-Radio($Control) {
    $pattern = $null
    if ($Control.TryGetCurrentPattern([System.Windows.Automation.SelectionItemPattern]::Pattern, [ref]$pattern)) {
        $pattern.Select()
    } else {
        $Control.GetCurrentPattern([System.Windows.Automation.InvokePattern]::Pattern).Invoke()
    }
}

function Press([string]$Name) {
    $control = Wait-Control $Name -Type Button -Seconds 120
    $control.GetCurrentPattern([System.Windows.Automation.InvokePattern]::Pattern).Invoke()
}
function Fill([string]$Name, [string]$Value) {
    $control = Wait-Control $Name -Type Edit
    $control.GetCurrentPattern([System.Windows.Automation.ValuePattern]::Pattern).SetValue($Value)
}
function Confirm-ServerAction([string]$Action, [string]$Outcome) {
    Press $Action
    $null = Wait-Control "$Action Server" -Type Button
    $window = [System.Windows.Automation.AutomationElement]::FromHandle($app.MainWindowHandle)
    $field = $window.FindAll($tree, $all) | Where-Object { $_.Current.ControlType.ProgrammaticName -eq 'ControlType.Edit' -and $_.Current.Name -eq 'Enter your Manager password to continue' } | Select-Object -First 1
    if ($field) { $field.GetCurrentPattern([System.Windows.Automation.ValuePattern]::Pattern).SetValue($managerPassword) }
    Press "$Action Server"
    $null = Wait-Control $Outcome -PollOperation -Seconds 360
}
if ($InstalledHost) {
    if (Test-Path (Join-Path $env:LOCALAPPDATA 'Frameleaf Desktop Host')) { throw 'Expected a fresh user profile' }
    if (Get-NetTCPConnection -State Listen -LocalPort 2283,9443,54329 -ErrorAction SilentlyContinue) { throw 'Expected unused local server ports' }
}
$app = Start-Process -FilePath $Executable -PassThru
try {
    $null = Wait-Control 'Welcome'
    $null = Wait-Control 'Server address'
    Select-Radio (Wait-Control 'Run Frameleaf here' -Radio)
    if ($InstalledHost) {
        $managerPassword = 'Synthetic!' + [guid]::NewGuid().ToString('N')
        $receipt = Join-Path $env:RUNNER_TEMP ('synthetic-photo-' + [guid]::NewGuid() + '.json')
        Press 'Prepare Profile'
        $null = Wait-Control 'Your private server profile is ready. Check installation to continue.' -Seconds 180
        Write-Output 'Installed desktop prepared the Windows user profile'
        Press 'Prepare local Manager'
        $null = Wait-Control 'Local Manager is ready' -Seconds 360
        Fill 'Local Manager password' $managerPassword
        $permissions = Wait-Control 'Permissions Allow this computer to manage this local server.' -Type CheckBox
        $permissions.GetCurrentPattern([System.Windows.Automation.TogglePattern]::Pattern).Toggle()
        Press 'Authorize local management'
        $null = Wait-Control 'Open local Photos' -Type Button -Seconds 120
        Write-Output 'Installed desktop started and authorized local Manager'
        Press 'Start'
        $null = Wait-Control 'Start operation completed. Check Photos to confirm it is ready.' -PollOperation -Seconds 360
        $env:FRAMELEAF_SYNTHETIC_PHOTO_PASSWORD = 'Synthetic!' + [guid]::NewGuid().ToString('N')
        & node (Join-Path $PSScriptRoot 'qualify_installed_photo.mjs') upload $receipt
        if ($LASTEXITCODE) { throw 'Installed photo signup/upload/thumbnail failed' }
        Confirm-ServerAction 'Restart' 'Restart operation completed. Check Photos to confirm it is ready.'
        & node (Join-Path $PSScriptRoot 'qualify_installed_photo.mjs') verify $receipt
        if ($LASTEXITCODE) { throw 'Installed photo persistence failed' }
        Confirm-ServerAction 'Stop' 'Server stop completed.'
        Press 'Stop local management'
        $null = Wait-Control 'Prepare local Manager' -Type Button
        Write-Output 'Installed desktop Server start, restart, media persistence and shutdown passed'
        return
    }
    $null = Wait-Control 'Server component not installed'
    Select-Radio (Wait-Control 'Connect to my server' -Radio)
    $null = Wait-Control 'Server address'
    Write-Output 'Installed Welcome, native host discovery, and return to connection passed'
} finally {
    if ($InstalledHost) {
        Remove-Item Env:FRAMELEAF_SYNTHETIC_PHOTO_PASSWORD -ErrorAction SilentlyContinue
        if ($receipt -and (Test-Path $receipt)) { Remove-Item -LiteralPath $receipt }
    }
    if (!$app.HasExited) { Stop-Process -Id $app.Id -Force }
}
