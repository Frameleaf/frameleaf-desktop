param([Parameter(Mandatory)][string]$Executable, [switch]$InstalledHost, [string]$WatchedFolder)

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
function Check-Box([string]$Prefix) {
    $window = [System.Windows.Automation.AutomationElement]::FromHandle($app.MainWindowHandle)
    $items = @($window.FindAll($tree, $all) | Where-Object {
        $_.Current.ControlType -eq [System.Windows.Automation.ControlType]::CheckBox -and
        $_.Current.Name.StartsWith($Prefix) -and $_.Current.IsEnabled
    })
    if ($items.Count -ne 1) { throw 'Expected one enabled watcher consent checkbox' }
    $toggle = $items[0].GetCurrentPattern([System.Windows.Automation.TogglePattern]::Pattern)
    if ($toggle.Current.ToggleState -ne [System.Windows.Automation.ToggleState]::On) { $toggle.Toggle() }
}
function Pick-WatchedFolder([string]$Path) {
    $desktop = [System.Windows.Automation.AutomationElement]::RootElement
    $timer = [Diagnostics.Stopwatch]::StartNew()
    do {
        $dialog = $desktop.FindAll([System.Windows.Automation.TreeScope]::Children, $all) | Where-Object {
            $_.Current.ProcessId -eq $app.Id -and $_.Current.Name -ceq 'Choose a photo folder'
        } | Select-Object -First 1
        if ($dialog) { break }
        Start-Sleep -Milliseconds 250
    } while ($timer.Elapsed.TotalSeconds -lt 30)
    if (!$dialog) { throw 'The installed app did not open its folder picker' }
    $fields = @($dialog.FindAll($tree, $all) | Where-Object {
        $_.Current.ControlType -eq [System.Windows.Automation.ControlType]::Edit -and $_.Current.IsEnabled
    })
    $field = $fields | Where-Object { $_.Current.Name -in 'Folder', 'Folder:', 'File name', 'File name:' } | Select-Object -First 1
    if (!$field -and $fields.Count -eq 1) { $field = $fields[0] }
    $accept = $dialog.FindAll($tree, $all) | Where-Object {
        $_.Current.Name -ceq 'Select Folder' -and $_.Current.ControlType -eq [System.Windows.Automation.ControlType]::Button
    } | Select-Object -First 1
    if (!$field -or !$accept) { throw 'Expected a folder path field and Select Folder button' }
    $field.GetCurrentPattern([System.Windows.Automation.ValuePattern]::Pattern).SetValue($Path)
    $accept.GetCurrentPattern([System.Windows.Automation.InvokePattern]::Pattern).Invoke()
}
function Wait-WindowVisibility([IntPtr]$Handle, [bool]$Visible) {
    $timer = [Diagnostics.Stopwatch]::StartNew()
    do {
        $app.Refresh()
        if ($app.HasExited -or ![FrameleafSmokeWindow]::IsWindow($Handle)) {
            throw 'The original Desktop window or process was destroyed'
        }
        if ([FrameleafSmokeWindow]::IsWindowVisible($Handle) -eq $Visible) { return }
        Start-Sleep -Milliseconds 250
    } while ($timer.Elapsed.TotalSeconds -lt 30)
    throw 'The original Desktop window did not reach the expected visibility'
}
function Test-WatchedFolder {
    $photoTool = Join-Path $PSScriptRoot 'qualify_installed_photo.mjs'
    & node $photoTool watch-signup
    if ($LASTEXITCODE) { throw 'A fresh disposable Library is required' }
    Press ('Enter Address' + [char]0x2026)
    Fill 'Server address' 'http://127.0.0.1:2283'
    Press 'Continue'
    Fill 'Account' 'native-photo@example.invalid'
    Fill 'Password' $env:FRAMELEAF_SYNTHETIC_PHOTO_PASSWORD
    Press 'Sign In'
    Press 'Photo sources'
    Press ('Add Folder' + [char]0x2026)
    Pick-WatchedFolder $WatchedFolder
    $null = Wait-Control $WatchedFolder
    Check-Box 'Watch this folder'
    Check-Box 'Allow Frameleaf to read this folder in the background'
    Press 'Approve and Watch'
    $null = Wait-Control 'Pause Watching' -Type Button -Seconds 120

    $app.Refresh()
    $handle = $app.MainWindowHandle
    $window = [System.Windows.Automation.AutomationElement]::FromHandle($handle)
    $window.GetCurrentPattern([System.Windows.Automation.WindowPattern]::Pattern).Close()
    Wait-WindowVisibility $handle $false
    $original = Join-Path $WatchedFolder 'synthetic-watched-photo.png'
    & node $photoTool watch-create $original
    if ($LASTEXITCODE) { throw 'Could not create the synthetic watched original' }
    $originalHash = (Get-FileHash -LiteralPath $original -Algorithm SHA256).Hash
    & node $photoTool watch-verify
    if ($LASTEXITCODE) { throw 'The watched original did not verify while Desktop was hidden' }
    Wait-WindowVisibility $handle $false
    if ((Get-FileHash -LiteralPath $original -Algorithm SHA256).Hash -ne $originalHash) {
        throw 'Watcher changed the source original'
    }

    $second = Start-Process -FilePath $Executable -PassThru
    if (!$second.WaitForExit(20000)) {
        Stop-Process -Id $second.Id -Force
        throw 'Expected a second launch to reopen the original Desktop process'
    }
    Wait-WindowVisibility $handle $true
    $null = Wait-Control 'Pause Watching' -Type Button -Seconds 30
    Press ('Remove' + [char]0x2026)
    Press 'Remove Permission'
    $null = Wait-Control 'No folder approved'
    Press 'Overview'
    Press ('Sign Out' + [char]0x2026)
    Press 'Sign Out'
    $null = Wait-Control 'Welcome'
    Write-Output 'Installed Desktop watched a synthetic folder while hidden, verified the copy, and reopened with watching still active'
}

if ($WatchedFolder) {
    if ($InstalledHost -or $env:GITHUB_ACTIONS -ne 'true' -or $env:FRAMELEAF_SYNTHETIC_PHOTO_PASSWORD.Length -lt 32) {
        throw 'Requires the installed watched-folder fixture on a disposable Windows runner'
    }
    if ([Console]::ReadLine() -cne 'frameleaf-watch-smoke') { throw 'The owned acceptance harness must launch this check' }
    $folder = Get-Item -LiteralPath $WatchedFolder
    if (!$folder.PSIsContainer -or ($folder.Attributes -band [IO.FileAttributes]::ReparsePoint) -or
        $folder.Name -cnotmatch '^frameleaf-watch-source-[a-f0-9-]{36}$' -or
        $folder.Parent.FullName -ine (Get-Item -LiteralPath $env:USERPROFILE).FullName -or
        (Get-ChildItem -LiteralPath $WatchedFolder -Force | Select-Object -First 1) -or
        (Get-Process -Name frameleaf-desktop -ErrorAction SilentlyContinue)) {
        throw 'Expected a fresh synthetic watch folder and no running Desktop app'
    }
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class FrameleafSmokeWindow {
    [DllImport("user32.dll")] public static extern bool IsWindow(IntPtr handle);
    [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr handle);
}
'@
}
if ($InstalledHost) {
    if (Test-Path (Join-Path $env:LOCALAPPDATA 'Frameleaf Desktop Host')) { throw 'Expected a fresh user profile' }
    if (Get-NetTCPConnection -State Listen -LocalPort 2283,9443,54329 -ErrorAction SilentlyContinue) { throw 'Expected unused local server ports' }
}
$app = Start-Process -FilePath $Executable -PassThru
try {
    $null = Wait-Control 'Welcome'
    # Welcome lists servers on this network and always offers another server by its address.
    $null = Wait-Control 'Another server'
    if ($WatchedFolder) { Test-WatchedFolder; return }
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
    $null = Wait-Control 'Another server'
    Write-Output 'Installed Welcome, native host discovery, and return to connection passed'
} finally {
    if ($InstalledHost) {
        Remove-Item Env:FRAMELEAF_SYNTHETIC_PHOTO_PASSWORD -ErrorAction SilentlyContinue
        if ($receipt -and (Test-Path $receipt)) { Remove-Item -LiteralPath $receipt }
    }
    if (!$app.HasExited) { Stop-Process -Id $app.Id -Force }
}
