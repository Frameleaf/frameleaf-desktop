param([Parameter(Mandatory)][string]$Executable)

$ErrorActionPreference = 'Stop'
if ($env:RUNNER_ENVIRONMENT -ne 'github-hosted') { throw 'Requires a disposable Windows runner' }
Add-Type -AssemblyName UIAutomationClient
Add-Type -AssemblyName UIAutomationTypes
$tree = [System.Windows.Automation.TreeScope]::Descendants
$all = [System.Windows.Automation.Condition]::TrueCondition

function Wait-Control([string]$Name, [switch]$Radio) {
    $timer = [Diagnostics.Stopwatch]::StartNew()
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
                } elseif ($label -eq $Name) { return $control }
            }
        }
        Start-Sleep -Milliseconds 350
    } while ($timer.Elapsed.TotalSeconds -lt 45)
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

$app = Start-Process -FilePath $Executable -PassThru
try {
    $null = Wait-Control 'Welcome'
    $null = Wait-Control 'Server address'
    Select-Radio (Wait-Control 'Run Frameleaf here' -Radio)
    $null = Wait-Control 'Server component not installed'
    Select-Radio (Wait-Control 'Connect to my server' -Radio)
    $null = Wait-Control 'Server address'
    Write-Output 'Installed Welcome, native host discovery, and return to connection passed'
} finally {
    if (!$app.HasExited) { Stop-Process -Id $app.Id -Force }
}
