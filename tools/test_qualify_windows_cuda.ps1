<#
.SYNOPSIS
What tools/qualify_windows_cuda.ps1 does with its evidence folder when junctions are involved.
Windows only; run in the PowerShell under test (Windows PowerShell 5.1 and PowerShell 7 alike).
Each case runs the script with -PrepareOutputOnly, which stops once the evidence folder is ready.
#>
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$script = Join-Path $PSScriptRoot 'qualify_windows_cuda.ps1'
$shell = (Get-Process -Id $PID).Path
$root = Join-Path ([System.IO.Path]::GetTempPath()) "fl-evidence-$([guid]::NewGuid().ToString('N'))"
$marker = '.frameleaf-cuda-evidence'
$failures = New-Object System.Collections.Generic.List[string]
$junctions = New-Object System.Collections.Generic.List[string]

function Folder([string]$Path) { New-Item -ItemType Directory -Force -Path $Path | Out-Null; $Path }
function Keep([string]$Folder) { $file = Join-Path (Folder $Folder) 'keep.txt'; Set-Content -LiteralPath $file -Value 'keep'; $file }
function Junction([string]$Link, [string]$Target) { New-Item -ItemType Junction -Path $Link -Target $Target | Out-Null; $junctions.Add($Link); $Link }
function Run([string]$Case, [int]$Expected, [string[]]$Arguments) {
    $output = & $shell -NoProfile -ExecutionPolicy Bypass -File $script @Arguments -PrepareOutputOnly 2>&1 | ForEach-Object { "$_" }
    $code = $LASTEXITCODE
    Write-Host "--- $Case (exit $code)"; $output | ForEach-Object { Write-Host "    $_" }
    if ($code -ne $Expected) { $failures.Add("$Case exited $code, expected $Expected") }
}
function Still([string]$Case, [string]$File) { if (-not (Test-Path -LiteralPath $File)) { $failures.Add("$Case removed $File") } }

try {
    $work = Join-Path $root 'work'

    # The review's case: -ServerSource reached through a junction into the evidence folder, which
    # carries the marker of an earlier run. Its text does not overlap -Output; where it leads does.
    $evidence = Folder (Join-Path $root 'evidence')
    Set-Content -LiteralPath (Join-Path $evidence $marker) -Value 'earlier run'
    $server = Keep (Join-Path $evidence 'server')
    Junction (Join-Path $root 'link') $evidence | Out-Null
    Run 'server source through a junction into the evidence folder' 1 @('-Output', $evidence, '-ServerSource', (Join-Path $root 'link\server'), '-Work', $work)
    Still 'server source through a junction' $server

    # An evidence folder that is itself reached through a junction is never emptied.
    Run 'evidence folder below a junction' 1 @('-Output', (Join-Path $root 'link\server'), '-Work', $work)
    Run 'evidence folder that is a junction' 1 @('-Output', (Join-Path $root 'link'), '-Work', $work)
    Still 'evidence folder through a junction' $server

    # -Work reached through a junction that leads to -ServerSource.
    $source = Folder (Join-Path $root 'source')
    $sourceFile = Keep $source
    Junction (Join-Path $root 'work-link') $source | Out-Null
    Run 'work through a junction onto the server source' 1 @('-Output', (Join-Path $root 'other'), '-ServerSource', $source, '-Work', (Join-Path $root 'work-link'))
    Still 'work through a junction' $sourceFile

    # A folder that holds other things and no marker is refused untouched.
    $foreign = Folder (Join-Path $root 'foreign')
    $foreignFile = Keep $foreign
    Run 'a folder that is not an evidence folder' 1 @('-Output', $foreign, '-Work', $work)
    Still 'not an evidence folder' $foreignFile

    # An earlier evidence folder is emptied, but a junction inside it is removed itself, never
    # what it leads to.
    $protected = Folder (Join-Path $root 'protected')
    $protectedFile = Keep $protected
    $again = Folder (Join-Path $root 'again')
    Set-Content -LiteralPath (Join-Path $again $marker) -Value 'earlier run'
    Keep (Join-Path $again 'old') | Out-Null
    Junction (Join-Path $again 'inside-link') $protected | Out-Null
    Run 'an earlier evidence folder holding a junction' 0 @('-Output', $again, '-Work', $work)
    Still 'clearing an earlier evidence folder' $protectedFile
    foreach ($gone in @('old', 'inside-link')) {
        if (Test-Path -LiteralPath (Join-Path $again $gone)) { $failures.Add("the earlier evidence folder still holds $gone") }
    }
    if (-not (Test-Path -LiteralPath (Join-Path $again $marker))) { $failures.Add('the prepared evidence folder has no marker') }

    # The default inside -Work is accepted.
    Run 'the default evidence folder' 0 @('-Work', $work)
} finally {
    # Junctions first, so removing the rest never goes through one.
    foreach ($link in $junctions) { if (Test-Path -LiteralPath $link) { [System.IO.Directory]::Delete($link, $false) } }
    Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
}
if ($failures.Count -gt 0) { $failures | ForEach-Object { Write-Host "FAILED: $_" -ForegroundColor Red }; exit 1 }
Write-Host 'evidence folder checks ok'
