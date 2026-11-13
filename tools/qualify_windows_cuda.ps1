<#
.SYNOPSIS
Qualify the Windows CUDA runtime pack on this computer's NVIDIA card, end to end.

.DESCRIPTION
One run, the same on a GitHub runner and on a PC:

  1. `nvidia-smi` must report an NVIDIA card (driver, model, memory). No card: the run fails.
  2. The exact pack the app ships is built: profile `cuda-ort` of runtime/profiles.json, from
     its `sourceRevision` of Frameleaf/frameleaf-app, with tools/build_runtime.py (locked,
     hash-checked wheels). It is then moved to a folder as deep as an installed pack, with a
     space and non-ASCII characters in it, as under a user's profile.
  3. tools/smoke_accelerated_runtime.py: a session must be created on CUDAExecutionProvider and run.
  4. tools/check_windows_cuda_libraries.py --session: every NVIDIA library the provider needs is
     in the pack and is found the way the app starts the runtime; the libraries loaded are listed.
  5. The app's own qualification (the ignored test
     `local_pack_qualifies_each_provider_against_the_catalogue`) downloads the catalogue's models
     and qualifies every profile of buffalo_s, buffalo_l, PP-OCRv5_mobile and ViT-B-32__openai on
     CUDA and on the processor, through the code the app runs.
  6. The run passes only if every profile qualified on CUDA with nodes executed by
     CUDAExecutionProvider on a card the driver reports, and qualified on the processor.

Evidence (nvidia-smi, timings, providers, loaded libraries, reports) is written to -Output.
Nothing is signed, published or installed.

Needs: git, Python 3.12, Node.js, Rust (cargo), and access to Frameleaf/frameleaf-app. `uv` 0.11.2
is installed into a private folder when it is not already that version. About 15 GB of disk.

.PARAMETER ServerSource
A git checkout of Frameleaf/frameleaf-app. It is switched to the pack's source revision. Without
it the repository is cloned into -Work.

.PARAMETER Work
Where the pack, models and build go. Default: %LOCALAPPDATA%\frameleaf-cuda-hardware. It must be
a folder only this user can write to (under the user's profile): the app refuses to keep models
anywhere else.

.PARAMETER Output
Where the evidence goes. Default: <Work>\evidence. A folder of its own: it must be new, empty, or
the evidence folder of an earlier run of this script, whose contents are then replaced. It may not
be, contain or lie inside the Desktop checkout or -ServerSource, and inside -Work only the default
is accepted. Anything else is refused before a single file is touched.

.PARAMETER WithoutGpuRehearsal
For CI on a computer WITHOUT a card only: runs every step, expects the processor to qualify and
CUDA to be refused cleanly. It proves the script and the refusal path, never CUDA; its verdict is
REHEARSAL and can not be mistaken for a pass.

.EXAMPLE
powershell -ExecutionPolicy Bypass -File tools\qualify_windows_cuda.ps1
#>
[CmdletBinding()]
param(
    [string]$ServerSource,
    [string]$Work = (Join-Path $env:LOCALAPPDATA 'frameleaf-cuda-hardware'),
    [string]$Output,
    [switch]$WithoutGpuRehearsal
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$Provider = 'CUDAExecutionProvider'
$Processor = 'CPUExecutionProvider'
# What the app reports when the runtime itself declines to qualify (here: no card for CUDA).
$Refusal = 'runtime_qualification_failed'
$Models = @('buffalo_s', 'buffalo_l', 'PP-OCRv5_mobile', 'ViT-B-32__openai')
$Desktop = Split-Path -Parent $PSScriptRoot

function Step([string]$Text) { Write-Host "`n=== $Text ===" -ForegroundColor Cyan }
function Fail([string]$Text) { Write-Host "FAILED: $Text" -ForegroundColor Red; exit 1 }

# Run a program, show and keep everything it prints, return its exit code. (A program writing to
# its error stream must not stop the script by itself: only its exit code decides.)
function Invoke-Logged([string]$Log, [string]$Program, [string[]]$Arguments) {
    $previous = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        & $Program @Arguments 2>&1 | ForEach-Object { "$_" } | Tee-Object -FilePath $Log | Out-Host
        return $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $previous
    }
}
function Require-Tool([string]$Name, [string]$Hint) {
    if (-not (Get-Command $Name -ErrorAction SilentlyContinue)) { Fail "$Name is not installed. $Hint" }
}

# Full paths first; nothing is created or removed until the evidence folder is known to be safe.
function Full([string]$Path) { [System.IO.Path]::GetFullPath($Path).TrimEnd('\', '/') }
function Inside([string]$Path, [string]$Folder) { ($Path + '\').StartsWith($Folder + '\', [System.StringComparison]::OrdinalIgnoreCase) }
function Overlap([string]$First, [string]$Second) { (Inside $First $Second) -or (Inside $Second $First) }
$Marker = '.frameleaf-cuda-evidence'
$Work = Full $Work
$default = Join-Path $Work 'evidence'
if (-not $Output) { $Output = $default }
$Output = Full $Output
if ($ServerSource) { $ServerSource = Full $ServerSource }
if (Overlap $Output (Full $Desktop)) { Fail "-Output ($Output) overlaps the Desktop checkout; give it a folder of its own" }
if ($ServerSource -and (Overlap $Output $ServerSource)) { Fail "-Output ($Output) overlaps -ServerSource; give it a folder of its own" }
if ((Overlap $Output $Work) -and $Output -ne (Full $default)) { Fail "-Output ($Output) overlaps -Work; inside it only $default is accepted" }
if ($ServerSource -and (Overlap $Work $ServerSource)) { Fail '-Work overlaps -ServerSource' }
if (Overlap $Work (Full $Desktop)) { Fail '-Work overlaps the Desktop checkout' }
if (Test-Path -LiteralPath $Output) {
    if (-not (Test-Path -LiteralPath $Output -PathType Container)) { Fail "-Output ($Output) is a file" }
    $existing = @(Get-ChildItem -LiteralPath $Output -Force)
    if ($existing.Count -gt 0) {
        if (-not (Test-Path -LiteralPath (Join-Path $Output $Marker))) { Fail "-Output ($Output) is not empty and is not this script's evidence folder; nothing was removed" }
        $existing | Remove-Item -Recurse -Force
    }
}
New-Item -ItemType Directory -Force -Path $Work | Out-Null
New-Item -ItemType Directory -Force -Path $Output | Out-Null
Set-Content -LiteralPath (Join-Path $Output $Marker) -Value 'Evidence of tools/qualify_windows_cuda.ps1; replaced by its next run.'
$Reports = Join-Path $Output 'reports'
New-Item -ItemType Directory -Force -Path $Reports | Out-Null

# 1. The card.
Step 'NVIDIA card'
$smi = Get-Command 'nvidia-smi.exe' -ErrorAction SilentlyContinue
if (-not $smi) {
    $candidate = Join-Path $env:SystemRoot 'System32\nvidia-smi.exe'
    if (Test-Path $candidate) { $smi = Get-Item $candidate }
}
$cards = @()
if ($smi) {
    $smiPath = if ($smi -is [System.IO.FileInfo]) { $smi.FullName } else { $smi.Source }
    $code = Invoke-Logged (Join-Path $Output 'nvidia-smi.txt') $smiPath @()
    if ($code -eq 0) {
        $cards = @(& $smiPath '--query-gpu=name,driver_version,memory.total' '--format=csv,noheader' | Where-Object { $_ -and $_.Trim() })
        if ($LASTEXITCODE -ne 0) { $cards = @() }
    }
}
$driverLibrary = Test-Path (Join-Path $env:SystemRoot 'System32\nvcuda.dll')
Write-Host "cards: $($cards.Count); driver library nvcuda.dll present: $driverLibrary"
$cards | ForEach-Object { Write-Host "  $_" }
if ($WithoutGpuRehearsal) {
    if ($cards.Count -gt 0) { Fail 'this computer has an NVIDIA card: run without -WithoutGpuRehearsal' }
    Write-Host 'REHEARSAL: no card here. This run can not show that CUDA works.' -ForegroundColor Yellow
} elseif ($cards.Count -eq 0) {
    Fail 'nvidia-smi reports no NVIDIA card (or is not installed). This check needs a Windows computer with an NVIDIA card and its driver.'
}

# 2. Tools.
Step 'Tools'
Require-Tool 'git' 'Install Git for Windows.'
Require-Tool 'python' 'Install Python 3.12.'
Require-Tool 'npm' 'Install Node.js.'
Require-Tool 'cargo' 'Install Rust from https://rustup.rs.'
$profiles = Get-Content -Raw (Join-Path $Desktop 'runtime\profiles.json') | ConvertFrom-Json
$packProfile = $profiles.profiles.'cuda-ort'
$revision = $packProfile.sourceRevision
if ($packProfile.provider -ne $Provider -or $revision -notmatch '^[a-f0-9]{40}$') { Fail 'runtime/profiles.json has no usable cuda-ort profile' }
$uvVersion = ''
if (Get-Command 'uv' -ErrorAction SilentlyContinue) { $uvVersion = (& uv --version) -join ' ' }
if ($uvVersion -notmatch "^uv $([regex]::Escape($packProfile.uv))(\s|$)") {
    $tools = Join-Path $Work 'tools-venv'
    if (-not (Test-Path (Join-Path $tools 'Scripts\uv.exe'))) {
        if ((Invoke-Logged (Join-Path $Output 'uv-install.txt') 'python' @('-m', 'venv', $tools)) -ne 0) { Fail 'could not create a folder for uv' }
        $pip = Join-Path $tools 'Scripts\python.exe'
        if ((Invoke-Logged (Join-Path $Output 'uv-install.txt') $pip @('-m', 'pip', 'install', '--quiet', "uv==$($packProfile.uv)")) -ne 0) { Fail 'could not install uv' }
    }
    $env:PATH = (Join-Path $tools 'Scripts') + ';' + $env:PATH
}
Write-Host "runtime source revision $revision; $((& uv --version) -join ' ')"

# The runtime source, at the revision the profile names.
if (-not $ServerSource) {
    $ServerSource = Join-Path $Work 'frameleaf-app'
    if (-not (Test-Path (Join-Path $ServerSource '.git'))) {
        if ((Invoke-Logged (Join-Path $Output 'source.txt') 'git' @('clone', '--filter=blob:none', 'https://github.com/Frameleaf/frameleaf-app.git', $ServerSource)) -ne 0) { Fail 'could not clone Frameleaf/frameleaf-app (sign in to GitHub with access to it)' }
    }
}
$ServerSource = (Resolve-Path $ServerSource).Path
$head = (& git -C $ServerSource rev-parse HEAD) -join ''
if ($head -ne $revision) {
    $null = Invoke-Logged (Join-Path $Output 'source.txt') 'git' @('-C', $ServerSource, 'fetch', 'origin', $revision)
    if ((Invoke-Logged (Join-Path $Output 'source.txt') 'git' @('-C', $ServerSource, 'checkout', '--detach', $revision)) -ne 0) { Fail "could not check out $revision in $ServerSource" }
}

# 3. The pack, then where an installed pack lives: as deep as
# C:\Users\<20 characters>\AppData\Local\app.frameleaf.desktop\gpu\releases\<id>\payload,
# with a space and non-ASCII characters in the path. (Characters by code: this file stays ASCII.)
Step 'Build the cuda-ort pack'
$built = Join-Path $Work 'pack'
$installPrefix = 'C:\Users\'.Length + 20 + '\AppData\Local\app.frameleaf.desktop\gpu\releases\'.Length + 64 + '\payload\'.Length
$name = 'Zo' + [char]0x00EB + ' ' + [char]0x7528 + [char]0x6237
$pad = $installPrefix - ($Work.Length + 1 + $name.Length + '\releases\'.Length + 64 + '\payload\'.Length)
if ($pad -gt 1) { $name = $name + ' ' + ('x' * ($pad - 1)) } else { Write-Host "note: -Work is already deep; the pack path is longer than an installed one by $(-$pad) characters" }
$home_ = Join-Path $Work $name
$pack = Join-Path (Join-Path $home_ 'releases') ('a' * 64)
foreach ($stale in @($built, $home_)) { if (Test-Path -LiteralPath $stale) { Remove-Item -LiteralPath $stale -Recurse -Force } }
$code = Invoke-Logged (Join-Path $Output 'build.txt') 'python' @((Join-Path $Desktop 'tools\build_runtime.py'), '--source', $ServerSource, '--output', $built, '--revision', $revision, '--epoch', '7', '--profile', 'cuda-ort')
if ($code -ne 0) {
    $errorLog = Join-Path $Work '.pack.error.log'
    if (Test-Path $errorLog) { Get-Content $errorLog -Tail 60 | Out-Host; Copy-Item $errorLog (Join-Path $Output 'build-error.txt') }
    Fail 'the pack did not build'
}
New-Item -ItemType Directory -Force -Path (Split-Path -Parent $pack) | Out-Null
Move-Item -LiteralPath $built -Destination $pack
$payload = Join-Path $pack 'payload'
$python = Join-Path $payload 'python\python.exe'
Write-Host "pack: $pack"
Write-Host "payload folder is $(("$payload\").Length) characters deep (an installed one: $installPrefix)"
$manifest = Get-Content -Raw -Encoding UTF8 (Join-Path $pack 'manifest-accelerated.json') | ConvertFrom-Json
if ($manifest.provider -ne $Provider -or $manifest.sourceRevision -ne $revision) { Fail 'the pack is not the cuda-ort pack of this revision' }
Copy-Item (Join-Path $pack 'manifest-accelerated.json') $Output
Copy-Item (Join-Path $payload 'requirements.txt') $Output

$failures = New-Object System.Collections.Generic.List[string]

# 4. A session on the card, and the libraries.
Step 'CUDA session (smoke)'
$code = Invoke-Logged (Join-Path $Output 'smoke.txt') $python @('-I', '-B', (Join-Path $Desktop 'tools\smoke_accelerated_runtime.py'), $Provider)
if ($code -ne 0) { $failures.Add('the pack did not pass tools/smoke_accelerated_runtime.py') }
elseif (-not $WithoutGpuRehearsal -and -not (Select-String -Path (Join-Path $Output 'smoke.txt') -SimpleMatch 'CUDA session ran on the card' -Quiet)) {
    $failures.Add('the smoke check did not run a CUDA session on the card')
}

Step 'NVIDIA libraries: needed, carried, found'
$arguments = @('-I', '-B', (Join-Path $Desktop 'tools\check_windows_cuda_libraries.py'), '--pack', $pack, '--output', $Output)
if (-not $WithoutGpuRehearsal) { $arguments += '--session' }
$code = Invoke-Logged (Join-Path $Output 'libraries.txt') $python $arguments
if ($code -ne 0) { $failures.Add('the pack did not pass tools/check_windows_cuda_libraries.py') }
$libraries = $null
$librariesPath = Join-Path $Output 'cuda-libraries.json'
if (Test-Path $librariesPath) { $libraries = Get-Content -Raw -Encoding UTF8 $librariesPath | ConvertFrom-Json }
$sessionProviders = @()
if ($libraries -and $libraries.loader.PSObject.Properties['sessionProviders']) { $sessionProviders = @($libraries.loader.sessionProviders) }
if ($libraries -and $libraries.loader.PSObject.Properties['loadedLibraries']) {
    @($libraries.loader.loadedLibraries) | Set-Content -Encoding UTF8 (Join-Path $Output 'loaded-libraries.txt')
}
if (-not $WithoutGpuRehearsal -and ($sessionProviders.Count -eq 0 -or $sessionProviders[0] -ne $Provider)) {
    $failures.Add("the session's providers are [$($sessionProviders -join ', ')], not $Provider first: onnxruntime fell back to the processor")
}

# 5. The app's own qualification of every profile, on both providers.
Step 'Qualification of every profile on CUDA and on the processor'
Push-Location $Desktop
try {
    if ((Invoke-Logged (Join-Path $Output 'frontend.txt') 'npm' @('ci')) -ne 0) { Fail 'npm ci failed' }
    if ((Invoke-Logged (Join-Path $Output 'frontend.txt') 'npm' @('run', 'build')) -ne 0) { Fail 'npm run build failed' }
} finally { Pop-Location }
$cache = Join-Path $Work 'models'
New-Item -ItemType Directory -Force -Path $cache | Out-Null
$env:FRAMELEAF_TEST_ACCELERATED_PACK = $pack
$env:FRAMELEAF_TEST_MODEL_CACHE = $cache
$env:FRAMELEAF_TEST_QUALIFY_MODELS = $Models -join ','
$env:FRAMELEAF_TEST_QUALIFY_REPORTS = $Reports
Push-Location (Join-Path $Desktop 'src-tauri')
try {
    $cargo = Invoke-Logged (Join-Path $Output 'qualification.txt') 'cargo' @('test', '--locked', '--lib', 'native_runtime::metal::local_pack::local_pack_qualifies_each_provider_against_the_catalogue', '--', '--ignored', '--exact', '--nocapture')
} finally { Pop-Location }

# 6. The verdict, from the reports themselves.
Step 'Verdict'
$records = @(Get-ChildItem -Path $Reports -Filter 'qualification-*.json' | Sort-Object Name | ForEach-Object { Get-Content -Raw -Encoding UTF8 $_.FullName | ConvertFrom-Json })
function Key($Record) { "$($Record.model) $($Record.fixtureKind)" }
$rows = @()
$cuda = @($records | Where-Object { $_.provider -eq $Provider })
$cpu = @($records | Where-Object { $_.provider -eq $Processor })
if ($cuda.Count -lt 6) { $failures.Add("only $($cuda.Count) CUDA profiles were tried; six are required") }
if ($cpu.Count -ne $cuda.Count) { $failures.Add("the processor tried $($cpu.Count) profiles and CUDA $($cuda.Count)") }
foreach ($model in $Models) {
    foreach ($side in @($Provider, $Processor)) {
        if (@($records | Where-Object { $_.model -eq $model -and $_.provider -eq $side }).Count -eq 0) { $failures.Add("$model was not tried on $side") }
    }
}
foreach ($record in $cpu) {
    if (-not $record.qualified) { $failures.Add("$(Key $record) did not qualify on the processor: $($record.failure)") }
}
for ($index = 0; $index -lt $cuda.Count; $index++) {
    $record = $cuda[$index]
    $twin = if ($index -lt $cpu.Count -and (Key $cpu[$index]) -eq (Key $record)) { $cpu[$index] } else { $null }
    if (-not $twin) { $failures.Add("$(Key $record) has no processor twin in the same position") }
    $cpuWarm = if ($twin -and $twin.qualified) { [double]$twin.report.warmMilliseconds } else { $null }
    $row = [ordered]@{ profile = (Key $record); cpuWarmMs = $cpuWarm; cudaWarmMs = $null; cudaColdMs = $null; state = 'NOT QUALIFIED'; cudaNodes = 0; processorNodes = 0; cards = 0 }
    if ($record.qualified) {
        $report = $record.report
        $row.cudaWarmMs = [double]$report.warmMilliseconds
        $row.cudaColdMs = [double]$report.coldMilliseconds
        $row.state = $report.state
        foreach ($item in @($report.execution)) {
            $onCard = $item.nodes.PSObject.Properties[$Provider]
            $onProcessor = $item.nodes.PSObject.Properties[$Processor]
            if (-not $onCard -or [int]$onCard.Value -le 0) { $failures.Add("$(Key $record): a model ran no node on $Provider") } else { $row.cudaNodes += [int]$onCard.Value }
            if ($onProcessor) { $row.processorNodes += [int]$onProcessor.Value }
        }
        $row.cards = @($report.runtime.gpus).Count
        if ($report.provider -ne $Provider) { $failures.Add("$(Key $record): the report is for $($report.provider)") }
        if ($report.state -notin @('ready-accelerator', 'ready-mixed')) { $failures.Add("$(Key $record): state $($report.state)") }
        if ($row.cards -lt 1) { $failures.Add("$(Key $record): the report names no card") }
        if ($WithoutGpuRehearsal) { $failures.Add("$(Key $record) qualified on CUDA on a computer said to have no card") }
    } elseif (-not $WithoutGpuRehearsal) {
        $failures.Add("$(Key $record) did not qualify on CUDA: $($record.failure)")
    } elseif ($record.failure -eq $Refusal) {
        $row.state = "refused ($($record.failure))"
    } else {
        # Only the runtime's own refusal counts: a process that did not start or did not finish is a fault.
        $row.state = "FAULT ($($record.failure))"
        $failures.Add("$(Key $record): CUDA was not refused cleanly without a card: $($record.failure)")
    }
    $rows += New-Object PSObject -Property $row
}
if (-not $WithoutGpuRehearsal -and $cargo -ne 0) { $failures.Add("the qualification test exited with $cargo") }
if ($WithoutGpuRehearsal -and $records.Count -eq 0) { $failures.Add('the qualification test wrote no report') }

$verdict = if ($failures.Count -gt 0) { 'FAILED' } elseif ($WithoutGpuRehearsal) { 'REHEARSAL (no card: CUDA not verified)' } else { 'QUALIFIED' }
$format = { param($Value) if ($null -eq $Value) { '-' } else { '{0:N1}' -f $Value } }
$lines = @("# Windows CUDA on hardware: $verdict", '')
$lines += "- Card: $(if ($cards.Count) { $cards -join '; ' } else { 'none' })"
$lines += "- Pack: cuda-ort, runtime source ``$revision``, onnxruntime $(if ($libraries) { $libraries.onnxruntime } else { '?' }), payload $(if ($libraries) { '{0:N2} GB' -f ($libraries.payloadBytes / 1GB) } else { '?' })"
$lines += "- Session providers: $(if ($sessionProviders.Count) { $sessionProviders -join ', ' } else { 'not created (no card)' })"
$lines += ''
$lines += '| Profile | Processor warm (ms) | CUDA warm (ms) | CUDA cold (ms) | CUDA state | Nodes on CUDA / processor | Speed-up |'
$lines += '| --- | --- | --- | --- | --- | --- | --- |'
foreach ($row in $rows) {
    $speed = if ($row.cpuWarmMs -and $row.cudaWarmMs) { '{0:N1}x' -f ($row.cpuWarmMs / $row.cudaWarmMs) } else { '-' }
    $lines += "| $($row.profile) | $(& $format $row.cpuWarmMs) | $(& $format $row.cudaWarmMs) | $(& $format $row.cudaColdMs) | $($row.state) | $($row.cudaNodes) / $($row.processorNodes) | $speed |"
}
if ($failures.Count -gt 0) { $lines += ''; $lines += 'Failures:'; $failures | ForEach-Object { $lines += "- $_" } }
$lines | Set-Content -Encoding UTF8 (Join-Path $Output 'summary.md')
[ordered]@{ verdict = $verdict; cards = $cards; revision = $revision; sessionProviders = $sessionProviders; profiles = $rows; failures = @($failures) } |
    ConvertTo-Json -Depth 6 | Set-Content -Encoding UTF8 (Join-Path $Output 'summary.json')
if ($env:GITHUB_STEP_SUMMARY) {
    $lines | Add-Content -Encoding UTF8 $env:GITHUB_STEP_SUMMARY
    $table = Join-Path $Output 'cuda-libraries.md'
    if (Test-Path $table) { Get-Content -Encoding UTF8 $table | Add-Content -Encoding UTF8 $env:GITHUB_STEP_SUMMARY }
}
$lines | Out-Host
Write-Host "`nEvidence: $Output"
Write-Host "Pack, models and build are in $Work (delete that folder when done)."
if ($failures.Count -gt 0) { exit 1 }
Write-Host $verdict -ForegroundColor Green
exit 0
