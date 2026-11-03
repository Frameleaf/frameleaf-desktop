$ErrorActionPreference = 'Stop'
$root = Join-Path ([IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString())
New-Item -ItemType Directory -Path $root | Out-Null
$path = Join-Path $root 'Frameleaf app.exe'
Set-Content -LiteralPath $path -Value 'test fixture'
$tools = New-Item -ItemType Directory -Path (Join-Path $root 'tools')
$signer = Join-Path $tools.FullName 'windows_sign.ps1'
Copy-Item -LiteralPath "$PSScriptRoot/windows_sign.ps1" -Destination $signer
$names = @('WINDOWS_SIGNING_SUBJECT', 'AZURE_SIGNING_ENDPOINT', 'AZURE_SIGNING_ACCOUNT', 'AZURE_SIGNING_PROFILE')
$saved = @{}
foreach ($name in $names) { $saved[$name] = [Environment]::GetEnvironmentVariable($name) }

$state = @{ Calls = 0; SignFails = $false; Signature = $null }

# Mock only the external signing service and Windows trust API.
function Import-Module { param($Name, $RequiredVersion)
    if ($Name -ne 'ArtifactSigning' -or $RequiredVersion -ne '0.1.20') { throw 'Unexpected signing module' }
}
function Invoke-ArtifactSigning {
    $state.Calls++
    if ($state.SignFails) { throw 'service unavailable' }
    $arguments = $args -join ' '
    foreach ($expected in @($path, 'SHA256', 'http://timestamp.acs.microsoft.com', '-ExcludeEnvironmentCredential', '-ExcludeInteractiveBrowserCredential')) {
        if (!$arguments.Contains($expected)) { throw "Missing signing argument: $expected" }
    }
    if ($arguments.Contains('-ExcludeAzureCliCredential')) { throw 'OIDC CLI credential excluded' }
}
function Get-AuthenticodeSignature { param($LiteralPath)
    if ($LiteralPath -ne $path) { throw 'Wrong file verified' }
    return $state.Signature
}
function Assert-Rejected([scriptblock]$Action, [string]$Message) {
    try { & $Action } catch {
        if (!$_.Exception.Message.Contains($Message)) { throw }
        return
    }
    throw "Expected rejection: $Message"
}
try {
    $env:WINDOWS_SIGNING_SUBJECT = 'CN=Fixture Publisher, C=CA'
    $env:AZURE_SIGNING_ENDPOINT = 'https://eus.codesigning.azure.net/'
    $env:AZURE_SIGNING_ACCOUNT = 'fixture'
    $env:AZURE_SIGNING_PROFILE = 'public-trust'
    $state.Calls = 0
    $state.SignFails = $false
    $state.Signature = [pscustomobject]@{
        Status = 'Valid'
        SignerCertificate = [pscustomobject]@{ Subject = $env:WINDOWS_SIGNING_SUBJECT }
        TimeStamperCertificate = [pscustomobject]@{ Subject = 'timestamp fixture' }
    }
    & $signer -Path $path
    & $signer -Path $path -VerifyOnly
    if ($state.Calls -ne 1) { throw 'Verification must not sign again' }
    $app = $path
    $path = Join-Path $root 'nsis plugin.dll'
    Set-Content -LiteralPath $path -Value 'plugin fixture'
    & $signer -Path $path
    if ($state.Calls -ne 2) { throw 'Installer plugin DLL must be signed' }
    $runtime = New-Item -ItemType Directory -Path (Join-Path $root 'release-runtime/payload')
    foreach ($extension in '.exe', '.dll') {
        $resource = Join-Path $runtime.FullName "runtime$extension"
        Set-Content -LiteralPath $resource -Value 'factory inventory fixture'
        $before = (Get-FileHash -LiteralPath $resource).Hash
        & $signer -Path $resource
        if ($state.Calls -ne 2 -or (Get-FileHash -LiteralPath $resource).Hash -ne $before) { throw 'Factory resource changed' }
    }
    $sibling = New-Item -ItemType Directory -Path (Join-Path $root 'release-runtime-other')
    $path = Join-Path $sibling.FullName 'app.exe'
    Set-Content -LiteralPath $path -Value 'not a factory resource'
    & $signer -Path $path
    if ($state.Calls -ne 3) { throw 'Runtime exclusion must require a directory boundary' }
    $path = $app
    foreach ($status in 'NotSigned', 'HashMismatch', 'NotTrusted') {
        $state.Signature.Status = $status
        Assert-Rejected { & $signer -Path $path -VerifyOnly } 'Invalid or untimestamped'
    }
    $state.Signature.Status = 'Valid'
    $state.Signature.SignerCertificate.Subject = 'CN=Other Publisher'
    Assert-Rejected { & $signer -Path $path -VerifyOnly } 'Invalid or untimestamped'
    $state.Signature.SignerCertificate.Subject = $env:WINDOWS_SIGNING_SUBJECT
    $state.Signature.TimeStamperCertificate = $null
    Assert-Rejected { & $signer -Path $path -VerifyOnly } 'Invalid or untimestamped'
    $state.SignFails = $true
    Assert-Rejected { & $signer -Path $path } 'service unavailable'
    $env:AZURE_SIGNING_PROFILE = ''
    Assert-Rejected { & $signer -Path $path } 'Missing AZURE_SIGNING_PROFILE'
    $env:WINDOWS_SIGNING_SUBJECT = ''
    Assert-Rejected { & $signer -Path $path -VerifyOnly } 'Missing Windows publisher'
    Write-Output 'Windows signing checks passed: app/plugin signing, factory resource preservation, verify-only, trust/publisher/timestamp/config checks, service failure'
} finally {
    foreach ($name in $names) { [Environment]::SetEnvironmentVariable($name, $saved[$name]) }
    Remove-Item -LiteralPath $root -Recurse -Force
}
