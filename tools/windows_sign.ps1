param(
    [Parameter(Mandatory)][string]$Path,
    [switch]$VerifyOnly
)
$ErrorActionPreference = 'Stop'
$file = Get-Item -LiteralPath $Path
if ($file.PSIsContainer) { throw 'Expected a Windows signing file' }
# Tauri also signs resources; the factory inventory already authenticates these exact bytes.
$runtime = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../release-runtime')) + [IO.Path]::DirectorySeparatorChar
if (!$VerifyOnly -and $file.FullName.StartsWith($runtime, [StringComparison]::OrdinalIgnoreCase)) { return }
if ($file.Extension -notin '.exe', '.dll', '.msi') { throw 'Expected a Windows executable, DLL or MSI' }
if ([string]::IsNullOrWhiteSpace($env:WINDOWS_SIGNING_SUBJECT)) { throw 'Missing Windows publisher subject' }

if (!$VerifyOnly) {
    foreach ($name in 'AZURE_SIGNING_ENDPOINT', 'AZURE_SIGNING_ACCOUNT', 'AZURE_SIGNING_PROFILE') {
        if ([string]::IsNullOrWhiteSpace([Environment]::GetEnvironmentVariable($name))) { throw "Missing $name" }
    }
    Import-Module ArtifactSigning -RequiredVersion 0.1.20
    # Use only the Azure CLI session established by GitHub OIDC.
    Invoke-ArtifactSigning -Endpoint $env:AZURE_SIGNING_ENDPOINT `
        -CodeSigningAccountName $env:AZURE_SIGNING_ACCOUNT -CertificateProfileName $env:AZURE_SIGNING_PROFILE `
        -Files $file.FullName -FileDigest SHA256 -TimestampRfc3161 'http://timestamp.acs.microsoft.com' `
        -TimestampDigest SHA256 -Description Frameleaf -DescriptionUrl 'https://frameleaf.app' `
        -ExcludeEnvironmentCredential -ExcludeWorkloadIdentityCredential -ExcludeManagedIdentityCredential `
        -ExcludeSharedTokenCacheCredential -ExcludeVisualStudioCredential -ExcludeVisualStudioCodeCredential `
        -ExcludeAzurePowerShellCredential -ExcludeAzureDeveloperCliCredential -ExcludeInteractiveBrowserCredential
}

# Azure certificates rotate frequently; bind to the verified publisher, not a leaf thumbprint.
$signature = Get-AuthenticodeSignature -LiteralPath $file.FullName
if ($signature.Status -ne 'Valid' -or !$signature.SignerCertificate -or
    $signature.SignerCertificate.Subject -cne $env:WINDOWS_SIGNING_SUBJECT -or
    !$signature.TimeStamperCertificate) {
    throw "Invalid or untimestamped publisher signature: $($file.Name)"
}
