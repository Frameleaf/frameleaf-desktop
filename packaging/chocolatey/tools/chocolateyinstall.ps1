$ErrorActionPreference = 'Stop'

$packageArgs = @{
  packageName    = $env:ChocolateyPackageName
  fileType       = 'msi'
  url64bit       = 'https://github.com/Frameleaf/frameleaf-desktop/releases/download/v0.1.1/Frameleaf_0.1.1_x64_en-US-unsigned.msi'
  checksum64     = '100bf753d0328ebdaf87e6a8023ef5e2582b0ccfefdfd0023944e36781d3bb89'
  checksumType64 = 'sha256'
  softwareName   = 'Frameleaf'
  silentArgs     = "/qn /norestart /l*v `"$($env:TEMP)\$($env:ChocolateyPackageName).$($env:ChocolateyPackageVersion).MsiInstall.log`""
  validExitCodes = @(0, 1641, 3010)
}

Install-ChocolateyPackage @packageArgs
