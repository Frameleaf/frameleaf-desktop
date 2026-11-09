$ErrorActionPreference = 'Stop'

$packageArgs = @{
  packageName    = $env:ChocolateyPackageName
  fileType       = 'msi'
  url64bit       = 'https://github.com/Frameleaf/frameleaf-desktop/releases/download/v0.1.4/Frameleaf_0.1.4_x64_en-US-unsigned.msi'
  checksum64     = 'db4612436950dc6db6b3324ce10c42125687b8c8cc4f48ee6e674b3e445425f1'
  checksumType64 = 'sha256'
  softwareName   = 'Frameleaf'
  silentArgs     = "/qn /norestart /l*v `"$($env:TEMP)\$($env:ChocolateyPackageName).$($env:ChocolateyPackageVersion).MsiInstall.log`""
  validExitCodes = @(0, 1641, 3010)
}

Install-ChocolateyPackage @packageArgs
