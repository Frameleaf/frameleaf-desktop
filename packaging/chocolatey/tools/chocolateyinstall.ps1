$ErrorActionPreference = 'Stop'
throw 'No signed Windows installer exists for Frameleaf 0.1.6, so this package must not be published.'

$packageArgs = @{
  packageName    = $env:ChocolateyPackageName
  fileType       = 'msi'
  url64bit       = 'https://github.com/Frameleaf/frameleaf-desktop/releases/download/v0.1.6/Frameleaf_0.1.6_x64_en-US.msi'
  checksum64     = 'checksum-pending-release'
  checksumType64 = 'sha256'
  softwareName   = 'Frameleaf'
  silentArgs     = "/qn /norestart /l*v `"$($env:TEMP)\$($env:ChocolateyPackageName).$($env:ChocolateyPackageVersion).MsiInstall.log`""
  validExitCodes = @(0, 1641, 3010)
}

Install-ChocolateyPackage @packageArgs
