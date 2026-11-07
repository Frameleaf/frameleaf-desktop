$ErrorActionPreference = 'Stop'

$packageArgs = @{
  packageName    = $env:ChocolateyPackageName
  fileType       = 'msi'
  url64bit       = 'https://github.com/Frameleaf/frameleaf-desktop/releases/download/v0.1.3/Frameleaf_0.1.3_x64_en-US-unsigned.msi'
  checksum64     = 'd9e342650fb820196702272ed250cb896877080a3894347ec38a3728ccd1f97f'
  checksumType64 = 'sha256'
  softwareName   = 'Frameleaf'
  silentArgs     = "/qn /norestart /l*v `"$($env:TEMP)\$($env:ChocolateyPackageName).$($env:ChocolateyPackageVersion).MsiInstall.log`""
  validExitCodes = @(0, 1641, 3010)
}

Install-ChocolateyPackage @packageArgs
