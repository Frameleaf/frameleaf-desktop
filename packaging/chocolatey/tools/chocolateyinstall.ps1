$ErrorActionPreference = 'Stop'

$packageArgs = @{
  packageName    = $env:ChocolateyPackageName
  fileType       = 'msi'
  url64bit       = 'https://github.com/Frameleaf/frameleaf-desktop/releases/download/v0.1.5/Frameleaf_0.1.5_x64_en-US-unsigned.msi'
  checksum64     = 'd0f7d106397e3dd340f31d1c8012e14a14e85cbddd4610d528bd47c9aa6f1c50'
  checksumType64 = 'sha256'
  softwareName   = 'Frameleaf'
  silentArgs     = "/qn /norestart /l*v `"$($env:TEMP)\$($env:ChocolateyPackageName).$($env:ChocolateyPackageVersion).MsiInstall.log`""
  validExitCodes = @(0, 1641, 3010)
}

Install-ChocolateyPackage @packageArgs
