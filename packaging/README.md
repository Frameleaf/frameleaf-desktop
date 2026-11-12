# Package manager packaging

| Manager | Where it lives | Install |
| --- | --- | --- |
| Homebrew | [Frameleaf/homebrew-tap](https://github.com/Frameleaf/homebrew-tap) | `brew install --cask frameleaf/tap/frameleaf` |
| Scoop | [Frameleaf/scoop-bucket](https://github.com/Frameleaf/scoop-bucket) | `scoop bucket add frameleaf https://github.com/Frameleaf/scoop-bucket` then `scoop install frameleaf/frameleaf` |
| winget | `Frameleaf.Desktop` in [microsoft/winget-pkgs](https://github.com/microsoft/winget-pkgs) | `winget install Frameleaf.Desktop` |
| Chocolatey | [`chocolatey/`](chocolatey/) | `choco install frameleaf` |
| AUR | [`aur/`](aur/), published as `frameleaf-desktop-bin` | `yay -S frameleaf-desktop-bin` |

The Chocolatey and AUR files here always state the application version; `npm test` fails when they differ from
`package.json`, `src-tauri/Cargo.toml` or `src-tauri/tauri.conf.json`. After changing the version, run
`node tools/release_packaging.mjs` to restamp them. Checksums are never typed by hand: until a release supplies
them they read `checksum-pending-release`, which makes both package managers refuse the download.

The `Signed desktop release` workflow stamps the checksums from the release's own `SHA256SUMS` and keeps the result
as the `package-manager-files` artifact; its run summary says which packages are publishable. To stamp from a
published release instead, download its `SHA256SUMS` and run `node tools/release_packaging.mjs <path to SHA256SUMS>`.

Chocolatey installs only the signed MSI (`Frameleaf_<version>_x64_en-US.msi`). While a release has no signed Windows
installer, `chocolateyinstall.ps1` starts with a `throw` and the package must not be pushed. AUR is publishable once
both Linux DEB checksums are stamped.

For the other managers, update the version, URLs and SHA256s (from the release's `SHA256SUMS`) on each release.
Scoop's `autoupdate` and Homebrew's `livecheck` follow GitHub releases.

## Publishing Chocolatey

Needs a [community.chocolatey.org](https://community.chocolatey.org/) account and its API key, on Windows:

```powershell
choco apikey --key <api key> --source https://push.chocolatey.org/
cd packaging\chocolatey
choco pack
choco push frameleaf.<version>.nupkg --source https://push.chocolatey.org/
```

Moderation then runs automated validation and an install test before a human review.

## Publishing the AUR package

Needs an [AUR account](https://aur.archlinux.org/register) with an SSH public key in *My Account*, and that key
configured for `aur.archlinux.org` in `~/.ssh/config`:

```sh
git clone ssh://aur@aur.archlinux.org/frameleaf-desktop-bin.git
cp packaging/aur/PKGBUILD packaging/aur/.SRCINFO frameleaf-desktop-bin/
cd frameleaf-desktop-bin
git add PKGBUILD .SRCINFO
git commit -m "Frameleaf Desktop <version>"
git push
```

The stamping script keeps `.SRCINFO` in step with the version and checksums. After any other PKGBUILD edit,
regenerate it with `makepkg --printsrcinfo > .SRCINFO`.
