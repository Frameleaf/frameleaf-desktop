# Package manager packaging

| Manager | Where it lives | Install |
| --- | --- | --- |
| Homebrew | [Frameleaf/homebrew-tap](https://github.com/Frameleaf/homebrew-tap) | `brew install --cask frameleaf/tap/frameleaf` |
| Scoop | [Frameleaf/scoop-bucket](https://github.com/Frameleaf/scoop-bucket) | `scoop bucket add frameleaf https://github.com/Frameleaf/scoop-bucket` then `scoop install frameleaf/frameleaf` |
| winget | `Frameleaf.Desktop` in [microsoft/winget-pkgs](https://github.com/microsoft/winget-pkgs) | `winget install Frameleaf.Desktop` |
| Chocolatey | [`chocolatey/`](chocolatey/) | `choco install frameleaf` |
| AUR | [`aur/`](aur/), published as `frameleaf-desktop-bin` | `yay -S frameleaf-desktop-bin` |

On each release, update the version, URLs and SHA256s (from the release's `SHA256SUMS`). Scoop's `autoupdate` and
Homebrew's `livecheck` follow GitHub releases.

## Publishing Chocolatey

Needs a [community.chocolatey.org](https://community.chocolatey.org/) account and its API key, on Windows:

```powershell
choco apikey --key <api key> --source https://push.chocolatey.org/
cd packaging\chocolatey
choco pack
choco push frameleaf.0.1.4.nupkg --source https://push.chocolatey.org/
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
git commit -m "Frameleaf Desktop 0.1.4"
git push
```

Regenerate `.SRCINFO` with `makepkg --printsrcinfo > .SRCINFO` after editing the PKGBUILD.
