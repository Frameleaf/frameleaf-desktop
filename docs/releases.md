# Desktop release pipeline

Tracked in [FD-2](https://heroit.atlassian.net/browse/FD-2). The first pipeline
packages the current `main` worker-enabled desktop, not the stacked native-host
drafts. CodeRabbit remains independent of Actions.

## Installed Windows watched-folder acceptance

On a fresh GitHub-hosted Windows runner, install the approved signed Library
companion with the photo-source API and the approved Desktop candidate under
`RUNNER_TEMP`. Use an interactive Windows desktop with WebView2, Node and an
unmetered network. Initialize the runner's cloud-files filter as in the Windows
compiled host qualification before running the test. Do not start the app first.

Set `FRAMELEAF_INSTALLED_HOST_MANIFEST` to the approved companion manifest
SHA-256 in lowercase hexadecimal, and `FRAMELEAF_WATCH_DESKTOP_EXE` and `FRAMELEAF_WATCH_DESKTOP_SHA256`
to the installed `frameleaf-desktop.exe` path and the verified installed
executable's SHA-256 in lowercase hexadecimal. The harness holds the executable
and directory handles across both launches. Run the test from the repository root:

```powershell
cargo test --release --locked --manifest-path src-tauri/Cargo.toml --lib host_setup::tests::disposable_runner_installed_desktop_watches_while_hidden -- --ignored --exact --nocapture
```

The test owns a temporary loopback Library and a new synthetic folder. It creates
the test image after the Desktop window hides, reads back the original and
thumbnail, and reopens the same window before revoking permission and signing
out. A passing run applies to those installed bytes.

## Installed macOS and Linux watched-folder acceptance

Use a disposable, unprivileged graphical account on Apple silicon macOS or
x86-64 Linux. Install the approved Desktop candidate and the signed Library
companion with the photo-source API. Linux needs a working system tray,
WebKitGTK, and an unlocked Secret Service session. Use an unmetered connection,
an interactive terminal, and a home directory on a supported local filesystem.
Leave ports 2283 and 54329 free. Start with a fresh Desktop profile and keychain
and leave Desktop closed before starting the harness.

From a Desktop checkout containing this harness, set the reviewed identities and
run the ignored qualification explicitly. Use the physical installed binary
path, for example `/Applications/Frameleaf.app/Contents/MacOS/frameleaf-desktop`
or `/usr/bin/frameleaf-desktop`. Install the app as an administrator so the
executable and its parent directories are root-owned and the qualification
account cannot modify them. The macOS harness also checks the bundle signature.
Copy the lowercase hashes from the reviewed companion manifest and verified
candidate, respectively.

```sh
export FRAMELEAF_WATCH_DISPOSABLE=1
export FRAMELEAF_INSTALLED_HOST_MANIFEST='<approved-companion-manifest-sha256>'
export FRAMELEAF_WATCH_DESKTOP_EXE='<physical-installed-executable>'
export FRAMELEAF_WATCH_DESKTOP_SHA256='<verified-executable-sha256>'
cargo test --release --locked --manifest-path src-tauri/Cargo.toml --lib \
  host_setup::tests::disposable_unix_installed_desktop_watch_and_resume \
  -- --ignored --exact --nocapture
```

The harness verifies the installed executable and starts an isolated signed
Library. Use the temporary synthetic sign-in shown in the terminal. Follow the
prompts to approve background reads, close the window, reopen it from the Dock
or tray, pause, resume the same approval, and remove permission before signing
out. Window visibility and button state are operator observations. The harness
checks the original bytes and thumbnails over the Library API, requires the
second original to stay absent for two scan intervals while paused, and checks
that each filename still resolves to exactly one stable asset ID after resume.
Keep the final result and hashes, and discard the account and its terminal
transcript after the run. This is a manual qualification on the identified
installed bytes.

## Supported systems

### macOS minimum versions

Two floors are declared in `packaging/macos/minimum-versions.json`:

| Key | Value | Meaning |
| --- | --- | --- |
| `app` | 11.0 | The oldest macOS the app installs and runs on: photos, imports, Manager and local hosting. |
| `aiRuntime` | 15.0 | The oldest macOS the optional AI runtime pack runs on. AI processing needs it; nothing else does. |

`bundle.macOS.minimumSystemVersion` in `src-tauri/tauri.conf.json` and
`MACOSX_DEPLOYMENT_TARGET` in the macOS build jobs of `desktop.yml` and
`release.yml` carry the `app` value. The AI runtime floor is never written
into the bundle, so an older Mac still installs and opens the app.

Both values are the highest minimum recorded in the binaries of each part,
read with `tools/check_macos_minimum.py` from the installed 0.1.6 Apple
silicon app:

| Part | Shipped binary | Minimum macOS |
| --- | --- | --- |
| App | `frameleaf-desktop` and the `frameleaf-native-host` sidecar | 11.0 |
| App | Rust default for `aarch64-apple-darwin` (`rustc --print deployment-target`) | 11.0 |
| App | Rust default for `x86_64-apple-darwin` | 10.12 |
| App | Tauri default when no minimum is declared (the 0.1.6 `LSMinimumSystemVersion`) | 10.13 |
| AI runtime | Python interpreter and most libraries | 11.0 |
| AI runtime | protobuf | 12.0 |
| AI runtime | OpenCV (`cv2`) and its libraries | 13.0 |
| AI runtime | NumPy, ONNX Runtime | 14.0 |
| AI runtime | `orjson` | 15.0 |

`python3 tools/check_macos_minimum.py --deployment-target "$MACOSX_DEPLOYMENT_TARGET" Frameleaf.app`
treats the `native-runtime` folder as the AI runtime and everything else as
the app. It fails when an app binary needs a newer macOS than `app`, when a
runtime binary needs a newer macOS than `aiRuntime`, when a loaded binary
records no minimum, when the bundle's `LSMinimumSystemVersion` or
`tauri.conf.json` differs from `app`, or when `MACOSX_DEPLOYMENT_TARGET`
does. `--report FILE` writes the declared and measured values as JSON.
`Desktop candidate` runs the check on the unsigned shell. `Desktop release`
runs it on the app with its runtime before signing and adds the report to the
run summary. A runtime rebuilt for an older macOS lets `aiRuntime` be lowered;
to change `app`, change the declaration, `tauri.conf.json` and both workflows
together (`tools/test_check_macos_minimum.py` fails when they disagree).

The app reads `aiRuntime` from the same declaration when it is built. On an
older macOS, AI setup stops before it prepares anything, with the code
`runtime_os_unsupported`, and the AI processing card says which macOS is
needed. It does not retry by itself and offers no Retry Setup. Photos and
everything else keep working.

### Linux tray library

The tray icon loads `libayatana-appindicator3.so.1` at run time and falls back
to `libappindicator3.so.1`; it is not a link-time dependency of the binary. The
package dependency is chosen by the Tauri bundler from the development package
present at build time, so every Linux build job installs
`libayatana-appindicator3-dev`. The `.deb` then depends on
`libayatana-appindicator3-1`, which Ubuntu 22.04, Ubuntu 24.04 and Debian 12
ship; `libappindicator3-1` is not in Debian 12. The AUR package depends on
`libayatana-appindicator`.

`tools/qualify_linux_deb_install.sh PACKAGE.deb` installs the package with
`apt-get install` in clean `ubuntu:24.04`, `ubuntu:22.04` and `debian:12`
containers and fails on an unmet dependency or a missing tray dependency. It
then runs every binary the package installs in `/usr/bin` with `--version` in
each container, and fails when one does not load there. `Desktop candidate`
runs it on every pull request.

### Linux C library

A Linux binary needs at least the glibc of the machine it was linked on.
Ubuntu 22.04 has glibc 2.35 and Debian 12 has 2.36, so the Linux jobs that
build what ships run on `ubuntu-22.04`: the `linux-package` job of `Desktop
candidate`, and `Desktop release`, the installer candidates and the runtime
factory through `releaseMatrix` in `tools/release_inputs.mjs`. The `check` job
of `Desktop candidate` stays on `ubuntu-24.04`, which the host package
qualification needs; its package is not shipped. Ubuntu 22.04 ships
WebKitGTK 4.1 and `libayatana-appindicator3`, so nothing else changes.

`tools/check_linux_glibc.py --max 2.35 PATH...` reads the `GLIBC_x.y` versions
every ELF file under a folder, or inside a `.deb`, needs and fails when one is
newer than the limit. The same three workflows run it on the `.deb` they
build, and the runtime candidate workflow runs it on the runtime payload.

## Browser UI tests

`tools/test_*_ui.mjs` drive the real interface in headless Chromium against a
synthetic IPC bridge: the Manager page, navigation and local server setup. They
need no server, credentials or saved sign-in. `npm test` skips them;
`npm run test:ui` runs them and needs Playwright, which is not a project
dependency:

```sh
npm install --no-save --prefix /tmp/frameleaf-playwright playwright-core@1.63.0
node /tmp/frameleaf-playwright/node_modules/playwright-core/cli.js install chromium-headless-shell
FRAMELEAF_TEST_PLAYWRIGHT=/tmp/frameleaf-playwright/node_modules/playwright-core/index.mjs npm run test:ui
```

Set `FRAMELEAF_TEST_BROWSER` to the absolute path of another Chromium build to
use it instead, and `FRAMELEAF_TEST_OUTPUT` to an absolute folder to keep
screenshots of the Manager page. `Desktop candidate` runs these tests on Linux
for every pull request.

## Build and signing boundaries

`Desktop candidate` tests and builds unsigned shell smoke-test installers
on Windows, macOS and Linux. Those omit the ML runtime and are not release builds.

`Installer candidates` is manually dispatched from `main` with a
`runtime_run_id` from a successful `factory-runtime.yml` main dispatch in this
repository. The factory commit must be an ancestor of the candidate commit.
It reuses the approved signed runtimes. The default `linux` selection builds
Ubuntu 24 x86-64 and ARM64 DEB/AppImage installers, one architecture at a time.
Choose `windows` for Windows x86-64 NSIS/MSI installers. Windows candidates use Azure Artifact Signing for the application, NSIS
uninstaller and both installers through Tauri's custom signing command. The
Windows build uses the main-only `desktop-release` environment and GitHub OIDC. Runtime signature, inventory,
source approval and target checks run before native compilation. Linux packages
keep the signed runtime under `/usr/share/Frameleaf/native-runtime`, outside the
AppImage bundler's library rewrite scan. Both finished Linux installers are
extracted and their embedded runtime signatures and inventory verified before
upload. Linux candidates need no signing credentials. Candidates do not require a
version tag or publishing permissions.

Download `frameleaf-installer-candidates-linux-x86_64` or
`frameleaf-installer-candidates-linux-aarch64` for Linux, or
`frameleaf-installer-candidates-windows-x86_64` for Windows, from that run. Each contains
`installer-candidates.tar.gz`; extract it to preserve the AppImage executable mode.
The archive includes installer checksums and `candidate.json` identifying the
desktop commit and factory run. These are GUI/existing-server helper candidates;
complete native hosting and installed-device qualification remain separate.
Artifacts expire after seven days. [Downloads follow repository access](https://docs.github.com/en/actions/how-tos/manage-workflow-runs/download-workflow-artifacts),
not a maintainer-only policy. In a public repository, signed-in users can
download these candidates. Only synthetic test fixtures belong in builds.
Candidate jobs also retain verbose bundler logs and generated configuration as
`frameleaf-installer-diagnostics-<target>` for seven days, including failed builds.
Diagnostics follow the same repository access policy.

```sh
gh workflow run installer-candidates.yml --repo Frameleaf/frameleaf-desktop \
  --ref main -f platforms=linux -f runtime_run_id=<successful-factory-run-id>
```

`Signed desktop release` is manually dispatched from `main`. A supplied tag must
point to that exact workflow commit and match `package.json`, `Cargo.toml` and
`tauri.conf.json`. An empty tag retains installer artifacts and skips draft staging.
The default selection requests macOS ARM64/Intel DMG and Linux x86-64/ARM64 DEB/AppImage.
The Intel macOS runtime ([FD-6](https://heroit.atlassian.net/browse/FD-6)) installs onnxruntime 1.23.2,
the last release with an Intel macOS wheel, in place of the version the runtime source locks: the
one wheel is named by version and SHA-256 under `targetPins` in `runtime/profiles.json`, recorded
in the pack's `provenance.json`, and built and run on the Intel image by the `intel-macos` job of
`runtime-pack.yml`. Every other dependency and every other target keeps the source lock.
Choose `all` to include Windows x86-64 NSIS/MSI after Azure Artifact Signing is configured,
or `linux` to build both Linux architectures independently.

The installer pipeline consumes factory-signed ML runtimes rather than exposing
the Infisical Ed25519 release key to app-build jobs. Specify a successful
`factory-runtime.yml` dispatch from `main` in this repository containing these Actions artifacts:

| Artifact | Required for |
| --- | --- |
| `factory-runtime-macos-aarch64` | `macos-aarch64`, `macos-linux`, `all` |
| `factory-runtime-macos-x86_64` | `macos-linux`, `all` |
| `factory-runtime-linux-x86_64` | `linux`, `macos-linux`, `all` |
| `factory-runtime-linux-aarch64` | `linux`, `macos-linux`, `all` |
| `factory-runtime-windows-x86_64` | `windows`, `all` |

Each artifact contains `runtime.tar`, with `manifest.json`, `manifest.sig` and
`payload/` at its root. Create the tar on the factory OS to retain executable
modes. Use the existing `build_runtime.py` and `sign_runtime.mjs` in the trusted
factory environment, with a source/profile approved by `runtime/profiles.json`.
Sign Mach-O runtime code with Developer ID and the required hardened-runtime
entitlements **before** measuring its final inventory and applying the Ed25519
manifest signature. Never re-sign payload bytes after the manifest is signed.
The runtime pack producer/upload is a separate factory-authoring prerequisite;
the existing `Private CPU runtime candidate` workflow uploads receipts only and
does not satisfy this artifact contract.

### Model catalogue and runtime profiles

`runtime/model-catalogue.json` is a copy of the server's
`server/resources/desktop/model-catalogue.json`; both sides compile it and must
hold the same epoch and profiles. Check it from this repository with the server
checkout beside it:

```sh
git -C ../immich show origin/main:server/resources/desktop/model-catalogue.json | python3 tools/check_catalogue_parity.py -
```

Add `--runtime-profiles <server runtime-profiles.json>` to also check that every
runtime in `runtime/profiles.json` is one the server approves.

`runtime/profiles.json` lists only runtimes Desktop can build and the server can
admit, and every source in it has profiles in the catalogue (the parity check
fails otherwise). Today that is the CPU runtime on every target, `coreml-ort` on
Apple Silicon, and `cuda-ort` and `openvino-ort` on Windows and Linux x86_64.
The accelerated profiles build their own runtime source (catalogue epoch 15),
which verifies the model bytes a session loads; the CPU profile is unchanged.

`python tools/build_runtime.py --profile coreml-ort` builds an accelerated pack:
one payload (the CPU dependency set plus the CoreML device collector from
`native/coreml_observer.m`, which the server requires) with two manifests,
`manifest.json` for the processor and `manifest-accelerated.json` for CoreML.
The factory workflow builds it for `macos-aarch64` by default (`accelerated:
default`; choose `none` for the processor pack alone), and signs both manifests
(`manifest-accelerated.sig`) after Apple code signing; packaging ships the second
manifest beside the first. Both manifests of that pack name the accelerated
profile's source, so the server must already carry catalogue epoch 15: against an
older server neither manifest is known and that Mac has no AI processing until
the server is updated. Release the server first. A new pack needs a runtime epoch
above the released one (the workflow default is 7).

```sh
gh workflow run factory-runtime.yml --ref main -f platforms=all -f epoch=7 -f accelerated=default
```

The app installs the accelerated manifest in its own store and qualifies each
workload with it. The first time with a runtime it also times the same fixtures
on the processor, without the server: the provider keeps a workload only where
its warm inference was faster, and that outcome is remembered for the runtime
(`provider-failures.json`). Slower, failed or not measurable means the processor
for that workload.
`cargo test --lib native_runtime::metal::local_pack -- --ignored` qualifies a
locally built pack against the catalogue under a throwaway key (see the test for
its three environment variables).

`--profile cuda-ort` and `--profile openvino-ort` build the same kind of pack on
Windows and Linux x86_64, from the runtime source's `desktop-cuda` and
`desktop-openvino` extras, which lock the libraries each provider library was
built against: for onnxruntime-gpu 1.29.0 the CUDA 12 runtime 12.9.79 (its
provider library imports functions the 12.6.77 runtime does not export, which on
Windows is error 127 at load), cuBLAS, cuFFT, cuRAND, NVRTC and cuDNN 9; for
onnxruntime-openvino 1.24.1 on Windows the `openvino` 2025.4.1 wheel (the Linux
wheel contains it). `onnxruntime-gpu`, and nothing else, comes from the feed the
server's lock names for it; every wheel is checked against the locked hash.

Pull-request CI builds the four packs on hosted runners and checks them without a
GPU (`tools/smoke_accelerated_runtime.py`). OpenVINO: a session runs on its CPU
device. CUDA: the bundled CUDA and cuDNN libraries are in the pack and open; on
Windows the provider library's import table is satisfied by the pack and the
library loads; on Linux everything it links against resolves from the pack
except the NVIDIA driver library. No CUDA session is created there. To verify on
a Windows or Linux computer with an NVIDIA card and driver, build the pack and
run the same script with the pack's interpreter; it must print `CUDA session ran
on the card`:

```sh
python tools/build_runtime.py --source <frameleaf-app checkout at the profile's sourceRevision> --output candidate --revision <that revision> --epoch 7 --profile cuda-ort
candidate/payload/python/python.exe -I -B tools/smoke_accelerated_runtime.py CUDAExecutionProvider   # Linux: candidate/payload/python/bin/python3.12
```

Neither provider has run on NVIDIA or Intel hardware. A CUDA pack is about 3 GB
and no installer carries either: the factory builds one only when `accelerated`
names it.

The pipeline safely extracts the tar and reuses `packageConfiguration` to verify
the complete signed payload, compiled public authority, epoch, source approval
and native target before bundling. macOS additionally verifies that the embedded
runtime still passes this contract after app signing, plus strict app signature,
Gatekeeper and stapled notarization checks. Windows verifies Authenticode on the
app and both installers for a trusted, timestamped signature with the exact
configured publisher subject. Azure rotates leaf certificates, so verification
does not pin a leaf thumbprint. Linux packages include
the same verified runtime. Linux package repositories use their own signing policy.

For a tagged build, the workflow signs the verified NSIS, MSI, DEB and AppImage
packages and archives the signed, stapled macOS app for in-app upgrades. Desktop
checks GitHub's Latest release for `latest.json` at launch and offers to install a
newer version when the manifest includes its architecture and installer format.
Users on builds that predate the updater need one manual install. Publish a release
covering all supported formats when promoting it to Latest so each can receive
the update.

Only after every selected target passes does a separate job receive repository
write permission and create a **draft prerelease** with installers, signed updater
packages, `latest.json` and `SHA256SUMS`. The run summary and the draft notes list
the targets in `latest.json` and state when Windows was excluded from the update
feed; the default selection excludes it until Azure Artifact Signing is qualified,
and Windows entries from an earlier release are not carried forward. The same job
stamps the AUR and Chocolatey files from those checksums (see
[`packaging/README.md`](../packaging/README.md)). The updater sees the manifest after the
release is published as Latest. The workflow never publishes automatically or
replaces an existing release.
If a draft already exists for the tag, the create step fails; inspect/remove the
draft deliberately before retrying. Successful CI or code signing does not prove
installed-device, NAS-job, GPU or native-host acceptance.

## Signing credentials

The `desktop-release` GitHub environment allows only the `main` branch. Store
credentials in the Frameleaf Desktop Infisical project and provision only the
required values into that environment, never into pull-request jobs:

| Secret | Purpose |
| --- | --- |
| `APPLE_CERTIFICATE` | Base64 Developer ID Application P12, including private key |
| `APPLE_CERTIFICATE_PASSWORD` | P12 password |
| `APPLE_SIGNING_IDENTITY` | Full `Developer ID Application: …` identity |
| `APPLE_ID` | Apple account used for notarization |
| `APPLE_PASSWORD` | App-specific notarization password |
| `APPLE_DEVELOPER_ID_PROVISION_PROFILE` | Base64 Developer ID provisioning profile for the desktop GUI’s private Keychain identity |
| `APPLE_TEAM_ID` | Developer team ID |
| `TAURI_SIGNING_PRIVATE_KEY` | Signs update packages with the version bound to the signature. The matching public key is embedded in Desktop. |

Apple App Store Distribution and Apple Development certificates do not replace
Developer ID Application for direct downloads. Developer ID Application
certificate `JZTDNMWT8T` was created for team `2SK9S5ZTVR` on November 1, 2026,
expires December 1, 2027 (America/Edmonton), and its matching key/certificate/P12
are backed up in the desktop Infisical production environment. The encrypted
P12, password, identity, Apple ID and team ID are provisioned into the main-only
GitHub `desktop-release` environment. The owner's app-specific notarization
password (`APPLE_PASSWORD`) is also backed up and provisioned; authentication
was verified using `notarytool history`. Ordinary Apple account passwords must
never be used for CI. Windows signing uses Azure Artifact Signing rather than an exportable PFX.
The workflow requires no Windows private key or client secret in GitHub or Infisical.

### Azure Artifact Signing setup

Create an Artifact Signing account and complete Microsoft's identity validation,
then create a **Public Trust** certificate profile. The provisioned account is
`frameleaf`, resource group `frameleaf-signing`, East US, Basic tier
(US$9.99/month, 5,000 signatures included; US$0.005 per additional signature).
The subscription was upgraded to pay-as-you-go and the signing account deployed
successfully on November 2, 2026. GitHub's `desktop-release` environment has the
tenant, subscription, endpoint, signing account and client ID.

Microsoft lists the public identity validation for Frameleaf Inc. as **Action
Required**. The named representative must complete Microsoft's verification.
Once approved, create the Public Trust profile, set `AZURE_SIGNING_PROFILE` and
`WINDOWS_SIGNING_SUBJECT`, and qualify a signed Windows installer candidate.

The dedicated single-tenant Entra application `frameleaf-desktop-windows-signing`
has one federated credential, `github-desktop-release`. GitHub uses immutable
organization and repository IDs in this repository's subject.

- Issuer: `https://token.actions.githubusercontent.com`
- Audience: `api://AzureADTokenExchange`
- Subject: `repo:Frameleaf@331460878/frameleaf-desktop@1421136454:environment:desktop-release`

Assign only **Artifact Signing Certificate Profile Signer** at the certificate
profile scope once the profile exists. Keep the existing GitHub environment's deployment policy restricted
to the `main` branch. Do not add pull-request or wildcard federated subjects.
The manual Windows candidate and release jobs use that environment. The ordinary
pull-request smoke build stays unsigned and receives no Azure identity.

Set these non-secret **environment variables** in GitHub's `desktop-release`
environment after provisioning and validation:

| Variable | Value |
| --- | --- |
| `AZURE_CLIENT_ID` | Dedicated Entra application's client ID |
| `AZURE_TENANT_ID` | Directory ID (`e15b1052-f1b2-4c39-a3bb-f892f80d25c7`) |
| `AZURE_SIGNING_ENDPOINT` | Account's regional endpoint; East US: `https://eus.codesigning.azure.net/` |
| `AZURE_SIGNING_ACCOUNT` | Provisioned signing account name |
| `AZURE_SIGNING_PROFILE` | Validated Public Trust certificate profile name |
| `WINDOWS_SIGNING_SUBJECT` | Exact complete certificate subject from that profile, not a guessed company name |

Missing configuration, a rejected signing request, an untrusted signature, an
unexpected publisher or a missing timestamp stops the Windows job before upload.
The shared local action logs in through Azure OIDC and installs Microsoft's
`ArtifactSigning` PowerShell module pinned to `0.1.20`. Tauri invokes
`tools/windows_sign.ps1` for each signing operation before packaging. The module
uses only the authenticated Azure CLI session. SHA-256 and Microsoft's RFC3161
timestamp service are required. Tauri's installer plugin DLLs are also signed.
Tauri attempts to sign resource executables too, so the signing command explicitly
leaves files inside this checkout's `release-runtime/` unchanged. Both Windows
workflows reverify the factory runtime inventory after bundling, before upload.

Temporary Apple keychains are removed on success or failure; `azure/login`
cleans up the Azure session. Use Microsoft's [OIDC setup guide](https://github.com/Azure/artifact-signing-action/blob/main/docs/OIDC.md),
[signing integrations](https://learn.microsoft.com/en-us/azure/artifact-signing/how-to-signing-integrations),
and Tauri's [Windows signing guide](https://v2.tauri.app/distribute/sign/windows/).

The macOS factory signer verifies the unsigned inventory, signs the interpreter and
embedded Mach-O libraries with Developer ID and secure timestamps, then seals the
final bytes with the factory key. The installer verifies that inventory again.

## Dispatch

For an Apple Silicon installer artifact, run the factory and signed desktop
workflows on `main` with `platforms=macos-aarch64`. Pass the successful factory
run ID to the signed workflow and leave the tag empty. After signing, notarization
and embedded runtime verification, the workflow submits the signed DMG to Apple,
retains the submitted bytes and Apple request ID as `notarization-pending-macos-aarch64`,
staples the accepted ticket, and checks Gatekeeper. If Apple outlasts the
runner, use the recorded request ID with `notarytool info` and staple the retained
DMG after acceptance. The verified DMG is available in the workflow artifact
`signed-installers-macos-aarch64`. Draft release staging requires a tag.

After the workflow is merged, factory packs and credentials are available, and
the chosen version is ready for a candidate:

```sh
git tag v0.1.0 <reviewed-main-commit>
git push origin v0.1.0
gh workflow run release.yml --repo Frameleaf/frameleaf-desktop --ref main \
  -f tag=v0.1.0 -f runtime_run_id=<successful-factory-run-id> \
  -f platforms=macos-linux
```

Review the draft's exact commit, signatures, checksums and installed-device
acceptance before publishing. No tag or public release is created by this change.
