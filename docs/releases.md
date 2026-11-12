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
Intel macOS runtime dependencies are tracked in [FD-6](https://heroit.atlassian.net/browse/FD-6).
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
fails otherwise). Today that is the CPU runtime on every target and `coreml-ort`
on Apple Silicon.

`python tools/build_runtime.py --profile coreml-ort` builds an accelerated pack:
one payload (the CPU dependency set plus the CoreML device collector from
`native/coreml_observer.m`, which the server requires) with two manifests,
`manifest.json` for the processor and `manifest-accelerated.json` for CoreML.
The factory workflow builds it for `macos-aarch64` only when dispatched with
`accelerated` checked, and then signs both manifests (`manifest-accelerated.sig`)
after Apple code signing; packaging ships the second manifest beside the first.
The app installs the accelerated manifest in its own store, qualifies each
workload with it and falls back to the processor runtime per workload when the
provider fails, remembering the failure for that runtime.
`cargo test --lib native_runtime::metal::local_pack -- --ignored` qualifies a
locally built pack against the catalogue under a throwaway key (see the test for
its three environment variables).

The catalogue also carries CUDA and OpenVINO profiles; Desktop ignores them.
Neither is buildable: the locked `cuda` extra has no CUDA or cuDNN libraries once
torch is left out and comes from a package feed the builder does not approve,
and the runtime source reports every OpenVINO qualification as incompatible.

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
