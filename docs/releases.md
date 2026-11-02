# Desktop release pipeline

Tracked in [FD-2](https://heroit.atlassian.net/browse/FD-2). The first pipeline
packages the current `main` worker-enabled desktop, not the stacked native-host
drafts. CodeRabbit remains independent of Actions.

## Build and signing boundaries

`Desktop candidate` tests and builds unsigned shell smoke-test installers
on Windows, macOS and Linux. Those omit the ML runtime and are not release builds.

`Installer candidates` is manually dispatched from `main` with a
`runtime_run_id` from a successful `factory-runtime.yml` main dispatch in this
repository. The factory commit must be an ancestor of the candidate commit.
It reuses the approved signed runtimes. The default `linux` selection builds
Ubuntu 24 x86-64 and ARM64 DEB/AppImage installers, one architecture at a time.
Choose `windows` for Windows x86-64 NSIS/MSI installers. Windows candidates have
no Authenticode signature and are for manual testing; the signed release workflow
retains its certificate requirement. Runtime signature, inventory,
source approval and target checks run before native compilation. No signing
credentials, version tag or publishing permissions are used.

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

`Signed desktop release` is manually dispatched from `main`. Its tag must already
point to that exact workflow commit and match `package.json`, `Cargo.toml` and
`tauri.conf.json`. It builds macOS ARM64/Intel DMG and Linux x86-64/ARM64 DEB/AppImage by default.
Choose `all` to include Windows x86-64 NSIS/MSI after its certificate is configured,
or `linux` to build both Linux architectures independently.

The installer pipeline consumes factory-signed ML runtimes rather than exposing
the Infisical Ed25519 release key to app-build jobs. Specify a successful
non-pull-request `main` run in this repository containing these Actions artifacts:

| Artifact | Required for |
| --- | --- |
| `factory-runtime-macos-aarch64` | `macos-linux`, `all` |
| `factory-runtime-macos-x86_64` | `macos-linux`, `all` |
| `factory-runtime-linux-x86_64` | Every selection |
| `factory-runtime-linux-aarch64` | Every selection |
| `factory-runtime-windows-x86_64` | `all` |

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

The pipeline safely extracts the tar and reuses `packageConfiguration` to verify
the complete signed payload, compiled public authority, epoch, source approval
and native target before bundling. macOS additionally verifies that the embedded
runtime still passes this contract after app signing, plus strict app signature,
Gatekeeper and stapled notarization checks. Windows verifies Authenticode on the
app and both installers against the imported certificate. Linux packages include
the same verified runtime; the final draft includes SHA-256 checksums for all
selected installers. Linux package/repository GPG signatures and automatic app
updates are outside this initial pipeline.

Only after every selected target passes does a separate job receive repository
write permission and create a **draft prerelease** with installers and
`SHA256SUMS`. It never publishes automatically or replaces an existing release.
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
| `APPLE_TEAM_ID` | Developer team ID |
| `WINDOWS_CERTIFICATE` | Base64 code-signing PFX, including private key |
| `WINDOWS_CERTIFICATE_PASSWORD` | PFX password |

Apple App Store Distribution and Apple Development certificates do not replace
Developer ID Application for direct downloads. Developer ID Application
certificate `JZTDNMWT8T` was created for team `2SK9S5ZTVR` on November 1, 2026,
expires December 1, 2027 (America/Edmonton), and its matching key/certificate/P12
are backed up in the desktop Infisical production environment. The encrypted
P12, password, identity, Apple ID and team ID are provisioned into the main-only
GitHub `desktop-release` environment. The owner's app-specific notarization
password (`APPLE_PASSWORD`) is also backed up and provisioned; authentication
was verified using `notarytool history`. Ordinary Apple account passwords must
never be used for CI. Windows signing has not been acquired. The Windows path supports an existing
exportable signing certificate; a future hardware/cloud-backed provider requires
its supported Tauri custom signing command instead. Missing credentials stop
their selected release target rather than producing an unsigned substitute.

Temporary Apple keychains and Windows certificate/private-key imports are removed
on success or failure. Use the official [Tauri macOS signing guide](https://v2.tauri.app/distribute/sign/macos/)
and [Windows signing guide](https://v2.tauri.app/distribute/sign/windows/) when
provisioning the actual distribution credentials.

## Dispatch

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
