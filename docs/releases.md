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

`Signed desktop release` is manually dispatched from `main`. Its tag must already
point to that exact workflow commit and match `package.json`, `Cargo.toml` and
`tauri.conf.json`. It builds macOS ARM64/Intel DMG and Linux x86-64/ARM64 DEB/AppImage by default.
Choose `all` to include Windows x86-64 NSIS/MSI after Azure Artifact Signing is configured,
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
app and both installers for a trusted, timestamped signature with the exact
configured publisher subject. Azure rotates leaf certificates, so verification
does not pin a leaf thumbprint. Linux packages include
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
successfully on November 2, 2026. Its tenant, subscription, endpoint and account
values are provisioned in GitHub's `desktop-release` environment. Identity
validation, acceptance of the Artifact Signing service terms, the Identity
Verifier role, a Public Trust profile and the GitHub signing identity remain
outstanding; live signing is not yet qualified.

Create a dedicated Entra application/service principal for this repository with
one federated credential:

- Issuer: `https://token.actions.githubusercontent.com`
- Audience: `api://AzureADTokenExchange`
- Subject: `repo:Frameleaf/frameleaf-desktop:environment:desktop-release`

Assign only **Artifact Signing Certificate Profile Signer** at the certificate
profile scope. Keep the existing GitHub environment's deployment policy restricted
to the `main` branch. Do not add pull-request or wildcard federated subjects.
The manual Windows candidate and release jobs use that environment. The ordinary
pull-request smoke build stays unsigned and receives no Azure identity.

Set these non-secret **environment variables** in GitHub's `desktop-release`
environment after provisioning and validation:

| Variable | Value |
| --- | --- |
| `AZURE_CLIENT_ID` | Dedicated Entra application's client ID |
| `AZURE_TENANT_ID` | Directory ID (`e15b1052-f1b2-4c39-a3bb-f892f80d25c7`) |
| `AZURE_SUBSCRIPTION_ID` | Signing subscription (`01c08b4d-6e09-4799-a468-bdfe59280ff2`) |
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
