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
point to that exact workflow commit and match the version in `package.json`,
`package-lock.json`, `Cargo.toml`, `Cargo.lock` and `tauri.conf.json`
(`node tools/release_inputs.mjs v<version>` checks all five). An empty tag retains
installer artifacts and skips draft staging.
The default selection requests macOS ARM64/Intel DMG and Linux x86-64/ARM64 DEB/AppImage.
The Intel macOS runtime ([FD-6](https://heroit.atlassian.net/browse/FD-6)) installs onnxruntime 1.23.2,
the last release with an Intel macOS wheel, in place of the version the runtime source locks: the
one wheel is named by version and SHA-256 under `targetPins` in `runtime/profiles.json`, recorded
in the pack's `provenance.json`, and built and run on the Intel image by the `intel-macos` job of
`runtime-pack.yml`. Every other dependency and every other target keeps the source lock.

Every platform can be released by itself, so one that cannot build or be signed
does not hold back the others. `platforms` is one of:

| Choice | Targets |
| --- | --- |
| `macos-linux` (default) | Both macOS and both Linux architectures |
| `all` | Everything, including Windows |
| `macos`, `linux` | Both architectures of that system |
| `macos-aarch64`, `macos-x86_64`, `linux-x86_64`, `linux-aarch64`, `windows` | That one target |

The factory workflow takes the same choices. Runs for the same tag add to one
draft (see [Staging](#staging-one-draft-per-tag)); the full order is in
[Publishing a release](#publishing-a-release-owner-checklist).

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
the server is updated. Release the server first: a tagged release run stops in
`prepare` with `catalogue_ahead_of_server` when `runtime/model-catalogue.json` has
a higher epoch than the catalogue in the latest published `frameleaf-v<version>`
release of `Frameleaf/frameleaf-app`, unless `allow_unreleased_catalogue` is set.

### Runtime epoch

An installed app remembers the highest runtime epoch it accepted for its
platform. It refuses a pack with a lower epoch (`runtime_epoch_rollback`) and a
different pack with the same epoch (`runtime_epoch_reused`), so an epoch is
never used twice for different bytes on one platform, and never goes down.

`runtime/factory-epochs.json` records `highestUsedEpoch`: the highest epoch any
pack was built with for a release or a draft. It is 8 (the 0.1.6 draft pack; the
packs built on November 9 for 0.1.5 used 6), so the next epoch to use is **9**. The factory workflow
has no default epoch: `epoch` must be given and must be above the record, and a
tagged release refuses a pack whose epoch is not above it. Every platform of one
release uses the same new epoch, in one factory run or several. After the
release is published, raise `highestUsedEpoch` to that epoch (and the number in
this paragraph) in the next version change. A pack rebuilt after an earlier one
with the same epoch reached a draft or a tester needs the next epoch: raise the
record first.

```sh
gh workflow run factory-runtime.yml --ref main -f platforms=all -f epoch=9 -f accelerated=default
```

The app installs the accelerated manifest in its own store and qualifies each
workload with it. The first time with a runtime it also times the same fixtures
on the processor, without the server: the provider keeps a workload only where
its warm inference was faster, and that outcome is remembered for the runtime
(`provider-failures.json`). Slower, failed or not measurable means the processor
for that workload. What is remembered is for that runtime with that device and
driver: a driver update, another card or Retry Setup tries the provider again,
and a process that was only late to start is not remembered at all.
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

Neither provider has run on NVIDIA or Intel hardware.

#### Delivery of the CUDA and OpenVINO packs (FD-60)

A CUDA pack is about 3 GB, too large for an installer and for one release file
(GitHub: "Each file included in a release must be under 2 GiB"). Installers keep
carrying the processor pack. The CUDA and OpenVINO packs for `windows-x86_64` and
`linux-x86_64` are release files the app downloads only when the person chooses
Download on the AI processing page, and only on a computer with the device.

- Factory: a `default` run (or one naming `cuda-ort` / `openvino-ort`) builds
  those packs beside each installer pack. The `deliver` job signs only the
  pack's accelerated manifest, cuts the pack into 1 GiB parts
  (`tools/deliver_runtime.mjs`: the manifest, its signature, then the payload
  files in the byte order of their names) and signs a delivery manifest naming
  every part by size and SHA-256 and the runtime manifest by SHA-256, and
  listing the payload files that are executable where the pack was built (the
  app makes exactly those executable, as a bundled pack keeps its files' modes).
  Artifacts:
  `factory-accelerated-manifest-<target>-<profile>` and
  `factory-accelerated-parts-<target>-<profile>`. The installer pack
  (`factory-runtime-<target>`) carries the delivery manifests in `accelerated/`;
  packaging refuses one that is unsigned, for another target or of another epoch.
- Release: the `stage` job verifies every part against its signed delivery
  manifest and uploads the parts beside the installers. The app fetches them
  from `releases/download/v<its own version>/`, so they are reachable once the
  release is published, and a release must be staged from the same factory run
  as its installers.
- App (`src-tauri/src/accelerated_pack.rs`): HTTPS only, resumable, each part
  checked against the delivery manifest the installer carried, then the pack is
  installed by the runtime store like a bundled one (signature, every file's
  digest, epoch rules) and qualified. A downloaded pack is admitted only at the
  processor runtime's own epoch. Any failure leaves the processor in charge and
  shows the reason with a retry.

To rebuild a pack from factory artifacts on a computer with the device (for the
hardware check above): `node tools/deliver_runtime.mjs --reassemble <profile>.json
<profile>.sig <parts folder> <output folder>`.

The processor manifest of a CUDA or OpenVINO pack is never signed (the signer
refuses it: another dependency set than the processor profile), so such a pack
cannot become an installer's own runtime.

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

### Checks before anything is built

The `prepare` job stops the run, with the reason as the job's error, when:

- the tag is missing, is not the version in the five version files, or does not
  point at the commit the workflow runs on;
- the factory run is not a successful manual `factory-runtime.yml` run on `main`,
  was built from a commit outside this commit's history, or has no unexpired
  `factory-runtime-<target>` artifact for a selected target
  (`runtime_run_pack_missing`);
- a selected pack was built from a source or profile `runtime/profiles.json` on
  this commit does not approve for that target (`runtime_run_pack_unapproved`),
  or, for a tagged release, with an epoch that is not above
  `runtime/factory-epochs.json` (`runtime_run_pack_epoch_used`). Only the pack's
  manifests are read here; the build job still verifies the whole signed payload;
- for a tagged release, the model catalogue is newer than the latest server
  release (`catalogue_ahead_of_server`), or the companion run is missing or not
  trusted (below).

When Windows is selected, the `signing-preflight` job then reads the
`desktop-release` variables before any platform builds and fails with
`windows_signing_unconfigured`, naming each variable that is not set and the
settings page to set it on.

### Companion packages

The app sends people to the releases page for the Library companion package
("Run Frameleaf here"), so a release carries it for Apple Silicon, Linux x64 and
Windows x64. Intel Macs and Linux ARM have none.

For each of those platforms one workflow installs the final package on a clean
runner, qualifies it, and only then retains two artifacts (for 90 days):

| Platform | Workflow | Package artifact | Release assets |
| --- | --- | --- | --- |
| Apple Silicon | `macos-host-package.yml` | `frameleaf-macos-arm64-companion-installed` | `FrameleafCompanion_<version>_arm64.pkg` |
| Linux x64 | `ubuntu-host-qualification.yml` | `frameleaf-linux-x64-companion-installed` | `FrameleafCompanion_<version>_amd64_bootstrap.deb`, `FrameleafCompanion_<version>_amd64_runtime.deb` |
| Windows x64 | `windows-compiled-host.yml` with `release_package=true` | `frameleaf-windows-x64-companion-installed` | `FrameleafCompanion_<version>_x64-setup.exe` |

`<version>` is the Library version in the package (`payload/server/package.json`),
the one the app shows as "Library 1.2.4". Beside the package artifact each run
uploads `<package artifact>-identity`: the signed host manifest from inside the
package (`manifest.json`, `manifest.sig`) and `companion.json`, which names the
package files by SHA-256 with the manifest and controller digests.

`companion_run_ids` on `release.yml` takes those run ids, comma-separated, one
per selected platform that has a companion package. `prepare` stops the release
before anything is built when:

- a run is not a successful manual run of its workflow on `main`, from a commit
  in this commit's history (`companion_run_untrusted`), a selected platform has
  no run (`companion_run_missing`), or a run is for a platform not being
  released (`companion_run_unselected`);
- the run has no unexpired package artifact, or no identity artifact
  (`companion_identity_missing`): for Windows that is a run without
  `release_package=true`;
- the manifest in the identity artifact is one the Desktop built from this
  commit refuses once installed (`companion_incompatible`): not signed by a key
  in `runtime/release-trust.json`, or not matching this commit's host pins
  (`runtime/host-database.json`, host protocol, Node version, minimum epoch).
  This is the check the app makes before local setup
  ([FD-19](https://heroit.atlassian.net/browse/FD-19)), made on the manifest
  alone, so a stale or wrong package never reaches a draft;
- the manifest is for another platform (`companion_target_mismatch`), or
  `companion.json` does not name exactly that workflow's files
  (`companion_identity_invalid`).

`stage` then downloads the package artifact and adds exactly the files
`companion.json` named, each checked against its SHA-256
(`companion_artifact_changed`). `companion_run_ids=none` stages the draft
without companion packages; the run summary and the draft notes then name each
platform whose package has to be added by hand before publishing.

The `SOURCES` files (`FrameleafCompanion_<version>_<arch>_SOURCES.md` or `.zip`)
are not produced by a workflow and are still added to the draft by hand.

#### Producing a companion package

Each chain starts from a host candidate uploaded as an asset of a **private
draft release kept for this purpose** (any tag that is not a version tag; never
the draft of the release itself, whose assets are rebuilt by `release.yml`).
Every workflow takes that draft's id in its approval; none names a draft.
All run on `main` with `gh workflow run <file> --repo Frameleaf/frameleaf-desktop
--ref main -f approval='<json>'`. Dispatch them in this order, each after the
one before has succeeded.

Apple Silicon:

1. `macos-host-signing.yml`, approval
   `{"archiveSha256","assetId","controllerSha256","manifestSha256","releaseId"}`
   for the unsigned host archive on the draft. It signs the native code with the
   Developer ID Application certificate, notarizes Chromium, seals the manifest
   and uploads an unsigned installer wrapper
   (`FrameleafCompanion-<version>-macOS-arm64-unsigned-<run>.pkg`) to the draft.
2. By hand, on a Mac with the Developer ID Installer certificate:
   `productsign` that wrapper and upload the signed package to the same draft.
   No workflow holds that certificate.
3. `macos-host-package.yml`, approval
   `{"assetId","controllerSha256","manifestSha256","packageSha256","releaseId"}`
   for the signed package. It checks the Developer ID Installer signature,
   notarizes and staples, installs on a fresh Mac, and retains the package.
   **This run id goes in `companion_run_ids`.**

Linux x64:

1. `linux-host-signing.yml`, approval
   `{"archiveSha256","assetId","manifestSha256","releaseId"}` for the unsigned
   host archive. It seals the manifest and retains `manifest.sig`
   (`frameleaf-linux-x64-host-signature`, 7 days).
2. By hand, on Ubuntu 24.04 x64: add that `manifest.sig` to the candidate, build
   the controller (`cargo build --release --locked --bin frameleaf-native-host`)
   and run `python tools/build_host_linux_deb.py --candidate <candidate>
   --controller <controller> --output <directory>`. Rename the two packages to
   `bootstrap.deb` and `runtime.deb` and upload a `tar.gz` holding exactly those
   to the draft.
3. `ubuntu-host-qualification.yml`, approval
   `{"archiveSha256","assetId","controllerSha256","manifestSha256","releaseId"}`
   for that archive. It installs both packages on a clean runner, recovers an
   interrupted `dpkg` retry, renders under AppArmor, and retains the packages.
   **This run id goes in `companion_run_ids`.**

Windows x64 (needs the Azure Artifact Signing variables,
[step 1 of the checklist](#publishing-a-release-owner-checklist)):

1. The nine component workflows and `windows-host-assembly.yml`
   (`approvals`, `epoch`), then `windows-host-signing.yml` (`approval` for the
   assembly run). These retain their artifacts for 7 days.
2. `installer-candidates.yml` with `platforms=windows` for the signed Desktop the
   next step installs.
3. `windows-compiled-host.yml` with `approvals` (the signing run),
   `desktop_sha256`, `desktop_approval` and **`release_package=true`**. It first
   checks the signing variables and stops with `windows_signing_unconfigured`,
   naming each one that is not set, before anything is built. It then signs the
   controller, builds the installer around it, signs the installer, installs it
   twice, checks the publisher signature on the installer and the installed
   controller, and retains the installer. **This run id goes in
   `companion_run_ids`.** Without `release_package` the workflow behaves as
   before: an unsigned `-setup-unsigned.exe` kept for 7 days, which a release
   never accepts.

#### Reusing a companion package

When the Library companion has not changed since the last release, do not
rebuild it: pass the same run ids again. A run stays usable while its two
artifacts are unexpired (90 days from the run; the run page shows the date), its
commit is in the history of the commit being released, and its manifest still
passes the check above. `prepare` says which of those failed.

Once the artifacts have expired, dispatch only the last workflow of that
platform's chain again with the same approval, the package still being on the
private draft: `macos-host-package.yml` (Apple's ticket is already stapled, so
it does not wait for Apple again) or `ubuntu-host-qualification.yml`. Windows
needs its chain from `windows-host-assembly.yml`, because those inputs are kept
for 7 days only.

The Library 1.2.4 packages were made before this:

- Apple Silicon: run `42148037724` holds the notarized 1.2.4 package until
  February 4, 2027. It has no identity artifact; `release.yml` accepts that one
  run on the checksum it recorded, without the manifest check.
- Linux x64: no run holds the 1.2.4 packages. Upload a `tar.gz` of
  `bootstrap.deb` and `runtime.deb` (the two packages on the 0.1.5 release,
  renamed) to a private draft and run `ubuntu-host-qualification.yml` once, with
  controller `045568dc0bbbe5a582516e83b2d4f11b4122a381cb91a6d29c778aff128b5cc7`
  and manifest `b3ce270798e290f89505e554dee9be0fd3006a49af11fe3bf5d0025dde5d7a74`.
- Windows x64: only the unsigned 1.2.4 installer exists. A signed one needs the
  Windows chain above once signing is configured; until then release Windows
  with `companion_run_ids=none` or leave Windows out.

### Staging: one draft per tag

Only after every selected target passes does a separate job receive repository
write permission. It verifies the updater signatures, then:

- when the tag has no release, creates a **draft prerelease** with the
  installers, signed updater packages, `latest.json` and `SHA256SUMS`;
- when the tag already has a draft, **adds** this run's assets to it and
  replaces `latest.json` and `SHA256SUMS` with ones rebuilt from everything on
  the draft. `latest.json` then offers every platform any run staged; each
  signature is carried through exactly as it was written.

`tools/release_draft.mjs` decides this (`tools/test_release_draft.mjs`). It
refuses, changing nothing, when the release for the tag is already published
(`release_not_draft`), when more than one release exists for the tag
(`release_tag_ambiguous`; GitHub allows two drafts for one tag, which is how
both 0.1.5 runs staged a partial draft each), and when the draft already has an
asset of the same name with different bytes (`release_asset_conflict`). A
rebuild never has the same bytes: to replace a platform, delete its assets and
their `.sig` files from the draft, then run again. Re-running only the failed
`stage` job reuses the built installers and is safe. Files added to the draft by
hand are kept and listed in the next run's `SHA256SUMS`.

The run summary and the draft notes list the targets in `latest.json` and state
when Windows was excluded from the update feed; Windows entries from an earlier
release are not carried forward. The same job stamps the AUR and Chocolatey
files from the checksums of the whole draft (see
[`packaging/README.md`](../packaging/README.md)). The updater sees the manifest after the
release is published as Latest. The workflow never publishes or deletes a
release. Successful CI or code signing does not prove installed-device, NAS-job,
GPU or native-host acceptance.

Release runs share one concurrency group: they run one at a time, and GitHub
keeps only one waiting. Dispatch the next run when no other is waiting, or the
waiting one is cancelled.

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

## Publishing a release: owner checklist

Steps 1 to 4 can be done ahead of time. Only Windows needs Microsoft's identity
validation; macOS and Linux ship without it.

1. **Windows only, once: finish Microsoft's identity validation.** When Microsoft
   approves Frameleaf Inc., create the Public Trust certificate profile, assign
   the signer role, and set `AZURE_SIGNING_PROFILE` and `WINDOWS_SIGNING_SUBJECT`
   as variables of the `desktop-release` environment
   ([Azure Artifact Signing setup](#azure-artifact-signing-setup)). Until then
   skip every Windows step below; a Windows run stops in `signing-preflight`.
2. **Release the server first** when `runtime/model-catalogue.json` has a higher
   epoch than the latest `frameleaf-v<version>` server release (today: Desktop
   15, `frameleaf-v1.2.21` 14).
3. **Merge everything that ships, including the version change**, to `main`.
   The commit to release is `<commit>`; `node tools/release_inputs.mjs v<version>`
   on it prints the tag.
4. **Build the runtime packs** on `main`, at or before `<commit>`, with the next
   epoch ([Runtime epoch](#runtime-epoch): 9), for every platform being
   released. Separate runs per platform are fine; note each run id. A run is
   only accepted by the release when every platform in it succeeded, so build
   Intel by itself until it has succeeded once.

   Run it once each for `macos-aarch64`, `linux`, `macos-x86_64` and (with step 1
   done) `windows`. Factory runs also go one at a time with only one waiting:
   dispatch the next when no other is waiting.

   ```sh
   gh workflow run factory-runtime.yml --repo Frameleaf/frameleaf-desktop --ref main \
     -f platforms=<platforms> -f epoch=9 -f accelerated=default
   ```

   With `accelerated=default` a `windows` or `linux` run also builds the CUDA and
   OpenVINO packs the app downloads on request
   ([Delivery of the CUDA and OpenVINO packs](#delivery-of-the-cuda-and-openvino-packs-fd-60)):
   its `deliver` jobs must succeed, or no installer pack is signed. No factory
   run has built those packs yet, so expect to iterate on the first one.
5. **Have the companion package runs ready** ([Companion packages](#companion-packages)):
   one run id per platform, from `macos-host-package.yml`,
   `ubuntu-host-qualification.yml` and (with step 1 done)
   `windows-compiled-host.yml` with `release_package=true`. Unchanged since the
   last release: pass the same run ids again
   ([Reusing a companion package](#reusing-a-companion-package); Apple Silicon
   1.2.4 is `42148037724`). Changed: dispatch that platform's chain in the order
   under [Producing a companion package](#producing-a-companion-package). Also
   have the `SOURCES` files to add by hand (the 1.2.4 ones are on the 0.1.5
   release).
6. **Tag the commit and push the tag.** A pushed tag is never moved.

   ```sh
   git tag v<version> <commit>
   git push origin v<version>
   ```
7. **Run the release once per platform group**, each with the factory run that
   built those platforms. Every run adds to the same draft.

   ```sh
   gh workflow run release.yml --repo Frameleaf/frameleaf-desktop --ref main \
     -f tag=v<version> -f platforms=macos-aarch64 \
     -f runtime_run_id=<factory run> -f companion_run_ids=<macos-host-package run>
   gh workflow run release.yml --repo Frameleaf/frameleaf-desktop --ref main \
     -f tag=v<version> -f platforms=linux -f runtime_run_id=<factory run> \
     -f companion_run_ids=<ubuntu-host-qualification run>
   gh workflow run release.yml --repo Frameleaf/frameleaf-desktop --ref main \
     -f tag=v<version> -f platforms=windows -f runtime_run_id=<factory run> \
     -f companion_run_ids=<windows-compiled-host run>   # needs step 1
   ```

   A run that selects several platforms takes their run ids comma-separated.
   `companion_run_ids=none` stages a platform without its companion package,
   which then has to be added to the draft by hand.

   Each run also verifies the CUDA and OpenVINO pack parts of its factory run
   (`frameleaf-accelerated-*.partNN`) and adds them to the draft. Use the same
   factory run for a platform's installers and its parts: the installer carries
   the signed list of exactly those parts.

   Intel Macs: the Intel runtime now builds with onnxruntime 1.23.2
   ([FD-6](https://heroit.atlassian.net/browse/FD-6)), but no signed factory run
   has produced an Intel pack yet. Until one succeeds, build and release it as
   its own `macos-x86_64` runs so a failure there does not stop Apple Silicon or
   Linux. Once one has, `platforms=macos-linux` (or `all` with step 1 done) in
   steps 4 and 7 replaces the separate macOS and Linux runs. A platform left out
   stays on its installed version; the draft notes say which.
8. **Add the `SOURCES` files to the draft** (step 5), and any companion package
   left out with `none`, before the last run of
   step 7, so the final `SHA256SUMS` lists them; or re-run the `stage` job of the
   last run afterwards.
9. **Review the draft**: one draft for the tag, the commit, the targets listed
   under "Update feed" in its notes, `SHA256SUMS`, the companion packages, the
   `frameleaf-accelerated-*` parts for Windows and Linux x86_64, and
   installed-device acceptance on each platform. The app can download the parts
   only once the release is published, so a GPU pack is accepted on a device
   after step 10 (or from the factory artifacts with
   `tools/deliver_runtime.mjs --reassemble` before it).
10. **Publish**: clear "pre-release", set it as the latest release and publish.
    From then the updater offers it to every target in `latest.json`.
11. **Afterwards**: publish the AUR files, and Chocolatey only when the release
    has the signed MSI (Windows; the `package-manager-files` artifact of the last
    run, [`packaging/README.md`](../packaging/README.md)); raise
    `highestUsedEpoch` in `runtime/factory-epochs.json` to the epoch released.

For an installer to try without publishing, run step 7 with no `tag`: the
installers are kept as `signed-installers-<target>` artifacts and nothing is
staged. For Apple Silicon the workflow submits the signed DMG to Apple, retains
the submitted bytes and Apple request ID as `notarization-pending-macos-aarch64`,
staples the accepted ticket, and checks Gatekeeper. If Apple outlasts the
runner, use the recorded request ID with `notarytool info` and staple the
retained DMG after acceptance.
