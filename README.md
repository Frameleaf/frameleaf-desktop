# Frameleaf Desktop

Native desktop apps for Windows, macOS and Linux, built on [Frameleaf/frameleaf-app PR #140](https://github.com/Frameleaf/frameleaf-app/pull/140).

## Setup modes

- **Connect to my server + help with AI processing**: sign in to an existing NAS server, manage it, and automatically enroll this computer as an authorized ML worker. This is the first delivery priority.
- **Run Frameleaf on this computer**: host the complete server locally through an installer-managed native runtime.

The desktop shell reuses the Frameleaf web photo UI. Native components provide background supervision, secure credentials, approved local photo sources, ML execution and OS integration. The browser remains supported.

Local photo-source work includes OneDrive folders and Apple Photos/iCloud through PhotoKit, with explicit copy/import or supported external-library references.

## Project resources

- [Jira project FD — Frameleaf Desktop](https://heroit.atlassian.net/jira/software/projects/FD/summary)
- [Confluence project home](https://heroit.atlassian.net/wiki/spaces/FD/overview)
- [Product and architecture plan](https://heroit.atlassian.net/wiki/spaces/FD/pages/73433098)
- [Implementation packets and acceptance gates](https://heroit.atlassian.net/wiki/spaces/FD/pages/73531393)

## Repository boundaries

This private repository owns the desktop shell, supervisor, native adapters, packaging and desktop tests. Proposed `desktop/...` paths in the planning documents map here. Backend, Manager, shared web and ML contract changes remain in `Frameleaf/frameleaf-app`. Shared UI, SDK and runtime artifacts must be pinned to reviewed versions; do not fork the photo application.

Planning baseline: PR #140 head `a85264d9e0973cce209d7539fb9fd5045488e7ea`. PR #140 remains draft/open and unmerged. The foundation candidate contains a Tauri desktop shell, secure native password sign-in, OS-keystore session/device identity, automatic signed enrollment and an unprivileged window for the existing Frameleaf photo interface. Worker inference, native full hosting, Manager pairing and local photo-source integrations are not implemented yet. Installed-device release acceptance remains pending.


## Development

Requires Node 22.12 or later, Rust stable and the Tauri platform prerequisites.

```sh
npm ci
npm run desktop:dev
```

Run `npm test`, `npm run check`, and `cargo test --manifest-path src-tauri/Cargo.toml`. Build with `npm run desktop:build`. Debug builds are unsigned development candidates.

Connect using the HTTPS origin of a Frameleaf server. This candidate supports password sign-in; external-browser OAuth/OIDC is not implemented. PR #140 needs the additive desktop-device API before automatic enrollment is available. Existing servers can still open their photo interface after sign-in, with an explicit worker-upgrade status. A server without an established identity requires a new sign-in after restart.

The setup window has narrow native commands; remote Photos windows have no native capabilities. Session credentials and the Ed25519 installation key are stored only in the OS credential store. Sign-out invalidates the active association; permanent device revocation remains separate.

The app symbol is reused from frameleaf-app at the pinned integration baseline. Inherited Frameleaf source/assets retain AGPL-3.0 obligations; see LICENSE. Detailed architecture and execution plans remain in Confluence.

## Private inference supervision

The native Rust supervisor accepts an installed runtime only after verifying its
Ed25519 signature against application-trusted keys, release epoch, OS/architecture,
protocol, and complete SHA-256 file inventory. The signed manifest identifies the
private Python executable, selected provider and exact Frameleaf server source revision.
Links, unexpected files, changed bytes and ambiguous paths are refused. Runtime files
are checked again before launch and after qualification. The manifest and detached
signature are stored outside the pack inventory.

Sidecars launch fixed Frameleaf modules through isolated Python, with bytecode writes
disabled and no inherited photo, cloud or worker credentials. A fresh loopback token,
private scratch/cache settings and offline model policy are supplied explicitly.
A startup pipe gates execution until OS process ownership is installed; closing that
pipe also terminates the runtime after an owner crash. Windows uses an unnamed Job
Object; macOS/Linux use a private process group. Process output is not exposed to the
webview. Cancellation, failed exits, deadlines and invalid/oversized qualification
reports cannot produce a qualified model. The report binds the exact approved fixture
spec and is returned with its verified runtime manifest identity.

These supervisor APIs are native-only and are not yet wired to a background worker.
Release signing keys, packaged runtime installation, NAS model approval and automatic
processing remain required before enabling worker readiness. CI exercises the process
owner on all three OS builds; installed hardware acceptance remains separate.

## Constructing a runtime candidate

Use Python 3.12 and uv 0.11.2 on the target OS. The builder reads immutable Git
blobs from a clean, explicitly pinned Frameleaf server checkout, exports the frozen
ML dependency lock with hashes, and installs private standalone Python 3.12.13.
Dependencies remain hash checked; the source-only ANTLR 4.9.3 package builds with the
lockfile's hash-checked setuptools. Other source builds are refused. Model weights
are acquired separately through approved staging and never included implicitly.

```sh
python tools/build_runtime.py --source /path/to/frameleaf-app \
  --output /new/private/runtime-candidate --revision FULL_SERVER_COMMIT \
  --epoch 1 --profile cpu-ort
```

The output contains `payload/` plus an unsigned `manifest.json`. The builder tests
relocation and imports before publishing that candidate directory. Windows checkout
line endings cannot alter the source/preprocessing identity. Python/dependency
licences and sanitized acquisition provenance are retained. Release signing must use
an application-trusted key; the builder never generates a production signing key.
The separate CPU workflow builds all three OS candidates and retains small private
validation receipts. These builds do not prove GPU execution or installed release
acceptance. CUDA/CoreML/OpenVINO/AMD packs remain required.

`RuntimeStore` verifies and copies signed candidates into immutable release folders,
reverifies the copy and atomically switches its active pointer. Old releases remain
available; lower epochs and conflicting reuse of an epoch are refused. A shared OS
file lease held by an installed runtime and its child prevents activation until they
are dropped. Partial staging is never adopted. The release authority still needs its
OS-keystore trust/floor policy, download/extraction/update orchestration and GUI wiring.
Power-loss and installed-platform acceptance remain release gates.

A dedicated real-model test is deliberately excluded from ordinary CI. Supply only
synthetic fixtures and a dedicated approved model cache:

```sh
FRAMELEAF_NATIVE_TEST_PACK=/private/runtime-candidate \
FRAMELEAF_NATIVE_TEST_CACHE=/private/model-cache \
FRAMELEAF_NATIVE_TEST_SPEC=/private/approved-fixture.json \
  cargo test --manifest-path src-tauri/Cargo.toml --test runtime_store \
  installed_private_cpu_pack -- --ignored --nocapture
```

That test's temporary signing key is fixture-only and never becomes application trust.

Native prediction now requires `start_qualified_sidecar` with the sealed qualification from the same signed runtime. An unqualified sidecar exposes authenticated health only. Each prediction must use the qualified entries and input kind; the private runtime rechecks artifact hashes, preprocessing, available memory and driver/runtime identity before and after inference, refusing changed inputs before returning a result. NAS model/index admission and automatic sign-in preparation remain pending.

`NativePredictor::execute_next` connects an installed qualified sidecar to the existing scoped worker transport for one NAS claim: bounded input download, exact model/configuration checks, multipart text/image inference, periodic lease renewal and NAS result acknowledgement. Cancellation, deadline, lease loss or inference failure stops the owned process before failure acknowledgement. The loopback client disables proxies/redirects and bounds responses. This is the execution seam; NAS model admission, resource policy and the automatic sign-in background loop are still required before enabling worker readiness.

Release signing is an authoring operation, separate from app code signing and publication. The public authority in `runtime/release-trust.json` is compiled into `release_policy::open_runtime_store`; a NAS or candidate cannot replace it. The corresponding Ed25519 private key is held only in the Frameleaf Desktop Infisical project (`prod`, `/`, `DESKTOP_RELEASE_ED25519_PRIVATE_KEY`). `tools/sign_runtime.mjs` accepts that key through stdin, verifies the complete payload, pinned profile and provenance, and writes a new 64-byte detached signature without overwriting an existing signature. It never logs key material. Run it only in the trusted release-authoring environment; pull-request CI has no signing credential.

The compiled initial epoch floor is 2. A persistent monotonic OS-keystore floor, protected key rotation, downloads and update recovery are still required before enabling automatic runtime updates. A valid component signature proves byte identity and release authority; it does not establish GPU qualification, app code signing or installed-device acceptance.

The app-compiled model catalogue now pins default SigLIP image/text profiles with 768-value CPU references, exact artifact/snapshot/preprocessing identity and measured memory floors. `model_catalogue::approved_profile` selects only an exact model/configuration/runtime/provider match; its returned type cannot be deserialized from a NAS response. Fresh canonical UUID challenges retain the model and fixture while changing the raw-spec digest. The catalogue matches the NAS resource byte for byte. Durable NAS challenge/admission state and the automatic worker loop are still pending; unsupported profiles remain unavailable.

`RuntimeStore::attestation` reverifies a leased installed release and exports its
exact signed manifest as canonical gzip/base64. The NAS uses its own matching
public release authority, with 2 MiB compressed and 8 MiB decompressed limits.
This establishes release identity only; qualification, session-bound admission
and model grants remain separate requirements.

The native worker transport can request/read NAS qualification challenges and
submit sealed runtime reports over its signed outbound connection. Returned
specifications and fixtures must exactly match the app-compiled profile, and
the manifest binding must match the locally verified runtime. Challenges also bind
the server, account, device, session and credential generation. Report submission
refuses an expired challenge or a different nonce/runtime. An accepted report is
stored evidence; automatic orchestration and NAS inference admission remain
pending.

Accepted runtime evidence is read through the signed worker API and sealed against the compiled profile, local qualified runtime, NAS-canonical report digest, connection association and absolute expiry. Token renewal preserves that association; a new sign-in changes it. Claims now require the exact accepted qualification ID and expiry, and all input/heartbeat/result/failure requests retain that binding. Native startup and execution stop at qualification expiry. Accepted evidence does not by itself enable NAS processing scope.

The qualified predictor now provides a continuous, serial job loop. It retains the accepted qualification and connection binding for every claim, input, heartbeat and result. Empty long-polls have a minimum idle delay; the first execution/authority failure stops the loop and owned process. Cancellation, a closed control channel, or dropping the loop future terminates in-flight work. The loop does not enable processing scope or automatically replace expired qualification evidence. Automatic preparation, renewal, resource/network policy and sign-in integration remain required before the app can report active NAS assistance.
