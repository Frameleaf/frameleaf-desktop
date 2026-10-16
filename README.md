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

Original planning baseline: PR #140 head `a85264d9e0973cce209d7539fb9fd5045488e7ea`. PR #140 remains draft/open and unmerged. The foundation candidate contains a Tauri desktop shell, secure native password sign-in, OS-keystore session/device identity, automatic signed enrollment and an unprivileged window for the existing Frameleaf photo interface. Native inference and signed worker transport are implemented; serial multi-role scheduling is connected; Local macOS CPU fixtures have accepted actual NAS CLIP and OCR library jobs through the signed native runtime, including stale-source publication refusal. OCR runs without a NAS inference backend. Native full hosting, Manager pairing and local photo-source integrations remain unfinished. Installed-device release acceptance remains pending.


## Development

Requires Node 22.12 or later, Rust stable and the Tauri platform prerequisites.

```sh
npm ci
npm run desktop:dev
```

Run `npm test`, `npm run check`, and `cargo test --manifest-path src-tauri/Cargo.toml`. Build a desktop installer with `npm run desktop:build -- --runtime /absolute/path/to/factory-signed-pack` (add `--debug` for an unsigned development candidate). The command verifies the release signature, complete payload, target platform and current bundle source before invoking Tauri. It includes the runtime at the resource path used by automatic worker setup. Shell smoke tests can use `npm run desktop:build:shell -- --debug`; those candidates deliberately omit the ML runtime.

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

The native background worker retains accepted per-role evidence, starts one warm process
before claiming work, and serializes matching jobs through it. It refreshes expiring
qualifications and stops inference on cancellation or unsuitable power, network cost
or available memory. Multi-role launches use an explicit flag rejected by older runtimes.
The default installer build requires a signed runtime resource; actual NAS library-job
acceptance on installed Windows, macOS and Linux devices remains required before enabling release readiness. CI exercises the process
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

Native prediction requires `start_qualified_sidecar` with the sealed qualification from the same signed runtime. An unqualified sidecar exposes authenticated health only. Each prediction must use the qualified entries and input kind; the private runtime rechecks artifact hashes, preprocessing, available memory and driver/runtime identity before and after inference, refusing changed inputs before returning a result. NAS model/index admission is implemented in the companion backend candidate; resource-aware automatic scheduling remains pending.

`NativePredictor::execute_next` connects an installed qualified sidecar to the scoped worker transport for one NAS claim: bounded input download, exact model/configuration checks, multipart text/image inference, periodic lease renewal and NAS result acknowledgement. Cancellation, deadline, lease loss or inference failure stops the owned process before failure acknowledgement. The loopback client disables proxies/redirects and bounds responses. Resource policy and automatic scheduling still need to consume this execution seam before enabling worker readiness.

Release signing is an authoring operation, separate from app code signing and publication. The public authority in `runtime/release-trust.json` is compiled into `release_policy::open_runtime_store`; a NAS or candidate cannot replace it. The corresponding Ed25519 private key is held only in the Frameleaf Desktop Infisical project (`prod`, `/`, `DESKTOP_RELEASE_ED25519_PRIVATE_KEY`). `tools/sign_runtime.mjs` accepts that key through stdin, verifies the complete payload, pinned profile and provenance, and writes a new 64-byte detached signature without overwriting an existing signature. It never logs key material. Run it only in the trusted release-authoring environment; pull-request CI has no signing credential.

The compiled initial epoch floor is 2. A persistent monotonic OS-keystore floor, protected key rotation, downloads and update recovery are still required before enabling automatic runtime updates. A valid component signature proves byte identity and release authority; it does not establish GPU qualification, app code signing or installed-device acceptance.

The app-compiled model catalogue pins default SigLIP image/text profiles with 768-value CPU references, exact artifact/snapshot/preprocessing identity and measured memory floors. `model_catalogue::approved_profile` selects only an exact model/configuration/runtime/provider match; its returned type cannot be deserialized from a NAS response. Fresh canonical UUID challenges retain the model and fixture while changing the raw-spec digest. The catalogue matches the NAS resource byte for byte. Durable NAS challenge/admission state is implemented in companion PR #315. The automatic worker loop is implemented; unsupported profiles stay unavailable and installed sign-in acceptance remains required.

## Automatic preparation checkpoint

Administrator sign-in and restored associations now start background runtime/model preparation. The app installs a factory-signed `native-runtime` resource when present, or verifies its already installed runtime. It reads the current NAS model selection and selects matching compiled profiles without changing server settings. Model files come only from the pinned Frameleaf mirror snapshot, with exact byte counts and SHA-256 checks. Interrupted staging reuses verified files; only a complete cache and offline receipt are published. Acquisition finishes before fresh NAS challenge nonces are requested. Each profile then runs local qualification and submits its bound report through the signed worker transport.

Power, network cost and available-memory checks now gate qualification. macOS uses IOKit, Network.framework and Mach VM statistics; Windows uses native power/memory APIs and connection cost; Linux reads UPower/NetworkManager through D-Bus and kernel memory availability. Unknown state, battery power, metered networks or insufficient memory keep qualification paused. The UI reports the reason, and sign-out cancels the wait. Inference children run below foreground priority, with at most four intra-op threads, one inter-op thread and one request thread.

Missing model files download automatically only when the OS reports an unmetered network. Metered or unclassified downloads require an explicit local button; retrying setup alone does not grant permission. Sign-out cancels setup, waits for process cleanup, and clears credentials afterward. Remote Photos windows receive no preparation commands or events.

The ordinary unsigned candidate does not yet bundle the signed runtime. It reports that missing component and keeps Photos usable. A qualified status records model checks only. The supervisor now starts a warm multi-profile predictor, refreshes expiring qualification and executes serial NAS jobs while enforcing resource and association checks. The multi-model claim API binds each returned job to its exact role and qualification. Capability advertisement remains gated on complete installed acceptance. The native resource probe has been exercised on macOS; Windows/Linux installed behavior remains an acceptance gate.

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
stored evidence; processing still requires live NAS admission for that exact
association and model.

Accepted runtime evidence is read through the signed worker API and sealed against the compiled profile, local qualified runtime, NAS-canonical report digest, connection association and absolute expiry. Token renewal preserves that association; a new sign-in changes it. Claims now require the exact accepted qualification ID and expiry, and all input/heartbeat/result/failure requests retain that binding. Native startup and execution stop at qualification expiry. Accepted evidence does not by itself enable NAS processing scope.

The qualified predictor provides a continuous, serial job loop. It retains the accepted qualification and connection binding for every claim, input, heartbeat and result. Empty long-polls have a minimum idle delay; the first execution/authority failure stops the loop and owned process. Cancellation, a closed control channel, or dropping the loop future terminates in-flight work. The loop does not enable processing scope or automatically replace expired qualification evidence. The sign-in supervisor applies qualification refresh and resource/network policy; installed-platform acceptance remains required before release.

### Building a desktop installer

The `cpu-ort` profile’s `sourceRevision` selects the runtime source for a new desktop
bundle. This authoring pin is separate from the NAS catalogue, which retains older
approved qualification identities. A pack for another OS/architecture, a stale source,
an untrusted signature or changed files stops the build. No private signing key is
needed during desktop packaging.

Tauri maps only `manifest.json`, `manifest.sig` and the verified `payload/` tree into
`native-runtime/`. Build intermediates and release-authoring files are excluded. The
installed app verifies that signed resource again before copying it into its private
runtime store. macOS app/DMG packaging has been exercised locally; OS release signing,
notarization and installed Windows/Linux acceptance remain separate gates.

The approved CPU catalog includes the default `PP-OCRv5_mobile` detection and recognition
engines with exact pinned weights and inference options. OCR qualification does not change
CLIP index membership or model identities. Each workload retains its own live worker grant;
NAS policy, default route, full OCR configuration, source and job authority are checked before
input disclosure and result publication. Automatic setup combines verified model snapshots
for one runtime and budgets the distinct model groups together. Other OCR models/options
require their own approved qualification profile.

Automatic preparation reads a narrow installation-signed model inventory, without
requesting administrator settings. The inventory is advisory: qualification and
live NAS policy, route and source checks still grant processing authority. Pinned
and legacy routes stay on their chosen destinations. Unsupported models and
unavailable NAS producers appear separately for each workload; eligible workloads
can continue. Smart search requires its complete three-role qualification group.
Credential failures, runtime tampering and interrupted connections stop preparation
or enter the existing reconnect path. Member desktop processing requires explicit
administrator approval in the account’s Security tab. The member then selects Check approval in Desktop to securely
re-enroll. Removing approval invalidates existing worker sessions and grants;
automatic administrator consent does not become member permission after demotion.

### CoreML candidate packs

The runtime builder accepts `--profile coreml-ort` for native Apple-silicon macOS
authoring. The profile uses the pinned ONNX Runtime macOS package and source
revision. Signing binds the declared profile to its provider, target and payload
provenance; packaging also checks its approved source revision. CPU remains the
default profile.

CoreML model processing remains gated on output conformance, actual device
execution and measured benefit. The approved model catalogue and runtime report
validators retain that gate. CoreML can choose CPU, GPU or Neural Engine execution;
provider registration and a compute plan alone cannot establish acceleration.
See the [ONNX Runtime CoreML provider options](https://onnxruntime.ai/docs/execution-providers/CoreML-ExecutionProvider.html)
and [Apple's runtime performance instruments](https://developer.apple.com/documentation/CoreAI/analyzing-model-runtime-performance-with-instruments).

### Fresh sign-in acceptance fixture

The opt-in NAS library-job fixture starts with an empty process-only credential
store and no enrolled devices. It uses the same login and enrollment sequence as
the native command against real HTTPS authentication, signed device enrollment and
PostgreSQL session storage. Repeating preparation must retain one device identity.
It then qualifies the approved model, executes a native job and verifies that stale
source publication is refused. It uses generated credentials and public fixtures;
it never reads the operating system credential store.

This covers the login sequence and native processing, while runtime/model setup in
the installed window and fresh-install Windows/macOS/Linux journeys remain separate
acceptance gates.

The same fixture accepts `FRAMELEAF_FACTORY_AUTOMATIC_SETUP=1` with the OCR workload.
That mode hands the enrolled connection to `WorkerSetup`, which installs the signed
runtime, acquires the selected models, qualifies them and starts its own job loop.
It requires real external power, an unmetered connection and sufficient memory;
the fixture does not override those checks. Its dedicated NAS configuration enables
OCR only. The private HTTPS fixture client is available only under Rust's test
configuration and cannot alter the installed application's certificate policy.

### Local photo-source preview

The local setup window can find known OneDrive sync folders and open the native
folder picker. Windows discovery uses the current user's OneDrive environment
hints; macOS checks OneDrive directories under Library/CloudStorage. These hints
are incomplete: relocated roots and additional accounts can be selected manually.
Linux uses ordinary selected folders without claiming OneDrive placeholder support.

After the user chooses a folder, the preview counts photo/video filenames and
logical sizes using metadata only. Capability-relative directory access confines
traversal; links, dot-prefixed entries and application/Photos packages are excluded.
The scan stops at 10,000 entries, 16 levels or 256 pending directories and reports
partial/skipped results. It refuses the whole home folder or filesystem root.
Cloud residency, required downloads and cloud-account completeness remain unknown.
On macOS, preview and known-root discovery disable dataless materialization on the
current OS thread before filesystem traversal, restoring its prior policy on exit.
Cloud-only directory access can therefore be unavailable or partial rather than
triggering a download during preview. Approved copy staging uses its separate read
permission; the preview policy never grants download authority.

The preview opens no source content. A separate explicit approval stores a signed,
photo-session-bound folder permission in the OS credential store and registers its
opaque scope with the NAS. The UI sends only an expiring native picker handle;
it cannot approve an arbitrary filesystem path. A failed secure-store write keeps
the selection retryable, and a failed registration keeps the same source identity.
Removing permission clears local authority before contacting the NAS; offline or
unconfirmed server revocation remains visible. Sign-out invalidates pending picker
handles and removes the permission; a different photo sign-in cannot reuse it.
Provider-aware hydration, external references and PhotoKit integration remain
required before full source capabilities are advertised by the NAS.
Approval does not begin a copy.
The native picker uses the [Tauri dialog plugin](https://v2.tauri.app/plugin/dialog/)
through local-only Rust commands; remote Photos windows receive no dialog or
filesystem capabilities.

### Verified copy staging foundation

The Rust copy engine binds a signed folder approval to the current server origin,
server/account/device IDs, installation identity, root identity, per-file size cap
and explicit download permission. It rejects other document types, traversal,
linked ancestors/files and replaced roots. Directory handles constrain reads to the
approved root; every item is checked before and after reading. A native free-space
check retains 256 MiB beyond the file size, and incomplete staging is cleaned up.

An immutable private staging directory holds independent original bytes and a signed
SHA-256 receipt, with the source version and original filesystem dates. Creation time
falls back to modification time when unavailable. Restore checks the approval,
receipt and bytes before returning a read-only handle positioned at the beginning.
A staged copy survives source eviction; changed bytes, journal tampering or a different
account/server/device are refused.

The UI prepares a metadata-only copy plan, shows its original count and logical size,
and requires a separate start action. It refuses incomplete scans and stages one
original at a time while checking current consent, connection and unmetered-network
policy. Logical run limits and per-file free-space checks do not reserve provider
hydration space or account for all provider network traffic. Real OneDrive hydration
and installed Windows/Linux file behavior remain unqualified.

### Resumable source transfer

The internal native uploader consumes signed staged originals through the existing
NAS resumable-upload API. It checks the live server identity and photo account
before sharing filenames or bytes, negotiates current size limits, and creates an
empty resource before requesting a durable signed journal checkpoint. Restarts use
HEAD offsets on that same resource. Appends are bounded to 1 MiB, preserve source
filesystem dates, send a whole-file SHA-256 digest, and support request cancellation.
Requests and signed v2 resume journals bind the exact folder source, run and item;
changed bindings and legacy unbound journals are refused before network use.
Redirects and foreign, ambiguous or noncanonical resource locations are refused.

A matching ingestion response is not proof of a healthy independent managed copy.
The native job stores a device-signed manifest and atomic progress checkpoints before
reading or uploading bytes. Pause, explicit resume and cancellation retain existing
server copies and unconfirmed staged originals. Sign-out and permission removal stop
the active job before clearing credentials. Lost replies recover the existing upload
and item identities rather than creating another upload.

Only a bound NAS receipt, produced after hashing the independent managed original,
permits cache release. A saved receipt is revalidated on restart before release.
Foreign receipts, unhealthy NAS originals and failed checkpoints retain local staging.
The app never removes source files. Protocol fixtures exercise real loopback HTTP
requests with synthetic media; actual NAS HTTPS transfer, provider hydration and
installed-device acceptance remain unqualified. External references and PhotoKit are
separate unfinished integrations.

### Native folder-copy NAS integration fixture

From the companion server checkout's `server` directory, run:

```sh
FRAMELEAF_NATIVE_DESKTOP_ROOT=/absolute/path/to/frameleaf-desktop \
  pnpm exec vitest run --config test/vitest.config.medium.mjs \
  test/medium/specs/services/photo-source-upload.spec.ts
```

This builds the consuming Rust test and starts an owned HTTPS/Nest/PostgreSQL
fixture with canonical migrations. Generated photo-session credentials travel only
through the child process's stdin; its credential store is process-only. The test
uses real authentication, signed enrollment, source/run/item APIs, chunked upload,
managed publication and stored-byte verification. It loses a receipt reply, damages
the NAS copy, verifies that resume retains staging, then repairs and completes with
the same upload. Source bytes remain unchanged. Ordinary tests skip this fixture.

Job/event dispatch is mocked: this does not prove background decoding, thumbnails,
OS credential storage, provider hydration or installed-device acceptance.
