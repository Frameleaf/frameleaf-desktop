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

Original planning baseline: PR #140 head `a85264d9e0973cce209d7539fb9fd5045488e7ea`. The server integration now includes merged PR #140 and the PR #274 UI changes on main. The foundation candidate contains a Tauri desktop shell, secure native password sign-in, OS-keystore session/device identity, automatic signed enrollment and an unprivileged window for the existing Frameleaf photo interface. Native inference and signed worker transport are implemented; serial multi-role scheduling is connected; Local macOS CPU fixtures have accepted actual NAS CLIP and OCR library jobs through the signed native runtime, including stale-source publication refusal. OCR runs without a NAS inference backend. Native full hosting, Manager pairing and local photo-source integrations remain unfinished. Installed-device release acceptance remains pending.


## Development

Requires Node 22.12 or later, Rust stable and the Tauri platform prerequisites.

```sh
npm ci
npm run desktop:dev
```

Run `npm test`, `npm run check`, and `cargo test --manifest-path src-tauri/Cargo.toml`. Build a desktop installer with `npm run desktop:build -- --runtime /absolute/path/to/factory-signed-pack` (add `--debug` for an unsigned development candidate). The command verifies the release signature, complete payload, target platform and current bundle source before invoking Tauri. It includes the runtime at the resource path used by automatic worker setup. Shell smoke tests can use `npm run desktop:build:shell -- --debug`; those candidates deliberately omit the ML runtime.

Connect using the HTTPS origin of a Frameleaf server. This candidate supports password sign-in; external-browser OAuth/OIDC is not implemented. Automatic enrollment requires a server version containing the desktop-device API from PR #140. Existing servers can still open their photo interface after sign-in, with an explicit worker-upgrade status. A server without an established identity requires a new sign-in after restart.

The setup window has narrow native commands; remote Photos windows have no native capabilities. Session credentials and the Ed25519 installation key are stored only in the OS credential store. Sign-out invalidates the active association; permanent device revocation remains separate.

The app symbol is reused from frameleaf-app at the pinned integration baseline. Inherited Frameleaf source/assets retain AGPL-3.0 obligations; see LICENSE. Detailed architecture and execution plans remain in Confluence.

## Private inference supervision

The native Rust supervisor accepts an installed runtime only after verifying its
Ed25519 signature against application-trusted keys, release epoch, OS/architecture,
protocol, and complete SHA-256 file inventory. The signed manifest identifies the
private Python executable, selected provider and exact Frameleaf server source revision.
New packs also bind `moduleNamespace` to `frameleaf_ml` or `immich_ml`. Older manifests
retain the `immich_ml` default. The builder reads exactly one complete package from
the pinned source revision and checks both native entry points after relocation.
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

The catalogue also retains five CPU profiles for the reconciled PR274 runtime:
three SigLIP roles, the OCR pair and the face pair. Their preprocessing identities
and model keys are distinct from the historical profiles, which remain unchanged.
The newer OCR confidence and face embeddings require the matching NAS producer;
they do not reuse an old qualification. Catalogue membership does not install a
runtime or change the default bundled source pin. The PR274 CPU pack has passed
all five model profiles on macOS ARM64 and received a verified factory signature.
Packaging also permits this source on that target only; other targets retain the
historical source. Hosted rebuilding of the new source and installed-platform
acceptance remain pending.

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
The preview reports OS availability hints, known download-needed logical sizes,
provider-not-ready files, unknown states and separate pinning intent. Pinning does
not establish that bytes are resident. Account completeness remains unknown.
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
Before opening an original, capacity admission also allows a full original to
materialize when residency is unknown or download-needed. It checks the opened
source-parent and staging volumes, summing hydration and staging when their
volume identities match. Unknown residency may conservatively require space for
two copies even for an already local file. Checks repeat for each original, so
retained provider downloads consume the next item's available space. These are
free-space snapshots, not reservations against other writers; separate APFS
volumes sharing a storage pool are not detected as a single volume.

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


### Source availability and exclusions

Windows metadata probes request attributes only, bypass reparse processing and
request no recall. Windows preview roots and named child directories now use a
source-specific opener: only disk/share anchors are ambient, named components
open relative to the parent handle, and directory type plus Cloud Files
classification are checked before listing rights are requested through a pinned
directory self-open. Hidden ancestors are traversed without inventorying them;
privacy exclusions apply to the selected root and its descendants.
Junctions, symbolic links and unknown reparse types remain excluded. Runtime and
private staging roots retain their original strict path checks. Windows cloud-root
copy approval still refuses explicitly until hydration-aware source-version checks
are implemented; this change enables the preview path, not placeholder copies.
Windows compilation and actual provider enumeration still need qualification.
Cloud Files states distinguish available placeholders, missing
local data, and provider-not-ready data (which may already be downloaded). Pinning
intent is counted separately. Unknown or invalid states never become proof of local
residency. Unknown reparse points and Hidden/System entries are excluded.

macOS checks dataless and hidden flags relative to the approved directory handle;
absence of the dataless flag stays unknown because it does not rule out network I/O.
Linux folders also report unknown availability. No file allocation or zero-block
heuristic is used. Copy plans retain their observed summary as a snapshot, and old
signed manifests without it keep their original signature and progress identity.

OS hidden flags are checked again at the source root, intermediate directories and
file before staging. Actual macOS tests cover hidden-file/directory exclusion and
hiding a file after approval. Windows provider probes and placeholder copies still
need installed-provider qualification; existing copy-time reparse refusals remain.
These hints do not reserve hydration storage or measure provider network traffic.

### Photo-copy upload allowance

Each prepared folder copy starts with an original-payload upload allowance of twice its planned size, displayed before copying. Every chunk is charged in the signed local progress journal before sending; failed or uncertain sends are not refunded. Restarting or resuming keeps the used allowance. Exhaustion pauses the copy and retains its staged originals. The user can explicitly approve another allowance of twice the remaining originals, then resume. Older saved runs and missing-progress recovery require this explicit approval before sending more originals; lost historical usage cannot be reconstructed, so recovery starts a new accounting record. This bounds original upload payloads, not HTTP/TLS overhead or cloud-provider hydration/download traffic; provider download accounting remains unfinished.

Windows source versions bind the opened file's volume and full 128-bit file ID in addition to metadata. Identity snapshots use metadata-only, no-recall handles; content handles and the source path are checked before staged publication. Filesystems that cannot return this identity are refused rather than identified only by timestamps ([Microsoft file identity contract](https://learn.microsoft.com/en-us/windows/desktop/api/winbase/ns-winbase-file_id_info)). Existing Unix version strings and signed staged receipts remain compatible. Windows cloud-placeholder hydration is still unfinished.

### Native host media feasibility

`tools/build_host_media.py` builds a disposable **macOS HDR-only feasibility candidate**, using the selected Frameleaf revision's exact libheif/libultrahdr Git and patch pins. It snapshots the native module and existing HDR fixtures, builds the codecs under a new private output directory, and runs every ISO/HDR fixture with ISO tests enabled. It requires developer CMake/pkg-config and a dependency prefix; it does not install system libraries.

```sh
python3 tools/build_host_media.py \
  --source /absolute/path/to/frameleaf-app \
  --revision <reviewed-40-character-source-commit> \
  --node-root /absolute/path/to/the-source-pinned-node \
  --dependency-prefix /opt/homebrew \
  --output /absolute/path/to/a-new-feasibility-directory
```

The receipt records source fixture hashes, Node and binding hashes, codec pins, platform and qualification scope, and always declares `redistributable: false`. The pinned macOS candidate passed 38/38 HDR tests; a stock-library control passed 27 and failed 11. The JPEG include path must come from package metadata to avoid stock HEIF headers shadowing the patched headers. This closes one native-host feasibility gap; it does not establish RAW/Studio parity, a portable dependency bundle, private PostgreSQL, Manager hosting, signing or installed three-platform acceptance.

The [Windows HDR candidate workflow](.github/workflows/windows-host-hdr.yml) uses
the same source-pinned codecs and HDR fixtures with an MSVC binding, matching Node
import library, and audited private DLL closure. Its component checks remain
separate from a complete host pack, Windows 11 installation, and release signing.

### Native host database feasibility

`tools/build_host_database.py` builds PostgreSQL and pgvector under a fresh private macOS output directory. The lock in `runtime/host-database.json` must match the selected Frameleaf revision's database image, extension version and source digest. Downloaded source archives must match their SHA-256 pins before extraction.

```sh
python3 tools/build_host_database.py \
  --source /absolute/path/to/frameleaf-app \
  --revision <reviewed-40-character-source-commit> \
  --dependency-prefix /opt/homebrew \
  --output /absolute/path/to/a-new-database-feasibility-directory
```

This developer fixture requires macOS build tools and dependency libraries. It initializes fresh data with checksums, uses a private Unix socket with TCP disabled, and checks all baseline extensions (cube, earthdistance, pg_trgm, unaccent, uuid-ossp and vector/HNSW), logical dump/restore, restart and physical checksums. Local trust authentication is restricted to that disposable fixture; it is not the product authentication design. The receipt records source/binary/backup hashes and always declares `redistributable: false`; the lock remains `certified: false`. PostgreSQL 19 beta 4 with pgvector 0.8.7 passed this fixture on macOS ARM64. Full application migrations, server startup, portable dependency packaging and installed Windows/Linux acceptance remain separate gates.

The Windows x64 authoring path is `tools/build_host_database_windows.py`;
[its private candidate workflow](.github/workflows/windows-host-database.yml)
prepares pinned MSVC build dependencies and invokes it with the same source,
revision, dependency-prefix and fresh-output arguments. It builds PostgreSQL
with Meson and pgvector with nmake, stages private DLLs and audits their imports.
Its disposable loopback fixture uses SCRAM and checks all six extensions,
dump/restore, restart and physical checksums with developer dependency paths
removed. A submitted workflow is not qualification evidence: actual Windows
build/runtime results, database certification and installed acceptance remain
required; receipts retain `redistributable: false`.

### Native host controller

The desktop now contains a separate signed host-pack verifier and an owned host process controller. `release_policy::verify_host_runtime` uses the desktop's compiled release keys; host packs require the pinned Node/PostgreSQL/vector versions, the current database certification status, all component entry points, geodata inputs and a complete hash-verified payload. ML manifests cannot substitute for host manifests. The existing ML file checks are shared without changing their validation rules.

`VerifiedHostRuntime::start` acquires the profile lease and installs OS process-tree ownership before opening the agent's start gate. Credentials pass through the private input pipe, not command-line arguments. Initial databases use checksums and SCRAM authentication on loopback; temporary initialization credentials are removed. Startup checks both the real API and Microservices. Same-runtime restarts preserve data; changed runtime identities require Manager rather than silently migrating an existing profile. The controller stops the app before PostgreSQL and monitors agent failure to terminate remaining owned processes. Unix termination retains the leader PID until group signalling completes.

Before starting any process, the controller checks the actual profile volume and
any existing database directory. Database admission requires writable local
APFS/HFS on macOS, an ext-family/XFS/Btrfs/ZFS filesystem on Linux, or a fixed NTFS
volume on Windows, with at least 2 GiB available to the current user. Unknown,
network and linked paths are refused. This is a startup floor, not a complete
library/model/backup budget or cloud-sync exclusion check. Photo-library storage
has separate requirements. The native volume probe is exercised locally on macOS;
installed Windows/Linux volume behavior remains unqualified.

Real macOS controller fixtures passed fresh setup, restart and recovery after `initdb` but before application-database creation, using PostgreSQL 19 beta 4, pgvector 0.8.7 and all 38 application migrations. Wrong database passwords were rejected. Those developer fixtures link external development artifacts; they do not prove a complete signed or portable host bundle. A separate Rust test uses synthetic components to exercise the owner, output pipe, restart and forced-agent-crash paths.

Local hosting remains unavailable in the setup UI. A complete private dependency bundle, local-filesystem qualification, OS credential-store setup, Manager operations/recovery and installed platform acceptance are still required. Studio/edge/full media processing are not qualified by startup alone. A private IPC application drain is now drafted; Windows lifecycle acceptance is still required before host release. No database upgrade or restore is enabled by this controller.

### macOS native component relocation

`python3 tools/relocate_macos.py --entries /absolute/path/to/entries.json --output /absolute/path/to/new-payload`
copies an explicitly selected thin Mach-O graph into a new private directory.
The entries JSON maps payload-relative filenames to absolute component binaries.
The tool resolves local and inherited search paths, refuses missing or ambiguous
dependencies, rewrites non-Apple dependencies to private loader-relative paths,
removes build search paths and audits the result. Different loader contexts keep
separate copies even when the input library bytes match. Sources remain unchanged;
existing output and reserved metadata/library destinations are refused.

The receipt records original and relocated SHA-256 values. Local ad-hoc signatures
allow qualification after rewriting; they are separate from release identity
signing and notarization. The receipt remains `redistributable: false` and does
not certify every runtime `dlopen` or plugin/resource requirement.

The macOS ARM64 candidate closed 144 Node/PostgreSQL/HDR objects. A moved payload
passed Node 26.11.1, PostgreSQL 19 beta 4/pgvector 0.8.7 fresh/restore/restart,
all six baseline extensions and physical checksums. Private Node/HDR passed all
38 HDR fixtures. Loaded-image traces for those fixtures contained only private
payload or Apple system images. PostgreSQL's native build reserves linker-header
space for relocation. This does not qualify the complete server, RAW/Studio,
Windows/Linux dependency closure, release signing or installed-device acceptance.


### Production server package

`python3 tools/build_host_server.py --source /absolute/path/to/frameleaf-app --revision <full-commit-sha> --node /absolute/path/to/private-node --output /absolute/path/to/new-output`
builds the selected source revision from a fresh Git archive. The builder requires
Node 26.11.1 and the source revision's pinned pnpm version, builds the SDKs before
the server, uses frozen dependency installs and stages a production hoisted
package. It removes package-manager metadata and CLI aliases, refuses retained
links or special files, and runs that revision's server-package verifier. The
receipt records the source archive, lockfile, Node and staged-file hashes; pnpm
provenance records its version, not an executable digest.

A macOS ARM64 fixture built source
`614425745a23c1a015711bcf06d7e2f8b91661b2` into 30,805 regular files with no
symlinks. Using physically copied private Node/PostgreSQL/HDR components and
geodata, the actual host agent passed fresh API/Microservices startup, restart,
all 38 migrations, checksums, SCRAM authentication and clean stops. This fixture
bypasses the complete signed-host manifest gate. `redistributable` and
`nativeClosureQualified` remain false: full native bindings, RAW/Studio/media,
web assets, release signing and installed three-platform acceptance still need
qualification before local hosting can be enabled.


### Native core workflow plugin

`python3 tools/build_host_plugin.py --source /absolute/path/to/frameleaf-app --revision <full-commit-sha> --node /absolute/path/to/private-node --output /absolute/path/to/new-output`
builds the core workflow WASM and manifest from an exact source archive. Extism
and Binaryen compiler archives must match that revision's platform-specific
`mise.lock` checksums. SDK/plugin installs use the frozen source lockfile; the
plugin's own tests run before staging. The output records tool and artifact
hashes and refuses retained links through the shared production staging gate.

Run `private-node tools/qualify_host_plugin.mjs /absolute/private-runtime /absolute/plugin-build-output`
to execute the receipt-bound WASM through the private server's Extism package.
The macOS ARM64 candidate passed all 54 source tests and five real calls in each
of foreground and worker modes, including the scoped host callback payload.
No host filesystem mounts are granted. This is synthetic workflow acceptance,
not complete workflow/server/UI, redistribution or installed-platform approval.


### Native photo UI and Studio assets

`python3 tools/build_host_web.py --source /absolute/path/to/frameleaf-app --revision <full-commit-sha> --node /absolute/path/to/private-node --output /absolute/path/to/new-output`
builds the shared photo UI and Studio editor into `www/` from an exact Git
archive. The selected source's Studio attestation config supplies npm's version;
bootstrap npm installs it only into the new private toolchain prefix, with
lifecycle scripts disabled. Studio preparation verifies its pinned upstream
archive, patches and adapted-source digest. The existing adapter build preserves
its attribution and unchanged-source audits. SDK/web installs use the frozen
source lockfile. Staging rejects retained links and requires the photo index,
Studio editor and Studio command pages together.

The build receipt records source, lockfile, tool and output hashes. Its build
qualification does not grant Studio rights approval, browser/media execution or
installed-host acceptance; `runtimeQualified` and `redistributable` remain false.


An actual macOS ARM64 integration fixture installed the exact staged core plugin
into the private server database and served byte-matching photo, Studio editor
and Studio command pages over HTTP on fresh startup and restart. Both boots
retained all 38 migrations, checksums, SCRAM authentication and clean stops.
This fixture used copied private components and bypassed the complete signed-host
manifest; it does not prove browser interactions, Studio rendering or media jobs.


### Private native FFmpeg

`python3 tools/build_host_ffmpeg.py --source /absolute/path/to/frameleaf-app --revision <full-commit-sha> --output /absolute/path/to/new-output`
selects the requested platform's portable FFmpeg release from that revision's
`mise.lock` and requires the server's FFmpeg version to agree. Downloaded archives
must match their pinned SHA-256. ZIP extraction rejects unsafe paths, links and
case-insensitive duplicates before writing; staging refuses retained links.
macOS binaries additionally pass architecture, Apple-only load-command and
signature checks. Receipts record the source pins, binaries and synthetic codec
outputs; redistribution and installed-platform qualification remain false.

The [Windows media candidate workflow](.github/workflows/windows-host-media.yml)
runs the existing source-pin and archive-safety tests on Windows before exercising
the portable binaries against the synthetic codec fixtures. It retains the
component, qualification receipt and failure diagnostics as private seven-day
artifacts. Windows execution and installed acceptance remain unverified until
their corresponding checks have actually passed.

The macOS ARM64 candidate passed H.264, HEVC, VP9 and AV1 CPU encode/decode,
AAC/Opus encoding and explicit PCM decoding, video/audio probing and thumbnail
extraction. These are synthetic component checks, not full media/HDR/subtitle or
GPU conformance. The host agent requires sibling `ffmpeg`/`ffprobe` executable
names (`.exe` on Windows), places their verified directory first on PATH and
sets their explicit environment paths. Other inherited caller variables remain
excluded. Actual packaged `MediaRepository` probing and H.264/AAC-to-VP9/Opus
transcoding passed inside the private-server fresh/restart fixture; complete
signed-host and installed three-platform acceptance remain outstanding.

### Private native ExifTool

`python3 tools/build_host_perl.py --output /absolute/path/to/new-perl-output`
builds the checksum-pinned Unix Perl source in `runtime/host-perl.json`. Its module
tree is relocatable without shared libperl. The builder moves the runtime and
makes its original installation unavailable before testing module lookup; loaded
modules and native libraries must remain inside the private tree. macOS native
objects also pass architecture, Apple-only dependency and signature checks.

`python3 tools/build_host_exiftool.py --server /absolute/path/to/server-build-output --perl /absolute/path/to/perl-build-output --output /absolute/path/to/new-exiftool-output`
copies qualified server and Perl packages, checks their complete file inventories,
and binds the packaged ExifTool Node module to sibling `perl/bin/perl`. The
adaptation requires the approved vendor version and exact source fragments,
records original/adapted hashes, and refuses system-interpreter fallback.
Frameleaf-app source is unchanged. Windows uses the vendored executable instead;
this Unix builder does not qualify it.

`python tools/build_host_exiftool_windows.py --server C:/absolute/server-output --output C:/absolute/new-metadata-output`
binds a qualified Windows x64 server to its complete vendored ExifTool 13.59.3
executable and private Perl tree. It verifies the input inventory, approved
vendor-module hash and versions, and required runtime/license files before
removing the resolver's global executable fallback. The Windows server candidate
workflow pins the draft shared migration-loader fix by exact commit; that pin
does not imply the server change has merged.

`/absolute/path/to/private-node tools/qualify_host_exiftool.mjs /absolute/path/to/exiftool-build-output`
checks the actual packaged `MetadataRepository` with synthetic JPEGs: Unicode
metadata read/write, location removal, original and decoded-pixel preservation,
and refusal when the private Perl or Windows executable is missing. This passed on macOS ARM64 with Perl
5.44.0 and exiftool-vendored 39.0.1. Component receipts remain non-redistributable;
complete signed-host assembly and installed three-platform acceptance are pending.

### Private native RAW engine

The Windows authoring path uses MSYS2 UCRT64 GCC/Ninja to build the same pinned
LibRaw, Lensfun and patched darktable sources. `windows-host-raw.yml` builds in
private CI and records the installed toolchain package versions. Staging follows
the transitive x64 PE imports, retains private DLLs, data and notices, rejects
ambiguous or missing libraries and MSYS/Cygwin runtime dependencies, and tests
startup after moving the original installation away. The toolchain is used only
for authoring. Windows production RAW rendering and installed acceptance still
require qualification; a successful component build is insufficient.

`python3 tools/build_host_raw.py --source /absolute/path/to/frameleaf-app --revision <full-commit-sha> --dependency-prefix /opt/homebrew --output /absolute/path/to/new-raw-output`

This macOS authoring builder checks the selected source's darktable, Lensfun,
LibRaw and Frameleaf patch pins, builds the CPU engine, and stages its native
closure, resources and license sources. Developer CMake, Ninja, pkg-config,
autotools, intltool, xsltproc and the engine's build dependencies are required.
Relocation removes original loader search paths; the staged CLI must start with
its original install directory unavailable.

`private-node tools/qualify_host_raw.mjs /absolute/path/to/server-build-output /absolute/path/to/raw-build-output`

Stage the qualified RAW component under the assembled runtime’s `raw/` directory.
The acceptance fixture uses those copied binaries, the packaged Frameleaf renderer and the host launch
environment against a generated Bayer DNG. It checks profiled 16-bit output,
exposure, repeatable pixels, JPEG preview, unchanged original and actual loaded
native images. Host manifests must inventory both `rawRenderer`
(`darktable-cli`) and sibling `rawDecoder` (`dcraw_emu`); both are required before
startup. These are macOS component checks. Full RAW format/recipe conformance,
complete signed host assembly, installed Windows/Linux support, minimum OS and
redistribution qualification remain pending.

### Native Studio worker draft

`tools/build_host_studio.py` is a source-pinned authoring recipe. It snapshots a
selected server revision, prepares the existing pinned engine, builds and attests
its headless harness, then uses the existing bundled-worker packager. The staged
worker includes its JavaScript runtime packages, subtitle sidecar, notices and
server font resources. Required entries and font headers are checked before the
package is accepted; Git LFS pointers are not usable font payloads.

The host supplies profile-local Studio trust and scratch directories, applying
the existing private-directory checks before launching processes. This lets the
server write the worker's enrollment outside container-specific paths.

This draft excludes Chromium and reports `runtimeQualified: false` and
`redistributable: false`. The host manifest requires a `studioBrowser` entry
covered by the signed file inventory, and the host supplies that explicit path
through `FRAMELEAF_STUDIO_CHROMIUM`. A required `studioBrowserGuard` role and its
inventoried Node helper are staged with the worker. On macOS/Linux the guardian
forwards Playwright's CDP pipes to Chromium in the same private group, waits for
an IPC watchdog before launching, and stops that group on owner or watchdog loss.
The watchdog stops the group if the guardian dies. Windows uses the host's Job
Object instead. Native launches request Chromium sandboxing and reject sandbox
disable flags; no fallback is added for sandbox launch failures.

The native path does not select a system or
cached Playwright browser. A qualified browser payload, native font discovery,
loopback worker admission, lifecycle ownership and actual render conformance
remain required before Studio can be enabled. The build/test hold has been lifted.
Local worker, host-owner, guardian and staging tests pass. On macOS ARM64, real
Chromium 156.0.8078.4 (Playwright revision 1248) passed GPU render conformance,
owner/guardian-loss process-group cleanup and browser-session cancellation.
Those component checks used an isolated engine build and system FFmpeg tools;
they do not qualify the complete assembled host or private-font identity.
The Studio authoring recipe completed end to end on macOS ARM64 from local
server revision `1de4d43db65c52db52356cc809454f0b0f08437e`; its packaged
renderer/engine/guardian passed GPU codec/format conformance with the private
headless browser. That check still used system FFmpeg and does not establish
that admission conformance uses the packaged fonts. The local server draft now
registers claim-granted TrueType bytes in each render page, checks their identity,
limits font memory, and refuses titles without a granted family. Real Chromium
reported a custom face for a private test family with all network blocked, and
the renderer produced a title video. The executor also gives each downloaded
font a distinct scratch file. These font changes are included in local source revision
`ba85c33305772ba9f7415ef7d452f011bd4fc75f`. The native builder stages a separate
admission face and metadata from the server font catalog. Native conformance
verifies those bytes and registers them before rendering; missing or changed
private fonts refuse admission before browser launch. The rebuilt package passed
GPU codec/format conformance using its default private font location. This still
uses system FFmpeg and is not assembled-host enrollment/job acceptance.

`tools/stage_host_browser.py` materializes internal browser framework aliases into
a link-free component with a complete hash inventory. It rejects escaped, cyclic
or broken links, special files and unsafe destinations, and keeps its receipt
outside source and payload. It does not acquire or sign browsers; the selected
payload must match the pinned engine's Playwright browser registry. Its receipt
always reports `runtimeQualified: false` and `redistributable: false`.
The full macOS Chrome for Testing app cannot be used in this materialized layout:
macOS rejects signing its flattened framework as an ambiguous bundle. The pinned
headless-shell payload avoids that layout. On macOS ARM64 its five native objects
passed local ad-hoc signing/strict verification, and the signed copy passed GPU
render conformance, owner/guardian-loss cleanup and cancellation. Production
Developer ID signing, hardened runtime and notarization remain unqualified;
component receipts do not enable Studio.

The server worker's native `--owner-pipe` draft also requires Node IPC. Stdin
accepts only `stop\n`; EOF or IPC disconnect cancels work. The dedicated IPC
channel reports `{protocolVersion: 1, state: "qualifying"}` and, only after real
conformance and validated admission, a `ready` message with the pinned engine
digest and session expiry. Tokens and enrolment secrets are omitted. Returning
to admission clears readiness, and its maximum lifetime ends at the worker's
renewal deadline, ten minutes before session expiry. `studioReadyUntil` validates
these messages independently of stdout. The host worker launcher and readiness
consumer are now drafted behind the compiled `STUDIO_ENABLED = false` gate;
this protocol does not enable Studio. The child inherits host group/Job ownership,
uses the loopback API and private profile paths, and has ten minutes to qualify.
An IPC disconnect, process failure or invalid readiness stops the host path.
Shutdown sends one stdin stop command, waits up to 35 seconds for worker/pipe
closure, then forces termination and waits five more seconds. The API and
PostgreSQL remain available during that drain; forced or failed cleanup is
reported after their cleanup. The outer owner allows 150 seconds for the full
shutdown and retains group/Job termination as a final fallback. The controller,
gated launch branch still requires assembled-runtime acceptance; controller and
protocol regression tests pass locally.

The native API/supervisor draft uses `FRAMELEAF_NATIVE_OWNER=1` with a private Node
IPC channel. The host requires the exact `frameleaf:owner-ready:v1` acknowledgement
before API readiness; incompatible older server payloads cannot claim readiness.
`frameleaf:stop` reuses the existing worker shutdown path. Native API and edge
forks receive IPC stops, and owner loss also requests cleanup; container workers
retain signal handling. The host waits up to 40 seconds for process and pipe
closure, then forces and waits five more seconds before PostgreSQL shutdown.
Failed IPC, failed worker cleanup and forced deadlines are reported as failures.
Source protocol regression tests pass locally. Real Windows in-flight request/job
cleanup remains unqualified. Studio remains disabled by its separate gate.


A macOS component host fixture using local server/Studio revision
`ba85c33305772ba9f7415ef7d452f011bd4fc75f` passed fresh and restarted worker
admission with private FFmpeg, browser and font bytes. Each boot required a new
conformance report, followed by ordered Studio/API/database stop and an empty
owned host process group. This exercised a fixture-only copy with Studio enabled;
the shipping gate stays false. The complete signed-host manifest was bypassed.
An authenticated synthetic 720p title export also passed the real worker claim,
server validation, library publication and original download path. It exposed and
fixed the expanded font family's legacy-alias handling in local source revision
`102cab85941bacde1c76accd47a05b4d85093c08`; all eight fixture worker modules
match that source. The downloaded H.264 frame was visually checked.
In-flight drain, other media/recipe cases, complete ML/Manager hosting and
installed Windows/macOS/Linux acceptance remain separate requirements.


A follow-up Mac component fixture interrupted real renders after nonzero frame
progress. Owner cancellation removed browser processes and scratch files; the
cancelled export stayed cancelled after restart. Host stop during another render
queued a retry rather than owner cancellation, stopped all owned processes, then
restarted and published exactly one 30-second result on attempt two. Live-render
shutdown took 7.769 seconds in that fixture. Owner cancellation took 32.827 seconds
with the current 30-second server heartbeat; responsiveness remains a limitation.
These results do not enable the shipping Studio gate or qualify installed platforms.


### Complete host inventory authoring

`tools/build_host_bundle.py` combines the staged private host components with an
application-trusted signed ML candidate. It excludes the fixture agent, checks
all 27 roles and required resources, including Manager backend, recovery UI and the private backup engine, and verifies the nested ML signature and
payload again after copying. The output has `payload/`, an unsigned host
`manifest.json`, and a scoped `qualification.json`; it does not sign or certify
release readiness. The earlier 24-role Mac assembly contains 67,015 files and a 10.9 MB
manifest. Host manifests are bounded at 16 MiB to fit that inventory; larger
manifests are refused. The real payload passed the Rust verifier contract with
an in-memory test authority. A factory host signature, complete controller/ML
runtime qualification and installed three-OS acceptance remain required.


`tools/sign_host_runtime.mjs --candidate /absolute/candidate --private-key-stdin`
checks the full host inventory and independently signed nested ML candidate before
writing a new `manifest.sig`. The existing Infisical-owned release key is supplied
through a protected stdin channel in the trusted authoring environment. The tool
never prints key material or overwrites a signature. Host signing has separate
schema/pin checks; ML signing retains its existing validation and limits.

The earlier 24-role Mac component candidate has a factory-authority signature.
The actual Rust controller verified it through compiled application trust,
started/stopped the server, and restarted/stopped the same database profile.
This establishes the signed controller path. Database certification remains false;
ML execution, app code signing/notarization and installed three-platform acceptance
remain required before release enablement.


The opt-in `factory_host_nested_ml_installs_qualifies_and_predicts` integration check also passed on macOS/aarch64: compiled release authority verifies the complete host, its nested signed CPU runtime installs through RuntimeStore, SigLIP textual qualification and authenticated 768-value inference match the compiled reference, live leases block replacement, and shutdown removes scratch before reactivation. This establishes one installed runtime/model component path; GPU/NAS jobs, other model entries and installed desktop acceptance remain open.


Native database admission now rejects standard macOS File Provider/iCloud paths and probes Windows registered sync-root membership through the opened directory handle. Ordinary local Mac startup/restart and an owned mock-provider refusal pass. This applies only to database state; photo sources keep their separate consent path. Legacy sync-root, Windows runtime and Linux user-space sync qualification remain open before hosting setup is enabled.


The development `frameleaf-native-host --owner-pipe` helper now provides bounded, manifest-pinned native host control using the compiled release authority. Actual signed Mac host startup, same-profile restart, explicit stop, owner-pipe closure and invalid-command drain pass; the final Rust suite has 176 passing tests with 15 opt-in cases skipped. This helper is not yet packaged/signed or wired into Manager’s operation journal/APIs or setup UI. It accepts credentials only on its private stdin pipe and exposes no listener. Existing desktop launches keep `frameleaf-desktop` as Cargo’s default target.


### Native Manager packaging

`tools/build_host_manager.py --source /absolute/repo --revision <commit> --node /absolute/private-node --output /absolute/new-output` builds Manager and its UI from an exact Git archive with the frozen npm lockfile. It ignores package lifecycle scripts, prunes development dependencies and checks deployed production imports, including the shared release verifier. Only runtime code, production dependencies, worker scripts, public release-verification resources, UI assets and licenses enter `output/manager`. `component.json` records the Manager revision independently of the photo server revision.

Pass that folder to `tools/build_host_bundle.py --manager /absolute/output/manager --backup /absolute/backup-output/backup` with the existing host/ML arguments. Manager code, UI, dependencies, release-verification resources and the backup engine are mandatory in the signed host inventory. An older pack that omits these components refuses admission. The previous factory-signed 24-role candidate and its component results remain historical evidence; a new complete candidate/signature and installed qualification are required. This package does not enable native hosting or supply the still-required protected installed supervisor and OS-keystore bootstrap.

Build the private backup component with `python tools/build_host_backup.py --output /absolute/backup-output` using a new output directory. The builder verifies the pinned official restic archive and executable digests, retains its license, and exercises encrypted synthetic backup/check/restore before producing the component receipt. Assembly checks the approved target, executable and license hashes, and rechecks the staged component before constructing the host manifest. Manager backup integration and installed-host recovery qualification remain separate requirements; this component does not enable the native backup action.


Native Manager accepts internal bootstrap protocol 2 through a single bounded private stdin record. The desktop TLS identity is generated in Rust and must be persisted through the OS keystore before use; native Manager validates its key, certificate, validity and exact origin. Native mode does not use OpenSSL or write TLS key files. The administration origin must be canonical HTTPS with a literal loopback address and an unprivileged port. Docker Manager retains its existing listener; the photo server has its separate listener.

After the native HTTPS listener binds, Manager writes one JSON line to its private stdout: `protocolVersion: 2`, `state: "ready"`, `installationId`, `manifestSha256`, and `origin`. A supervisor must validate this receipt from its own live child before declaring readiness; a healthy HTTP listener alone is insufficient. Listener failure emits no readiness receipt. The installed supervisor, protected resource authority and actual OS-keystore acceptance are still required before enabling native setup.


`VerifiedHostRuntime::manager_programs()` now prepares a native Manager launch authority. It checks every payload file and directory, including empty directories, under root-owned non-writable physical ancestors; macOS rejects extended ACLs through its native ACL API. The complete signed inventory is then revalidated. Windows now has a read-only handle-based package ACL validator for stable kernel-volume paths. Runtime verification resolves the opened code root to this kernel spelling before inventory/hash checks and retains it for derived executable paths. It requires a SYSTEM, Administrators or locally resolved TrustedInstaller owner and refuses untrusted mutation grants, unknown ACL forms and reparses. Drive-letter, network and DOS-device aliases remain refused; installed Windows setup and consistent verification/launch path integration are still unfinished. There is no arbitrary executable-path launcher exposed to the webview.

The native `Programs::start` requires a separately protected controller and a previously persisted database password/TLS identity. It sends borrowed bootstrap fields through a bounded private stdin pipe, clears inherited environment and keeps secret bytes zeroized. `NativeManager` owns its child, validates bounded process-specific readiness and scoped HTTPS, and reaps the child after startup failure/cancellation. `shutdown` confirms Manager exit only; host/database quiescence still requires the controller journal/lease proof. The compiled Manager fixture passed this owner with empty PATH; setup, installed package authority, actual keychain persistence and background-role lifecycle remain unfinished.


`Programs::start_from_keystore` now loads a configuration-bound database credential and TLS identity through the existing OS-keystore wrapper. The credential account is scoped by installation/configuration, exact runtime manifest and both physical profile-directory identities. Setup holds an OS file lease through bootstrap, and checks the retained directory identities after TLS keystore work. A missing credential against an existing reservation or database requires recovery; locked or failed storage never falls back to plaintext or a new password.

Native profile roots require root-owned, non-writable, ACL-free parents as well as private user-owned leaf directories. These must be provisioned by the installer; ordinary user-writable home/profile parents refuse native hosting. Physical topology checks reuse the existing controller boundary and reject runtime overlap, state/data aliases and links. Only a nonsecret binding hash is written to `.host-profile`. Marker publication is complete before linking; a crash before unlinking its temporary hard link currently requires explicit recovery, which remains a release gate. Callback-backed profile tests do not establish actual OS-keystore or installed setup acceptance.

TLS keystore records use the same complete profile binding as the database credential, under a separate account namespace. The profile lease remains held across TLS persistence and bootstrap. A changed runtime/configuration requires the future managed migration to preserve and rebind both secrets; automatic replacement currently refuses.

The ignored cross-platform test `actual_postgres_restore_selection_finalization_and_writer_admission`
exercises the compiled controller with a real synthetic PostgreSQL restore. Set
`FRAMELEAF_TEST_HOST_PACK` to a complete measured candidate directory containing
`manifest.json` and `payload`, and `FRAMELEAF_TEST_RESTORE_ROOT` to a new absolute
fixture directory, then run:

```sh
cargo test --manifest-path src-tauri/Cargo.toml --lib \
  actual_postgres_restore_selection_finalization_and_writer_admission -- --ignored --nocapture
```

The test signs only in memory with its test key. It creates an encrypted selected
snapshot and a separate current-state safety backup through the compiled Manager,
requires real owner-pipe verification before selection and independent finalization,
checks writer refusal while pending, retries finalization after a lost acknowledgement,
and starts the selected server before comparing selected and retained original rows.
It retains the synthetic profile and receipt for inspection. Use a fresh fixture root
for each run. This does not establish release trust, OS credential storage, installed
application acceptance, or GPU qualification.

Windows CI checks that this ignored test is compiled. Actual Windows execution
requires a complete Windows candidate with private database, Manager, backup and
media dependencies; compilation alone does not qualify Windows restore.

Windows profile credential bindings now use normalized volume-GUID names captured from opened handles, together with the existing physical state/data identities. Kernel-volume paths remain the authority for runtime verification and execution; GUID names are metadata only. An existing reservation without its matching credential requires recovery. Unix bindings are unchanged. Actual Windows reboot, credential-store and installed-server acceptance remain unverified.

Windows kernel-volume storage separation now stops physical-identity ancestry checks at the actual filesystem root. It preserves self, descendant, ancestor and case-alias overlap refusals without trying to inspect Object Manager directories above the volume. The native Windows regression is present; actual Windows execution and installation remain unverified.

Disposable hosted Linux CI now includes a real `dpkg` failed-install lifecycle probe with a separate package database and log. Its synthetic unsigned runtime must remain half-configured and fenced across retries; an active code lease must block removal. This verifies refusal/recovery behavior only, not successful signed installation or installed-server acceptance.

The opt-in `native_photo` integration test uses a measured test candidate and a new
synthetic profile to check the native web entry, admin signup, generated PNG upload,
thumbnail processing, clean controller stop/restart, and persisted metadata plus
byte-exact original and thumbnail retrieval. Set `FRAMELEAF_TEST_HOST_PACK` as above
and `FRAMELEAF_TEST_PHOTO_STATE` to a new absolute profile path, then run:

```sh
cargo test --manifest-path src-tauri/Cargo.toml --test native_photo -- \
  --ignored --exact actual_native_photo_upload_thumbnail_and_restart
```

It retains only generated fixture data for inspection and uses in-memory test
signing authority. This does not qualify the Owner journal, OS keystore, installed
desktop UI, release signing, or NAS/GPU work.

Windows code capture now uses the device form of the opened object's kernel path
(`\\.\GLOBALROOT\Device\HarddiskVolumeN`), which the standalone Windows process
probe can launch. Both kernel spellings retain strict physical-volume parsing and
bounded ancestor checks; drive/GUID aliases remain excluded from execution authority.
The existing alias-rebind regression and a hosted Node file/module/nested-process
regression cover this boundary. Full bundled-host and installed Windows acceptance
remain separate gates.

Temporary native inspection and restore leases explicitly unlock on scope exit,
as the controller journal lease already does. A descriptor duplicated by a
concurrent fork must not keep a completed operation's lock alive. Active host
ownership and package code leases keep their existing lifetime rules.

The active Windows RAW workflow now pins both the engine builder and server consumer to public source `ee7e711a263f1fdfed14414f1af987c9209a6765`. Engine/patch contracts and the prior consumer sources remain unchanged. New Windows engine rendering and the complete host still require qualification; packaging tests do not establish installed acceptance.

The active Windows database qualifier includes the reviewed startup-pipe and SQL argument fixes from the retained Windows replay. That replay passed fresh/restore/restart and physical checksum checks on its pinned old component; the current-source producer and full Windows host still need separate qualification. The producer workflow now pins public source `ee7e711a263f1fdfed14414f1af987c9209a6765`.

Windows native Node launches use fixed path-preservation options for the verified device-kernel namespace. The host agent, Manager and owned server/admin children receive these options from trusted code rather than the caller environment. The Windows regression checks captured-path file I/O, CommonJS, ESM and nested module loading; this does not qualify an installed full host.

Windows installation layout discovery uses the OS-owned Program Files x64 folder, captures its physical device path and checks existing path protection before appending fixed version/profile names. It ignores caller-selected installation roots and uses `frameleaf-native-host.exe`. This is read-only layout support; privileged installation, SID profile provisioning and installed Windows server startup remain gated.

The Windows installed-host list uses this same anchor and the existing bounded inventory, protected receipt and controller-path checks. Missing or unfinished installations are omitted; malformed entries refuse discovery. Listing installed identities does not verify or start their runtimes.

Windows package authoring has a dedicated `--prepare-windows-package <manifest-sha256> <controller-sha256>` phase. It requires an elevated process and effective Administrators membership before filesystem work, then prepares fixed machine containers with an explicit protected ACL. Existing objects are checked without changing their permissions, and existing versions are refused pending verified maintenance/recovery support. This phase publishes no runtime, receipt or user profile and starts no server. The separate `--finalize-windows-package <manifest-sha256> <controller-sha256>` phase verifies the protected controller and factory-signed runtime under an exclusive, unfenced package lease, then publishes a complete protected installation receipt without replacing existing authority. Matching receipts permit retries; conflicting or malformed receipts and existing profiles are refused. Finalization creates no profile and starts no server. Generic Windows install and maintenance commands remain unavailable pending their implementation. Its actual ACL fixture runs only on an elevated disposable GitHub-hosted Windows runner, using a unique test directory rather than the real Frameleaf installation.

Windows mutable runtime and host-state directories are created with an explicit user-owned protected ACL granting only that user, SYSTEM and Administrators. Reuse checks physical ancestors and existing descendants, refusing foreign access grants (including public read and inherit-only grants), reparse points and thread impersonation. Existing permissions are never repaired automatically. Inspection is bounded to 100,000 descendants; exceeding it refuses admission. This privacy boundary is a prerequisite for Windows SID profile provisioning, which remains gated.

Windows installers can use `--provision-windows-profile <manifest-sha256> <controller-sha256> <user-sid>` after verified package finalization. It resolves a canonical Windows user account, holds an exclusive unfenced lease while verifying the installed resources, and creates only that SID’s protected parent and private `state`/`manager` directories. A scoped ownership privilege permits a different UAC administrator to assign the selected user as owner and restores its previous state afterward. Retries preserve existing data and refuse unexpected entries or unsafe ACLs. This command stores no credentials and starts no server; desktop UAC orchestration and Windows installed-host startup remain gated.

Windows controller CI inspects the actual x64 PE dependency list with the installed MSVC tools, refusing non-OS dependencies such as a private Visual C++ runtime. It then checks the bounded controller error entrypoint with only OS-derived SystemRoot, WINDIR and System32 PATH values, no inherited user/developer runtime paths, and a System32 working directory. Existing Tauri runtime-linking settings are reused. This qualifies a component launch only; UAC consent, installed Windows startup and fresh-machine acceptance remain separate checks.
