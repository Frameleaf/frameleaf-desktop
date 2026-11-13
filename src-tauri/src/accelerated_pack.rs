//! FD-60: accelerated runtime packs too large for an installer (CUDA, OpenVINO) are downloaded on
//! demand, with the person's consent, and only where this computer has the device.
//!
//! Trust: the installer carries a small delivery manifest per pack, signed with the runtime
//! release key compiled into the app. It names every part of the pack by size and SHA-256 and the
//! SHA-256 of the pack's own signed runtime manifest. Parts are fetched over HTTPS from this
//! version's release, each checked against the delivery manifest, and unpacked using only what
//! the two signed manifests say. The result is then installed by the runtime store exactly like
//! a bundled pack: signature, every file's digest, epoch rules, then qualification.
//!
//! A pack is the concatenation of its runtime manifest, that manifest's 64-byte signature and
//! the payload files in the byte order of their names, cut into parts. The delivery manifest
//! also lists the files that were executable where the pack was built; only those are made
//! executable here, as a bundled pack keeps the modes of its files.
use crate::{
    model_cache::{acquire_file_with_progress, check_cancel},
    native_runtime::{digest_valid, relative, Artifact},
    provider_selection::{device_eligible, Probe, ACCELERATED_MANIFEST, ACCELERATED_SIGNATURE},
    runtime_store::{private_directory, read_bounded},
};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
};

/// Where the installer keeps the delivery manifests, beside the processor runtime.
const DELIVERIES: &str = "accelerated";
/// The app's own folder for a downloaded pack, inside the worker's private data.
const DIRECTORY: &str = "accelerated-pack";
/// GitHub refuses a release file of 2 GiB or more.
const PART_LIMIT: u64 = 2 * 1024 * 1024 * 1024 - 1;
const PACK_LIMIT: u64 = 16 * 1024 * 1024 * 1024;
/// A delivery manifest lists the executable files of a pack, so it can be far larger than its
/// few parts alone would make it.
const DELIVERY_LIMIT: usize = 2 * 1024 * 1024;
/// The release of this very version: the parts the installer's delivery manifests describe.
const RELEASE: &str = concat!(
    "https://github.com/Frameleaf/frameleaf-desktop/releases/download/v",
    env!("CARGO_PKG_VERSION"),
    "/"
);
/// Which pack is offered when a computer has the device for more than one.
const PROVIDERS: [&str; 2] = ["CUDAExecutionProvider", "OpenVINOExecutionProvider"];
/// Serializes changes to the unpacked pack between a download and the worker installing it.
static READY: Mutex<()> = Mutex::new(());

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Part {
    name: String,
    bytes: u64,
    sha256: String,
}
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Manifest {
    schema_version: u32,
    profile: String,
    platform: String,
    architecture: String,
    provider: String,
    epoch: u64,
    manifest_sha256: String,
    manifest_bytes: u64,
    bytes: u64,
    /// Payload files that were executable where the pack was built, in byte order.
    executable: Vec<String>,
    parts: Vec<Part>,
}
/// The few fields of the pack's runtime manifest unpacking needs. The runtime store parses and
/// checks the whole of it before anything runs.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PackManifest {
    platform: String,
    architecture: String,
    provider: String,
    epoch: u64,
    files: BTreeMap<String, Artifact>,
}

fn name_valid(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && name.as_bytes()[0].is_ascii_alphanumeric()
        && !name.contains("..")
        && name.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'-' | b'_')
        })
}
fn signed(raw: &[u8], signature: &[u8; 64], keys: &[VerifyingKey]) -> bool {
    keys.iter().any(|key| {
        key.verify_strict(raw, &Signature::from_bytes(signature))
            .is_ok()
    })
}

/// A delivery manifest whose signature and contents have been checked.
#[derive(Clone, Debug)]
pub(crate) struct Delivery(Manifest);
impl Delivery {
    /// `keys` and `floor` are the app's compiled release authority; `os` and `arch` this computer.
    fn verify(
        raw: &[u8],
        signature: &[u8; 64],
        keys: &[VerifyingKey],
        floor: u64,
        os: &str,
        arch: &str,
    ) -> Result<Self, String> {
        if raw.is_empty() || raw.len() > DELIVERY_LIMIT || !signed(raw, signature, keys) {
            return Err("accelerated_pack_signature_invalid".into());
        }
        let manifest: Manifest =
            serde_json::from_slice(raw).map_err(|_| "accelerated_pack_manifest_invalid")?;
        let mut names = std::collections::BTreeSet::new();
        let mut total = 0u64;
        for part in &manifest.parts {
            total = total.saturating_add(part.bytes);
            if !name_valid(&part.name)
                || !names.insert(part.name.as_str())
                || part.bytes == 0
                || part.bytes > PART_LIMIT
                || !digest_valid(&part.sha256, 64)
            {
                return Err("accelerated_pack_manifest_invalid".into());
            }
        }
        if manifest.schema_version != 1
            || !name_valid(&manifest.profile)
            || manifest.platform != os
            || manifest.architecture != arch
            || !PROVIDERS.contains(&manifest.provider.as_str())
            || manifest.epoch < floor
            || manifest.epoch == 0
            || !digest_valid(&manifest.manifest_sha256, 64)
            || manifest.manifest_bytes == 0
            || manifest.manifest_bytes > 8 * 1024 * 1024
            || manifest.parts.is_empty()
            || manifest.parts.len() > 64
            || total != manifest.bytes
            || manifest.bytes > PACK_LIMIT
            || manifest.bytes <= manifest.manifest_bytes + 64
            || manifest.executable.len() > 100_000
            || manifest
                .executable
                .iter()
                .any(|name| relative(name).is_err())
            || manifest
                .executable
                .windows(2)
                .any(|pair| pair[0] >= pair[1])
        {
            return Err("accelerated_pack_manifest_invalid".into());
        }
        Ok(Self(manifest))
    }
    pub(crate) fn provider(&self) -> &str {
        &self.0.provider
    }
    pub(crate) fn bytes(&self) -> u64 {
        self.0.bytes
    }
}

/// The delivery manifests the installer carries, each only if its signature and contents hold.
fn deliveries(
    bundle: &Path,
    keys: &[VerifyingKey],
    floor: u64,
    os: &str,
    arch: &str,
) -> Vec<Delivery> {
    let directory = bundle.join(DELIVERIES);
    let mut names: Vec<String> = fs::read_dir(&directory)
        .into_iter()
        .flatten()
        .filter_map(|entry| entry.ok()?.file_name().into_string().ok())
        .filter(|name| name.ends_with(".json"))
        .take(16)
        .collect();
    names.sort();
    names
        .iter()
        .filter_map(|name| {
            let raw = read_bounded(&directory.join(name), DELIVERY_LIMIT as u64).ok()?;
            let signature: [u8; 64] = read_bounded(
                &directory.join(format!("{}.sig", name.strip_suffix(".json")?)),
                64,
            )
            .ok()?
            .try_into()
            .ok()?;
            Delivery::verify(&raw, &signature, keys, floor, os, arch).ok()
        })
        .collect()
}
fn installable_with(
    bundle: &Path,
    data: &Path,
    keys: &[VerifyingKey],
    floor: u64,
    os: &str,
    arch: &str,
    probe: &dyn Probe,
) -> Option<PathBuf> {
    let delivery = offer_with(bundle, keys, floor, os, arch, probe)?;
    let _guard = READY
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    ready_matches(data, &delivery).then(|| ready(data))
}
fn offer_with(
    bundle: &Path,
    keys: &[VerifyingKey],
    floor: u64,
    os: &str,
    arch: &str,
    probe: &dyn Probe,
) -> Option<Delivery> {
    // An installer that carries an accelerated runtime itself has nothing to download.
    if fs::symlink_metadata(bundle.join(ACCELERATED_MANIFEST)).is_ok() {
        return None;
    }
    let found = deliveries(bundle, keys, floor, os, arch);
    PROVIDERS.iter().find_map(|provider| {
        found
            .iter()
            .find(|delivery| {
                delivery.provider() == *provider && device_eligible(provider, os, arch, probe)
            })
            .cloned()
    })
}
/// The pack this computer may download: one the installer describes, for a device it has.
pub(crate) fn offer(bundle: &Path, probe: &dyn Probe) -> Option<Delivery> {
    let (floor, keys) = crate::release_policy::trust().ok()?;
    offer_with(
        bundle,
        &keys,
        floor,
        std::env::consts::OS,
        std::env::consts::ARCH,
        probe,
    )
}

fn root(data: &Path) -> PathBuf {
    data.join(DIRECTORY)
}
fn ready(data: &Path) -> PathBuf {
    root(data).join("ready")
}
/// The unpacked pack is the one this delivery describes.
fn ready_matches(data: &Path, delivery: &Delivery) -> bool {
    read_bounded(&ready(data).join(ACCELERATED_MANIFEST), 8 * 1024 * 1024)
        .is_ok_and(|raw| format!("{:x}", Sha256::digest(raw)) == delivery.0.manifest_sha256)
}
/// Remove a directory of ours without following a link that stands in its place.
fn remove_tree(path: &Path) {
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.is_dir() => {
            let _ = fs::remove_dir_all(path);
        }
        Ok(_) => {
            let _ = fs::remove_file(path);
        }
        Err(_) => {}
    }
}

/// The downloaded pack the worker should install: the folder holding its signed runtime manifest
/// and (until it is installed) its payload. `None` when the app has no eligible pack downloaded.
pub(crate) fn installable(bundle: &Path, data: &Path, probe: &dyn Probe) -> Option<PathBuf> {
    let (floor, keys) = crate::release_policy::trust().ok()?;
    installable_with(
        bundle,
        data,
        &keys,
        floor,
        std::env::consts::OS,
        std::env::consts::ARCH,
        probe,
    )
}
/// The runtime store holds the pack now: the unpacked payload is no longer needed. Its signed
/// manifest stays, so the worker keeps finding the installed runtime.
pub(crate) fn installed(directory: &Path) {
    let _guard = READY
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    remove_tree(&directory.join("payload"));
}
/// A downloaded pack with a different epoch from the processor runtime must not be admitted: a
/// newer one would make the runtime store refuse the processor runtime as a rollback, and an
/// older one is itself a rollback.
pub(crate) fn epoch_admissible(manifest: &[u8], processor_epoch: u64) -> Result<(), String> {
    match serde_json::from_slice::<serde_json::Value>(manifest)
        .ok()
        .and_then(|value| value.get("epoch")?.as_u64())
    {
        Some(epoch) if epoch == processor_epoch => Ok(()),
        _ => Err("accelerated_pack_epoch_mismatch".into()),
    }
}
/// Whether a failed install says the downloaded pack itself can never be installed here. A busy
/// store, a locked credential store or a device that is absent right now say nothing about it.
pub(crate) fn install_failure_is_final(code: &str) -> bool {
    matches!(
        code,
        "accelerated_pack_missing"
            | "accelerated_pack_epoch_mismatch"
            | "runtime_signature_invalid"
            | "runtime_manifest_invalid"
            | "runtime_manifest_incompatible"
            | "runtime_artifact_changed"
            | "runtime_artifact_invalid"
            | "runtime_inventory_mismatch"
            | "runtime_interpreter_unapproved"
            | "runtime_path_invalid"
            | "runtime_link_forbidden"
            | "runtime_special_file_forbidden"
            | "runtime_size_invalid"
            | "runtime_epoch_rollback"
            | "runtime_epoch_reused"
    )
}
/// The downloaded pack could not be installed: discard it and keep the reason, so the person
/// sees why the processor is used and can download it again.
pub(crate) fn discard(data: &Path, directory: &Path, code: &str) {
    let _guard = READY
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let manifest = read_bounded(&directory.join(ACCELERATED_MANIFEST), 8 * 1024 * 1024)
        .map(|raw| format!("{:x}", Sha256::digest(raw)));
    remove_tree(directory);
    if let Ok(manifest) = manifest {
        remember_failure(data, &manifest, code);
    }
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Failure {
    manifest_sha256: String,
    code: String,
}
fn code_shaped(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}
fn remember_failure(data: &Path, manifest_sha256: &str, code: &str) {
    if !code_shaped(code) || private_directory(&root(data)).is_err() {
        return;
    }
    if let Ok(raw) = serde_json::to_vec(&Failure {
        manifest_sha256: manifest_sha256.into(),
        code: code.into(),
    }) {
        let _ = fs::write(root(data).join("failure.json"), raw);
    }
}
fn remembered_failure(data: &Path, delivery: &Delivery) -> Option<String> {
    read_bounded(&root(data).join("failure.json"), 1024)
        .ok()
        .and_then(|raw| serde_json::from_slice::<Failure>(&raw).ok())
        .filter(|failure| {
            failure.manifest_sha256 == delivery.0.manifest_sha256 && code_shaped(&failure.code)
        })
        .map(|failure| failure.code)
}
fn declined(data: &Path, delivery: &Delivery) -> bool {
    read_bounded(&root(data).join("declined"), 64)
        .is_ok_and(|raw| raw == delivery.0.manifest_sha256.as_bytes())
}

/// What the AI page shows about the downloadable pack.
#[derive(Clone, Debug, Default, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PackStatus {
    /// `none` (nothing to offer here), `available`, `downloading`, `unpacking`, `ready` (the
    /// worker installs and qualifies it when it next starts) or `failed`.
    pub state: String,
    pub provider: Option<String>,
    pub bytes: u64,
    pub received_bytes: u64,
    pub code: Option<String>,
    /// The person chose Not now for this pack: offer it quietly.
    pub declined: bool,
    /// The connection is known to be metered; the download still needs the same consent.
    pub metered: bool,
}
fn status_of(data: &Path, delivery: Option<&Delivery>) -> PackStatus {
    let Some(delivery) = delivery else {
        return PackStatus {
            state: "none".into(),
            ..PackStatus::default()
        };
    };
    let failure = remembered_failure(data, delivery);
    let state = if ready_matches(data, delivery) {
        "ready"
    } else if failure.is_some() {
        "failed"
    } else {
        "available"
    };
    PackStatus {
        state: state.into(),
        provider: Some(delivery.provider().into()),
        bytes: delivery.bytes(),
        received_bytes: 0,
        code: failure.filter(|_| state == "failed"),
        declined: state == "available" && declined(data, delivery),
        metered: false,
    }
}

/// The codes of the shared downloader, in this download's words.
fn download_code(code: String) -> String {
    match code.as_str() {
        "worker_setup_cancelled" => code,
        "model_download_unavailable" | "model_download_interrupted" => {
            "accelerated_pack_download_interrupted".into()
        }
        "model_download_invalid" | "model_download_hash_mismatch" | "model_file_changed" => {
            "accelerated_pack_download_invalid".into()
        }
        _ => "accelerated_pack_storage_failed".into(),
    }
}
/// The public address of one part. These downloads never use plain HTTP.
fn part_url(base: &str, name: &str) -> Result<String, String> {
    if !base.starts_with("https://") || !base.ends_with('/') || !name_valid(name) {
        return Err("accelerated_pack_download_invalid".into());
    }
    Ok(format!("{base}{name}"))
}
/// A client for the release host: HTTPS only, through the redirect GitHub answers with.
fn release_client() -> Result<reqwest::Client, String> {
    release_client_builder()
        .build()
        .map_err(|_| "network_client_unavailable".into())
}
fn release_client_builder() -> reqwest::ClientBuilder {
    crate::transport::streaming_client_builder()
        .https_only(true)
        .redirect(reqwest::redirect::Policy::limited(5))
}

/// Download every part into `parts/`, resuming what an earlier attempt left and checking each
/// against the signed delivery manifest. `progress` hears the bytes of the whole pack received.
async fn fetch_parts(
    delivery: &Delivery,
    data: &Path,
    client: &reqwest::Client,
    urls: &[String],
    cancel: &AtomicBool,
    progress: &(impl Fn(u64) + Sync),
) -> Result<(), String> {
    let parts = root(data).join("parts");
    if urls.len() != delivery.0.parts.len() {
        return Err("accelerated_pack_download_invalid".into());
    }
    private_directory(&root(data))?;
    private_directory(&parts)?;
    let mut done = 0u64;
    for (part, url) in delivery.0.parts.iter().zip(urls) {
        acquire_file_with_progress(
            client,
            url,
            &parts.join(&part.name),
            part.bytes,
            &part.sha256,
            cancel,
            |received| progress(done + received),
        )
        .await
        .map_err(download_code)?;
        done += part.bytes;
        progress(done);
    }
    Ok(())
}

/// The parts read as one stream, each checked again for its exact size and digest as it ends.
struct Parts<'a> {
    directory: PathBuf,
    parts: std::slice::Iter<'a, Part>,
    current: Option<(fs::File, u64, Sha256, &'a Part)>,
}
impl Read for Parts<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        let invalid = || std::io::Error::from(std::io::ErrorKind::InvalidData);
        if buffer.is_empty() {
            return Ok(0);
        }
        loop {
            if self.current.is_none() {
                let Some(part) = self.parts.next() else {
                    return Ok(0);
                };
                let path = self.directory.join(&part.name);
                let meta = fs::symlink_metadata(&path)?;
                if !meta.is_file() || meta.len() != part.bytes {
                    return Err(invalid());
                }
                self.current = Some((fs::File::open(path)?, 0, Sha256::new(), part));
            }
            let (file, read, hash, part) = self.current.as_mut().unwrap();
            let limit = buffer.len().min((part.bytes - *read) as usize);
            let count = file.read(&mut buffer[..limit])?;
            if count > 0 {
                hash.update(&buffer[..count]);
                *read += count as u64;
                return Ok(count);
            }
            let (_, read, hash, part) = self.current.take().unwrap();
            if read != part.bytes || format!("{:x}", hash.finalize()) != part.sha256 {
                return Err(invalid());
            }
        }
    }
}

fn create_file(path: &Path, executable: bool) -> Result<fs::File, String> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(if executable { 0o700 } else { 0o600 });
    }
    #[cfg(not(unix))]
    let _ = executable;
    options
        .open(path)
        .map_err(|_| "accelerated_pack_storage_failed".into())
}
fn write_stream(
    source: &mut impl Read,
    target: &mut fs::File,
    bytes: u64,
    cancel: &AtomicBool,
) -> Result<(), String> {
    let mut buffer = vec![0u8; 1024 * 1024];
    let mut left = bytes;
    while left > 0 {
        check_cancel(cancel)?;
        let limit = buffer.len().min(left.min(usize::MAX as u64) as usize);
        let count = source
            .read(&mut buffer[..limit])
            .map_err(|_| "accelerated_pack_archive_invalid")?;
        if count == 0 {
            return Err("accelerated_pack_archive_invalid".into());
        }
        target
            .write_all(&buffer[..count])
            .map_err(|_| "accelerated_pack_storage_failed")?;
        left -= count as u64;
    }
    Ok(())
}
fn unpack_into(
    delivery: &Delivery,
    parts: &Path,
    staging: &Path,
    keys: &[VerifyingKey],
    cancel: &AtomicBool,
) -> Result<(), String> {
    let mut stream = Parts {
        directory: parts.into(),
        parts: delivery.0.parts.iter(),
        current: None,
    };
    let mut raw = vec![0u8; delivery.0.manifest_bytes as usize];
    let mut signature = [0u8; 64];
    stream
        .read_exact(&mut raw)
        .and_then(|()| stream.read_exact(&mut signature))
        .map_err(|_| "accelerated_pack_archive_invalid")?;
    // The delivery manifest names this exact runtime manifest; its own signature is checked here
    // so nothing is written for a pack the runtime store would refuse.
    if format!("{:x}", Sha256::digest(&raw)) != delivery.0.manifest_sha256
        || !signed(&raw, &signature, keys)
    {
        return Err("accelerated_pack_archive_invalid".into());
    }
    let manifest: PackManifest =
        serde_json::from_slice(&raw).map_err(|_| "accelerated_pack_archive_invalid")?;
    let payload_bytes = manifest
        .files
        .values()
        .try_fold(0u64, |total, artifact| total.checked_add(artifact.bytes));
    if manifest.platform != delivery.0.platform
        || manifest.architecture != delivery.0.architecture
        || manifest.provider != delivery.0.provider
        || manifest.epoch != delivery.0.epoch
        || manifest.files.is_empty()
        || manifest.files.len() > 100_000
        || payload_bytes.and_then(|total| total.checked_add(raw.len() as u64 + 64))
            != Some(delivery.0.bytes)
        || delivery
            .0
            .executable
            .iter()
            .any(|name| !manifest.files.contains_key(name))
    {
        return Err("accelerated_pack_archive_invalid".into());
    }
    let payload = staging.join("payload");
    fs::create_dir(&payload).map_err(|_| "accelerated_pack_storage_failed")?;
    for (name, artifact) in &manifest.files {
        let path = payload.join(relative(name).map_err(|_| "accelerated_pack_archive_invalid")?);
        fs::create_dir_all(path.parent().ok_or("accelerated_pack_archive_invalid")?)
            .map_err(|_| "accelerated_pack_storage_failed")?;
        // Executable exactly where the signed delivery manifest says the built file was.
        let executable = delivery.0.executable.binary_search(name).is_ok();
        let mut file = create_file(&path, executable)?;
        write_stream(&mut stream, &mut file, artifact.bytes, cancel)?;
        file.sync_all()
            .map_err(|_| "accelerated_pack_storage_failed")?;
    }
    // Nothing may follow the last file, and the last part must end with it.
    if !matches!(stream.read(&mut [0u8; 1]), Ok(0)) {
        return Err("accelerated_pack_archive_invalid".into());
    }
    for (name, bytes) in [
        (ACCELERATED_MANIFEST, raw.as_slice()),
        (ACCELERATED_SIGNATURE, signature.as_slice()),
    ] {
        create_file(&staging.join(name), false)?
            .write_all(bytes)
            .map_err(|_| "accelerated_pack_storage_failed")?;
    }
    Ok(())
}
/// Rebuild the pack from its downloaded parts and put it where the worker installs it from. The
/// parts are removed once that succeeded, or when they can never make a pack.
fn unpack(
    delivery: &Delivery,
    data: &Path,
    keys: &[VerifyingKey],
    cancel: &AtomicBool,
) -> Result<(), String> {
    let parts = root(data).join("parts");
    let staging = root(data).join(format!("staging-{}", uuid::Uuid::new_v4()));
    private_directory(&staging)?;
    let unpacked = unpack_into(delivery, &parts, &staging, keys, cancel).and_then(|()| {
        let _guard = READY
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        remove_tree(&ready(data));
        fs::rename(&staging, ready(data)).map_err(|_| "accelerated_pack_storage_failed".into())
    });
    match &unpacked {
        Ok(()) => remove_tree(&parts),
        Err(code) => {
            remove_tree(&staging);
            if code == "accelerated_pack_archive_invalid" {
                remove_tree(&parts);
            }
        }
    }
    unpacked
}
/// Earlier attempts that were interrupted while unpacking.
fn remove_stale_staging(data: &Path) {
    for entry in fs::read_dir(root(data)).into_iter().flatten().flatten() {
        if entry
            .file_name()
            .to_str()
            .is_some_and(|name| name.starts_with("staging-"))
        {
            remove_tree(&entry.path());
        }
    }
}

/// The app's one download of an accelerated pack.
#[derive(Default)]
pub(crate) struct AcceleratedPack {
    /// The status while a download runs; what is on disk says the rest.
    active: Arc<Mutex<Option<PackStatus>>>,
    cancel: Arc<AtomicBool>,
}
impl AcceleratedPack {
    pub(crate) fn status(&self, bundle: &Path, data: &Path, probe: &dyn Probe) -> PackStatus {
        if let Some(active) = self.active.lock().unwrap().clone() {
            return active;
        }
        status_of(data, offer(bundle, probe).as_ref())
    }
    /// Not now: nothing is ever downloaded without the person asking, so this only quiets the offer.
    pub(crate) fn decline(&self, bundle: &Path, data: &Path, probe: &dyn Probe) -> PackStatus {
        if let Some(delivery) = offer(bundle, probe) {
            if private_directory(&root(data)).is_ok() {
                let _ = fs::write(root(data).join("declined"), &delivery.0.manifest_sha256);
            }
        }
        self.status(bundle, data, probe)
    }
    /// Stop the running download. What it received stays and the next download resumes it.
    pub(crate) fn cancel(&self) {
        self.cancel.store(true, Ordering::Release);
    }
    /// Download and unpack the offered pack; the person asked for it. Returns once it is ready
    /// for the worker, was cancelled or failed; `notify` hears every change on the way.
    pub(crate) async fn download(
        &self,
        bundle: PathBuf,
        data: PathBuf,
        notify: impl Fn(PackStatus) + Send + Sync + 'static,
    ) -> Result<PackStatus, String> {
        let probe = crate::provider_selection::Host;
        let delivery = offer(&bundle, &probe).ok_or("accelerated_pack_unavailable")?;
        if ready_matches(&data, &delivery) {
            return Ok(status_of(&data, Some(&delivery)));
        }
        let starting = PackStatus {
            state: "downloading".into(),
            provider: Some(delivery.provider().into()),
            bytes: delivery.bytes(),
            ..PackStatus::default()
        };
        {
            let mut active = self.active.lock().unwrap();
            if active.is_some() {
                return Err("accelerated_pack_busy".into());
            }
            *active = Some(starting.clone());
        }
        self.cancel.store(false, Ordering::Release);
        notify(starting);
        let result = self.run(&delivery, &data, &notify).await;
        if let Err(code) = &result {
            if code != "worker_setup_cancelled" {
                remember_failure(&data, &delivery.0.manifest_sha256, code);
            }
        }
        *self.active.lock().unwrap() = None;
        let status = status_of(&data, Some(&delivery));
        notify(status.clone());
        Ok(status)
    }
    async fn run(
        &self,
        delivery: &Delivery,
        data: &Path,
        notify: &(impl Fn(PackStatus) + Send + Sync),
    ) -> Result<(), String> {
        private_directory(&root(data))?;
        let _ = fs::remove_file(root(data).join("failure.json"));
        let _ = fs::remove_file(root(data).join("declined"));
        remove_stale_staging(data);
        // The parts and the unpacked files exist side by side for a moment. An unreadable
        // volume decides nothing here: writing reports a full disk itself.
        let needed = delivery.bytes().saturating_mul(2);
        if crate::host_storage::available_bytes(&root(data)).is_ok_and(|free| free < needed) {
            return Err("accelerated_pack_disk_space".into());
        }
        let urls = delivery
            .0
            .parts
            .iter()
            .map(|part| part_url(RELEASE, &part.name))
            .collect::<Result<Vec<_>, _>>()?;
        let client = release_client()?;
        let active = self.active.clone();
        let progress = |received: u64| {
            let mut active = active.lock().unwrap();
            if let Some(status) = active.as_mut() {
                status.received_bytes = received;
                let snapshot = status.clone();
                drop(active);
                notify(snapshot);
            }
        };
        fetch_parts(delivery, data, &client, &urls, &self.cancel, &progress).await?;
        if let Some(status) = self.active.lock().unwrap().as_mut() {
            status.state = "unpacking".into();
            notify(status.clone());
        }
        let (delivery, data, cancel) = (delivery.clone(), data.to_path_buf(), self.cancel.clone());
        tauri::async_runtime::spawn_blocking(move || {
            let (_, keys) = crate::release_policy::trust()?;
            unpack(&delivery, &data, &keys, &cancel)
        })
        .await
        .map_err(|_| "accelerated_pack_storage_failed")?
    }
}

#[cfg(test)]
mod tests;
