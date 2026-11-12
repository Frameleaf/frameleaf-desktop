use reqwest::{
    header::{HeaderValue, CONTENT_RANGE, ETAG, IF_RANGE, LAST_MODIFIED, RANGE},
    Client,
};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, SystemTime},
};

pub(crate) fn check_cancel(cancel: &AtomicBool) -> Result<(), String> {
    if cancel.load(Ordering::Acquire) {
        Err("worker_setup_cancelled".into())
    } else {
        Ok(())
    }
}
pub(crate) fn verify_file(
    path: &Path,
    bytes: u64,
    sha256: &str,
    cancel: &AtomicBool,
) -> Result<(), String> {
    crate::native_runtime::absolute_directory(path.parent().ok_or("model_path_invalid")?)?;
    let meta = fs::symlink_metadata(path).map_err(|_| "model_file_unavailable")?;
    if !meta.is_file() || meta.file_type().is_symlink() || meta.len() != bytes {
        return Err("model_file_changed".into());
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if meta.file_attributes() & 0x400 != 0 {
            return Err("model_link_forbidden".into());
        }
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let mut file = options.open(path).map_err(|_| "model_file_unavailable")?;
    let mut hash = Sha256::new();
    let mut count = 0u64;
    let mut buffer = [0; 65536];
    loop {
        check_cancel(cancel)?;
        let read = file
            .read(&mut buffer)
            .map_err(|_| "model_file_unavailable")?;
        if read == 0 {
            break;
        }
        count += read as u64;
        if count > bytes {
            return Err("model_file_changed".into());
        }
        hash.update(&buffer[..read]);
    }
    if count != bytes || format!("{:x}", hash.finalize()) != sha256 {
        return Err("model_file_changed".into());
    }
    Ok(())
}
fn partial_path(path: &Path, sha256: &str) -> PathBuf {
    path.with_file_name(format!(".download-{sha256}"))
}
/// Open the kept partial for appending, or create it, and report how much it already holds.
fn open_partial(partial: &Path) -> Result<(fs::File, u64), String> {
    let existing = match fs::symlink_metadata(partial) {
        Ok(meta) if !meta.is_file() || meta.file_type().is_symlink() => {
            return Err("model_partial_invalid".into())
        }
        Ok(meta) => Some(meta),
        Err(_) => None,
    };
    // Appending to a partial that shares its data with another name would write through to it.
    #[cfg(unix)]
    let existing = match existing {
        Some(meta) if std::os::unix::fs::MetadataExt::nlink(&meta) != 1 => {
            fs::remove_file(partial).map_err(|_| "model_partial_invalid")?;
            None
        }
        existing => existing,
    };
    let existing = existing.map(|meta| meta.len());
    let mut options = OpenOptions::new();
    // Not append mode: Windows refuses to truncate through an append-only handle.
    options.write(true).create_new(existing.is_none());
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let mut file = options
        .open(partial)
        .map_err(|_| "model_file_create_failed")?;
    file.seek(SeekFrom::End(0))
        .map_err(|_| "model_file_create_failed")?;
    Ok((file, existing.unwrap_or(0)))
}
/// Empty the partial and write from its start again.
fn truncate(mut file: &fs::File) -> std::io::Result<()> {
    file.set_len(0)?;
    file.seek(SeekFrom::Start(0)).map(|_| ())
}
fn write_pinned(path: &Path, bytes: &[u8], cancel: &AtomicBool) -> Result<(), String> {
    check_cancel(cancel)?;
    let digest = format!("{:x}", Sha256::digest(bytes));
    if fs::symlink_metadata(path).is_ok() {
        return verify_file(path, bytes.len() as u64, &digest, cancel);
    }
    let temporary = partial_path(path, &digest);
    if let Ok(meta) = fs::symlink_metadata(&temporary) {
        if !meta.is_file() || meta.file_type().is_symlink() {
            return Err("model_partial_invalid".into());
        }
        fs::remove_file(&temporary).map_err(|_| "model_partial_invalid")?;
    }
    let (mut file, _) = open_partial(&temporary)?;
    let written = file
        .write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|_| "model_file_write_failed".to_string())
        .and_then(|()| {
            fs::hard_link(&temporary, path).map_err(|_| "model_file_publish_failed".into())
        });
    let _ = fs::remove_file(&temporary);
    written
}

/// Time allowed to connect and receive response headers.
const RESPONSE_TIMEOUT: Duration = Duration::from_secs(30);
/// Longest silence tolerated between body chunks before the attempt is resumed.
const STALL_TIMEOUT: Duration = Duration::from_secs(60);
/// The shared client carries a 30 s whole-request timeout and reqwest only lets a request replace
/// it, not remove it. No real download reaches this ceiling; stalls end at `STALL_TIMEOUT`.
const ATTEMPT_CEILING: Duration = Duration::from_secs(24 * 60 * 60);
const ATTEMPTS: u32 = 5;

fn backoff(attempt: u32) -> Duration {
    if cfg!(test) {
        Duration::from_millis(10)
    } else {
        Duration::from_secs(1 << attempt.min(4))
    }
}
enum Halt {
    /// Transient: the partial is kept and the next attempt resumes from it.
    Retry(&'static str),
    Fatal(String),
}
fn validator(response: &reqwest::Response) -> Option<HeaderValue> {
    let headers = response.headers();
    headers
        .get(ETAG)
        .filter(|tag| !tag.as_bytes().starts_with(b"W/"))
        .or_else(|| headers.get(LAST_MODIFIED))
        .cloned()
}
/// `(first byte, complete length)` of a `206` response.
fn content_range(response: &reqwest::Response) -> Option<(u64, u64)> {
    let value = response.headers().get(CONTENT_RANGE)?.to_str().ok()?;
    let (range, total) = value.strip_prefix("bytes ")?.split_once('/')?;
    Some((range.split_once('-')?.0.parse().ok()?, total.parse().ok()?))
}
fn restart(file: &fs::File, offset: &mut u64) -> Result<(), Halt> {
    truncate(file).map_err(|_| Halt::Fatal("model_file_write_failed".into()))?;
    *offset = 0;
    Ok(())
}
/// One request: continue the partial from `offset` with `Range`, or start over when the mirror
/// answers with the whole object or a different one.
#[allow(clippy::too_many_arguments)]
async fn fetch(
    client: &Client,
    url: &str,
    file: &mut fs::File,
    offset: &mut u64,
    known: &mut Option<HeaderValue>,
    bytes: u64,
    cancel: &AtomicBool,
    progress: &impl Fn(u64),
) -> Result<(), Halt> {
    use reqwest::StatusCode;
    let mut request = client.get(url).timeout(ATTEMPT_CEILING);
    if *offset > 0 {
        request = request.header(RANGE, format!("bytes={offset}-"));
        if let Some(known) = known.as_ref() {
            request = request.header(IF_RANGE, known);
        }
    }
    let Ok(Ok(mut response)) = tokio::time::timeout(RESPONSE_TIMEOUT, request.send()).await else {
        return Err(Halt::Retry("model_download_unavailable"));
    };
    let current = validator(&response);
    match response.status() {
        StatusCode::OK => {
            if response.content_length().is_some_and(|size| size != bytes) {
                return Err(Halt::Fatal("model_download_invalid".into()));
            }
            // The mirror ignored Range or the object changed: this body is the whole file.
            if *offset > 0 {
                restart(file, offset)?;
            }
        }
        StatusCode::PARTIAL_CONTENT if *offset > 0 => {
            let same = known.is_none() || current.is_none() || *known == current;
            if content_range(&response) != Some((*offset, bytes)) || !same {
                restart(file, offset)?;
                *known = None;
                return Err(Halt::Retry("model_download_interrupted"));
            }
        }
        StatusCode::RANGE_NOT_SATISFIABLE if *offset > 0 => {
            restart(file, offset)?;
            *known = None;
            return Err(Halt::Retry("model_download_interrupted"));
        }
        status
            if status.is_server_error()
                || matches!(
                    status,
                    StatusCode::REQUEST_TIMEOUT | StatusCode::TOO_MANY_REQUESTS
                ) =>
        {
            return Err(Halt::Retry("model_download_unavailable"));
        }
        _ => return Err(Halt::Fatal("model_download_invalid".into())),
    }
    *known = current;
    progress(*offset);
    let mut reported_percent = offset.saturating_mul(100) / bytes.max(1);
    loop {
        let chunk = match tokio::time::timeout(STALL_TIMEOUT, response.chunk()).await {
            Ok(Ok(Some(chunk))) => chunk,
            Ok(Ok(None)) => break,
            _ => return Err(Halt::Retry("model_download_interrupted")),
        };
        check_cancel(cancel).map_err(Halt::Fatal)?;
        let count = offset
            .checked_add(chunk.len() as u64)
            .filter(|count| *count <= bytes)
            .ok_or_else(|| Halt::Fatal("model_download_invalid".into()))?;
        file.write_all(&chunk)
            .map_err(|_| Halt::Fatal("model_file_write_failed".into()))?;
        *offset = count;
        let percent = count.saturating_mul(100) / bytes.max(1);
        if percent > reported_percent {
            reported_percent = percent;
            progress(count);
        }
    }
    if *offset != bytes {
        return Err(Halt::Retry("model_download_interrupted"));
    }
    file.sync_all()
        .map_err(|_| Halt::Fatal("model_file_write_failed".into()))
}
/// Fill the partial until it passes the catalogue size and SHA-256 check. Transient failures
/// resume it with bounded, backed-off retries; a partial that fails the check is fetched again
/// from the start once.
async fn download(
    client: &Client,
    url: &str,
    partial: &Path,
    bytes: u64,
    sha256: &str,
    cancel: &AtomicBool,
    progress: &impl Fn(u64),
) -> Result<(), String> {
    let (mut file, mut offset) = open_partial(partial)?;
    let mut known = None;
    let mut refetched = false;
    let mut failure = "model_download_unavailable";
    if offset > bytes {
        truncate(&file).map_err(|_| "model_file_write_failed")?;
        offset = 0;
    }
    for attempt in 0..ATTEMPTS {
        if attempt > 0 {
            tokio::time::sleep(backoff(attempt)).await;
        }
        check_cancel(cancel)?;
        if offset < bytes {
            match fetch(
                client,
                url,
                &mut file,
                &mut offset,
                &mut known,
                bytes,
                cancel,
                progress,
            )
            .await
            {
                Ok(()) => {}
                Err(Halt::Retry(code)) => {
                    failure = code;
                    continue;
                }
                Err(Halt::Fatal(code)) => return Err(code),
            }
        }
        match verify_file(partial, bytes, sha256, cancel) {
            Err(code) if code == "model_file_changed" => {
                if refetched {
                    return Err("model_download_hash_mismatch".into());
                }
                refetched = true;
                truncate(&file).map_err(|_| "model_file_write_failed")?;
                offset = 0;
                known = None;
            }
            result => return result,
        }
    }
    Err(failure.into())
}

#[cfg(test)]
pub(crate) async fn acquire_file(
    client: &Client,
    url: &str,
    path: &Path,
    bytes: u64,
    sha256: &str,
    cancel: &AtomicBool,
) -> Result<(), String> {
    acquire_file_with_progress(client, url, path, bytes, sha256, cancel, |_| {}).await
}

async fn acquire_file_with_progress(
    client: &Client,
    url: &str,
    path: &Path,
    bytes: u64,
    sha256: &str,
    cancel: &AtomicBool,
    progress: impl Fn(u64),
) -> Result<(), String> {
    check_cancel(cancel)?;
    crate::native_runtime::absolute_directory(path.parent().ok_or("model_path_invalid")?)?;
    let partial = partial_path(path, sha256);
    if fs::symlink_metadata(path).is_ok() {
        verify_file(path, bytes, sha256, cancel)?;
        // A crash right after publication leaves the partial linked beside the model.
        let _ = fs::remove_file(&partial);
        return Ok(());
    }
    let result = download(client, url, &partial, bytes, sha256, cancel, &progress)
        .await
        // Hard-link publication cannot overwrite a cache another process already published.
        .and_then(|()| {
            fs::hard_link(&partial, path).map_err(|_| "model_file_publish_failed".into())
        });
    // Only an interrupted transfer is worth resuming; everything else starts clean next time.
    let resumable = matches!(
        result.as_ref().map_err(String::as_str),
        Err("model_download_unavailable" | "model_download_interrupted" | "worker_setup_cancelled")
    ) && fs::symlink_metadata(&partial).is_ok_and(|meta| meta.len() > 0);
    if !resumable {
        let _ = fs::remove_file(&partial);
    }
    result
}

/// Delete one direct child of the cache root. Links are never followed or removed, and the
/// resolved path must still be a child of the resolved root.
pub(crate) fn remove_contained(root: &Path, name: &str) -> Result<(), String> {
    use std::path::Component;
    let failed = || "model_cache_remove_failed".to_string();
    crate::native_runtime::absolute_directory(root)?;
    let mut parts = Path::new(name).components();
    if !matches!(
        (parts.next(), parts.next()),
        (Some(Component::Normal(_)), None)
    ) {
        return Err(failed());
    }
    let path = root.join(name);
    let Ok(meta) = fs::symlink_metadata(&path) else {
        return Ok(());
    };
    if meta.file_type().is_symlink() {
        return Err(failed());
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if meta.file_attributes() & 0x400 != 0 {
            return Err(failed());
        }
    }
    let resolved_root = root.canonicalize().map_err(|_| failed())?;
    let resolved = path.canonicalize().map_err(|_| failed())?;
    if resolved.parent() != Some(&resolved_root) {
        return Err(failed());
    }
    if meta.is_dir() {
        fs::remove_dir_all(&path)
    } else {
        fs::remove_file(&path)
    }
    .map_err(|_| failed())
}
fn newest_change(path: &Path) -> Option<SystemTime> {
    let meta = fs::symlink_metadata(path).ok()?;
    let mut newest = meta.modified().ok()?;
    if meta.is_dir() {
        for entry in fs::read_dir(path).ok()? {
            newest = newest.max(newest_change(&entry.ok()?.path())?);
        }
    }
    Some(newest)
}
const STAGING_RETENTION: Duration = Duration::from_secs(7 * 24 * 60 * 60);
/// Reclaim disk once the current selection has qualified: published revisions the selection no
/// longer references, and staging nothing has touched for a week. Only recognised entries that
/// are direct children of `root` are removed; anything unreadable or unexpected is left alone.
pub(crate) fn prune(
    root: &Path,
    referenced: &std::collections::BTreeSet<String>,
    now: SystemTime,
) -> Result<(), String> {
    crate::native_runtime::absolute_directory(root)?;
    for entry in fs::read_dir(root).map_err(|_| "model_cache_remove_failed")? {
        let Ok(entry) = entry else { continue };
        let Ok(name) = entry.file_name().into_string() else {
            continue;
        };
        if !entry.file_type().is_ok_and(|kind| kind.is_dir()) {
            continue;
        }
        let stale = if name.starts_with(".staging-") {
            untouched_for_retention(&entry.path(), now)
        } else {
            hex_name(&name, 40) && !referenced.contains(&name)
        };
        if stale {
            let _ = remove_contained(root, &name);
        }
    }
    Ok(())
}

fn untouched_for_retention(path: &Path, now: SystemTime) -> bool {
    newest_change(path)
        .and_then(|newest| now.duration_since(newest).ok())
        .is_some_and(|age| age > STAGING_RETENTION)
}
fn hex_name(name: &str, length: usize) -> bool {
    name.len() == length && name.bytes().all(|b| b.is_ascii_hexdigit())
}
/// Whether a process still owns this inference scratch: `Some(true)` while its owner holds the
/// lock, `Some(false)` once the lock is free, `None` when that cannot be told.
fn scratch_in_use(scratch: &Path) -> Option<bool> {
    let owner = scratch.join(crate::native_runtime::SCRATCH_OWNER);
    let meta = match fs::symlink_metadata(&owner) {
        Ok(meta) => meta,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return None,
        Err(_) => return Some(true),
    };
    if !meta.is_file() {
        return Some(true);
    }
    let Ok(file) = fs::OpenOptions::new().read(true).write(true).open(&owner) else {
        return Some(true);
    };
    match file.try_lock() {
        Ok(()) => {
            let _ = file.unlock();
            Some(false)
        }
        Err(_) => Some(true),
    }
}
/// Remove inference scratch no running worker owns. A scratch whose owner lock is held is never
/// touched; one without an owner record (written by an earlier version, or unreadable) is only
/// removed once nothing in it has changed for a week.
pub(crate) fn prune_scratch(root: &Path, now: SystemTime) -> Result<(), String> {
    crate::native_runtime::absolute_directory(root)?;
    for entry in fs::read_dir(root).map_err(|_| "model_cache_remove_failed")? {
        let Ok(entry) = entry else { continue };
        let Ok(name) = entry.file_name().into_string() else {
            continue;
        };
        if !entry.file_type().is_ok_and(|kind| kind.is_dir())
            || name
                .strip_prefix("inference-")
                .is_none_or(|id| uuid::Uuid::parse_str(id).is_err())
        {
            continue;
        }
        let stale = match scratch_in_use(&entry.path()) {
            Some(true) => false,
            Some(false) => true,
            None => untouched_for_retention(&entry.path(), now),
        };
        if stale {
            let _ = remove_contained(root, &name);
        }
    }
    Ok(())
}
/// Remove combined model sets other than the one the current selection runs from, and set
/// staging nothing has touched for a week. `active` is the directory `shared_cache` returned; a
/// selection served from a single model cache has no set of its own.
pub(crate) fn prune_model_sets(root: &Path, active: &Path, now: SystemTime) -> Result<(), String> {
    if fs::symlink_metadata(root).is_err() {
        return Ok(());
    }
    crate::native_runtime::absolute_directory(root)?;
    let active = active
        .parent()
        .filter(|parent| *parent == root)
        .and_then(|_| active.file_name());
    for entry in fs::read_dir(root).map_err(|_| "model_cache_remove_failed")? {
        let Ok(entry) = entry else { continue };
        let Ok(name) = entry.file_name().into_string() else {
            continue;
        };
        if !entry.file_type().is_ok_and(|kind| kind.is_dir()) {
            continue;
        }
        let stale = if name.starts_with(".composition-") {
            untouched_for_retention(&entry.path(), now)
        } else {
            hex_name(&name, 64) && active != Some(entry.file_name().as_os_str())
        };
        if stale {
            let _ = remove_contained(root, &name);
        }
    }
    Ok(())
}

#[derive(Clone, Copy)]
pub(crate) struct CachePlan<'a> {
    pub task: &'a str,
    pub name: &'a str,
    pub revision: &'a str,
    pub hashes: &'a serde_json::Map<String, serde_json::Value>,
    pub sizes: &'a std::collections::BTreeMap<String, u64>,
}
#[derive(Debug, PartialEq)]
pub(crate) enum CacheProgress {
    Verified(u64),
    Download { received: u64, total: u64 },
}
const MIRROR: &str = "https://models.frameleaf.cloud/frameleaf";
pub(crate) async fn prepare(
    plan: CachePlan<'_>,
    root: &Path,
    client: &Client,
    cancel: &AtomicBool,
    allow_download: bool,
    progress: impl Fn(CacheProgress),
) -> Result<PathBuf, String> {
    prepare_from(MIRROR, plan, root, client, cancel, allow_download, progress).await
}
/// A cache that fails its hash or inventory check is discarded and acquired again once; nothing
/// is returned for use until every file has passed the catalogue check.
async fn prepare_from(
    mirror: &str,
    plan: CachePlan<'_>,
    root: &Path,
    client: &Client,
    cancel: &AtomicBool,
    allow_download: bool,
    progress: impl Fn(CacheProgress),
) -> Result<PathBuf, String> {
    let credited = std::sync::atomic::AtomicU64::new(0);
    let first = prepare_once(
        mirror,
        plan,
        root,
        client,
        cancel,
        allow_download,
        |event| {
            if let CacheProgress::Verified(bytes) = event {
                credited.fetch_add(bytes, Ordering::AcqRel);
            }
            progress(event)
        },
    )
    .await;
    let code = match first {
        Err(code)
            if matches!(
                code.as_str(),
                "model_file_changed" | "model_inventory_invalid"
            ) =>
        {
            code
        }
        result => return result,
    };
    check_cancel(cancel)?;
    for name in [
        plan.revision.to_owned(),
        format!(".staging-{}", plan.revision),
    ] {
        if remove_contained(root, &name).is_err() {
            return Err(code);
        }
    }
    // Files already reported as verified must not be counted twice.
    prepare_once(
        mirror,
        plan,
        root,
        client,
        cancel,
        allow_download,
        |event| match event {
            CacheProgress::Verified(bytes) if credited.load(Ordering::Acquire) >= bytes => {
                credited.fetch_sub(bytes, Ordering::AcqRel);
            }
            event => progress(event),
        },
    )
    .await
}
async fn prepare_once(
    mirror: &str,
    plan: CachePlan<'_>,
    root: &Path,
    client: &Client,
    cancel: &AtomicBool,
    allow_download: bool,
    progress: impl Fn(CacheProgress),
) -> Result<PathBuf, String> {
    use crate::{native_runtime::absolute_directory, runtime_store::private_directory};
    use std::collections::BTreeSet;
    if !matches!(plan.task, "clip" | "ocr" | "facial-recognition") {
        return Err("model_plan_invalid".into());
    }
    absolute_directory(root)?;
    check_cancel(cancel)?;
    let active = root.join(plan.revision);
    let complete = fs::symlink_metadata(&active).is_ok();
    let candidate = if complete {
        active.clone()
    } else {
        root.join(format!(".staging-{}", plan.revision))
    };
    if complete {
        absolute_directory(&candidate)?;
    } else {
        private_directory(&candidate)?;
    }
    let model = candidate.join(plan.task).join(plan.name);
    if !complete {
        private_directory(&candidate.join(plan.task))?;
        private_directory(&model)?;
    }
    let reference = format!("models--frameleaf--{}/refs/main", plan.name);
    for (name, bytes) in plan.sizes {
        check_cancel(cancel)?;
        let path = model.join(name);
        if complete {
            verify_file(
                &path,
                *bytes,
                plan.hashes[name].as_str().ok_or("model_plan_invalid")?,
                cancel,
            )?;
            progress(CacheProgress::Verified(*bytes));
            continue;
        }
        let mut directory = model.clone();
        for part in Path::new(name)
            .parent()
            .ok_or("model_path_invalid")?
            .components()
        {
            directory.push(part);
            private_directory(&directory)?;
        }
        if name == &reference {
            write_pinned(&path, plan.revision.as_bytes(), cancel)?;
        } else {
            if !path.exists() && !allow_download {
                return Err("model_download_permission_required".into());
            }
            let url = format!("{mirror}/{}/resolve/{}/{name}", plan.name, plan.revision);
            acquire_file_with_progress(
                client,
                &url,
                &path,
                *bytes,
                plan.hashes[name].as_str().ok_or("model_plan_invalid")?,
                cancel,
                |received| {
                    progress(CacheProgress::Download {
                        received,
                        total: *bytes,
                    })
                },
            )
            .await?;
        }
        progress(CacheProgress::Verified(*bytes));
    }
    let receipt = serde_json::to_vec(plan.hashes).map_err(|_| "model_plan_invalid")?;
    let receipt_path = model.join(".frameleaf-staged.json");
    if complete {
        verify_file(
            &receipt_path,
            receipt.len() as u64,
            &format!("{:x}", Sha256::digest(&receipt)),
            cancel,
        )?;
    } else {
        write_pinned(&receipt_path, &receipt, cancel)?;
    }
    let mut expected: BTreeSet<_> = plan.sizes.keys().cloned().collect();
    expected.insert(".frameleaf-staged.json".into());
    let mut pending = vec![model.clone()];
    let mut actual = BTreeSet::new();
    let mut count = 0usize;
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(&directory).map_err(|_| "model_inventory_invalid")? {
            check_cancel(cancel)?;
            count += 1;
            if count > 8192 {
                return Err("model_inventory_invalid".into());
            }
            let entry = entry.map_err(|_| "model_inventory_invalid")?;
            let path = entry.path();
            let meta = entry.file_type().map_err(|_| "model_inventory_invalid")?;
            if meta.is_dir() {
                absolute_directory(&path)?;
                pending.push(path);
            } else if meta.is_file() {
                // Finder and Explorer drop these into any folder the user opens.
                if [".DS_Store", "Thumbs.db", "desktop.ini"]
                    .iter()
                    .any(|name| entry.file_name().eq_ignore_ascii_case(name))
                {
                    continue;
                }
                actual.insert(
                    path.strip_prefix(&model)
                        .map_err(|_| "model_inventory_invalid")?
                        .to_string_lossy()
                        .replace('\\', "/"),
                );
            } else {
                return Err("model_inventory_invalid".into());
            }
        }
    }
    if actual != expected {
        return Err("model_inventory_invalid".into());
    }
    check_cancel(cancel)?;
    if !complete {
        fs::rename(&candidate, &active).map_err(|_| "model_cache_publish_failed")?;
    }
    Ok(active)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};
    use std::{
        fs,
        io::{Read, Write},
        net::TcpListener,
    };
    use uuid::Uuid;

    fn response(body: &'static [u8], status: u16) -> (String, std::thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/model", listener.local_addr().unwrap());
        let task = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                .unwrap();
            let mut request = [0; 4096];
            assert!(stream.read(&mut request).unwrap() > 0);
            write!(
                stream,
                "HTTP/1.1 {status} Test\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            )
            .unwrap();
            let _ = stream.write_all(body);
        });
        (url, task)
    }
    /// Serve one scripted raw reply per connection, then report the requests it received.
    fn serve(script: Vec<Vec<u8>>) -> (String, std::thread::JoinHandle<Vec<String>>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let task = std::thread::spawn(move || {
            script
                .into_iter()
                .map(|reply| {
                    let (mut stream, _) = listener.accept().unwrap();
                    stream
                        .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                        .unwrap();
                    let mut request = [0; 4096];
                    let read = stream.read(&mut request).unwrap();
                    let _ = stream.write_all(&reply);
                    String::from_utf8_lossy(&request[..read]).to_lowercase()
                })
                .collect()
        });
        (url, task)
    }
    /// A reply that declares `length` body bytes; a shorter `body` drops the connection early.
    fn reply(status: &str, headers: &str, length: usize, body: &[u8]) -> Vec<u8> {
        let mut reply = format!(
            "HTTP/1.1 {status}\r\n{headers}Content-Length: {length}\r\nConnection: close\r\n\r\n"
        )
        .into_bytes();
        reply.extend_from_slice(body);
        reply
    }
    fn weights_hash() -> String {
        format!("{:x}", Sha256::digest(b"weights"))
    }
    struct Staged {
        revision: String,
        hashes: serde_json::Value,
        sizes: std::collections::BTreeMap<String, u64>,
    }
    impl Staged {
        /// Verified weights left in staging, as an interrupted setup leaves them.
        fn new(root: &Path) -> Self {
            let revision = "1".repeat(40);
            let model = root.join(format!(".staging-{revision}")).join("clip/test");
            let mut directory = root.to_path_buf();
            for part in [
                model.parent().unwrap().parent().unwrap(),
                "clip".as_ref(),
                "test".as_ref(),
                "visual".as_ref(),
            ] {
                directory.push(part);
                crate::runtime_store::private_directory(&directory).unwrap();
            }
            fs::write(model.join("visual/model.onnx"), b"weights").unwrap();
            Self {
                hashes: serde_json::json!({
                    "visual/model.onnx": weights_hash(),
                    "models--frameleaf--test/refs/main": format!("{:x}", Sha256::digest(revision.as_bytes())),
                }),
                sizes: std::collections::BTreeMap::from([
                    ("visual/model.onnx".into(), 7),
                    ("models--frameleaf--test/refs/main".into(), 40),
                ]),
                revision,
            }
        }
        fn plan(&self) -> CachePlan<'_> {
            CachePlan {
                task: "clip",
                name: "test",
                revision: &self.revision,
                hashes: self.hashes.as_object().unwrap(),
                sizes: &self.sizes,
            }
        }
    }
    struct Root(std::path::PathBuf);
    impl Root {
        fn new() -> Self {
            let path = std::env::temp_dir()
                .canonicalize()
                .unwrap()
                .join(format!("frameleaf-model-{}", Uuid::new_v4()));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
    }
    impl Drop for Root {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[tokio::test]
    async fn verified_download_is_installed_and_reused_without_a_second_request() {
        let root = Root::new();
        let path = root.0.join("model.onnx");
        let (url, response) = response(b"weights", 200);
        let hash = format!("{:x}", Sha256::digest(b"weights"));
        let client = crate::transport::client().unwrap();
        let cancel = AtomicBool::new(false);
        acquire_file(&client, &url, &path, 7, &hash, &cancel)
            .await
            .unwrap();
        response.join().unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"weights");
        acquire_file(
            &client,
            "http://127.0.0.1:1/unreachable",
            &path,
            7,
            &hash,
            &cancel,
        )
        .await
        .unwrap();
        assert_eq!(fs::read_dir(&root.0).unwrap().count(), 1);
    }

    #[tokio::test]
    async fn corrupt_oversized_and_http_error_downloads_never_publish_a_model() {
        for (body, size, status) in [
            (b"weights".as_slice(), 7, 200),
            (b"oversized", 7, 200),
            (b"error", 7, 403),
        ] {
            let root = Root::new();
            let (url, response) = response(body, status);
            let result = acquire_file(
                &crate::transport::client().unwrap(),
                &url,
                &root.0.join("model"),
                size,
                &"0".repeat(64),
                &AtomicBool::new(false),
            )
            .await;
            response.join().unwrap();
            assert!(result.is_err());
            assert_eq!(fs::read_dir(&root.0).unwrap().count(), 0);
        }
    }

    #[tokio::test]
    async fn cancellation_and_changed_existing_files_fail_without_network_or_replacement() {
        let root = Root::new();
        let path = root.0.join("model");
        let hash = format!("{:x}", Sha256::digest(b"weights"));
        let client = crate::transport::client().unwrap();
        assert!(acquire_file(
            &client,
            "http://127.0.0.1:1",
            &path,
            7,
            &hash,
            &AtomicBool::new(true)
        )
        .await
        .is_err());
        assert!(!path.exists());
        fs::write(&path, b"changed").unwrap();
        assert!(acquire_file(
            &client,
            "http://127.0.0.1:1",
            &path,
            7,
            &hash,
            &AtomicBool::new(false)
        )
        .await
        .is_err());
        assert_eq!(fs::read(&path).unwrap(), b"changed");
    }

    #[tokio::test]
    async fn unknown_network_requires_permission_before_acquiring_missing_weights() {
        let root = Root::new();
        let hashes = serde_json::json!({"visual/model.onnx": "a".repeat(64)});
        let sizes = std::collections::BTreeMap::from([("visual/model.onnx".into(), 7)]);
        let result = prepare(
            CachePlan {
                task: "clip",
                name: "test",
                revision: &"1".repeat(40),
                hashes: hashes.as_object().unwrap(),
                sizes: &sizes,
            },
            &root.0,
            &crate::transport::client().unwrap(),
            &AtomicBool::new(false),
            false,
            |_| {},
        )
        .await;
        assert_eq!(result.unwrap_err(), "model_download_permission_required");
        assert!(!root.0.join("1".repeat(40)).exists());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn linked_model_or_parent_is_never_read_or_replaced() {
        let root = Root::new();
        let original = root.0.join("original");
        fs::write(&original, b"weights").unwrap();
        let link = root.0.join("model");
        std::os::unix::fs::symlink(&original, &link).unwrap();
        let hash = format!("{:x}", Sha256::digest(b"weights"));
        let client = crate::transport::client().unwrap();
        assert!(acquire_file(
            &client,
            "http://127.0.0.1:1",
            &link,
            7,
            &hash,
            &AtomicBool::new(false)
        )
        .await
        .is_err());
        assert!(fs::symlink_metadata(&link)
            .unwrap()
            .file_type()
            .is_symlink());
        let directory = root.0.join("linked-directory");
        std::os::unix::fs::symlink(&root.0, &directory).unwrap();
        assert!(acquire_file(
            &client,
            "http://127.0.0.1:1",
            &directory.join("original"),
            7,
            &hash,
            &AtomicBool::new(false)
        )
        .await
        .is_err());
        assert_eq!(fs::read(&original).unwrap(), b"weights");
    }

    #[tokio::test]
    async fn interrupted_staging_reuses_verified_files_and_publishes_an_offline_receipt() {
        let root = Root::new();
        let stage = root.0.join(format!(".staging-{}", "1".repeat(40)));
        let model = stage.join("clip/test");
        for path in [&stage, &stage.join("clip"), &model, &model.join("visual")] {
            crate::runtime_store::private_directory(path).unwrap();
        }
        fs::write(model.join("visual/model.onnx"), b"weights").unwrap();
        let reference = "1".repeat(40);
        let hashes = serde_json::json!({"visual/model.onnx":format!("{:x}",Sha256::digest(b"weights")), "models--frameleaf--test/refs/main":format!("{:x}",Sha256::digest(reference.as_bytes()))});
        let sizes = std::collections::BTreeMap::from([
            ("visual/model.onnx".into(), 7),
            ("models--frameleaf--test/refs/main".into(), 40),
        ]);
        let plan = || CachePlan {
            task: "clip",
            name: "test",
            revision: &reference,
            hashes: hashes.as_object().unwrap(),
            sizes: &sizes,
        };
        let client = crate::transport::client().unwrap();
        let cancel = AtomicBool::new(false);
        let events = std::cell::RefCell::new(Vec::new());
        let cache = prepare(plan(), &root.0, &client, &cancel, false, |event| {
            events.borrow_mut().push(event)
        })
        .await
        .unwrap();
        let events = events.into_inner();
        assert!(events
            .iter()
            .all(|event| matches!(event, CacheProgress::Verified(_))));
        assert!(events.contains(&CacheProgress::Verified(7)));
        assert_eq!(cache, root.0.join(&reference));
        assert!(!stage.exists());
        assert_eq!(
            fs::read(cache.join("clip/test/models--frameleaf--test/refs/main")).unwrap(),
            reference.as_bytes()
        );
        let receipt: serde_json::Value = serde_json::from_slice(
            &fs::read(cache.join("clip/test/.frameleaf-staged.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(receipt, hashes);
        assert_eq!(
            prepare(plan(), &root.0, &client, &cancel, false, |_| {})
                .await
                .unwrap(),
            cache
        );
        // Without download permission a changed cache is discarded, never returned for use.
        fs::write(cache.join("clip/test/visual/model.onnx"), b"changed").unwrap();
        assert_eq!(
            prepare(plan(), &root.0, &client, &cancel, false, |_| {})
                .await
                .unwrap_err(),
            "model_download_permission_required"
        );
        assert!(!cache.exists());
    }

    #[tokio::test]
    async fn interrupted_download_resumes_with_range_and_verifies() {
        let root = Root::new();
        let path = root.0.join("model.onnx");
        let (url, server) = serve(vec![
            reply("200 OK", "ETag: \"v1\"\r\n", 7, b"wei"),
            reply(
                "206 Partial Content",
                "ETag: \"v1\"\r\nContent-Range: bytes 3-6/7\r\n",
                4,
                b"ghts",
            ),
        ]);
        let client = crate::transport::client().unwrap();
        let cancel = AtomicBool::new(false);
        acquire_file(&client, &url, &path, 7, &weights_hash(), &cancel)
            .await
            .unwrap();
        let requests = server.join().unwrap();
        assert!(!requests[0].contains("range:"));
        assert!(requests[1].contains("\r\nrange: bytes=3-\r\n"));
        assert!(requests[1].contains("\r\nif-range: \"v1\"\r\n"));
        assert_eq!(fs::read(&path).unwrap(), b"weights");
        assert_eq!(fs::read_dir(&root.0).unwrap().count(), 1);
    }

    #[tokio::test]
    async fn partial_survives_exhausted_retries_and_resumes_on_the_next_call() {
        let root = Root::new();
        let path = root.0.join("model.onnx");
        let partial = root.0.join(format!(".download-{}", weights_hash()));
        let client = crate::transport::client().unwrap();
        let cancel = AtomicBool::new(false);
        let (url, server) = serve(vec![reply("200 OK", "", 7, b"wei")]);
        let error = acquire_file(&client, &url, &path, 7, &weights_hash(), &cancel)
            .await
            .unwrap_err();
        server.join().unwrap();
        assert!(matches!(
            error.as_str(),
            "model_download_interrupted" | "model_download_unavailable"
        ));
        assert!(!path.exists());
        assert_eq!(fs::read(&partial).unwrap(), b"wei");
        let (url, server) = serve(vec![reply(
            "206 Partial Content",
            "Content-Range: bytes 3-6/7\r\n",
            4,
            b"ghts",
        )]);
        acquire_file(&client, &url, &path, 7, &weights_hash(), &cancel)
            .await
            .unwrap();
        assert!(server.join().unwrap()[0].contains("\r\nrange: bytes=3-\r\n"));
        assert_eq!(fs::read(&path).unwrap(), b"weights");
        assert!(!partial.exists());
    }

    #[tokio::test]
    async fn mirror_without_range_support_restarts_cleanly() {
        let root = Root::new();
        let path = root.0.join("model.onnx");
        let (url, server) = serve(vec![
            reply("200 OK", "", 7, b"wei"),
            reply("200 OK", "", 7, b"weights"),
        ]);
        acquire_file(
            &crate::transport::client().unwrap(),
            &url,
            &path,
            7,
            &weights_hash(),
            &AtomicBool::new(false),
        )
        .await
        .unwrap();
        assert!(server.join().unwrap()[1].contains("\r\nrange: bytes=3-\r\n"));
        assert_eq!(fs::read(&path).unwrap(), b"weights");
        assert_eq!(fs::read_dir(&root.0).unwrap().count(), 1);
    }

    #[tokio::test]
    async fn corrupted_partial_is_detected_by_hash_and_fetched_again() {
        let root = Root::new();
        let path = root.0.join("model.onnx");
        fs::write(root.0.join(format!(".download-{}", weights_hash())), b"XXX").unwrap();
        let (url, server) = serve(vec![
            reply(
                "206 Partial Content",
                "Content-Range: bytes 3-6/7\r\n",
                4,
                b"ghts",
            ),
            reply("200 OK", "", 7, b"weights"),
        ]);
        acquire_file(
            &crate::transport::client().unwrap(),
            &url,
            &path,
            7,
            &weights_hash(),
            &AtomicBool::new(false),
        )
        .await
        .unwrap();
        let requests = server.join().unwrap();
        assert!(requests[0].contains("\r\nrange: bytes=3-\r\n"));
        assert!(!requests[1].contains("range:"));
        assert_eq!(fs::read(&path).unwrap(), b"weights");
        assert_eq!(fs::read_dir(&root.0).unwrap().count(), 1);
    }

    #[tokio::test]
    async fn busy_mirror_is_retried_and_missing_or_forbidden_model_is_terminal() {
        let client = crate::transport::client().unwrap();
        let cancel = AtomicBool::new(false);
        for status in [
            "503 Service Unavailable",
            "408 Request Timeout",
            "429 Too Many Requests",
        ] {
            let root = Root::new();
            let path = root.0.join("model.onnx");
            let (url, server) = serve(vec![
                reply(status, "", 0, b""),
                reply("200 OK", "", 7, b"weights"),
            ]);
            acquire_file(&client, &url, &path, 7, &weights_hash(), &cancel)
                .await
                .unwrap();
            assert_eq!(server.join().unwrap().len(), 2);
            assert_eq!(fs::read(&path).unwrap(), b"weights");
        }
        for status in ["404 Not Found", "403 Forbidden"] {
            let root = Root::new();
            let (url, server) = serve(vec![reply(status, "", 0, b"")]);
            // A retry would find the fixture gone and report the mirror unavailable instead.
            assert_eq!(
                acquire_file(
                    &client,
                    &url,
                    &root.0.join("model.onnx"),
                    7,
                    &weights_hash(),
                    &cancel
                )
                .await
                .unwrap_err(),
                "model_download_invalid"
            );
            server.join().unwrap();
            assert_eq!(fs::read_dir(&root.0).unwrap().count(), 0);
        }
    }

    #[tokio::test]
    async fn os_metadata_files_do_not_invalidate_the_inventory() {
        let root = Root::new();
        let staged = Staged::new(&root.0);
        let client = crate::transport::client().unwrap();
        let cancel = AtomicBool::new(false);
        let cache = prepare(staged.plan(), &root.0, &client, &cancel, false, |_| {})
            .await
            .unwrap();
        for name in [".DS_Store", "visual/Thumbs.db", "visual/desktop.ini"] {
            fs::write(cache.join("clip/test").join(name), b"os").unwrap();
        }
        assert_eq!(
            prepare(staged.plan(), &root.0, &client, &cancel, false, |_| {})
                .await
                .unwrap(),
            cache
        );
    }

    #[tokio::test]
    async fn tampered_model_is_downloaded_again_once_then_succeeds() {
        let root = Root::new();
        let staged = Staged::new(&root.0);
        let client = crate::transport::client().unwrap();
        let cancel = AtomicBool::new(false);
        let cache = prepare(staged.plan(), &root.0, &client, &cancel, false, |_| {})
            .await
            .unwrap();
        let model = cache.join("clip/test/visual/model.onnx");
        fs::write(&model, b"changed").unwrap();
        let (mirror, server) = serve(vec![reply("200 OK", "", 7, b"weights")]);
        let verified = std::cell::Cell::new(0);
        let repaired = prepare_from(
            &mirror,
            staged.plan(),
            &root.0,
            &client,
            &cancel,
            true,
            |event| {
                if let CacheProgress::Verified(bytes) = event {
                    verified.set(verified.get() + bytes);
                }
            },
        )
        .await
        .unwrap();
        let requests = server.join().unwrap();
        assert_eq!(requests.len(), 1);
        assert!(requests[0].starts_with(&format!(
            "get /test/resolve/{}/visual/model.onnx ",
            staged.revision
        )));
        assert_eq!(repaired, cache);
        assert_eq!(fs::read(&model).unwrap(), b"weights");
        assert_eq!(verified.get(), 47, "repair must not count a file twice");
        // A mirror that keeps serving other bytes fails after that one repair, with nothing
        // unverified left where the runtime would load it.
        fs::write(&model, b"changed").unwrap();
        let (mirror, server) = serve(vec![
            reply("200 OK", "", 7, b"changed"),
            reply("200 OK", "", 7, b"changed"),
        ]);
        assert_eq!(
            prepare_from(
                &mirror,
                staged.plan(),
                &root.0,
                &client,
                &cancel,
                true,
                |_| {}
            )
            .await
            .unwrap_err(),
            "model_download_hash_mismatch"
        );
        assert_eq!(server.join().unwrap().len(), 2);
        assert!(!cache.exists());
        assert!(!root
            .0
            .join(format!(
                ".staging-{}/clip/test/visual/model.onnx",
                staged.revision
            ))
            .exists());
    }

    #[test]
    fn prune_removes_only_unreferenced_revisions_and_old_staging_inside_the_cache_root() {
        let root = Root::new();
        let models = root.0.join("models");
        let (current, superseded, outside) = ("1".repeat(40), "2".repeat(40), "3".repeat(40));
        let staging = format!(".staging-{}", "4".repeat(40));
        for directory in [
            models.join(&current),
            models.join(&superseded),
            models.join(&staging),
            models.join("notes"),
            root.0.join(&outside),
        ] {
            fs::create_dir_all(directory.join("clip")).unwrap();
            fs::write(directory.join("clip/model.onnx"), b"weights").unwrap();
        }
        #[cfg(unix)]
        std::os::unix::fs::symlink(root.0.join(&outside), models.join("5".repeat(40))).unwrap();
        let referenced = std::collections::BTreeSet::from([current.clone()]);
        prune(&models, &referenced, SystemTime::now()).unwrap();
        assert!(!models.join(&superseded).exists());
        for kept in [
            models.join(&current),
            models.join(&staging),
            models.join("notes"),
            root.0.join(&outside),
        ] {
            assert!(kept.join("clip/model.onnx").exists(), "{kept:?}");
        }
        #[cfg(unix)]
        assert!(fs::symlink_metadata(models.join("5".repeat(40))).is_ok());
        prune(
            &models,
            &referenced,
            SystemTime::now() + STAGING_RETENTION + Duration::from_secs(60),
        )
        .unwrap();
        assert!(!models.join(&staging).exists());
        assert!(models.join(&current).join("clip/model.onnx").exists());
        for escape in [
            format!("../{outside}"),
            root.0.join(&outside).display().to_string(),
        ] {
            assert!(remove_contained(&models, &escape).is_err());
        }
        assert!(root.0.join(&outside).join("clip/model.onnx").exists());
    }

    #[test]
    fn scratch_prune_never_removes_scratch_a_worker_owns_or_anything_else() {
        let root = Root::new();
        let scratch = root.0.join("scratch");
        let id = || format!("inference-{}", uuid::Uuid::new_v4());
        let (owned, released, legacy, other) = (id(), id(), id(), "inference-notes".to_string());
        for name in [&owned, &released, &legacy, &other] {
            fs::create_dir_all(scratch.join(name).join("cache")).unwrap();
            fs::write(scratch.join(name).join("cache/blob"), b"scratch").unwrap();
        }
        fs::write(scratch.join("report.json"), b"file").unwrap();
        let outside = root.0.join(id());
        fs::create_dir_all(&outside).unwrap();
        #[cfg(unix)]
        let link = id();
        #[cfg(unix)]
        std::os::unix::fs::symlink(&outside, scratch.join(&link)).unwrap();
        let owner = |name: &str| {
            fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(false)
                .open(
                    scratch
                        .join(name)
                        .join(crate::native_runtime::SCRATCH_OWNER),
                )
                .unwrap()
        };
        let held = owner(&owned);
        held.try_lock().unwrap();
        drop(owner(&released));
        let later = SystemTime::now() + STAGING_RETENTION + Duration::from_secs(60);
        prune_scratch(&scratch, SystemTime::now()).unwrap();
        // The lock is free: its worker has gone. No owner record: unknown, so it is kept for now.
        assert!(!scratch.join(&released).exists());
        for kept in [&owned, &legacy, &other] {
            assert!(scratch.join(kept).join("cache/blob").exists(), "{kept}");
        }
        prune_scratch(&scratch, later).unwrap();
        assert!(!scratch.join(&legacy).exists());
        // A running worker's scratch survives however old it is; so does anything unrecognised.
        assert!(scratch.join(&owned).join("cache/blob").exists());
        assert!(scratch.join(&other).join("cache/blob").exists());
        assert!(scratch.join("report.json").exists());
        assert!(outside.exists());
        #[cfg(unix)]
        assert!(fs::symlink_metadata(scratch.join(&link)).is_ok());
        drop(held);
        prune_scratch(&scratch, SystemTime::now()).unwrap();
        assert!(!scratch.join(&owned).exists());
    }

    #[test]
    fn model_set_prune_keeps_the_active_set_and_everything_outside_the_set_root() {
        let root = Root::new();
        let sets = root.0.join("model-sets");
        let (active, superseded) = ("a".repeat(64), "b".repeat(64));
        let staging = format!(".composition-{}", uuid::Uuid::new_v4());
        let outside = root.0.join("c".repeat(64));
        for directory in [
            sets.join(&active),
            sets.join(&superseded),
            sets.join(&staging),
            sets.join("notes"),
            outside.clone(),
        ] {
            fs::create_dir_all(directory.join("clip")).unwrap();
            fs::write(directory.join("clip/model.onnx"), b"weights").unwrap();
        }
        #[cfg(unix)]
        std::os::unix::fs::symlink(&outside, sets.join("d".repeat(64))).unwrap();
        prune_model_sets(&sets, &sets.join(&active), SystemTime::now()).unwrap();
        assert!(!sets.join(&superseded).exists());
        for kept in [
            sets.join(&active),
            sets.join(&staging),
            sets.join("notes"),
            outside.clone(),
        ] {
            assert!(kept.join("clip/model.onnx").exists(), "{kept:?}");
        }
        #[cfg(unix)]
        assert!(fs::symlink_metadata(sets.join("d".repeat(64))).is_ok());
        let later = SystemTime::now() + STAGING_RETENTION + Duration::from_secs(60);
        // A selection served straight from one model cache has no set: every set is superseded,
        // and a path that merely shares the active set's name elsewhere protects nothing here.
        prune_model_sets(&sets, &outside, later).unwrap();
        assert!(!sets.join(&active).exists());
        assert!(!sets.join(&staging).exists());
        assert!(sets.join("notes/clip/model.onnx").exists());
        assert!(outside.join("clip/model.onnx").exists());
        // A missing set root is nothing to prune.
        prune_model_sets(&root.0.join("absent"), &outside, later).unwrap();
    }
}
