use reqwest::Client;
use sha2::{Digest, Sha256};
use std::{
    fs::{self, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, Ordering},
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
struct Partial(PathBuf);
impl Drop for Partial {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}
fn partial(path: &Path, sha256: &str) -> Result<(Partial, std::fs::File), String> {
    let temporary = Partial(path.with_file_name(format!(".download-{sha256}")));
    if let Ok(meta) = fs::symlink_metadata(&temporary.0) {
        if !meta.is_file() || meta.file_type().is_symlink() {
            return Err("model_partial_invalid".into());
        }
        fs::remove_file(&temporary.0).map_err(|_| "model_partial_invalid")?;
    }
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let file = options
        .open(&temporary.0)
        .map_err(|_| "model_file_create_failed")?;
    Ok((temporary, file))
}
fn write_pinned(path: &Path, bytes: &[u8], cancel: &AtomicBool) -> Result<(), String> {
    check_cancel(cancel)?;
    let digest = format!("{:x}", Sha256::digest(bytes));
    if fs::symlink_metadata(path).is_ok() {
        return verify_file(path, bytes.len() as u64, &digest, cancel);
    }
    let (temporary, mut file) = partial(path, &digest)?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|_| "model_file_write_failed")?;
    drop(file);
    fs::hard_link(&temporary.0, path).map_err(|_| "model_file_publish_failed")?;
    Ok(())
}

pub(crate) async fn acquire_file(
    client: &Client,
    url: &str,
    path: &Path,
    bytes: u64,
    sha256: &str,
    cancel: &AtomicBool,
) -> Result<(), String> {
    check_cancel(cancel)?;
    crate::native_runtime::absolute_directory(path.parent().ok_or("model_path_invalid")?)?;
    if fs::symlink_metadata(path).is_ok() {
        return verify_file(path, bytes, sha256, cancel);
    }
    let (temporary, mut file) = partial(path, sha256)?;
    let mut response = client
        .get(url)
        .timeout(std::time::Duration::from_secs(600))
        .send()
        .await
        .map_err(|_| "model_download_unavailable")?;
    if response.status() != reqwest::StatusCode::OK
        || response.content_length().is_some_and(|size| size != bytes)
    {
        return Err("model_download_invalid".into());
    }
    let mut count = 0u64;
    let mut hash = Sha256::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| "model_download_interrupted")?
    {
        check_cancel(cancel)?;
        count = count
            .checked_add(chunk.len() as u64)
            .ok_or("model_download_invalid")?;
        if count > bytes {
            return Err("model_download_invalid".into());
        }
        hash.update(&chunk);
        file.write_all(&chunk)
            .map_err(|_| "model_file_write_failed")?;
    }
    check_cancel(cancel)?;
    if count != bytes || format!("{:x}", hash.finalize()) != sha256 {
        return Err("model_download_hash_mismatch".into());
    }
    file.sync_all().map_err(|_| "model_file_write_failed")?;
    drop(file);
    // Hard-link publication cannot overwrite a cache another process already published.
    fs::hard_link(&temporary.0, path).map_err(|_| "model_file_publish_failed")?;
    Ok(())
}

pub(crate) struct CachePlan<'a> {
    pub task: &'a str,
    pub name: &'a str,
    pub revision: &'a str,
    pub hashes: &'a serde_json::Map<String, serde_json::Value>,
    pub sizes: &'a std::collections::BTreeMap<String, u64>,
}
pub(crate) async fn prepare(
    plan: CachePlan<'_>,
    root: &Path,
    client: &Client,
    cancel: &AtomicBool,
    allow_download: bool,
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
            let url = format!(
                "https://models.frameleaf.cloud/frameleaf/{}/resolve/{}/{name}",
                plan.name, plan.revision
            );
            acquire_file(
                client,
                &url,
                &path,
                *bytes,
                plan.hashes[name].as_str().ok_or("model_plan_invalid")?,
                cancel,
            )
            .await?;
        }
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
        let cache = prepare(plan(), &root.0, &client, &cancel, false)
            .await
            .unwrap();
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
            prepare(plan(), &root.0, &client, &cancel, false)
                .await
                .unwrap(),
            cache
        );
        fs::write(cache.join("clip/test/visual/model.onnx"), b"changed").unwrap();
        assert!(prepare(plan(), &root.0, &client, &cancel, false)
            .await
            .is_err());
        assert_eq!(
            fs::read(cache.join("clip/test/visual/model.onnx")).unwrap(),
            b"changed"
        );
    }
}
