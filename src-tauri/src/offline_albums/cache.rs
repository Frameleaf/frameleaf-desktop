use super::remote::{self, Library, Plan, CHUNK};
use crate::{connection::SavedConnection, credentials, runtime_store};
use rand::RngCore;
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};
use uuid::Uuid;
use zeroize::{ZeroizeOnDrop, Zeroizing};

const KEY: &str = "offline-albums-key";
pub(super) const CAP: u64 = 2 * 1024 * 1024 * 1024;
pub(super) const GRACE_SECONDS: u64 = 24 * 60 * 60;
const OVERHEAD: u64 = 12 + 16;
const MAX_MANIFEST: u64 = 1024 * 1024;
const MAX_ALBUMS: usize = 16;
pub(super) const MAX_RANGE: u64 = 4 * CHUNK as u64;
const ERROR: &str = "offline_album_storage_unavailable";

#[derive(Serialize, Deserialize, ZeroizeOnDrop)]
struct Credential {
    scope: [u8; 32],
    key: [u8; 32],
}

fn scope(saved: &SavedConnection) -> Result<[u8; 32], String> {
    let server = crate::connection::normalize_server(&saved.server)?;
    let binding = Zeroizing::new(
        serde_json::to_vec(&(
            &saved.server_id,
            &saved.account_id,
            server.as_str(),
            &saved.token,
        ))
        .map_err(|_| ERROR)?,
    );
    Ok(Sha256::digest(binding.as_slice()).into())
}

pub(super) struct Cache {
    root: PathBuf,
    key: Credential,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct Manifest {
    plan: Plan,
    checked_at: u64,
    bytes: u64,
    sizes: BTreeMap<Uuid, u64>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct AlbumView {
    id: Uuid,
    name: String,
    bytes: u64,
    expires_at: u64,
    items: Vec<ItemView>,
}

#[derive(Serialize)]
struct ItemView {
    id: Uuid,
    name: String,
    mime: String,
}

fn now() -> Result<u64, String> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ERROR)?
        .as_secs())
}

impl Manifest {
    fn valid_at(&self, timestamp: u64) -> bool {
        timestamp >= self.checked_at && timestamp < self.checked_at.saturating_add(GRACE_SECONDS)
    }

    fn view(self) -> AlbumView {
        AlbumView {
            id: self.plan.id,
            name: self.plan.name,
            bytes: self.bytes,
            expires_at: self.checked_at.saturating_add(GRACE_SECONDS),
            items: self
                .plan
                .items
                .into_iter()
                .map(|item| ItemView {
                    id: item.id,
                    name: item.name,
                    mime: item.mime,
                })
                .collect(),
        }
    }
}

impl Cache {
    pub fn open(
        base: &Path,
        saved: &SavedConnection,
        create: bool,
    ) -> Result<Option<Self>, String> {
        let binding = scope(saved)?;
        let key = match credentials::load::<Credential>(KEY)? {
            Some(key) if key.scope == binding => key,
            Some(_) => return Err("offline_album_access_changed".into()),
            None if create => {
                // A key discarded on sign-out cannot make earlier ciphertext readable again.
                Self::purge(base)?;
                let mut key = Credential {
                    scope: binding,
                    key: [0; 32],
                };
                rand::rngs::OsRng.fill_bytes(&mut key.key);
                credentials::save(KEY, &key)?;
                key
            }
            None => return Ok(None),
        };
        let root = base.join("offline-albums");
        runtime_store::private_directory(&root)?;
        let cache = Self { root, key };
        cache.clean_stages()?;
        Ok(Some(cache))
    }

    pub fn purge(base: &Path) -> Result<(), String> {
        let deleted = credentials::delete(KEY);
        let root = base.join("offline-albums");
        match fs::symlink_metadata(&root) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {
                runtime_store::private_directory(&root)?;
                fs::remove_dir_all(root).map_err(|_| ERROR)?;
            }
            _ => return Err(ERROR.into()),
        }
        deleted
    }

    fn clean_stages(&self) -> Result<(), String> {
        for entry in fs::read_dir(&self.root).map_err(|_| ERROR)? {
            let entry = entry.map_err(|_| ERROR)?;
            let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
                continue;
            };
            if name
                .strip_prefix(".stage-")
                .is_some_and(|value| Uuid::parse_str(value).is_ok())
            {
                runtime_store::private_directory(&entry.path())?;
                fs::remove_dir_all(entry.path()).map_err(|_| ERROR)?;
            }
        }
        Ok(())
    }

    fn album_ids(&self) -> Result<Vec<Uuid>, String> {
        let mut ids = Vec::new();
        for entry in fs::read_dir(&self.root).map_err(|_| ERROR)? {
            let entry = entry.map_err(|_| ERROR)?;
            let name = entry.file_name();
            let id = name
                .to_str()
                .and_then(|value| Uuid::parse_str(value).ok())
                .ok_or(ERROR)?;
            if name != id.to_string().as_str() || ids.len() >= MAX_ALBUMS {
                return Err(ERROR.into());
            }
            ids.push(id);
        }
        ids.sort_unstable();
        Ok(ids)
    }

    fn directory(&self, id: Uuid) -> PathBuf {
        self.root.join(id.to_string())
    }

    pub fn remove(&self, id: Uuid) -> Result<(), String> {
        let path = self.directory(id);
        match fs::symlink_metadata(&path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {
                runtime_store::private_directory(&path)?;
                fs::remove_dir_all(path).map_err(|_| ERROR.into())
            }
            _ => Err(ERROR.into()),
        }
    }

    fn manifest(&self, id: Uuid) -> Result<Manifest, String> {
        let dir = self.directory(id);
        crate::native_runtime::absolute_directory(&dir)?;
        let contents = self.read(&dir.join("album"), &format!("manifest:{id}"), MAX_MANIFEST)?;
        let manifest: Manifest = serde_json::from_slice(&contents).map_err(|_| ERROR)?;
        if manifest.plan.id != id
            || manifest.bytes > CAP
            || manifest.plan.items.is_empty()
            || manifest.plan.items.len() > remote::MAX_ITEMS
            || manifest.sizes.len() != manifest.plan.items.len()
            || manifest.plan.items.iter().any(|item| {
                manifest
                    .sizes
                    .get(&item.id)
                    .is_none_or(|size| *size == 0 || *size > CAP)
            })
            || manifest.sizes.values().sum::<u64>() != manifest.bytes
        {
            return Err(ERROR.into());
        }
        Ok(manifest)
    }

    fn write_manifest(&self, path: &Path, manifest: &Manifest) -> Result<(), String> {
        let id = manifest.plan.id;
        let bytes = serde_json::to_vec(manifest).map_err(|_| ERROR)?;
        if bytes.len() as u64 > MAX_MANIFEST {
            return Err(ERROR.into());
        }
        let file = path.join(format!(".manifest-{}", Uuid::new_v4()));
        let result = self
            .write(&file, &format!("manifest:{id}"), bytes)
            .and_then(|_| fs::rename(&file, path.join("album")).map_err(|_| ERROR.into()));
        if result.is_err() {
            let _ = fs::remove_file(file);
        }
        result
    }

    fn aead(&self) -> Result<LessSafeKey, String> {
        Ok(LessSafeKey::new(
            UnboundKey::new(&AES_256_GCM, &self.key.key).map_err(|_| ERROR)?,
        ))
    }

    fn write(&self, path: &Path, binding: &str, plaintext: Vec<u8>) -> Result<(), String> {
        let mut file = Self::create_file(path)?;
        self.seal(&mut file, binding, plaintext)?;
        file.sync_all().map_err(|_| ERROR.into())
    }

    fn create_file(path: &Path) -> Result<File, String> {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        options.open(path).map_err(|_| ERROR.into())
    }

    fn seal(&self, file: &mut File, binding: &str, mut plaintext: Vec<u8>) -> Result<(), String> {
        let mut nonce = [0u8; 12];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        self.aead()?
            .seal_in_place_append_tag(
                Nonce::assume_unique_for_key(nonce),
                Aad::from(binding),
                &mut plaintext,
            )
            .map_err(|_| ERROR)?;
        file.write_all(&nonce)
            .and_then(|_| file.write_all(&plaintext))
            .map_err(|_| ERROR.into())
    }

    fn read(&self, path: &Path, binding: &str, limit: u64) -> Result<Vec<u8>, String> {
        let metadata = fs::symlink_metadata(path).map_err(|_| ERROR)?;
        if !metadata.is_file()
            || metadata.file_type().is_symlink()
            || metadata.len() > limit + OVERHEAD
        {
            return Err(ERROR.into());
        }
        let mut file = File::open(path).map_err(|_| ERROR)?;
        let mut nonce = [0u8; 12];
        file.read_exact(&mut nonce).map_err(|_| ERROR)?;
        let mut bytes = Vec::new();
        file.take(limit + OVERHEAD + 1 - nonce.len() as u64)
            .read_to_end(&mut bytes)
            .map_err(|_| ERROR)?;
        if bytes.len() as u64 > limit + 16 {
            return Err(ERROR.into());
        }
        self.open_chunk(binding, nonce, bytes)
    }

    fn open_chunk(
        &self,
        binding: &str,
        nonce: [u8; 12],
        mut bytes: Vec<u8>,
    ) -> Result<Vec<u8>, String> {
        let size = self
            .aead()?
            .open_in_place(
                Nonce::assume_unique_for_key(nonce),
                Aad::from(binding),
                &mut bytes,
            )
            .map_err(|_| ERROR)?
            .len();
        bytes.truncate(size);
        Ok(bytes)
    }

    fn storage_used(&self) -> Result<u64, String> {
        let mut bytes = 0u64;
        for id in self.album_ids()? {
            let dir = self.directory(id);
            runtime_store::private_directory(&dir)?;
            for file in fs::read_dir(dir).map_err(|_| ERROR)? {
                let file = file.map_err(|_| ERROR)?;
                let metadata = fs::symlink_metadata(file.path()).map_err(|_| ERROR)?;
                if !metadata.is_file() || metadata.file_type().is_symlink() {
                    return Err(ERROR.into());
                }
                bytes = bytes.checked_add(metadata.len()).ok_or(ERROR)?;
            }
        }
        Ok(bytes)
    }

    pub async fn download(
        &self,
        library: &Library<'_>,
        plan: Plan,
        mut progress: impl FnMut(usize, usize),
    ) -> Result<(), String> {
        let destination = self.directory(plan.id);
        if destination.exists() {
            let manifest = self.manifest(plan.id)?;
            if manifest.plan == plan {
                return Ok(());
            }
            self.remove(plan.id)?;
        }
        if self.album_ids()?.len() >= MAX_ALBUMS || plan.items.is_empty() {
            return Err(if plan.items.is_empty() {
                "offline_album_no_originals"
            } else {
                "offline_album_storage_limit"
            }
            .into());
        }
        let mut remaining = CAP
            .checked_sub(self.storage_used()?)
            .and_then(|bytes| bytes.checked_sub(MAX_MANIFEST + OVERHEAD))
            .ok_or("offline_album_storage_limit")?;
        let stage = Stage(self.root.join(format!(".stage-{}", Uuid::new_v4())));
        runtime_store::create_private_directory(&stage.0)?;
        let total = plan.items.len();
        let mut bytes = 0;
        let mut sizes = BTreeMap::new();
        for (index, item) in plan.items.iter().enumerate() {
            progress(index, total);
            let budget = remaining
                .checked_sub(remaining.div_ceil(CHUNK as u64) * OVERHEAD)
                .ok_or("offline_album_storage_limit")?;
            let mut file = Self::create_file(&stage.0.join(item.id.to_string()))?;
            let size = library
                .original(item, budget, |block, plaintext| {
                    self.seal(
                        &mut file,
                        &format!("media:{}:{}:{block}", plan.id, item.id),
                        plaintext,
                    )
                })
                .await?;
            file.sync_all().map_err(|_| ERROR)?;
            bytes += size;
            remaining -= size + size.div_ceil(CHUNK as u64) * OVERHEAD;
            sizes.insert(item.id, size);
        }
        // Recheck access and the complete membership after the last original was received.
        if library.plan(plan.id).await? != plan {
            return Err("offline_album_access_changed".into());
        }
        self.write_manifest(
            &stage.0,
            &Manifest {
                plan,
                checked_at: now()?,
                bytes,
                sizes,
            },
        )?;
        fs::rename(&stage.0, destination).map_err(|_| ERROR)?;
        progress(total, total);
        Ok(())
    }

    async fn validated(
        &self,
        library: Option<&Library<'_>>,
        mut manifest: Manifest,
    ) -> Result<Option<Manifest>, String> {
        let Some(library) = library else {
            return Ok(manifest.valid_at(now()?).then_some(manifest));
        };
        match library.plan(manifest.plan.id).await {
            Ok(plan) if plan == manifest.plan => {
                let checked = now()?;
                // Limit rewrites without allowing a reconnect to use unverified media.
                if checked.saturating_sub(manifest.checked_at) >= 60 || !manifest.valid_at(checked)
                {
                    manifest.checked_at = checked;
                    self.write_manifest(&self.directory(manifest.plan.id), &manifest)?;
                }
                Ok(Some(manifest))
            }
            Ok(_) | Err(remote::Access::Denied) => {
                self.remove(manifest.plan.id)?;
                Ok(None)
            }
            Err(error) => Err(error.into()),
        }
    }

    pub async fn list(&self, saved: &SavedConnection) -> Result<Vec<AlbumView>, String> {
        let ids = self.album_ids()?;
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        let library = self.connect(saved).await?;
        let mut albums = Vec::new();
        for id in ids {
            if let Some(manifest) = self.validated(library.as_ref(), self.manifest(id)?).await? {
                albums.push(manifest.view());
            }
        }
        Ok(albums)
    }

    pub async fn authorize(
        &self,
        saved: &SavedConnection,
        album: Uuid,
        item: Uuid,
    ) -> Result<Authorized, String> {
        let library = self.connect(saved).await?;
        let manifest = self
            .validated(library.as_ref(), self.manifest(album)?)
            .await?
            .ok_or("offline_album_access_changed")?;
        let media = manifest
            .plan
            .items
            .iter()
            .find(|asset| asset.id == item)
            .ok_or("offline_album_access_changed")?;
        Ok(Authorized {
            size: *manifest.sizes.get(&item).ok_or(ERROR)?,
            mime: media.mime.clone(),
            name: media.name.clone(),
            expires_at: manifest.checked_at.saturating_add(GRACE_SECONDS),
            online: library.is_some(),
        })
    }

    pub fn range(
        &self,
        album: Uuid,
        item: Uuid,
        size: u64,
        start: u64,
        end: u64,
    ) -> Result<Vec<u8>, String> {
        if start >= end || end > size || end - start > MAX_RANGE {
            return Err(ERROR.into());
        }
        let dir = self.directory(album);
        crate::native_runtime::absolute_directory(&dir)?;
        let path = dir.join(item.to_string());
        let metadata = fs::symlink_metadata(&path).map_err(|_| ERROR)?;
        let chunk = CHUNK as u64;
        if !metadata.is_file()
            || metadata.file_type().is_symlink()
            || metadata.len() != size + size.div_ceil(chunk) * OVERHEAD
        {
            return Err(ERROR.into());
        }
        let mut file = File::open(path).map_err(|_| ERROR)?;
        let mut result = Vec::with_capacity((end - start) as usize);
        let first = start / chunk;
        file.seek(SeekFrom::Start(first * (chunk + OVERHEAD)))
            .map_err(|_| ERROR)?;
        for block in first..=(end - 1) / chunk {
            let offset = block * chunk;
            let mut nonce = [0u8; 12];
            let mut bytes = vec![0u8; ((size - offset).min(chunk) + 16) as usize];
            file.read_exact(&mut nonce)
                .and_then(|_| file.read_exact(&mut bytes))
                .map_err(|_| ERROR)?;
            let plaintext =
                self.open_chunk(&format!("media:{album}:{item}:{block}"), nonce, bytes)?;
            let lo = start.saturating_sub(offset) as usize;
            let hi = (end - offset).min(plaintext.len() as u64) as usize;
            result.extend_from_slice(&plaintext[lo..hi]);
        }
        Ok(result)
    }

    pub fn save(
        &self,
        album: Uuid,
        item: Uuid,
        access: &Authorized,
        path: &Path,
        mut cancelled: impl FnMut() -> bool,
    ) -> Result<(), String> {
        let parent = path.parent().ok_or("offline_album_save_failed")?;
        crate::native_runtime::absolute_directory(parent)?;
        if path.exists() {
            return Err("offline_album_save_exists".into());
        }
        let temporary = Export(parent.join(format!(".frameleaf-save-{}", Uuid::new_v4())));
        let mut file = Self::create_file(&temporary.0)?;
        let mut offset = 0;
        while offset < access.size {
            if cancelled() || !access.current() {
                return Err("offline_album_cancelled".into());
            }
            let end = (offset + MAX_RANGE).min(access.size);
            let bytes = self.range(album, item, access.size, offset, end)?;
            file.write_all(&bytes)
                .map_err(|_| "offline_album_save_failed")?;
            offset = end;
        }
        file.sync_all().map_err(|_| "offline_album_save_failed")?;
        drop(file);
        if cancelled() || !access.current() {
            return Err("offline_album_cancelled".into());
        }
        fs::hard_link(&temporary.0, path).map_err(|_| "offline_album_save_failed".into())
    }

    async fn connect<'a>(&self, saved: &'a SavedConnection) -> Result<Option<Library<'a>>, String> {
        match Library::connect(saved).await {
            Ok(library) => Ok(Some(library)),
            Err(remote::Access::Offline) => Ok(None),
            Err(remote::Access::Denied) => {
                for id in self.album_ids()? {
                    self.remove(id)?;
                }
                Err(remote::Access::Denied.into())
            }
            Err(error) => Err(error.into()),
        }
    }
}

#[derive(Clone)]
pub(super) struct Authorized {
    pub size: u64,
    pub mime: String,
    pub name: String,
    pub expires_at: u64,
    pub online: bool,
}
impl Authorized {
    pub fn current(&self) -> bool {
        now().is_ok_and(|now| {
            now < self.expires_at && now >= self.expires_at.saturating_sub(GRACE_SECONDS)
        })
    }
}

struct Export(PathBuf);
impl Drop for Export {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

struct Stage(PathBuf);
impl Drop for Stage {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::STANDARD, Engine};
    use std::{
        net::TcpListener,
        sync::{
            atomic::{AtomicU8, Ordering},
            Arc,
        },
        thread::JoinHandle,
    };

    struct Fixture {
        base: PathBuf,
        saved: SavedConnection,
        album: Uuid,
        item: Uuid,
        mode: Arc<AtomicU8>,
        server: Option<JoinHandle<()>>,
    }
    impl Fixture {
        fn new() -> Self {
            let base = std::env::temp_dir()
                .canonicalize()
                .unwrap()
                .join(format!("frameleaf-offline-{}", Uuid::new_v4()));
            runtime_store::create_private_directory(&base).unwrap();
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let saved = SavedConnection {
                server: format!("http://{}/", listener.local_addr().unwrap()),
                server_id: "fixture-library".into(),
                account_id: Uuid::new_v4().to_string(),
                name: "Fixture".into(),
                token: "synthetic".into(),
                device_name: "Fixture".into(),
                mode: "client-worker".into(),
                device_id: None,
            };
            let album = Uuid::new_v4();
            let item = Uuid::new_v4();
            let owner = saved.account_id.clone();
            let mode = Arc::new(AtomicU8::new(0));
            let server_mode = mode.clone();
            listener.set_nonblocking(true).unwrap();
            let server = std::thread::spawn(move || {
                while server_mode.load(Ordering::SeqCst) != 255 {
                    let (mut socket, _) = match listener.accept() {
                        Ok(value) => value,
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            std::thread::sleep(std::time::Duration::from_millis(5));
                            continue;
                        }
                        Err(error) => panic!("{error}"),
                    };
                    socket.set_nonblocking(false).unwrap();
                    socket
                        .set_read_timeout(Some(std::time::Duration::from_secs(2)))
                        .unwrap();
                    let mut request = [0u8; 4096];
                    let mut size = 0;
                    while size < request.len() && !request[..size].ends_with(b"\r\n\r\n") {
                        let Ok(bytes) = socket.read(&mut request[size..]) else {
                            break;
                        };
                        if bytes == 0 {
                            break;
                        }
                        size += bytes;
                    }
                    if size == 0 {
                        continue;
                    }
                    let request = String::from_utf8_lossy(&request[..size]);
                    assert!(request
                        .to_ascii_lowercase()
                        .contains("authorization: bearer synthetic"));
                    let path = request.split_whitespace().nth(1).unwrap();
                    let state = server_mode.load(Ordering::SeqCst);
                    let mut status = 200;
                    let body = match path {
                        "/api/users/me" => serde_json::json!({"id":owner}).to_string().into_bytes(),
                        "/api/desktop/capabilities" => serde_json::json!({
                            "protocolVersion":1,"serverId":"fixture-library",
                            "features":{"enrollment":false,"worker":false,"sources":false,"nativeHost":false}
                        }).to_string().into_bytes(),
                        path if path == format!("/api/albums/{album}") => serde_json::json!({
                            "id":album,"albumName":"Trip","kind":"album","isLocked":state == 2,
                            "albumUsers":[{"user":{"id":owner},"role":"owner"}]
                        }).to_string().into_bytes(),
                        path if path.starts_with(&format!("/api/albums/{album}/items")) => serde_json::json!({
                            "items":[{"kind":"asset","asset":{"id":item,"ownerId":owner,"type":"VIDEO",
                                "originalFileName":"original.mp4","originalMimeType":"video/mp4",
                                "visibility":"timeline","isTrashed":false,
                                "checksum":STANDARD.encode(Sha256::digest(b"original"))}}],
                            "nextCursor":null
                        }).to_string().into_bytes(),
                        path if path == format!("/api/assets/{item}/original?edited=false") => {
                            if state == 1 { b"altered!".to_vec() } else { b"original".to_vec() }
                        }
                        _ => { status = 403; Vec::new() }
                    };
                    let response = format!("HTTP/1.1 {status} Test\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len());
                    let _ = socket
                        .write_all(response.as_bytes())
                        .and_then(|_| socket.write_all(&body));
                }
            });
            Self {
                base,
                saved,
                album,
                item,
                mode,
                server: Some(server),
            }
        }
        fn cache(&self) -> Cache {
            let root = self.base.join("offline-albums");
            runtime_store::private_directory(&root).unwrap();
            Cache {
                root,
                key: Credential {
                    scope: scope(&self.saved).unwrap(),
                    key: [71; 32],
                },
            }
        }
        fn stop(&mut self) {
            self.mode.store(255, Ordering::SeqCst);
            if let Some(thread) = self.server.take() {
                let joined = thread.join();
                if !std::thread::panicking() {
                    joined.unwrap();
                }
            }
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            self.stop();
            let _ = fs::remove_dir_all(&self.base);
        }
    }

    #[tokio::test]
    async fn verified_originals_survive_restart_offline_and_partial_downloads_never_publish() {
        let mut fixture = Fixture::new();
        let cache = fixture.cache();
        let library = Library::connect(&fixture.saved).await.ok().unwrap();
        let plan = library.plan(fixture.album).await.ok().unwrap();
        assert_eq!(
            library
                .original(&plan.items[0], 4, |_, _| panic!(
                    "oversize original reached writer"
                ))
                .await
                .unwrap_err(),
            "offline_album_storage_limit",
        );
        fixture.mode.store(1, Ordering::SeqCst);
        assert_eq!(
            cache
                .download(&library, plan.clone(), |_, _| {})
                .await
                .unwrap_err(),
            "offline_album_original_changed"
        );
        assert!(cache.album_ids().unwrap().is_empty());
        assert_eq!(fs::read_dir(&cache.root).unwrap().count(), 0);
        fixture.mode.store(0, Ordering::SeqCst);
        cache.download(&library, plan, |_, _| {}).await.unwrap();
        assert_ne!(
            fs::read(
                cache
                    .directory(fixture.album)
                    .join(fixture.item.to_string())
            )
            .unwrap(),
            b"original"
        );
        drop(cache);
        fixture.stop();
        let restored = fixture.cache();
        let access = restored
            .authorize(&fixture.saved, fixture.album, fixture.item)
            .await
            .unwrap();
        assert!(!access.online);
        assert_eq!(
            restored
                .range(fixture.album, fixture.item, access.size, 0, 8)
                .unwrap(),
            b"original"
        );
        let destination = fixture.base.join("saved.mp4");
        restored
            .save(fixture.album, fixture.item, &access, &destination, || false)
            .unwrap();
        assert_eq!(fs::read(&destination).unwrap(), b"original");
        assert_eq!(
            restored
                .save(fixture.album, fixture.item, &access, &destination, || false)
                .unwrap_err(),
            "offline_album_save_exists"
        );
        let other = Uuid::new_v4();
        assert!(restored
            .range(fixture.album, other, access.size, 0, 8)
            .is_err());
    }

    #[tokio::test]
    async fn observed_locked_album_revokes_cached_bytes_before_replay() {
        let fixture = Fixture::new();
        let cache = fixture.cache();
        let library = Library::connect(&fixture.saved).await.ok().unwrap();
        let plan = library.plan(fixture.album).await.ok().unwrap();
        cache.download(&library, plan, |_, _| {}).await.unwrap();
        fixture.mode.store(2, Ordering::SeqCst);
        assert!(cache
            .authorize(&fixture.saved, fixture.album, fixture.item)
            .await
            .is_err());
        assert!(cache.album_ids().unwrap().is_empty());
        assert!(cache.range(fixture.album, fixture.item, 8, 0, 8).is_err());
    }

    #[test]
    fn chunk_authentication_binds_large_original_ranges_and_refuses_tampering() {
        let fixture = Fixture::new();
        let cache = fixture.cache();
        let dir = cache.directory(fixture.album);
        runtime_store::create_private_directory(&dir).unwrap();
        let path = dir.join(fixture.item.to_string());
        let mut file = Cache::create_file(&path).unwrap();
        let size = 80 * 1024 * 1024 + 73;
        for block in 0..(size as u64).div_ceil(CHUNK as u64) {
            let remaining = size - block as usize * CHUNK;
            cache
                .seal(
                    &mut file,
                    &format!("media:{}:{}:{block}", fixture.album, fixture.item),
                    vec![block as u8; remaining.min(CHUNK)],
                )
                .unwrap();
        }
        file.sync_all().unwrap();
        drop(file);
        assert_eq!(
            cache
                .range(
                    fixture.album,
                    fixture.item,
                    size as u64,
                    CHUNK as u64 - 2,
                    CHUNK as u64 + 2
                )
                .unwrap(),
            [0, 0, 1, 1]
        );
        assert_eq!(
            cache
                .range(
                    fixture.album,
                    fixture.item,
                    size as u64,
                    size as u64 - 5,
                    size as u64
                )
                .unwrap(),
            [80; 5]
        );
        assert!(cache
            .range(fixture.album, fixture.item, size as u64, 0, MAX_RANGE + 1)
            .is_err());
        let mut overwrite = OpenOptions::new().write(true).open(&path).unwrap();
        overwrite.seek(SeekFrom::Start(40)).unwrap();
        overwrite.write_all(b"tampered").unwrap();
        drop(overwrite);
        assert!(cache
            .range(fixture.album, fixture.item, size as u64, 0, 64)
            .is_err());
        let plan = Plan {
            id: fixture.album,
            name: "Trip".into(),
            items: vec![],
        };
        let manifest = Manifest {
            plan,
            checked_at: 100,
            bytes: 0,
            sizes: BTreeMap::new(),
        };
        assert!(manifest.valid_at(100));
        assert!(!manifest.valid_at(99));
        assert!(!manifest.valid_at(100 + GRACE_SECONDS));
        let mut other = fixture.saved.clone();
        other.token = "changed".into();
        assert_ne!(scope(&fixture.saved).unwrap(), scope(&other).unwrap());
    }
}
