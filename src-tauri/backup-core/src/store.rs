use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, ErrorKind, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::SystemTime;

use rand::RngCore;

use crate::{invalid, Error, Result};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredObject {
    pub key: String,
    pub size: u64,
    pub modified: SystemTime,
}

/// `end` is exclusive. `Suffix` reads that many bytes from the end.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ByteRange {
    Span { start: u64, end: u64 },
    Suffix(u64),
}

/// Where a repository keeps its objects. Objects are written once: storing under a name that is taken is
/// refused, so nothing is ever replaced.
/// ponytail: `put` takes the whole object in memory (packs are about 64 MiB); stream when that matters.
pub trait Store: Send + Sync {
    /// Storage that keeps versions says which one this write made; a signed record of a backup names it.
    fn put(&self, key: &str, body: &[u8]) -> Result<Option<String>>;
    fn get(&self, key: &str, range: Option<ByteRange>) -> Result<Vec<u8>>;
    fn list(&self, prefix: &str) -> Result<Vec<StoredObject>>;
    fn delete(&self, key: &str) -> Result<()>;
}

fn slice(body: &[u8], range: Option<ByteRange>) -> &[u8] {
    let length = body.len() as u64;
    let (start, end) = match range {
        None => (0, length),
        Some(ByteRange::Suffix(suffix)) => (length.saturating_sub(suffix), length),
        Some(ByteRange::Span { start, end }) => {
            (start.min(length), end.min(length).max(start.min(length)))
        }
    };
    &body[start as usize..end as usize]
}

#[derive(Default)]
pub struct MemoryStore {
    pub objects: Mutex<BTreeMap<String, (Vec<u8>, SystemTime)>>,
}

impl MemoryStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// An independent copy, as a test that stops a process part-way needs.
    pub fn copy(&self) -> Self {
        MemoryStore {
            objects: Mutex::new(self.objects.lock().unwrap().clone()),
        }
    }
}

impl Store for MemoryStore {
    fn put(&self, key: &str, body: &[u8]) -> Result<Option<String>> {
        let mut objects = self.objects.lock().unwrap();
        if objects.contains_key(key) {
            return Err(Error::ObjectExists(key.to_string()));
        }
        objects.insert(key.to_string(), (body.to_vec(), SystemTime::now()));
        Ok(None)
    }

    fn get(&self, key: &str, range: Option<ByteRange>) -> Result<Vec<u8>> {
        let objects = self.objects.lock().unwrap();
        let (body, _) = objects.get(key).ok_or_else(|| {
            Error::Io(io::Error::new(
                ErrorKind::NotFound,
                format!("No such object: {key}"),
            ))
        })?;
        Ok(slice(body, range).to_vec())
    }

    fn list(&self, prefix: &str) -> Result<Vec<StoredObject>> {
        let objects = self.objects.lock().unwrap();
        Ok(objects
            .range(prefix.to_string()..)
            .take_while(|(key, _)| key.starts_with(prefix))
            .map(|(key, (body, modified))| StoredObject {
                key: key.clone(),
                size: body.len() as u64,
                modified: *modified,
            })
            .collect())
    }

    fn delete(&self, key: &str) -> Result<()> {
        self.objects.lock().unwrap().remove(key);
        Ok(())
    }
}

/// A folder on disk: for tests, and for backing up to a local drive.
pub struct DirStore {
    root: PathBuf,
}

impl DirStore {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        DirStore { root: root.into() }
    }

    fn path(&self, key: &str) -> Result<PathBuf> {
        let fine = key.split('/').all(|part| {
            !part.is_empty()
                && part
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
        });
        if !fine {
            return Err(invalid(format!("Not a repository object name: {key}")));
        }
        Ok(key
            .split('/')
            .fold(self.root.clone(), |path, part| path.join(part)))
    }

    fn walk(
        &self,
        folder: &Path,
        at: &str,
        prefix: &str,
        found: &mut Vec<StoredObject>,
    ) -> Result<()> {
        for item in fs::read_dir(folder)? {
            let item = item?;
            let name = item.file_name().to_string_lossy().into_owned();
            let key = if at.is_empty() {
                name
            } else {
                format!("{at}/{name}")
            };
            // A name that was just listed and cannot be looked at is a failure, not an absence: leaving a
            // snapshot out of a listing would let a prune remove what that snapshot needs.
            let info = fs::metadata(item.path())?;
            if info.is_dir() {
                if prefix.starts_with(&format!("{key}/"))
                    || key.starts_with(prefix)
                    || prefix.is_empty()
                {
                    self.walk(&item.path(), &key, prefix, found)?;
                }
            } else if info.is_file() && key.starts_with(prefix) && !key.ends_with(".part") {
                found.push(StoredObject {
                    key,
                    size: info.len(),
                    modified: info.modified()?,
                });
            }
        }
        Ok(())
    }
}

/// What a drive answers when it cannot make hard links.
fn no_links(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        ErrorKind::Unsupported | ErrorKind::PermissionDenied
    )
}

impl Store for DirStore {
    fn put(&self, key: &str, body: &[u8]) -> Result<Option<String>> {
        let target = self.path(key)?;
        let folder = target.parent().expect("under the root").to_path_buf();
        fs::create_dir_all(&folder)?;
        // Written beside the target and flushed to disk first, so a crash or a power cut never leaves half
        // an object under its real name.
        let mut tag = [0u8; 6];
        rand::thread_rng().fill_bytes(&mut tag);
        let temporary = PathBuf::from(format!("{}.{}.part", target.display(), hex::encode(tag)));
        let placed = (|| -> Result<()> {
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
            let mut file = options.open(&temporary)?;
            file.write_all(body)?;
            file.sync_all()?;
            drop(file);
            // Linked into place, not renamed: a link fails when the name is taken, so nothing is ever replaced.
            match fs::hard_link(&temporary, &target) {
                Ok(()) => Ok(()),
                Err(error) if error.kind() == ErrorKind::AlreadyExists => {
                    Err(Error::ObjectExists(key.to_string()))
                }
                // Only a drive that can't make links at all (exFAT, some network shares) gets the fallback. It
                // looks first, and leans on the format's rule of one writer per repository.
                Err(error) if no_links(&error) => {
                    if fs::symlink_metadata(&target).is_ok() {
                        return Err(Error::ObjectExists(key.to_string()));
                    }
                    fs::rename(&temporary, &target)?;
                    Ok(())
                }
                Err(error) => Err(error.into()),
            }
        })();
        let _ = fs::remove_file(&temporary);
        placed?;
        if let Ok(folder) = File::open(&folder) {
            let _ = folder.sync_all();
        }
        Ok(None)
    }

    fn get(&self, key: &str, range: Option<ByteRange>) -> Result<Vec<u8>> {
        let mut file = File::open(self.path(key)?)?;
        let size = file.metadata()?.len();
        let (start, end) = match range {
            None => (0, size),
            Some(ByteRange::Suffix(suffix)) => (size.saturating_sub(suffix), size),
            Some(ByteRange::Span { start, end }) => (start, end.min(size)),
        };
        let mut buffer = Vec::with_capacity(end.saturating_sub(start) as usize);
        file.seek(SeekFrom::Start(start))?;
        file.take(end.saturating_sub(start))
            .read_to_end(&mut buffer)?;
        Ok(buffer)
    }

    fn list(&self, prefix: &str) -> Result<Vec<StoredObject>> {
        // Only a root that isn't there yet is empty. Any other failure is passed on: reading "nothing
        // stored" from a drive that could not be read would let a new repository be started over an old one.
        match fs::metadata(&self.root) {
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(error.into()),
            Ok(_) => {}
        }
        let mut found = Vec::new();
        self.walk(&self.root, "", prefix, &mut found)?;
        Ok(found)
    }

    fn delete(&self, key: &str) -> Result<()> {
        match fs::remove_file(self.path(key)?) {
            Err(error) if error.kind() != ErrorKind::NotFound => Err(error.into()),
            _ => Ok(()),
        }
    }
}
