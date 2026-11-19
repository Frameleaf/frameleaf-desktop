#![allow(dead_code)]

use std::collections::BTreeMap;
use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use frameleaf_backup_core::{
    ByteRange, ChunkerParams, EntryType, Error, Result, Source, SourceEntry, Store, StoredObject,
};
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};

pub const CHUNKER: ChunkerParams = ChunkerParams {
    min: 1024,
    avg: 4096,
    max: 16_384,
};
pub const PACK_TARGET: usize = 64 * 1024;
pub const ROOT_KEY: [u8; 32] = [0x5a; 32];

pub fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

/// The same bytes every run, as the TypeScript tests make them.
pub fn noise(length: usize, seed: u32) -> Vec<u8> {
    let mut state = seed;
    (0..length)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            (state & 0xff) as u8
        })
        .collect()
}

pub fn sha256(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

pub fn path(names: &[&str]) -> Vec<String> {
    names.iter().map(|name| name.to_string()).collect()
}

#[derive(Clone, Debug, Deserialize)]
pub struct LibraryEntry {
    pub path: Vec<String>,
    #[serde(rename = "type")]
    pub kind: String,
    pub mode: u32,
    pub mtime: i64,
    pub content: Option<Value>,
    pub target: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct Version {
    pub time: String,
    pub entries: Vec<LibraryEntry>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Library {
    pub chunker: ChunkerParams,
    pub pack_target: usize,
    pub root_key: String,
    pub versions: Vec<Version>,
}

/// The cross-engine library, as tools/library.mjs defines it.
pub fn library() -> Library {
    serde_json::from_slice(&fs::read(fixtures().join("library.json")).unwrap()).unwrap()
}

pub fn content_of(content: &Value) -> Vec<u8> {
    if let Some(noise_args) = content.get("noise") {
        noise(
            noise_args[0].as_u64().unwrap() as usize,
            noise_args[1].as_u64().unwrap() as u32,
        )
    } else {
        content["text"]
            .as_str()
            .unwrap()
            .repeat(content["repeat"].as_u64().unwrap() as usize)
            .into_bytes()
    }
}

/// One library version as a source, keyed by content hash exactly as tools/library.mjs keys it.
pub struct VersionSource(pub Version);

impl Source for VersionSource {
    fn list(&self, at: &[String]) -> io::Result<Vec<SourceEntry>> {
        Ok(self
            .0
            .entries
            .iter()
            .filter(|entry| entry.path.len() == at.len() + 1 && entry.path.starts_with(at))
            .map(|entry| {
                let body = entry.content.as_ref().map(content_of);
                SourceEntry {
                    name: entry.path.last().unwrap().clone(),
                    kind: match entry.kind.as_str() {
                        "file" => EntryType::File,
                        "dir" => EntryType::Dir,
                        _ => EntryType::Symlink,
                    },
                    mode: entry.mode,
                    uid: 0,
                    gid: 0,
                    mtime: entry.mtime,
                    size: body.as_ref().map_or(0, |body| body.len() as u64),
                    target: entry.target.clone(),
                    unreadable: None,
                    key: body.as_ref().map(|body| sha256(body)),
                }
            })
            .collect())
    }

    fn read<'a>(&'a self, at: &[String]) -> io::Result<Box<dyn Read + 'a>> {
        let entry = self
            .0
            .entries
            .iter()
            .find(|entry| entry.path == at)
            .unwrap();
        Ok(Box::new(io::Cursor::new(content_of(
            entry.content.as_ref().unwrap(),
        ))))
    }
}

/// A flat folder of named buffers, as the TypeScript maintenance tests use.
pub struct Folder(pub Vec<(String, Vec<u8>)>);

impl Source for Folder {
    fn list(&self, _: &[String]) -> io::Result<Vec<SourceEntry>> {
        Ok(self
            .0
            .iter()
            .map(|(name, body)| SourceEntry {
                name: name.clone(),
                kind: EntryType::File,
                mode: 0o644,
                uid: 0,
                gid: 0,
                mtime: 0,
                size: body.len() as u64,
                target: None,
                unreadable: None,
                key: Some(sha256(body)),
            })
            .collect())
    }

    fn read<'a>(&'a self, at: &[String]) -> io::Result<Box<dyn Read + 'a>> {
        let (_, body) = self.0.iter().find(|(name, _)| *name == at[0]).unwrap();
        Ok(Box::new(body.as_slice()))
    }
}

/// Every name under a folder: content hash, link target or "folder", and for files their mode and time.
pub fn manifest(root: &Path) -> BTreeMap<String, String> {
    fn walk(root: &Path, at: &Path, found: &mut BTreeMap<String, String>) {
        let mut names: Vec<_> = fs::read_dir(root.join(at))
            .unwrap()
            .map(|item| item.unwrap().file_name())
            .collect();
        names.sort();
        for name in names {
            let relative = at.join(&name);
            let place = root.join(&relative);
            let info = fs::symlink_metadata(&place).unwrap();
            let key = relative.to_string_lossy().replace('\\', "/");
            if info.is_dir() {
                found.insert(format!("{key}/"), "folder".into());
                walk(root, &relative, found);
            } else if info.file_type().is_symlink() {
                found.insert(
                    key,
                    format!("link:{}", fs::read_link(&place).unwrap().display()),
                );
            } else {
                found.insert(key, sha256(&fs::read(&place).unwrap()));
            }
        }
    }
    let mut found = BTreeMap::new();
    walk(root, Path::new(""), &mut found);
    found
}

fn millis(time: std::time::SystemTime) -> i64 {
    match time.duration_since(std::time::UNIX_EPOCH) {
        Ok(after) => after.as_millis() as i64,
        Err(before) => -(before.duration().as_millis() as i64),
    }
}

/// Checks a restored folder against what tools/library.mjs says a restore must give.
pub fn assert_restored(root: &Path, expected: &Value) {
    let expected = expected.as_object().unwrap();
    for (name, want) in expected {
        let place = root.join(name);
        let info =
            fs::symlink_metadata(&place).unwrap_or_else(|_| panic!("{name} was not restored"));
        match want["type"].as_str().unwrap() {
            "file" => {
                assert_eq!(
                    sha256(&fs::read(&place).unwrap()),
                    want["sha256"].as_str().unwrap(),
                    "{name}"
                );
                assert_eq!(
                    millis(info.modified().unwrap()),
                    want["mtime"].as_i64().unwrap(),
                    "{name}"
                );
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    assert_eq!(
                        u64::from(info.permissions().mode() & 0o7777),
                        want["mode"].as_u64().unwrap(),
                        "{name}"
                    );
                }
            }
            "dir" => assert!(info.is_dir(), "{name}"),
            _ => assert_eq!(
                fs::read_link(&place).unwrap().to_string_lossy(),
                want["target"].as_str().unwrap(),
                "{name}"
            ),
        }
    }
    assert_eq!(
        manifest(root).len(),
        expected.len(),
        "nothing more was restored"
    );
}

pub fn copy_dir(from: &Path, to: &Path) {
    fs::create_dir_all(to).unwrap();
    for item in fs::read_dir(from).unwrap() {
        let item = item.unwrap();
        if item.file_type().unwrap().is_dir() {
            copy_dir(&item.path(), &to.join(item.file_name()));
        } else {
            fs::copy(item.path(), to.join(item.file_name())).unwrap();
        }
    }
}

/// A store that stops reaching storage from the `stop_at`-th change on, as a process that was killed.
pub struct Dying {
    pub inner: Arc<dyn Store>,
    pub stop_at: usize,
    pub changes: AtomicUsize,
}

impl Dying {
    pub fn new(inner: Arc<dyn Store>, stop_at: usize) -> Self {
        Dying {
            inner,
            stop_at,
            changes: AtomicUsize::new(0),
        }
    }

    fn change(&self) -> Result<()> {
        if self.changes.fetch_add(1, Ordering::SeqCst) + 1 >= self.stop_at {
            return Err(Error::Invalid("stopped".into()));
        }
        Ok(())
    }
}

impl Store for Dying {
    fn put(&self, key: &str, body: &[u8]) -> Result<Option<String>> {
        self.change()?;
        self.inner.put(key, body)
    }
    fn get(&self, key: &str, range: Option<ByteRange>) -> Result<Vec<u8>> {
        self.inner.get(key, range)
    }
    fn list(&self, prefix: &str) -> Result<Vec<StoredObject>> {
        self.inner.list(prefix)
    }
    fn delete(&self, key: &str) -> Result<()> {
        self.change()?;
        self.inner.delete(key)
    }
}

/// A store that refuses writes whose name starts with `prefix`.
pub struct Refusing {
    pub inner: Arc<dyn Store>,
    pub prefix: &'static str,
}

impl Store for Refusing {
    fn put(&self, key: &str, body: &[u8]) -> Result<Option<String>> {
        if key.starts_with(self.prefix) {
            return Err(Error::Invalid("connection lost".into()));
        }
        self.inner.put(key, body)
    }
    fn get(&self, key: &str, range: Option<ByteRange>) -> Result<Vec<u8>> {
        self.inner.get(key, range)
    }
    fn list(&self, prefix: &str) -> Result<Vec<StoredObject>> {
        self.inner.list(prefix)
    }
    fn delete(&self, key: &str) -> Result<()> {
        self.inner.delete(key)
    }
}
