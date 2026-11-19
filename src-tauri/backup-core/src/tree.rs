use std::cmp::Ordering;
use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::repository::Repository;
use crate::{parse_id, Id, Result};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EntryType {
    File,
    Dir,
    Symlink,
}

/// What a source says about one name in a folder.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SourceEntry {
    pub name: String,
    pub kind: EntryType,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    /// Milliseconds since 1970.
    pub mtime: i64,
    pub size: u64,
    /// Symlinks only.
    pub target: Option<String>,
    /// Set when this one entry could not be looked at. The backup reports it and keeps what the entry held
    /// last time; its neighbours are backed up as usual.
    pub unreadable: Option<String>,
    /// Anything that changes whenever the content might have. When a file's key is the same as last time,
    /// it isn't read again.
    pub key: Option<String>,
}

/// Where a backup reads from: a folder on disk, or a tree the caller makes up. Paths are lists of names.
pub trait Source {
    fn list(&self, path: &[String]) -> io::Result<Vec<SourceEntry>>;
    fn read<'a>(&'a self, path: &[String]) -> io::Result<Box<dyn Read + 'a>>;
}

/// One name in a stored folder. The field order is the TypeScript engine's, so both write the same bytes
/// for the same folder and equal folders have equal ids whichever engine stored them.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    pub name: String,
    #[serde(rename = "type")]
    pub kind: EntryType,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub mtime: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    #[serde(default)]
    pub size: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    /// Files: the ids of the chunks, in order.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chunks: Option<Vec<String>>,
    /// Very large files: ids of blobs that each hold a run of chunk ids, 32 bytes apiece.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lists: Option<Vec<String>>,
    /// Folders: how many files are below, at any depth (their bytes are the folder's `size`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub files: Option<u64>,
    /// Folders: the id of the tree blob.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tree: Option<String>,
}

/// A name that can be put back inside a folder without leaving it.
pub fn safe_name(name: &str) -> bool {
    !name.is_empty() && name != "." && name != ".." && !name.contains(['/', '\\', '\0'])
}

/// JavaScript's string order: UTF-16 code units.
fn code_unit_order(a: &str, b: &str) -> Ordering {
    a.encode_utf16().cmp(b.encode_utf16())
}

#[derive(Serialize, Deserialize)]
struct Tree {
    v: u32,
    entries: Vec<Entry>,
}

pub fn encode_tree(entries: &[Entry]) -> Vec<u8> {
    let mut entries = entries.to_vec();
    entries.sort_by(|a, b| code_unit_order(&a.name, &b.name));
    serde_json::to_vec(&Tree { v: 1, entries }).expect("a tree serialises")
}

pub fn decode_tree(data: &[u8]) -> Result<Vec<Entry>> {
    Ok(serde_json::from_slice::<Tree>(data)
        .map_err(|_| crate::invalid("A folder in this backup cannot be read"))?
        .entries)
}

pub fn read_tree(repository: &Repository, id: &str) -> Result<Vec<Entry>> {
    decode_tree(&repository.read_blob(&parse_id(id)?)?)
}

/// The chunk ids of a file, in order.
pub fn file_chunks(repository: &Repository, entry: &Entry) -> Result<Vec<Id>> {
    let Some(lists) = &entry.lists else {
        return entry
            .chunks
            .iter()
            .flatten()
            .map(|id| parse_id(id))
            .collect();
    };
    let mut ids = Vec::new();
    for list in lists {
        let data = repository.read_blob(&parse_id(list)?)?;
        ids.extend(data.as_chunks::<32>().0.iter().copied());
    }
    Ok(ids)
}

/// Floor of a time in milliseconds, as Node's `Math.floor(mtimeMs)`.
fn millis(time: io::Result<std::time::SystemTime>) -> i64 {
    match time {
        Ok(time) => match time.duration_since(std::time::UNIX_EPOCH) {
            Ok(after) => after.as_millis() as i64,
            Err(before) => -(before.duration().as_nanos().div_ceil(1_000_000) as i64),
        },
        Err(_) => 0,
    }
}

struct FsSource {
    root: PathBuf,
}

/// A folder on disk. Sockets, devices and pipes are left out: there is nothing in them to keep.
pub fn fs_source(root: impl Into<PathBuf>) -> impl Source {
    FsSource { root: root.into() }
}

fn under(root: &Path, path: &[String]) -> PathBuf {
    path.iter()
        .fold(root.to_path_buf(), |at, name| at.join(name))
}

impl Source for FsSource {
    fn list(&self, path: &[String]) -> io::Result<Vec<SourceEntry>> {
        let folder = under(&self.root, path);
        let mut entries = Vec::new();
        for item in fs::read_dir(&folder)? {
            let item = item?;
            // ponytail: a name that is not UTF-8 is stored as its lossy text, and restores under that name.
            let name = item.file_name().to_string_lossy().into_owned();
            let place = folder.join(item.file_name());
            // A file deleted between the listing and this look is simply no longer there. Any other trouble is
            // this entry's alone: it is reported, and the rest of the folder is still listed.
            let looked = fs::symlink_metadata(&place).and_then(|info| {
                let target = if info.file_type().is_symlink() {
                    Some(fs::read_link(&place)?)
                } else {
                    None
                };
                Ok((info, target))
            });
            let (info, target) = match looked {
                Ok(found) => found,
                Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                Err(error) => {
                    entries.push(SourceEntry {
                        name,
                        kind: EntryType::File,
                        mode: 0,
                        uid: 0,
                        gid: 0,
                        mtime: 0,
                        size: 0,
                        target: None,
                        unreadable: Some(error.to_string()),
                        key: None,
                    });
                    continue;
                }
            };
            let file_type = info.file_type();
            let kind = if file_type.is_file() {
                EntryType::File
            } else if file_type.is_dir() {
                EntryType::Dir
            } else if file_type.is_symlink() {
                EntryType::Symlink
            } else {
                continue;
            };
            let mtime = millis(info.modified());
            #[cfg(unix)]
            let (mode, uid, gid, key) = {
                use std::os::unix::fs::MetadataExt;
                let ctime = info.ctime() * 1000 + info.ctime_nsec().div_euclid(1_000_000);
                (
                    info.mode() & 0o7777,
                    info.uid(),
                    info.gid(),
                    format!("{}:{}:{}:{}", info.ino(), info.len(), mtime, ctime),
                )
            };
            #[cfg(not(unix))]
            let (mode, uid, gid, key) = {
                let mode = if file_type.is_dir() {
                    0o755
                } else if info.permissions().readonly() {
                    0o444
                } else {
                    0o644
                };
                (mode, 0, 0, format!("{}:{}", info.len(), mtime))
            };
            entries.push(SourceEntry {
                name,
                kind,
                mode,
                uid,
                gid,
                mtime,
                size: if kind == EntryType::File {
                    info.len()
                } else {
                    0
                },
                target: target.map(|target| target.to_string_lossy().into_owned()),
                unreadable: None,
                key: (kind == EntryType::File).then_some(key),
            });
        }
        Ok(entries)
    }

    fn read<'a>(&'a self, path: &[String]) -> io::Result<Box<dyn Read + 'a>> {
        Ok(Box::new(fs::File::open(under(&self.root, path))?))
    }
}

fn starts_with(path: &[String], start: &[String]) -> bool {
    path.len() >= start.len() && path[..start.len()] == *start
}

struct MountSource<'a> {
    mounts: Vec<(Vec<String>, &'a dyn Source)>,
}

/// Several sources shown as one tree, each at its own path, so a backup knows where each file belongs.
pub fn mount_source<'a>(mounts: Vec<(Vec<String>, &'a dyn Source)>) -> Result<impl Source + 'a> {
    for (index, (path, _)) in mounts.iter().enumerate() {
        if path.is_empty() && mounts.len() > 1 {
            return Err(crate::invalid(
                "A source at the top leaves no room for others",
            ));
        }
        if mounts
            .iter()
            .enumerate()
            .any(|(at, (other, _))| at != index && starts_with(other, path))
        {
            return Err(crate::invalid("One chosen folder is inside another"));
        }
    }
    Ok(MountSource { mounts })
}

impl MountSource<'_> {
    fn owner(&self, path: &[String]) -> Option<&(Vec<String>, &dyn Source)> {
        self.mounts
            .iter()
            .find(|(mount, _)| starts_with(path, mount))
    }
}

impl Source for MountSource<'_> {
    fn list(&self, path: &[String]) -> io::Result<Vec<SourceEntry>> {
        if let Some((mount, source)) = self.owner(path) {
            return source.list(&path[mount.len()..]);
        }
        // Above the chosen folders there are only the folders that lead to them.
        let mut names: Vec<&String> = Vec::new();
        for (mount, _) in self
            .mounts
            .iter()
            .filter(|(mount, _)| starts_with(mount, path))
        {
            if !names.contains(&&mount[path.len()]) {
                names.push(&mount[path.len()]);
            }
        }
        Ok(names
            .into_iter()
            .map(|name| SourceEntry {
                name: name.clone(),
                kind: EntryType::Dir,
                mode: 0o755,
                uid: 0,
                gid: 0,
                mtime: 0,
                size: 0,
                target: None,
                unreadable: None,
                key: None,
            })
            .collect())
    }

    fn read<'a>(&'a self, path: &[String]) -> io::Result<Box<dyn Read + 'a>> {
        match self.owner(path) {
            Some((mount, source)) => source.read(&path[mount.len()..]),
            None => Err(io::Error::new(io::ErrorKind::NotFound, "No such file")),
        }
    }
}

struct FilterSource<'a, F> {
    source: &'a dyn Source,
    skip: F,
}

/// A source without the entries `skip` picks: caches, temporary files, a folder the owner left out.
pub fn filter_source<'a, F: Fn(&[String], &SourceEntry) -> bool + 'a>(
    source: &'a dyn Source,
    skip: F,
) -> impl Source + 'a {
    FilterSource { source, skip }
}

impl<F: Fn(&[String], &SourceEntry) -> bool> Source for FilterSource<'_, F> {
    fn list(&self, path: &[String]) -> io::Result<Vec<SourceEntry>> {
        let mut entries = self.source.list(path)?;
        entries.retain(|entry| {
            let mut child = path.to_vec();
            child.push(entry.name.clone());
            !(self.skip)(&child, entry)
        });
        Ok(entries)
    }

    fn read<'a>(&'a self, path: &[String]) -> io::Result<Box<dyn Read + 'a>> {
        self.source.read(path)
    }
}

/// How much a source holds, for showing progress: (files, bytes). Folders that can't be listed count as empty.
pub fn measure_source(source: &dyn Source, path: &[String]) -> (u64, u64) {
    let (mut files, mut bytes) = (0, 0);
    for entry in source.list(path).unwrap_or_default() {
        if entry.kind == EntryType::Dir {
            let mut child = path.to_vec();
            child.push(entry.name);
            let (inner_files, inner_bytes) = measure_source(source, &child);
            files += inner_files;
            bytes += inner_bytes;
        } else if entry.kind == EntryType::File && entry.unreadable.is_none() {
            files += 1;
            bytes += entry.size;
        }
    }
    (files, bytes)
}
