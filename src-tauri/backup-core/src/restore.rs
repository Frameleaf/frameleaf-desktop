use std::fs::{self, File, FileTimes, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::repository::{Repository, Snapshot};
use crate::tree::{file_chunks, read_tree, safe_name, Entry, EntryType};
use crate::{invalid, Result};

fn stamp(milliseconds: i64) -> SystemTime {
    if milliseconds >= 0 {
        UNIX_EPOCH + Duration::from_millis(milliseconds as u64)
    } else {
        UNIX_EPOCH - Duration::from_millis(milliseconds.unsigned_abs())
    }
}

fn top(snapshot: &Snapshot) -> Entry {
    let mtime = time::OffsetDateTime::parse(
        &snapshot.time,
        &time::format_description::well_known::Rfc3339,
    )
    .map(|time| (time.unix_timestamp_nanos() / 1_000_000) as i64)
    .unwrap_or(0);
    Entry {
        name: String::new(),
        kind: EntryType::Dir,
        mode: 0o755,
        uid: 0,
        gid: 0,
        mtime,
        key: None,
        size: 0,
        target: None,
        chunks: None,
        lists: None,
        files: None,
        tree: Some(snapshot.tree.clone()),
    }
}

/// Finds one file or folder in a snapshot. An empty path is the top.
pub fn find(
    repository: &Repository,
    snapshot: &Snapshot,
    path: &[String],
) -> Result<Option<Entry>> {
    let mut found = top(snapshot);
    for name in path {
        let Some(tree) = found
            .tree
            .as_deref()
            .filter(|_| found.kind == EntryType::Dir)
        else {
            return Ok(None);
        };
        match read_tree(repository, tree)?
            .into_iter()
            .find(|entry| &entry.name == name)
        {
            Some(next) => found = next,
            None => return Ok(None),
        }
    }
    Ok(Some(found))
}

/// What a folder held in a snapshot. Reads only that folder, so browsing a huge backup stays quick.
pub fn list_folder(
    repository: &Repository,
    snapshot: &Snapshot,
    path: &[String],
) -> Result<Vec<Entry>> {
    match find(repository, snapshot, path)? {
        Some(Entry {
            kind: EntryType::Dir,
            tree: Some(tree),
            ..
        }) => read_tree(repository, &tree),
        _ => Err(invalid("No such folder in this backup")),
    }
}

/// A file's content as stored, chunk by chunk.
pub fn read_file<'a>(
    repository: &'a Repository,
    entry: &Entry,
) -> Result<impl Iterator<Item = Result<Vec<u8>>> + 'a> {
    Ok(file_chunks(repository, entry)?
        .into_iter()
        .map(move |id| repository.read_blob(&id)))
}

#[derive(Debug, Default)]
pub struct RestoreResult {
    pub files: u64,
    pub bytes: u64,
    /// What was already there and was renamed out of the way. Nothing is ever deleted.
    pub moved_aside: Vec<(PathBuf, PathBuf)>,
}

#[cfg(unix)]
fn chmod(place: &Path, mode: u32) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(place, fs::Permissions::from_mode(mode))
}

#[cfg(not(unix))]
fn chmod(place: &Path, mode: u32) -> std::io::Result<()> {
    // Windows keeps one bit: read-only.
    let mut permissions = fs::metadata(place)?.permissions();
    permissions.set_readonly(mode & 0o222 == 0);
    fs::set_permissions(place, permissions)
}

/// Ownership needs root; a restore by an ordinary user keeps the files and skips it.
fn own(place: &Path, entry: &Entry) {
    #[cfg(unix)]
    let _ = std::os::unix::fs::chown(place, Some(entry.uid), Some(entry.gid));
    #[cfg(not(unix))]
    let _ = (place, entry);
}

fn set_times(file: &File, mtime: i64) -> std::io::Result<()> {
    let at = stamp(mtime);
    file.set_times(FileTimes::new().set_accessed(at).set_modified(at))
}

struct Restorer<'a> {
    repository: &'a Repository,
    aside: &'a dyn Fn(&Path) -> PathBuf,
    result: RestoreResult,
}

impl Restorer<'_> {
    fn clear(&mut self, place: &Path) -> Result<()> {
        if fs::symlink_metadata(place).is_ok() {
            // Never onto something moved aside earlier: a taken name gets a number until one is free.
            let wanted = (self.aside)(place);
            let mut to = wanted.clone();
            let mut attempt = 2;
            while fs::symlink_metadata(&to).is_ok() {
                to = PathBuf::from(format!("{}-{attempt}", wanted.display()));
                attempt += 1;
            }
            fs::rename(place, &to)?;
            self.result.moved_aside.push((place.to_path_buf(), to));
        }
        Ok(())
    }

    fn put(&mut self, entry: &Entry, place: &Path) -> Result<()> {
        match entry.kind {
            EntryType::Dir => {
                let existing = fs::symlink_metadata(place).ok();
                if existing.as_ref().is_some_and(|info| !info.is_dir()) {
                    self.clear(place)?;
                }
                let made = !existing.is_some_and(|info| info.is_dir());
                if made {
                    // Made writable for the one restoring, whatever its stored mode, so a read-only folder can be
                    // filled. Set after it is made: the mode given to mkdir is cut down by the umask, chmod's is not.
                    fs::create_dir(place)?;
                    chmod(place, 0o700)?;
                }
                if let Some(tree) = &entry.tree {
                    for child in read_tree(self.repository, tree)? {
                        if !safe_name(&child.name) {
                            return Err(invalid(
                                "This backup holds a name that cannot be restored safely",
                            ));
                        }
                        self.put(&child, &place.join(&child.name))?;
                    }
                }
                own(place, entry);
                if made {
                    chmod(place, entry.mode)?;
                }
                if let Ok(folder) = File::open(place) {
                    let _ = set_times(&folder, entry.mtime);
                }
            }
            EntryType::Symlink => {
                self.clear(place)?;
                let target = entry.target.as_deref().unwrap_or("");
                #[cfg(unix)]
                std::os::unix::fs::symlink(target, place)?;
                #[cfg(windows)]
                std::os::windows::fs::symlink_file(target, place)?;
            }
            EntryType::File => {
                self.clear(place)?;
                let mut options = OpenOptions::new();
                options.write(true).create_new(true);
                #[cfg(unix)]
                std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
                let mut file = options.open(place)?;
                for chunk in read_file(self.repository, entry)? {
                    let chunk = chunk?;
                    file.write_all(&chunk)?;
                    self.result.bytes += chunk.len() as u64;
                }
                own(place, entry);
                set_times(&file, entry.mtime)?;
                drop(file);
                // Set outright, after ownership and times: the mode a file is made with is cut down by the umask,
                // and a read-only file could not have its times set on every system afterwards.
                chmod(place, entry.mode)?;
                self.result.files += 1;
            }
        }
        Ok(())
    }
}

/// Puts one file, one folder or everything (an empty path) from a snapshot into `target`. A folder that
/// exists is filled in; a file or link in the way is moved aside first (by default to
/// `<name>.before-restore-<time>`).
pub fn restore(
    repository: &Repository,
    snapshot: &Snapshot,
    path: &[String],
    target: &Path,
    aside: Option<&dyn Fn(&Path) -> PathBuf>,
) -> Result<RestoreResult> {
    let started = crate::iso(time::OffsetDateTime::now_utc()).replace([':', '.'], "-");
    let default_aside = move |existing: &Path| {
        PathBuf::from(format!("{}.before-restore-{started}", existing.display()))
    };
    let start = find(repository, snapshot, path)?
        .ok_or_else(|| invalid("No such file or folder in this backup"))?;
    if !path.is_empty() && !safe_name(&start.name) {
        return Err(invalid(
            "This backup holds a name that cannot be restored safely",
        ));
    }
    // A destination made here is made usable by the one restoring, whatever the umask. Its missing folders
    // are made one at a time for that reason.
    let absolute = std::path::absolute(target)?;
    let mut missing = Vec::new();
    let mut at = absolute.as_path();
    while fs::symlink_metadata(at).is_err() {
        missing.push(at.to_path_buf());
        match at.parent() {
            Some(parent) => at = parent,
            None => break,
        }
    }
    for folder in missing.iter().rev() {
        fs::create_dir(folder)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            chmod(
                folder,
                (fs::metadata(folder)?.permissions().mode() & 0o7777) | 0o700,
            )?;
        }
    }
    let mut restorer = Restorer {
        repository,
        aside: aside.unwrap_or(&default_aside),
        result: RestoreResult::default(),
    };
    // Everything goes straight into `target`; one file or folder keeps its own name inside it.
    let place = if path.is_empty() {
        target.to_path_buf()
    } else {
        target.join(&start.name)
    };
    restorer.put(&start, &place)?;
    Ok(restorer.result)
}
