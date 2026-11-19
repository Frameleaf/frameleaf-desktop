use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};

use crate::chunker::chunks;
use crate::keys::blob_id;
use crate::repository::{
    check_snapshot_id, PackWriter, Repository, Snapshot, SnapshotBody, Stats, PACK_TARGET,
};
use crate::tree::{
    encode_tree, file_chunks, read_tree, safe_name, Entry, EntryType, Source, SourceEntry,
};
use crate::{iso, Error, Result};

/// A file's chunk ids sit in its folder's tree up to this many; beyond it they move into list blobs.
const INLINE_CHUNKS: usize = 1024;
const LIST_CHUNKS: usize = 32_768;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BackupProblem {
    pub path: Vec<String>,
    pub message: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Progress {
    pub files: u64,
    pub bytes: u64,
    pub stored_bytes: u64,
}

#[derive(Default)]
pub struct BackupOptions<'a> {
    /// The snapshot's time; now when None.
    pub time: Option<time::OffsetDateTime>,
    /// Bytes per pack. Tests make it small.
    pub pack_target: Option<usize>,
    /// The snapshot's number, when a signed history kept elsewhere decides it. Otherwise one more than the newest stored.
    pub sequence: Option<u64>,
    /// The random part of the snapshot's name (16 to 64 hex characters), for a caller that must record the
    /// name before the run starts.
    pub snapshot_id: Option<String>,
    /// Stops the run. What was stored is kept for the next run.
    pub stop: Option<&'a AtomicBool>,
    /// Called after every file, and after every chunk of a file being read.
    pub on_progress: Option<&'a dyn Fn(Progress)>,
}

#[derive(Debug)]
pub struct BackupResult {
    pub key: String,
    pub snapshot: Snapshot,
    /// For the signed receipt Cloud keeps: the hash of the snapshot object as stored.
    pub ciphertext_sha256: String,
    /// The stored version of the snapshot object, where storage keeps versions.
    pub version_id: Option<String>,
    /// Files that could not be read, or changed while they were read. The backup still finishes.
    pub problems: Vec<BackupProblem>,
    /// Files taken from the previous backup without being read again.
    pub unchanged: u64,
}

/// Why reading one file failed: the source (the file is skipped) or anything else (the run ends).
enum ReadFailure {
    Source(String),
    Run(Error),
}

struct Run<'a> {
    repository: &'a mut Repository,
    source: &'a dyn Source,
    options: &'a BackupOptions<'a>,
    data: PackWriter,
    trees: PackWriter,
    problems: Vec<BackupProblem>,
    stats: Stats,
    unchanged: u64,
}

fn same(before: &Entry, now: &SourceEntry) -> bool {
    before.kind == EntryType::File
        && match (&before.key, &now.key) {
            (Some(before), Some(now)) => before == now,
            _ => before.size == now.size && before.mtime == now.mtime,
        }
}

fn stored_entry(now: &SourceEntry) -> Entry {
    Entry {
        name: now.name.clone(),
        kind: now.kind,
        mode: now.mode,
        uid: now.uid,
        gid: now.gid,
        mtime: now.mtime,
        key: now.key.clone(),
        size: now.size,
        target: now.target.clone(),
        chunks: None,
        lists: None,
        files: None,
        tree: None,
    }
}

impl Run<'_> {
    fn stopped(&self) -> Result<()> {
        match self.options.stop {
            Some(stop) if stop.load(Ordering::SeqCst) => Err(Error::Stopped),
            _ => Ok(()),
        }
    }

    fn report(&self, reading: u64) {
        if let Some(on_progress) = self.options.on_progress {
            on_progress(Progress {
                files: self.stats.files,
                bytes: self.stats.bytes + reading,
                stored_bytes: self.data.stored_bytes,
            });
        }
    }

    fn store_tree(&mut self, plain: &[u8]) -> Result<String> {
        let id = blob_id(&self.repository.keys, plain);
        self.trees.add(self.repository, &id, plain)?;
        Ok(hex::encode(id))
    }

    fn read_file(
        &mut self,
        path: &[String],
    ) -> std::result::Result<(Vec<String>, u64), ReadFailure> {
        let reader = self
            .source
            .read(path)
            .map_err(|error| ReadFailure::Source(error.to_string()))?;
        let gear = self.repository.gear;
        let (mut ids, mut bytes) = (Vec::new(), 0u64);
        for chunk in chunks(reader, self.repository.config.chunker, &gear) {
            let chunk = chunk.map_err(|error| ReadFailure::Source(error.to_string()))?;
            self.stopped().map_err(ReadFailure::Run)?;
            let id = blob_id(&self.repository.keys, &chunk);
            self.data
                .add(self.repository, &id, &chunk)
                .map_err(ReadFailure::Run)?;
            ids.push(hex::encode(id));
            bytes += chunk.len() as u64;
            self.report(bytes);
        }
        Ok((ids, bytes))
    }

    fn file(
        &mut self,
        path: &[String],
        now: &SourceEntry,
        before: Option<&Entry>,
    ) -> Result<Option<Entry>> {
        let mut entry = stored_entry(now);
        if let Some(before) = before.filter(|before| same(before, now)) {
            // Reuse only what storage really holds; anything else is read again.
            if let Ok(ids) = file_chunks(self.repository, before) {
                if ids.iter().all(|id| self.repository.index.contains_key(id)) {
                    self.unchanged += 1;
                    entry.size = before.size;
                    if before.lists.is_some() {
                        entry.lists = before.lists.clone();
                    } else {
                        entry.chunks = Some(before.chunks.clone().unwrap_or_default());
                    }
                    return Ok(Some(entry));
                }
            }
        }
        let read = match self.read_file(path) {
            // A file that grew or shrank while it was read is read once more, then kept as read.
            Ok(read) if read.1 != now.size => self.read_file(path).inspect(|again| {
                if again.1 != now.size {
                    self.problems.push(BackupProblem {
                        path: path.to_vec(),
                        message: "This file changed while it was being backed up".into(),
                    });
                }
            }),
            other => other,
        };
        let (ids, bytes) = match read {
            Ok(read) => read,
            // Only a file that can't be read is skipped. A storage failure or a stop ends the run.
            Err(ReadFailure::Source(message)) => {
                self.problems.push(BackupProblem {
                    path: path.to_vec(),
                    message,
                });
                return Ok(None);
            }
            Err(ReadFailure::Run(error)) => return Err(error),
        };
        entry.size = bytes;
        if ids.len() <= INLINE_CHUNKS {
            entry.chunks = Some(ids);
        } else {
            let mut lists = Vec::new();
            for run in ids.chunks(LIST_CHUNKS) {
                let raw: Vec<u8> = run
                    .iter()
                    .flat_map(|id| hex::decode(id).expect("hex we wrote"))
                    .collect();
                lists.push(self.store_tree(&raw)?);
            }
            entry.lists = Some(lists);
        }
        Ok(Some(entry))
    }

    /// A folder's tree, with the files and bytes below it (a folder entry carries both, for browsing).
    fn totals(tree: String, entries: &[Entry]) -> (String, u64, u64) {
        let files = entries
            .iter()
            .map(|entry| {
                if entry.kind == EntryType::File {
                    1
                } else {
                    entry.files.unwrap_or(0)
                }
            })
            .sum();
        let bytes = entries
            .iter()
            .filter(|entry| entry.kind != EntryType::Symlink)
            .map(|entry| entry.size)
            .sum();
        (tree, files, bytes)
    }

    fn folder(&mut self, path: &[String], before_tree: Option<&str>) -> Result<(String, u64, u64)> {
        let earlier = before_tree.and_then(|tree| read_tree(self.repository, tree).ok());
        let before: HashMap<String, Entry> = earlier
            .iter()
            .flatten()
            .map(|entry| (entry.name.clone(), entry.clone()))
            .collect();
        let listed = match self.source.list(path) {
            Ok(listed) => listed,
            Err(error) => {
                self.problems.push(BackupProblem {
                    path: path.to_vec(),
                    message: error.to_string(),
                });
                // A folder that can't be listed today keeps what it held in the last backup, instead of looking empty.
                if let (Some(tree), Some(earlier)) = (before_tree, &earlier) {
                    return Ok(Run::totals(tree.to_string(), earlier));
                }
                Vec::new()
            }
        };
        let mut entries = Vec::new();
        for now in &listed {
            self.stopped()?;
            let mut child = path.to_vec();
            child.push(now.name.clone());
            if !safe_name(&now.name) {
                self.problems.push(BackupProblem {
                    path: child,
                    message: "This name can’t be stored: it would not restore inside its folder"
                        .into(),
                });
                continue;
            }
            let earlier = before.get(&now.name);
            if let Some(unreadable) = &now.unreadable {
                // One entry that can't be looked at today keeps what it held in the last backup.
                self.problems.push(BackupProblem {
                    path: child,
                    message: unreadable.clone(),
                });
                entries.extend(earlier.cloned());
                continue;
            }
            match now.kind {
                EntryType::Dir => {
                    let below = self.folder(
                        &child,
                        earlier
                            .filter(|e| e.kind == EntryType::Dir)
                            .and_then(|e| e.tree.as_deref()),
                    )?;
                    let mut entry = stored_entry(now);
                    entry.target = None;
                    (entry.size, entry.files, entry.tree) = (below.2, Some(below.1), Some(below.0));
                    entries.push(entry);
                    self.stats.folders += 1;
                }
                EntryType::Symlink => {
                    let mut entry = stored_entry(now);
                    entry.size = 0;
                    entries.push(entry);
                }
                EntryType::File => {
                    if let Some(stored) = self.file(&child, now, earlier)? {
                        self.stats.files += 1;
                        self.stats.bytes += stored.size;
                        entries.push(stored);
                        self.report(0);
                    }
                }
            }
        }
        let tree = self.store_tree(&encode_tree(&entries))?;
        Ok(Run::totals(tree, &entries))
    }
}

/// Backs up everything `source` offers as one new snapshot.
/// Order matters for safety: packs first, then the index, then the snapshot. A run that stops early
/// leaves packs nobody points at, which the next run adopts; it never leaves a snapshot pointing at
/// something missing.
pub fn backup(
    repository: &mut Repository,
    source: &dyn Source,
    options: &BackupOptions,
) -> Result<BackupResult> {
    if options.stop.is_some_and(|stop| stop.load(Ordering::SeqCst)) {
        return Err(Error::Stopped);
    }
    check_snapshot_id(options.snapshot_id.as_deref())?;
    repository.load_index()?;
    let parent_key = repository
        .list_snapshots()?
        .last()
        .map(|(key, _)| key.clone());
    let parent = parent_key
        .as_deref()
        .map(|key| repository.read_snapshot(key))
        .transpose()?;
    let target = options.pack_target.unwrap_or(PACK_TARGET);
    let mut run = Run {
        repository,
        source,
        options,
        data: PackWriter::new(target),
        trees: PackWriter::new(target),
        problems: Vec::new(),
        stats: Stats::default(),
        unchanged: 0,
    };

    // A stop that arrives after the last file still stops: no snapshot is written.
    let walked = run
        .folder(&[], parent.as_ref().map(|parent| parent.tree.as_str()))
        .and_then(|tree| run.stopped().map(|()| tree));
    let tree = match walked {
        Ok((tree, _, _)) => tree,
        Err(error) => {
            // A stopped run keeps what it has: the next run adopts these packs and sends none of it again.
            if matches!(error, Error::Stopped) {
                run.data.flush(run.repository)?;
            }
            return Err(error);
        }
    };
    run.data.flush(run.repository)?;
    run.trees.flush(run.repository)?;
    let written: Vec<_> = run
        .data
        .written
        .iter()
        .chain(&run.trees.written)
        .cloned()
        .collect();
    run.repository.write_index(&written)?;
    // A stop that arrives while the last packs and the index are written still stops.
    run.stopped()?;
    run.stats.stored_bytes = run.data.stored_bytes + run.trees.stored_bytes;
    let time = iso(options.time.unwrap_or_else(time::OffsetDateTime::now_utc));
    let snapshot = run.repository.write_snapshot(
        SnapshotBody {
            time,
            tree,
            parent: parent_key,
            stats: run.stats.clone(),
        },
        options.sequence,
        options.stop,
        options.snapshot_id.as_deref(),
    )?;
    Ok(BackupResult {
        key: snapshot.key,
        snapshot: snapshot.snapshot,
        ciphertext_sha256: snapshot.ciphertext_sha256,
        version_id: snapshot.version_id,
        problems: run.problems,
        unchanged: run.unchanged,
    })
}
