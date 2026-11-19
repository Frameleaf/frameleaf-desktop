use std::collections::{BTreeSet, HashMap, HashSet};
use std::time::{Duration, SystemTime};

use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use crate::keys::{blob_id, open_blob};
use crate::repository::{Location, PackWriter, Repository, PACK_TARGET};
use crate::store::ByteRange;
use crate::tree::decode_tree;
use crate::{parse_id, Error, Id, Result};

const DAY_MS: i128 = 86_400_000;

/// Which packs `verify` reads byte for byte: given the pack's name and its place in name order.
pub type PackFilter<'a> = &'a dyn Fn(&str, usize) -> bool;
/// Chooses the snapshots to keep from (key, time), oldest first.
pub type KeepChooser<'a> = &'a dyn Fn(&[(String, String)]) -> Vec<String>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RetentionPolicy {
    /// The newest backups are kept whatever their age, so a wrong clock can never empty a repository.
    pub keep_last: usize,
    /// Every backup this recent is kept.
    pub keep_days: u32,
    /// Beyond that, the newest backup of each month, for this many months.
    pub keep_monthly: u32,
}

/// Wasabi bills every object for 90 days, so keeping every version that long costs nothing extra.
pub const DEFAULT_RETENTION: RetentionPolicy = RetentionPolicy {
    keep_last: 3,
    keep_days: 90,
    keep_monthly: 12,
};

fn millis(time: OffsetDateTime) -> i128 {
    time.unix_timestamp_nanos() / 1_000_000
}

fn month(time: OffsetDateTime) -> i64 {
    let time = time.to_offset(time::UtcOffset::UTC);
    i64::from(time.year()) * 12 + i64::from(u8::from(time.month())) - 1
}

/// Which backups to keep. `snapshots` is (key, time), oldest first. A backup whose time can't be read is kept.
pub fn retain(
    snapshots: &[(String, String)],
    policy: &RetentionPolicy,
    now: OffsetDateTime,
) -> HashSet<String> {
    let last = policy.keep_last.max(1);
    let mut keep: HashSet<String> = snapshots
        .iter()
        .rev()
        .take(last)
        .map(|(key, _)| key.clone())
        .collect();
    let mut months = HashSet::new();
    for (key, time) in snapshots.iter().rev() {
        match OffsetDateTime::parse(time, &Rfc3339) {
            Err(_) => {
                keep.insert(key.clone());
            }
            Ok(time) if millis(now) - millis(time) <= i128::from(policy.keep_days) * DAY_MS => {
                keep.insert(key.clone());
            }
            Ok(time) => {
                if month(now) - month(time) < i64::from(policy.keep_monthly)
                    && months.insert(month(time))
                {
                    keep.insert(key.clone());
                }
            }
        }
    }
    keep
}

/// Adds every blob a tree needs to `live`. With `missing`, a blob that isn't stored is noted there instead
/// of failing. `visited` is kept apart from `live`: a file's chunk can have the same id as a folder's tree.
fn mark(
    repository: &Repository,
    tree: &str,
    live: &mut HashSet<Id>,
    visited: &mut HashSet<Id>,
    mut missing: Option<&mut BTreeSet<String>>,
) -> Result<()> {
    let tree_id = parse_id(tree)?;
    if !visited.insert(tree_id) {
        return Ok(());
    }
    live.insert(tree_id);
    let read = |id: &Id, missing: &mut Option<&mut BTreeSet<String>>| match repository.read_blob(id)
    {
        Ok(data) => Ok(Some(data)),
        Err(Error::MissingBlob(_) | Error::Unseal) if missing.is_some() => {
            missing.as_mut().unwrap().insert(hex::encode(id));
            Ok(None)
        }
        Err(error) => Err(error),
    };
    let Some(data) = read(&tree_id, &mut missing)? else {
        return Ok(());
    };
    for entry in decode_tree(&data)? {
        if let Some(child) = &entry.tree {
            mark(repository, child, live, visited, missing.as_deref_mut())?;
        }
        for id in entry.chunks.iter().flatten() {
            live.insert(parse_id(id)?);
        }
        for list in entry.lists.iter().flatten() {
            let list = parse_id(list)?;
            live.insert(list);
            if let Some(ids) = read(&list, &mut missing)? {
                live.extend(ids.chunks_exact(32).map(|id| <Id>::try_from(id).unwrap()));
            }
        }
    }
    Ok(())
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct VerifyReport {
    pub snapshots: u64,
    pub blobs: u64,
    /// Backups that could not be opened at all.
    pub damaged_snapshots: Vec<String>,
    /// Pieces a backup needs that storage does not hold.
    pub missing: Vec<String>,
    pub packs_read: u64,
    /// Packs whose content no longer matches what was written.
    pub damaged_packs: Vec<String>,
    /// Index objects that can no longer be opened. Nothing is lost: packs describe themselves.
    pub damaged_indexes: Vec<String>,
}

/// Checks that every backup can still be restored. Changes nothing. `read_pack` picks the packs to
/// download and check byte for byte (pack name, its place in name order).
pub fn verify(repository: &mut Repository, read_pack: Option<PackFilter>) -> Result<VerifyReport> {
    repository.load_index()?;
    let (mut live, mut visited, mut missing) = (HashSet::new(), HashSet::new(), BTreeSet::new());
    let mut report = VerifyReport {
        damaged_indexes: repository.damaged_indexes.clone(),
        ..Default::default()
    };
    for (key, _) in repository.list_snapshots()? {
        match repository.read_snapshot(&key) {
            Ok(snapshot) => {
                mark(
                    repository,
                    &snapshot.tree,
                    &mut live,
                    &mut visited,
                    Some(&mut missing),
                )?;
                report.snapshots += 1;
            }
            Err(Error::Unseal) => report.damaged_snapshots.push(key),
            Err(error) => return Err(error),
        }
    }
    for id in &live {
        if !repository.index.contains_key(id) {
            missing.insert(hex::encode(id));
        }
    }
    report.blobs = live.len() as u64;
    report.missing = missing.into_iter().collect();

    let mut packs: Vec<String> = repository
        .store
        .list("p/")?
        .into_iter()
        .map(|object| object.key)
        .collect();
    packs.sort();
    for (index, pack) in packs.iter().enumerate() {
        if !read_pack.is_some_and(|read_pack| read_pack(pack, index)) {
            continue;
        }
        report.packs_read += 1;
        let whole = (|| -> Result<()> {
            let body = repository.store.get(pack, None)?;
            for entry in repository.read_trailer(pack)? {
                let blob = body
                    .get(entry.offset as usize..(entry.offset + entry.length) as usize)
                    .ok_or(Error::Unseal)?;
                if blob_id(
                    &repository.keys,
                    &open_blob(&repository.keys, &entry.id, blob)?,
                ) != entry.id
                {
                    return Err(Error::Unseal);
                }
            }
            Ok(())
        })();
        if whole.is_err() {
            report.damaged_packs.push(pack.clone());
        }
    }
    Ok(report)
}

pub struct PruneOptions<'a> {
    pub policy: RetentionPolicy,
    /// Chooses which backups to keep, in place of `policy`, for a caller with retention rules of its own.
    /// Given (key, time) oldest first. Whatever it answers, the newest backup is kept.
    pub keep: Option<KeepChooser<'a>>,
    /// Works out what a prune would remove and changes nothing.
    pub dry_run: bool,
    pub now: Option<OffsetDateTime>,
    /// A pack younger than this is never deleted or rewritten: it is billed for that long anyway.
    pub min_age_days: u32,
    /// A pack with less than this share of its bytes still needed is rewritten without the rest.
    pub repack_below: f64,
    pub pack_target: usize,
}

impl Default for PruneOptions<'_> {
    fn default() -> Self {
        PruneOptions {
            policy: DEFAULT_RETENTION,
            keep: None,
            dry_run: false,
            now: None,
            min_age_days: 90,
            repack_below: 0.5,
            pack_target: PACK_TARGET,
        }
    }
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct PruneReport {
    pub kept_snapshots: u64,
    pub removed_snapshots: Vec<String>,
    pub deleted_packs: u64,
    pub repacked_packs: u64,
    pub freed_bytes: i64,
}

/// Removes backups the policy no longer keeps, and the stored data only they needed.
///
/// The caller must hold the repository's lock: prune and backup never run together.
///
/// The order makes every stopping point safe:
/// 1. backups that are no longer kept are removed, so nothing points at what goes next;
/// 2. needed pieces of mostly-unneeded packs are copied into new packs;
/// 3. one new index replaces the old ones (new written before old deleted);
/// 4. unneeded packs are deleted last.
pub fn prune(repository: &mut Repository, options: &PruneOptions) -> Result<PruneReport> {
    let now = options.now.unwrap_or_else(OffsetDateTime::now_utc);
    let now_system = SystemTime::UNIX_EPOCH + Duration::from_millis(millis(now).max(0) as u64);
    let min_age = Duration::from_secs(u64::from(options.min_age_days) * 86_400);
    repository.load_index()?;

    let mut snapshots = Vec::new();
    for (key, _) in repository.list_snapshots()? {
        let snapshot = repository.read_snapshot(&key)?;
        snapshots.push((key, snapshot.time, snapshot.tree));
    }
    let listed: Vec<(String, String)> = snapshots
        .iter()
        .map(|(key, time, _)| (key.clone(), time.clone()))
        .collect();
    let mut keep: HashSet<String> = match options.keep {
        Some(choose) => choose(&listed).into_iter().collect(),
        None => retain(&listed, &options.policy, now),
    };
    // Whoever chooses, a repository is never left without its newest backup.
    if let Some((newest, _, _)) = snapshots.last() {
        keep.insert(newest.clone());
    }
    keep.retain(|key| snapshots.iter().any(|(snapshot, _, _)| snapshot == key));

    // A kept backup with a missing piece stops the prune here: a damaged repository is never thinned.
    let (mut live, mut visited) = (HashSet::new(), HashSet::new());
    for (key, _, tree) in &snapshots {
        if keep.contains(key) {
            mark(repository, tree, &mut live, &mut visited, None)?;
        }
    }
    if let Some(id) = live.iter().find(|id| !repository.index.contains_key(*id)) {
        return Err(Error::MissingBlob(hex::encode(id)));
    }

    let mut needed: HashMap<&str, Vec<(Id, Location)>> = HashMap::new();
    for (id, location) in &repository.index {
        if live.contains(id) {
            needed
                .entry(&location.pack)
                .or_default()
                .push((*id, location.clone()));
        }
    }
    let mut remove = Vec::new();
    let mut moves: Vec<(String, Vec<(Id, Location)>)> = Vec::new();
    let mut copied_bytes = 0i64;
    for pack in repository.store.list("p/")? {
        if now_system
            .duration_since(pack.modified)
            .map_or(true, |age| age < min_age)
        {
            continue;
        }
        let blobs = needed.get(pack.key.as_str()).cloned().unwrap_or_default();
        let bytes: u64 = blobs
            .iter()
            .map(|(_, location)| u64::from(location.length))
            .sum();
        if bytes == 0 {
            remove.push(pack);
        } else if (bytes as f64) < pack.size as f64 * options.repack_below {
            copied_bytes += bytes as i64;
            moves.push((pack.key.clone(), blobs));
            remove.push(pack);
        }
    }
    drop(needed);
    let removed_snapshots: Vec<String> = snapshots
        .iter()
        .filter(|(key, _, _)| !keep.contains(key))
        .map(|(key, _, _)| key.clone())
        .collect();
    let freed: i64 = remove.iter().map(|pack| pack.size as i64).sum();
    let mut report = PruneReport {
        kept_snapshots: keep.len() as u64,
        removed_snapshots: removed_snapshots.clone(),
        deleted_packs: remove.len() as u64,
        repacked_packs: moves.len() as u64,
        // An estimate for a dry run: new packs add a few bytes of their own.
        freed_bytes: freed - copied_bytes,
    };
    if options.dry_run {
        return Ok(report);
    }
    for key in &removed_snapshots {
        repository.store.delete(key)?;
    }
    let mut writer = PackWriter::new(options.pack_target);
    for (pack, blobs) in &moves {
        for (id, location) in blobs {
            let start = u64::from(location.offset);
            let blob = repository.store.get(
                pack,
                Some(ByteRange::Span {
                    start,
                    end: start + u64::from(location.length),
                }),
            )?;
            // Opened before it is copied, so damage is found here and never carried into a new pack.
            open_blob(&repository.keys, id, &blob)?;
            writer.add_sealed(repository, id, &blob)?;
        }
    }
    writer.flush(repository)?;

    let gone: HashSet<&str> = remove.iter().map(|pack| pack.key.as_str()).collect();
    repository
        .index
        .retain(|_, location| !gone.contains(&*location.pack));
    // Left alone when nothing changed, so a quiet week doesn't rewrite the index for no reason. A damaged
    // index object is replaced here too: the rewrite leaves it out and then removes it.
    if !remove.is_empty()
        || !repository.damaged_indexes.is_empty()
        || repository.store.list("i/")?.len() > 8
    {
        repository.rewrite_index()?;
    }
    for pack in &remove {
        repository.store.delete(&pack.key)?;
    }
    report.freed_bytes = freed - writer.stored_bytes as i64;
    Ok(report)
}
