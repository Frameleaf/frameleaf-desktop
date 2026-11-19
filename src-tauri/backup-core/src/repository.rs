use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::chunker::{check_chunker, gear_table, ChunkerParams, DEFAULT_CHUNKER};
use crate::keys::{
    derive_keys, open_blob, seal, seal_blob, unseal, RepositoryKeys, FORMAT, VERSION,
};
use crate::store::{ByteRange, Store};
use crate::{invalid, Error, Id, Result};

const PACK_MAGIC: &[u8; 8] = b"FLRP0001";
const PACK_FOOTER: u64 = 4 + 8;
const ENTRY: usize = 40;
/// Packs keep object counts low (Wasabi bills a 4 KB minimum per object) and hide chunk sizes from the provider.
pub const PACK_TARGET: usize = 64 * 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Location {
    pub pack: Arc<str>,
    pub offset: u32,
    pub length: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RepositoryConfig {
    pub format: String,
    pub version: u32,
    pub repo_id: String,
    pub chunker: ChunkerParams,
    /// The caller's label for the root key that wraps this repository's key.
    pub key_version: String,
    pub wrapped_key: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Stats {
    pub files: u64,
    pub folders: u64,
    pub bytes: u64,
    pub stored_bytes: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Snapshot {
    pub v: u32,
    pub repo_id: String,
    /// Order of snapshots. The clock never decides it.
    pub seq: u64,
    pub time: String,
    pub tree: String,
    pub parent: Option<String>,
    pub stats: Stats,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PackEntry {
    pub id: Id,
    pub offset: u32,
    pub length: u32,
}

#[derive(Clone, Debug)]
pub struct WrittenPack {
    pub pack: String,
    pub entries: Vec<PackEntry>,
}

/// What a caller says about a snapshot; the repository adds its number and its own id.
pub struct SnapshotBody {
    pub time: String,
    pub tree: String,
    pub parent: Option<String>,
    pub stats: Stats,
}

pub struct WrittenSnapshot {
    pub key: String,
    pub snapshot: Snapshot,
    pub version_id: Option<String>,
    pub ciphertext_sha256: String,
}

fn encode_entries(entries: &[PackEntry]) -> Vec<u8> {
    let mut out = Vec::with_capacity(entries.len() * ENTRY);
    for entry in entries {
        out.extend_from_slice(&entry.id);
        out.extend_from_slice(&entry.offset.to_be_bytes());
        out.extend_from_slice(&entry.length.to_be_bytes());
    }
    out
}

fn decode_entries(data: &[u8]) -> Result<Vec<PackEntry>> {
    if !data.len().is_multiple_of(ENTRY) {
        return Err(Error::Unseal);
    }
    Ok(data
        .chunks_exact(ENTRY)
        .map(|record| PackEntry {
            id: record[..32].try_into().unwrap(),
            offset: u32::from_be_bytes(record[32..36].try_into().unwrap()),
            length: u32::from_be_bytes(record[36..40].try_into().unwrap()),
        })
        .collect())
}

fn wrap_info(repo_id: &str) -> Vec<u8> {
    format!("{FORMAT}/{VERSION} {repo_id}").into_bytes()
}

fn random_hex(bytes: usize) -> String {
    let mut out = vec![0u8; bytes];
    rand::thread_rng().fill_bytes(&mut out);
    hex::encode(out)
}

fn is_hex(text: &str, min: usize, max: usize) -> bool {
    (min..=max).contains(&text.len())
        && text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// `s/<12 digits>-<16 to 64 hex>`: the sequence number, or None for anything else.
pub fn snapshot_seq(key: &str) -> Option<u64> {
    let rest = key.strip_prefix("s/")?;
    let (digits, id) = rest.split_once('-')?;
    (digits.len() == 12 && digits.bytes().all(|b| b.is_ascii_digit()) && is_hex(id, 16, 64))
        .then(|| digits.parse().unwrap())
}

/// Refused before a run does any work, and again where the name is made.
pub fn check_snapshot_id(id: Option<&str>) -> Result<()> {
    match id {
        Some(id) if !is_hex(id, 16, 64) => Err(invalid(
            "A snapshot id is 16 to 64 lower-case hex characters",
        )),
        _ => Ok(()),
    }
}

pub struct Repository {
    pub store: Arc<dyn Store>,
    pub config: RepositoryConfig,
    pub keys: RepositoryKeys,
    pub gear: [u32; 256],
    /// Every blob the repository holds, by id.
    /// ponytail: a map in memory, roughly 200 MB per million blobs (about 2 TB of data). Move to an
    /// on-disk cache before libraries of that size are common.
    pub index: HashMap<Id, Location>,
    /// Index objects the last `load_index` could not open.
    pub damaged_indexes: Vec<String>,
}

impl Repository {
    fn with(store: Arc<dyn Store>, config: RepositoryConfig, master: &[u8]) -> Result<Self> {
        let keys = derive_keys(master, &config.repo_id)?;
        let gear = gear_table(&keys.cut);
        Ok(Repository {
            store,
            config,
            keys,
            gear,
            index: HashMap::new(),
            damaged_indexes: Vec::new(),
        })
    }

    /// Starts a new repository. The repository key is made here and wrapped with `root_key`; it never leaves in the clear.
    pub fn init(
        store: Arc<dyn Store>,
        root_key: &[u8],
        key_version: Option<&str>,
        chunker: Option<ChunkerParams>,
    ) -> Result<Self> {
        if !store.list("config")?.is_empty() {
            return Err(invalid("This storage already holds a repository"));
        }
        let chunker = chunker.unwrap_or(DEFAULT_CHUNKER);
        check_chunker(&chunker)?;
        let mut master = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut master);
        let repo_id = uuid::Uuid::new_v4().to_string();
        let config = RepositoryConfig {
            format: FORMAT.into(),
            version: VERSION,
            wrapped_key: STANDARD.encode(seal(root_key, &wrap_info(&repo_id), &master)?),
            repo_id,
            chunker,
            key_version: key_version.unwrap_or("1").into(),
        };
        store.put(
            "config",
            &serde_json::to_vec(&config).expect("config serialises"),
        )?;
        Repository::with(store, config, &master)
    }

    /// The unencrypted description of a repository: enough to know which root key opens it.
    pub fn read_config(store: &dyn Store) -> Result<RepositoryConfig> {
        let config: RepositoryConfig = serde_json::from_slice(&store.get("config", None)?)
            .map_err(|_| invalid(format!("Not a {FORMAT} version {VERSION} repository")))?;
        if config.format != FORMAT || config.version != VERSION {
            return Err(invalid(format!(
                "Not a {FORMAT} version {VERSION} repository"
            )));
        }
        check_chunker(&config.chunker)?;
        Ok(config)
    }

    pub fn open(store: Arc<dyn Store>, root_key: &[u8]) -> Result<Self> {
        let config = Repository::read_config(store.as_ref())?;
        let wrapped = STANDARD
            .decode(&config.wrapped_key)
            .map_err(|_| Error::Unseal)?;
        let master = unseal(root_key, &wrap_info(&config.repo_id), &wrapped)?;
        Repository::with(store, config, &master)
    }

    /// Rebuilds the index from storage. Only blobs in packs that are really there count, and a pack no
    /// index mentions is adopted from its own trailer, so a run that stopped before writing its index
    /// loses nothing and re-sends nothing.
    pub fn load_index(&mut self) -> Result<()> {
        self.index.clear();
        self.damaged_indexes.clear();
        let packs: HashSet<String> = self
            .store
            .list("p/")?
            .into_iter()
            .map(|object| object.key)
            .collect();
        let mut indexed: HashSet<String> = HashSet::new();
        for object in self.store.list("i/")? {
            let sealed = self.store.get(&object.key, None)?;
            // The index is only a faster copy of what packs say about themselves. One that fails its seal is
            // left out; the packs it listed are read from their own trailers below.
            let data = match unseal(&self.keys.meta, object.key.as_bytes(), &sealed) {
                Ok(data) => data,
                Err(Error::Unseal) => {
                    self.damaged_indexes.push(object.key);
                    continue;
                }
                Err(error) => return Err(error),
            };
            // Bytes that passed their seal are the bytes a writer made. If they do not unpack, the cause is
            // here, not damage in storage, so that failure is passed on.
            let data = zstd::stream::decode_all(data.as_slice())?;
            let mut at = 0;
            while at < data.len() {
                let head = data
                    .get(at..at + 20)
                    .ok_or_else(|| invalid("An index object is cut short"))?;
                let pack = format!("p/{}", hex::encode(&head[..16]));
                let count = u32::from_be_bytes(head[16..20].try_into().unwrap()) as usize;
                let records = data
                    .get(at + 20..at + 20 + count * ENTRY)
                    .ok_or_else(|| invalid("An index object is cut short"))?;
                at += 20 + count * ENTRY;
                if !packs.contains(&pack) {
                    continue;
                }
                let name: Arc<str> = pack.as_str().into();
                for entry in decode_entries(records)? {
                    self.index.insert(
                        entry.id,
                        Location {
                            pack: name.clone(),
                            offset: entry.offset,
                            length: entry.length,
                        },
                    );
                }
                indexed.insert(pack);
            }
        }
        for pack in packs.difference(&indexed) {
            // A pack whose trailer can't be opened was never finished. A storage failure is not that, and is passed on.
            let adopted = match self.read_trailer(pack) {
                Ok(entries) => entries,
                Err(Error::Unseal) => Vec::new(),
                Err(error) => return Err(error),
            };
            let name: Arc<str> = pack.as_str().into();
            for entry in adopted {
                self.index.insert(
                    entry.id,
                    Location {
                        pack: name.clone(),
                        offset: entry.offset,
                        length: entry.length,
                    },
                );
            }
        }
        Ok(())
    }

    /// A pack's own list of what it holds. This, not the index, is the authority.
    pub fn read_trailer(&self, pack: &str) -> Result<Vec<PackEntry>> {
        let footer = self.store.get(pack, Some(ByteRange::Suffix(PACK_FOOTER)))?;
        if footer.len() as u64 != PACK_FOOTER || &footer[4..] != PACK_MAGIC {
            return Err(Error::Unseal);
        }
        let length = u64::from(u32::from_be_bytes(footer[..4].try_into().unwrap()));
        let tail = self
            .store
            .get(pack, Some(ByteRange::Suffix(PACK_FOOTER + length)))?;
        if (tail.len() as u64) < PACK_FOOTER + length {
            return Err(Error::Unseal);
        }
        decode_entries(&unseal(
            &self.keys.meta,
            pack.as_bytes(),
            &tail[..length as usize],
        )?)
    }

    /// One blob, fetched by byte range from its pack and opened.
    pub fn read_blob(&self, id: &Id) -> Result<Vec<u8>> {
        let location = self
            .index
            .get(id)
            .ok_or_else(|| Error::MissingBlob(hex::encode(id)))?;
        let start = u64::from(location.offset);
        let blob = self.store.get(
            &location.pack,
            Some(ByteRange::Span {
                start,
                end: start + u64::from(location.length),
            }),
        )?;
        open_blob(&self.keys, id, &blob)
    }

    /// Records which packs hold which blobs. Written after its packs and before any snapshot that needs them.
    pub fn write_index(&self, packs: &[WrittenPack]) -> Result<()> {
        if packs.is_empty() {
            return Ok(());
        }
        let mut plain = Vec::new();
        for WrittenPack { pack, entries } in packs {
            let mut head = [0u8; 16];
            hex::decode_to_slice(&pack[2..], &mut head).map_err(|_| invalid("Not a pack name"))?;
            plain.extend_from_slice(&head);
            plain.extend_from_slice(&(entries.len() as u32).to_be_bytes());
            plain.extend(encode_entries(entries));
        }
        let key = format!("i/{}", random_hex(16));
        self.store.put(
            &key,
            &seal(
                &self.keys.meta,
                key.as_bytes(),
                &zstd::bulk::compress(&plain, 3)?,
            )?,
        )?;
        Ok(())
    }

    /// Replaces every index object with one that lists exactly what the index holds now. The new one is written first.
    pub fn rewrite_index(&self) -> Result<()> {
        let old = self.store.list("i/")?;
        let mut packs: HashMap<&str, Vec<PackEntry>> = HashMap::new();
        for (id, location) in &self.index {
            packs.entry(&location.pack).or_default().push(PackEntry {
                id: *id,
                offset: location.offset,
                length: location.length,
            });
        }
        let written: Vec<WrittenPack> = packs
            .into_iter()
            .map(|(pack, entries)| WrittenPack {
                pack: pack.to_string(),
                entries,
            })
            .collect();
        self.write_index(&written)?;
        for object in old {
            self.store.delete(&object.key)?;
        }
        Ok(())
    }

    /// Snapshots oldest first: by sequence number, then by name.
    pub fn list_snapshots(&self) -> Result<Vec<(String, u64)>> {
        let mut found: Vec<(String, u64)> = self
            .store
            .list("s/")?
            .into_iter()
            .filter_map(|object| snapshot_seq(&object.key).map(|seq| (object.key, seq)))
            .collect();
        found.sort_by(|a, b| a.1.cmp(&b.1).then_with(|| a.0.cmp(&b.0)));
        Ok(found)
    }

    pub fn read_snapshot(&self, key: &str) -> Result<Snapshot> {
        let plain = unseal(&self.keys.meta, key.as_bytes(), &self.store.get(key, None)?)?;
        let snapshot: Snapshot = serde_json::from_slice(&plain).map_err(|_| Error::Unseal)?;
        if snapshot.repo_id != self.config.repo_id || Some(snapshot.seq) != snapshot_seq(key) {
            return Err(Error::Unseal);
        }
        Ok(snapshot)
    }

    /// The last step of a backup. Returns what a signed receipt needs: the object's name and the hash of what was stored.
    /// `stop` is checked last of all, right before the snapshot is stored: a run told to stop commits nothing.
    /// `id` is the random part of the name, when the caller must know the name before the run starts.
    pub fn write_snapshot(
        &self,
        body: SnapshotBody,
        sequence: Option<u64>,
        stop: Option<&AtomicBool>,
        id: Option<&str>,
    ) -> Result<WrittenSnapshot> {
        // Where a signed history is kept (Frameleaf Cloud), its next number is used, so the two never drift apart.
        let seq = match sequence {
            Some(seq) => seq,
            None => self.list_snapshots()?.last().map_or(0, |(_, seq)| *seq) + 1,
        };
        if !(1..=999_999_999_999).contains(&seq) {
            return Err(invalid(
                "A snapshot number must be a whole number from 1 to 999999999999",
            ));
        }
        check_snapshot_id(id)?;
        let key = format!(
            "s/{seq:012}-{}",
            id.map_or_else(|| random_hex(8), str::to_string)
        );
        let SnapshotBody {
            time,
            tree,
            parent,
            stats,
        } = body;
        let snapshot = Snapshot {
            v: 1,
            repo_id: self.config.repo_id.clone(),
            seq,
            time,
            tree,
            parent,
            stats,
        };
        let sealed = seal(
            &self.keys.meta,
            key.as_bytes(),
            &serde_json::to_vec(&snapshot).expect("snapshot serialises"),
        )?;
        if stop.is_some_and(|stop| stop.load(Ordering::SeqCst)) {
            return Err(Error::Stopped);
        }
        let version_id = self.store.put(&key, &sealed)?;
        Ok(WrittenSnapshot {
            key,
            snapshot,
            version_id,
            ciphertext_sha256: hex::encode(Sha256::digest(&sealed)),
        })
    }
}

/// Collects new blobs into packs. A blob the repository already holds is never stored twice.
pub struct PackWriter {
    pub written: Vec<WrittenPack>,
    pub stored_bytes: u64,
    target: usize,
    parts: Vec<u8>,
    entries: Vec<PackEntry>,
    pending: HashSet<Id>,
}

impl PackWriter {
    pub fn new(target: usize) -> Self {
        PackWriter {
            written: Vec::new(),
            stored_bytes: 0,
            target,
            parts: Vec::new(),
            entries: Vec::new(),
            pending: HashSet::new(),
        }
    }

    pub fn has(&self, repository: &Repository, id: &Id) -> bool {
        repository.index.contains_key(id) || self.pending.contains(id)
    }

    /// Returns false when the blob was already there.
    pub fn add(&mut self, repository: &mut Repository, id: &Id, plain: &[u8]) -> Result<bool> {
        if self.has(repository, id) {
            return Ok(false);
        }
        let sealed = seal_blob(&repository.keys, id, plain)?;
        self.add_sealed(repository, id, &sealed)?;
        Ok(true)
    }

    /// A blob already in its stored form, as copied out of another pack. Stored even if the index knows it.
    pub fn add_sealed(&mut self, repository: &mut Repository, id: &Id, blob: &[u8]) -> Result<()> {
        self.entries.push(PackEntry {
            id: *id,
            offset: self.parts.len() as u32,
            length: blob.len() as u32,
        });
        self.parts.extend_from_slice(blob);
        self.pending.insert(*id);
        if self.parts.len() >= self.target {
            self.flush(repository)?;
        }
        Ok(())
    }

    pub fn flush(&mut self, repository: &mut Repository) -> Result<()> {
        if self.entries.is_empty() {
            return Ok(());
        }
        let pack = format!("p/{}", random_hex(16));
        let trailer = seal(
            &repository.keys.meta,
            pack.as_bytes(),
            &encode_entries(&self.entries),
        )?;
        let mut body = std::mem::take(&mut self.parts);
        body.extend_from_slice(&trailer);
        body.extend_from_slice(&(trailer.len() as u32).to_be_bytes());
        body.extend_from_slice(PACK_MAGIC);
        if let Err(error) = repository.store.put(&pack, &body) {
            // Kept as they were, so a caller may flush again.
            body.truncate(body.len() - trailer.len() - PACK_FOOTER as usize);
            self.parts = body;
            return Err(error);
        }
        let name: Arc<str> = pack.as_str().into();
        for entry in &self.entries {
            repository.index.insert(
                entry.id,
                Location {
                    pack: name.clone(),
                    offset: entry.offset,
                    length: entry.length,
                },
            );
        }
        self.stored_bytes += body.len() as u64;
        self.written.push(WrittenPack {
            pack,
            entries: std::mem::take(&mut self.entries),
        });
        self.pending.clear();
        Ok(())
    }
}
