use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom};
use uuid::Uuid;
use zip::{CompressionMethod, ZipArchive};

const MANIFEST: &str = "manifest.json";
const INDEX: &str = "assets.jsonl";
const MAX_ITEMS: usize = 100_000;
pub(super) const MAX_MANIFEST: usize = 1024 * 1024;
const MAX_INDEX: u64 = 256 * 1024 * 1024;
const MAX_COLLECTION: u64 = 32 * 1024 * 1024;
const MAX_SIDECAR: u64 = 4 * 1024 * 1024;
const MAX_LINE: u64 = 64 * 1024;
const MAX_DIRECTORY: u64 = 64 * 1024 * 1024;
const MAX_PACKAGE: u64 = 16 * 1024_u64.pow(4);
const INVALID: &str = "media_copy_archive_invalid";

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct Manifest {
    format: String,
    schema_version: u8,
    package_id: Uuid,
    complete: bool,
    scope: Scope,
    counts: Counts,
    files: BTreeMap<String, FileDigest>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Scope {
    include_locked: bool,
}

#[derive(Deserialize)]
struct Counts {
    exported: usize,
    bytes: u64,
}

#[derive(Deserialize)]
struct FileDigest {
    bytes: u64,
    sha256: String,
}

#[derive(Deserialize)]
struct IndexFile {
    path: String,
    #[serde(flatten)]
    digest: FileDigest,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Item {
    source_asset_id: Uuid,
    locked: bool,
    original: IndexFile,
    metadata: Option<IndexFile>,
}

impl Manifest {
    pub(super) fn parse(bytes: &[u8], package: Uuid) -> Result<Self, &'static str> {
        if bytes.len() > MAX_MANIFEST {
            return Err(INVALID);
        }
        let manifest: Self = serde_json::from_slice(bytes).map_err(|_| INVALID)?;
        if manifest.format != "frameleaf-preservation-package"
            || !matches!(manifest.schema_version, 1 | 2)
            || manifest.package_id != package
            || !manifest.complete
            || manifest.scope.include_locked
            || manifest.counts.exported > MAX_ITEMS
            || !manifest.files.contains_key(INDEX)
            || manifest.files.iter().any(|(path, file)| {
                let limit = match path.as_str() {
                    INDEX => MAX_INDEX,
                    "albums.json" | "people.json" | "tags.json" => MAX_COLLECTION,
                    "bookmarks.json" if manifest.schema_version == 2 => MAX_COLLECTION,
                    _ => return true,
                };
                file.bytes > limit || !valid_hash(&file.sha256)
            })
        {
            return Err(INVALID);
        }
        Ok(manifest)
    }

    pub(super) fn download_limit(&self, manifest_bytes: usize) -> Result<u64, &'static str> {
        // The server writes a stored ZIP. Budget two 512-byte headers per entry plus the ZIP64 end.
        let overhead =
            (self.counts.exported as u64 * 2 + self.files.len() as u64 + 1) * 1024 + 1024;
        let document_bytes = self.files.values().map(|file| file.bytes).sum::<u64>();
        let payload = self
            .counts
            .bytes
            .checked_add(document_bytes)
            .and_then(|size| size.checked_add(manifest_bytes as u64))
            .filter(|&size| size <= MAX_PACKAGE)
            .ok_or(INVALID)?;
        Ok(payload + overhead)
    }

    pub(super) fn item_count(&self) -> usize {
        self.counts.exported
    }
}

fn valid_hash(hash: &str) -> bool {
    hash.len() == 64
        && hash
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn read_at<const N: usize>(
    reader: &mut (impl Read + Seek),
    at: u64,
) -> Result<[u8; N], &'static str> {
    let mut bytes = [0; N];
    reader.seek(SeekFrom::Start(at)).map_err(|_| INVALID)?;
    reader.read_exact(&mut bytes).map_err(|_| INVALID)?;
    Ok(bytes)
}

fn bounded_directory(
    reader: &mut (impl Read + Seek),
    expected_entries: usize,
) -> Result<u64, &'static str> {
    // The server's archive has no comment. Bound directory allocation before the ZIP reader runs.
    let end = reader.seek(SeekFrom::End(0)).map_err(|_| INVALID)?;
    let tail = end.checked_sub(22).ok_or(INVALID)?;
    let footer = read_at::<22>(reader, tail)?;
    if &footer[..8] != b"PK\x05\x06\0\0\0\0" || footer[20..] != [0, 0] {
        return Err(INVALID);
    }
    let u16_at = |offset| u16::from_le_bytes(footer[offset..offset + 2].try_into().unwrap());
    let u32_at = |offset| u32::from_le_bytes(footer[offset..offset + 4].try_into().unwrap());
    let count = u16_at(10);
    if count != u16_at(8) {
        return Err(INVALID);
    }
    let (count, size, start, directory_end) =
        if count == u16::MAX || u32_at(12) == u32::MAX || u32_at(16) == u32::MAX {
            let locator_at = tail.checked_sub(20).ok_or(INVALID)?;
            let locator = read_at::<20>(reader, locator_at)?;
            if &locator[..8] != b"PK\x06\x07\0\0\0\0" || locator[16..] != [1, 0, 0, 0] {
                return Err(INVALID);
            }
            let zip64_at = u64::from_le_bytes(locator[8..16].try_into().unwrap());
            if zip64_at.checked_add(56) != Some(locator_at) {
                return Err(INVALID);
            }
            let zip64 = read_at::<56>(reader, zip64_at)?;
            let u64_at = |offset| u64::from_le_bytes(zip64[offset..offset + 8].try_into().unwrap());
            if &zip64[..4] != b"PK\x06\x06"
                || u64_at(4) != 44
                || zip64[16..24] != [0; 8]
                || u64_at(24) != u64_at(32)
            {
                return Err(INVALID);
            }
            (u64_at(32), u64_at(40), u64_at(48), zip64_at)
        } else {
            (
                u64::from(count),
                u64::from(u32_at(12)),
                u64::from(u32_at(16)),
                tail,
            )
        };
    if count > expected_entries as u64
        || size > MAX_DIRECTORY
        || start.checked_add(size) != Some(directory_end)
    {
        return Err(INVALID);
    }
    Ok(start)
}

fn stored_entry<'a, R: Read + Seek>(
    archive: &'a mut ZipArchive<R>,
    name: &str,
    size: u64,
) -> Result<zip::read::ZipFile<'a, R>, &'static str> {
    let index = archive.index_for_name_raw(name.as_bytes()).ok_or(INVALID)?;
    let file = archive.by_index(index).map_err(|_| INVALID)?;
    if !file.is_file()
        || file
            .unix_mode()
            .is_some_and(|mode| !matches!(mode & 0o170000, 0 | 0o100000))
        || file.compression() != CompressionMethod::Stored
        || file.size() != size
        || file.compressed_size() != size
    {
        return Err(INVALID);
    }
    Ok(file)
}

fn check_file<R: Read + Seek>(
    archive: &mut ZipArchive<R>,
    name: &str,
    digest: &FileDigest,
    check: &impl Fn() -> Result<(), &'static str>,
) -> Result<(), &'static str> {
    let mut file = stored_entry(archive, name, digest.bytes)?;
    let mut sha = Sha256::new();
    let mut bytes = 0;
    let mut buffer = [0_u8; 128 * 1024];
    loop {
        check()?;
        let read = file.read(&mut buffer).map_err(|_| INVALID)?;
        if read == 0 {
            break;
        }
        sha.update(&buffer[..read]);
        bytes += read as u64;
    }
    if bytes != digest.bytes || format!("{:x}", sha.finalize()) != digest.sha256 {
        return Err(INVALID);
    }
    Ok(())
}

pub(super) fn verify(
    mut reader: impl Read + Seek,
    manifest: &Manifest,
    authoritative: &[u8],
    check: impl Fn() -> Result<(), &'static str>,
) -> Result<(), &'static str> {
    check()?;
    let entry_limit = manifest.counts.exported * 2 + manifest.files.len() + 1;
    let expected_start = bounded_directory(&mut reader, entry_limit)?;
    let mut archive = ZipArchive::with_config(
        zip::read::Config {
            archive_offset: zip::read::ArchiveOffset::Known(0),
        },
        reader,
    )
    .map_err(|_| INVALID)?;
    if archive.central_directory_start() != expected_start
        || archive.len() > entry_limit
        || archive.validate_header_consistency().is_err()
    {
        return Err(INVALID);
    }
    let mut archived_manifest = Vec::with_capacity(authoritative.len());
    stored_entry(&mut archive, MANIFEST, authoritative.len() as u64)?
        .read_to_end(&mut archived_manifest)
        .map_err(|_| INVALID)?;
    if archived_manifest != authoritative {
        return Err(INVALID);
    }
    for (path, digest) in &manifest.files {
        check_file(&mut archive, path, digest, &check)?;
    }
    let index = &manifest.files[INDEX];
    let mut reader = BufReader::new(stored_entry(&mut archive, INDEX, index.bytes)?);
    let mut seen = BTreeSet::new();
    let mut expected = BTreeMap::new();
    let mut total = 0_u64;
    let mut line = Vec::new();
    loop {
        check()?;
        line.clear();
        let length = reader
            .by_ref()
            .take(MAX_LINE + 1)
            .read_until(b'\n', &mut line)
            .map_err(|_| INVALID)?;
        if length == 0 {
            break;
        }
        if length as u64 > MAX_LINE || seen.len() >= manifest.counts.exported {
            return Err(INVALID);
        }
        let item: Item = serde_json::from_slice(&line).map_err(|_| INVALID)?;
        let original = format!("originals/{}", item.source_asset_id);
        let suffix = item.original.path.strip_prefix(&original).ok_or(INVALID)?;
        if item.locked
            || item.source_asset_id.is_nil()
            || !seen.insert(item.source_asset_id)
            || (!suffix.is_empty()
                && !suffix.strip_prefix('.').is_some_and(|ext| {
                    (1..=12).contains(&ext.len())
                        && ext
                            .bytes()
                            .all(|b| b.is_ascii_digit() || b.is_ascii_lowercase())
                }))
            || item.metadata.as_ref().is_some_and(|file| {
                file.path != format!("metadata/{}.json", item.source_asset_id)
                    || file.digest.bytes > MAX_SIDECAR
            })
        {
            return Err(INVALID);
        }
        for file in std::iter::once(item.original).chain(item.metadata) {
            total = total.checked_add(file.digest.bytes).ok_or(INVALID)?;
            if total > manifest.counts.bytes
                || !valid_hash(&file.digest.sha256)
                || expected.insert(file.path, file.digest).is_some()
            {
                return Err(INVALID);
            }
        }
    }
    drop(reader);
    if seen.len() != manifest.counts.exported
        || total != manifest.counts.bytes
        || archive.len() != expected.len() + manifest.files.len() + 1
    {
        return Err(INVALID);
    }
    for (name, digest) in expected {
        check_file(&mut archive, &name, &digest, &check)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::io::{Cursor, Write};
    use zip::write::SimpleFileOptions;

    const PACKAGE: &str = "018f3efc-ab8d-71bf-8c88-e7e21c81670c";
    const ORIGINAL: &str = "originals/aa000000-0000-4000-8000-000000000001.mov";
    const METADATA: &str = "metadata/aa000000-0000-4000-8000-000000000001.json";

    fn digest(bytes: &[u8]) -> serde_json::Value {
        json!({"bytes": bytes.len(), "sha256": format!("{:x}", Sha256::digest(bytes))})
    }

    fn fixture(original: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let item = json!({
            "sourceAssetId": "aa000000-0000-4000-8000-000000000001",
            "locked": false,
            "original": {"path": ORIGINAL, "bytes": original.len(), "sha256": digest(original)["sha256"]},
            "metadata": {"path": METADATA, "bytes": 2, "sha256": digest(b"{}")["sha256"]},
        });
        let index = format!("{item}\n").into_bytes();
        let manifest = serde_json::to_vec(&json!({
            "format": "frameleaf-preservation-package",
            "schemaVersion": 2,
            "packageId": PACKAGE,
            "complete": true,
            "scope": {"includeLocked": false},
            "counts": {"exported": 1, "bytes": original.len() + 2},
            "files": {"assets.jsonl": digest(&index)},
        }))
        .unwrap();
        (manifest, index)
    }

    fn archive(entries: &[(&str, &[u8])]) -> Cursor<Vec<u8>> {
        let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
        for (name, bytes) in entries {
            writer
                .start_file(
                    *name,
                    SimpleFileOptions::default().compression_method(CompressionMethod::Stored),
                )
                .unwrap();
            writer.write_all(bytes).unwrap();
        }
        writer.finish().unwrap()
    }

    #[test]
    fn only_the_authoritative_manifest_and_exact_named_originals_and_sidecars_verify() {
        let original = b"video bytes";
        let (manifest, index) = fixture(original);
        let parsed = Manifest::parse(&manifest, PACKAGE.parse().unwrap()).unwrap();
        let entries = [
            (MANIFEST, manifest.as_slice()),
            (INDEX, index.as_slice()),
            (ORIGINAL, original.as_slice()),
            (METADATA, b"{}"),
        ];
        assert_eq!(
            verify(archive(&entries), &parsed, &manifest, || Ok(())),
            Ok(())
        );
        assert!(
            parsed.download_limit(manifest.len()).unwrap()
                > archive(&entries).get_ref().len() as u64
        );
        let mut changed = entries;
        changed[2].1 = b"other bytes";
        assert_eq!(
            verify(archive(&changed), &parsed, &manifest, || Ok(())),
            Err(INVALID)
        );
        let mut changed = entries;
        changed[3].1 = b"[]";
        assert_eq!(
            verify(archive(&changed), &parsed, &manifest, || Ok(())),
            Err(INVALID)
        );
        assert_eq!(
            verify(archive(&entries[..3]), &parsed, &manifest, || Ok(())),
            Err(INVALID)
        );
        let mut unexpected = entries.to_vec();
        unexpected.push(("../outside", b""));
        assert_eq!(
            verify(archive(&unexpected), &parsed, &manifest, || Ok(())),
            Err(INVALID)
        );
        let foreign = fixture(b"other bytes").0;
        let mut changed = entries;
        changed[0].1 = &foreign;
        assert_eq!(
            verify(archive(&changed), &parsed, &manifest, || Ok(())),
            Err(INVALID)
        );
        assert_eq!(
            verify(archive(&entries), &parsed, &manifest, || Err("cancelled")),
            Err("cancelled")
        );
    }
}
