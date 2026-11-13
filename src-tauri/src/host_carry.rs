//! Carrying a library across companion packages whose database builds differ.
//!
//! One export run of the package the library last ran with, a restore of that export into a
//! fresh directory by the current package, then one journal write that selects the new package
//! and the new directory together. Until that write nothing of the library has changed. The
//! original database directory is only ever opened by its own Postgres, read-only, and is
//! never moved, rewritten or removed here; photo files are not touched at all.
//!
//! Every answer built on evidence that can be missing or unreadable has three values, and the
//! one that is neither yes nor no refuses: nothing starts, nothing is selected, nothing is
//! removed.
#![cfg_attr(not(any(target_os = "macos", target_os = "linux")), allow(dead_code))]
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    io::{Read, Write},
    path::Path,
};

/// What a package's Manager must declare before a library is carried to it: after the move the
/// library's existing backups come from the previous package, and only such a Manager restores
/// them.
pub(crate) const CAPABILITY: &str = "cross-package-restore";
/// How long after the move the previous database directory is described as kept for going
/// back. Nothing here removes it when that passes.
pub(crate) const RETENTION_SECONDS: u64 = 30 * 24 * 60 * 60;
const RECORD: &str = "desktop-carry-forward.json";
/// Room needed beyond the size of the database directory: for the export, and for the new
/// directory's write-ahead log while it is filled.
const EXPORT_MARGIN: u64 = 256 << 20;
const RESTORE_MARGIN: u64 = 1536 << 20;

fn version(text: &str) -> bool {
    !text.is_empty()
        && text.len() <= 32
        && text.starts_with(|first: char| first.is_ascii_digit())
        && text
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'.')
}

/// A package as a permit names it: its signed manifest and the database build it carries.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct PackageIdentity {
    pub manifest_sha256: String,
    pub postgres_version: String,
    pub pgvector_version: String,
}
impl PackageIdentity {
    fn valid(&self) -> bool {
        crate::native_runtime::digest_valid(&self.manifest_sha256, 64)
            && version(&self.postgres_version)
            && version(&self.pgvector_version)
    }
}

/// How far a carry-forward has come. It only ever moves forward.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Stage {
    /// The previous package may be run for its one export. Runs that fail leave this as it is.
    Permitted,
    /// A verified export exists. The permit is used: the previous package is not run again.
    Exported,
    /// The new package restored the export into a fresh directory and proved it.
    Restored,
    /// The journal names the new package and the new directory.
    Switched,
    /// The person confirmed the library works after the move.
    Confirmed,
}

/// The permit to run a library's previous package once more, for an export and nothing else,
/// and the record of what came of it. It is written before the run it permits, and is bound
/// to one library, one previous package and one set of current pins.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Permit {
    schema_version: u32,
    pub permit_id: String,
    pub library_id: String,
    pub previous: PackageIdentity,
    pub target: PackageIdentity,
    pub stage: Stage,
    /// Export runs started under this permit. Any number may fail; exactly one completes.
    pub export_runs: u32,
    pub export_sha256: Option<String>,
    pub attempt_id: Option<String>,
    pub created_at: u64,
    pub switched_at: Option<u64>,
}
impl Permit {
    fn new(
        library_id: &str,
        previous: &PackageIdentity,
        target: &PackageIdentity,
        now: u64,
    ) -> Self {
        Self {
            schema_version: 1,
            permit_id: uuid::Uuid::new_v4().to_string(),
            library_id: library_id.into(),
            previous: previous.clone(),
            target: target.clone(),
            stage: Stage::Permitted,
            export_runs: 0,
            export_sha256: None,
            attempt_id: None,
            created_at: now,
            switched_at: None,
        }
    }
    fn valid(&self) -> bool {
        self.schema_version == 1
            && crate::host_runtime::checkpoint_operation_id(&self.permit_id)
            && crate::native_runtime::digest_valid(&self.library_id, 12)
            && self.previous.valid()
            && self.target.valid()
            && self.previous.manifest_sha256 != self.target.manifest_sha256
            && self.export_runs <= 1_000_000
            // What each stage has proven is recorded with it.
            && (self.stage >= Stage::Exported)
                == self
                    .export_sha256
                    .as_deref()
                    .is_some_and(|value| crate::native_runtime::digest_valid(value, 64))
            && self.export_sha256.is_some() == (self.stage >= Stage::Exported)
            && (self.stage >= Stage::Restored)
                == self
                    .attempt_id
                    .as_deref()
                    .is_some_and(crate::host_runtime::checkpoint_operation_id)
            && self.attempt_id.is_some() == (self.stage >= Stage::Restored)
            && self.switched_at.is_some() == (self.stage >= Stage::Switched)
    }
    /// Until when the previous database directory is described as kept.
    pub(crate) fn keep_until(&self) -> Option<u64> {
        self.switched_at
            .map(|at| at.saturating_add(RETENTION_SECONDS))
    }
    /// Record that an export run is about to start. Refused once an export exists.
    pub(crate) fn begin_export(&mut self) -> Result<(), String> {
        if self.stage != Stage::Permitted {
            return Err("host_carry_permit_used".into());
        }
        self.export_runs += 1;
        Ok(())
    }
    pub(crate) fn exported(&mut self, export_sha256: String) -> Result<(), String> {
        if self.stage != Stage::Permitted {
            return Err("host_carry_permit_used".into());
        }
        self.export_sha256 = Some(export_sha256);
        self.stage = Stage::Exported;
        self.checked()
    }
    pub(crate) fn restored(&mut self, attempt_id: String) -> Result<(), String> {
        if self.stage != Stage::Exported {
            return Err("host_carry_permit_mismatch".into());
        }
        self.attempt_id = Some(attempt_id);
        self.stage = Stage::Restored;
        self.checked()
    }
    pub(crate) fn switched(&mut self, now: u64) -> Result<(), String> {
        if self.stage != Stage::Restored {
            return Err("host_carry_permit_mismatch".into());
        }
        self.switched_at = Some(now);
        self.stage = Stage::Switched;
        self.checked()
    }
    pub(crate) fn confirmed(&mut self) -> Result<(), String> {
        if self.stage != Stage::Switched {
            return Err("host_carry_permit_mismatch".into());
        }
        self.stage = Stage::Confirmed;
        self.checked()
    }
    fn checked(&self) -> Result<(), String> {
        if self.valid() {
            Ok(())
        } else {
            Err("host_carry_permit_mismatch".into())
        }
    }
}

/// What the record says. One that cannot be read is its own answer and is never taken for
/// "no permit": that would allow a second export run.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Stored {
    Absent,
    Present(Box<Permit>),
    Unreadable,
}
/// Read the permit kept in Manager's data directory.
pub(crate) fn stored(data: &Path) -> Stored {
    let Ok(directory) = crate::host_storage::directory(data) else {
        return Stored::Unreadable;
    };
    let directory = cap_std::fs::Dir::from_std_file(directory);
    let file = match directory.open_with(RECORD, &crate::host_state::options(false)) {
        Ok(file) => file.into_std(),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Stored::Absent,
        Err(_) => return Stored::Unreadable,
    };
    let mut bytes = Vec::new();
    if crate::host_state::valid_file(&file).is_err()
        || file.take(4097).read_to_end(&mut bytes).is_err()
        || bytes.len() > 4096
    {
        return Stored::Unreadable;
    }
    match serde_json::from_slice::<Permit>(&bytes) {
        Ok(permit) if permit.valid() => Stored::Present(Box::new(permit)),
        _ => Stored::Unreadable,
    }
}
/// Replace the permit in one step and make it durable before returning.
pub(crate) fn save(data: &Path, permit: &Permit) -> Result<(), String> {
    const TEMPORARY: &str = ".desktop-carry-forward.json.tmp";
    let failed = |_: std::io::Error| "host_carry_permit_unavailable".to_string();
    if !permit.valid() {
        return Err("host_carry_permit_unavailable".into());
    }
    let bytes = serde_json::to_vec(permit).map_err(|_| "host_carry_permit_unavailable")?;
    if bytes.len() > 4096 {
        return Err("host_carry_permit_unavailable".into());
    }
    let directory = cap_std::fs::Dir::from_std_file(
        crate::host_storage::directory(data).map_err(|_| "host_carry_permit_unavailable")?,
    );
    match directory.remove_file(TEMPORARY) {
        Err(error) if error.kind() != std::io::ErrorKind::NotFound => return Err(failed(error)),
        _ => {}
    }
    let mut options = crate::host_state::options(true);
    options.create_new(true);
    let mut file = directory
        .open_with(TEMPORARY, &options)
        .map_err(failed)?
        .into_std();
    file.write_all(&bytes)
        .and_then(|_| file.sync_all())
        .map_err(failed)?;
    drop(file);
    directory
        .rename(TEMPORARY, &directory, RECORD)
        .map_err(failed)?;
    #[cfg(unix)]
    crate::host_storage::directory(data)
        .map_err(|_| "host_carry_permit_unavailable".to_string())?
        .sync_all()
        .map_err(failed)?;
    if stored(data) != Stored::Present(Box::new(permit.clone())) {
        return Err("host_carry_permit_unavailable".into());
    }
    Ok(())
}

/// The permit for carrying this library from `previous` to `target`: the one on disk when it
/// is for exactly that, a new one when there is none or the one on disk was never used or has
/// finished. A permit under which an export exists for some other move refuses.
pub(crate) fn permit_for(
    found: Stored,
    library_id: &str,
    previous: &PackageIdentity,
    target: &PackageIdentity,
    now: u64,
) -> Result<Permit, String> {
    let fresh = || {
        let permit = Permit::new(library_id, previous, target, now);
        permit.checked().map(|()| permit)
    };
    match found {
        Stored::Unreadable => Err("host_carry_permit_unreadable".into()),
        Stored::Absent => fresh(),
        Stored::Present(permit) if permit.library_id != library_id => {
            Err("host_carry_permit_mismatch".into())
        }
        Stored::Present(permit) if permit.previous == *previous && permit.target == *target => {
            Ok(*permit)
        }
        // An earlier move that finished where this one starts, or a permit that never produced
        // an export, binds nothing any more.
        Stored::Present(permit)
            if permit.stage == Stage::Permitted
                || (permit.stage >= Stage::Switched
                    && permit.target.manifest_sha256 == previous.manifest_sha256) =>
        {
            fresh()
        }
        Stored::Present(_) => Err("host_carry_permit_mismatch".into()),
    }
}

/// Whether there is room. Room that cannot be measured is not room.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Room {
    Enough,
    Short,
    Unknown,
}
/// What is still to be written for a database directory of this size.
pub(crate) fn required_bytes(database_bytes: u64, stage: Stage) -> u64 {
    match stage {
        // The export, then a second directory about the size of the first.
        Stage::Permitted => database_bytes
            .saturating_mul(2)
            .saturating_add(EXPORT_MARGIN + RESTORE_MARGIN),
        Stage::Exported => database_bytes.saturating_add(RESTORE_MARGIN),
        Stage::Restored | Stage::Switched | Stage::Confirmed => 0,
    }
}
pub(crate) fn room(required: Result<u64, String>, available: Result<u64, String>) -> Room {
    match (required, available) {
        (Ok(required), Ok(available)) if available >= required => Room::Enough,
        (Ok(_), Ok(_)) => Room::Short,
        _ => Room::Unknown,
    }
}
/// The bytes under a directory. Anything that cannot be read makes the answer unknown.
pub(crate) fn directory_bytes(path: &Path) -> Result<u64, String> {
    let unknown = || "host_carry_space_unknown".to_string();
    let (mut bytes, mut entries, mut pending) = (0u64, 0u32, vec![path.to_path_buf()]);
    while let Some(current) = pending.pop() {
        let metadata = std::fs::symlink_metadata(&current).map_err(|_| unknown())?;
        entries += 1;
        if entries > 2_000_000 {
            return Err(unknown());
        }
        if metadata.is_dir() {
            for entry in std::fs::read_dir(&current).map_err(|_| unknown())? {
                pending.push(entry.map_err(|_| unknown())?.path());
            }
        } else {
            bytes = bytes.checked_add(metadata.len()).ok_or_else(unknown)?;
        }
    }
    Ok(bytes)
}

/// What the host agent is told for the export run.
pub(crate) fn export_request(permit: &Permit) -> serde_json::Value {
    serde_json::json!({"permitId": permit.permit_id, "libraryId": permit.library_id, "target": {
        "manifestSha256": permit.target.manifest_sha256, "postgresVersion": permit.target.postgres_version,
        "vectorVersion": permit.target.pgvector_version}})
}
/// What the host agent is told for the restore.
pub(crate) fn restore_request(
    permit: &Permit,
    source_revision: &str,
    source_major: &str,
) -> serde_json::Value {
    serde_json::json!({"permitId": permit.permit_id, "libraryId": permit.library_id, "source": {
        "manifestSha256": permit.previous.manifest_sha256, "sourceRevision": source_revision,
        "postgresMajor": source_major}})
}

fn record(
    state: &Path,
    permit: &Permit,
    name: &str,
) -> Result<Option<(serde_json::Value, String)>, String> {
    let invalid = || "host_carry_record_invalid".to_string();
    let mut directory = cap_std::fs::Dir::from_std_file(
        crate::host_storage::directory(state).map_err(|_| invalid())?,
    );
    for part in ["carry-forward", permit.permit_id.as_str()] {
        match directory.symlink_metadata(part) {
            Ok(metadata) if metadata.is_dir() => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            _ => return Err(invalid()),
        }
        directory = directory.open_dir(part).map_err(|_| invalid())?;
    }
    let file = match directory.open_with(name, &crate::host_state::options(false)) {
        Ok(file) => file.into_std(),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(invalid()),
    };
    const LIMIT: u64 = 1024 * 1024;
    let metadata = file.metadata().map_err(|_| invalid())?;
    let mut bytes = Vec::new();
    if !metadata.is_file()
        || metadata.len() > LIMIT
        || file.take(LIMIT + 1).read_to_end(&mut bytes).is_err()
        || bytes.len() as u64 > LIMIT
    {
        return Err(invalid());
    }
    let value = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
    Ok(Some((value, format!("{:x}", Sha256::digest(&bytes)))))
}
/// The export the agent recorded for this permit: its digest, or `None` when there is none.
/// The agent has already checked the dump against the record; this checks that the record is
/// for this permit, this library and these two packages.
pub(crate) fn read_export(state: &Path, permit: &Permit) -> Result<Option<String>, String> {
    let Some((value, digest)) = record(state, permit, "export.json")? else {
        return Ok(None);
    };
    let text = |pointer: &str| value.pointer(pointer).and_then(serde_json::Value::as_str);
    let is = |pointer: &str, expected: &str| text(pointer) == Some(expected);
    let major = permit
        .previous
        .postgres_version
        .get(..2)
        .filter(|major| major.bytes().all(|byte| byte.is_ascii_digit()));
    if value["schemaVersion"] != 1
        || !is("/permitId", &permit.permit_id)
        || !is("/libraryId", &permit.library_id)
        || !is("/source/manifestSha256", &permit.previous.manifest_sha256)
        || !is("/source/vectorVersion", &permit.previous.pgvector_version)
        || major.is_none()
        || text("/source/postgresMajor") != major
        || !is("/target/manifestSha256", &permit.target.manifest_sha256)
        || !is("/target/postgresVersion", &permit.target.postgres_version)
        || !is("/target/vectorVersion", &permit.target.pgvector_version)
        || !is("/checkpoint/operationId", &permit.permit_id)
        || value["tables"].as_array().is_none_or(Vec::is_empty)
    {
        return Err("host_carry_export_invalid".into());
    }
    Ok(Some(digest))
}
/// What a finished restore proved, as far as the person is told.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Restored {
    pub attempt_id: String,
    pub tables: u64,
    pub rows: u64,
    #[serde(skip)]
    identities: [String; 3],
}
/// The restore the agent recorded for this permit, or `None` when there is none. Every proof
/// must be present and true; the directory itself is checked by `reference`.
pub(crate) fn read_restore(state: &Path, permit: &Permit) -> Result<Option<Restored>, String> {
    let Some((value, _)) = record(state, permit, "restore.json")? else {
        return Ok(None);
    };
    let invalid = || "host_carry_target_invalid".to_string();
    let text = |pointer: &str| value.pointer(pointer).and_then(serde_json::Value::as_str);
    let proven = |name: &str| value["validation"][name] == true;
    let major = permit
        .target
        .postgres_version
        .get(..2)
        .and_then(|major| major.parse::<u64>().ok());
    if value["schemaVersion"] != 1
        || value["state"] != "carry-restored"
        || text("/permitId") != Some(permit.permit_id.as_str())
        || text("/exportSha256") != permit.export_sha256.as_deref()
        || permit.export_sha256.is_none()
        || major.is_none()
        || value["validation"]["postgresMajor"].as_u64() != major
        || text("/validation/vectorVersion") != Some(permit.target.pgvector_version.as_str())
        || ![
            "canonical",
            "executionStateReconstructed",
            "offlineChecksums",
            "schemaValidated",
        ]
        .into_iter()
        .all(proven)
    {
        return Err(invalid());
    }
    let attempt_id = text("/attemptId")
        .filter(|id| crate::host_runtime::checkpoint_operation_id(id))
        .ok_or_else(invalid)?;
    let identity = |pointer: &str| text(pointer).map(str::to_owned).ok_or_else(invalid);
    Ok(Some(Restored {
        attempt_id: attempt_id.into(),
        tables: value["validation"]["tables"].as_u64().ok_or_else(invalid)?,
        rows: value["validation"]["rows"].as_u64().ok_or_else(invalid)?,
        identities: [
            identity("/profileIdentity")?,
            identity("/targetIdentity")?,
            identity("/databaseIdentity")?,
        ],
    }))
}
impl Restored {
    /// The restored directory as the journal will name it: it must exist where the receipt
    /// says, be the very directories the agent proved, and hold no running database.
    pub(crate) fn reference(
        &self,
        state: &Path,
        permit: &Permit,
    ) -> Result<crate::host_database::Reference, String> {
        let invalid = |_| "host_carry_target_invalid".to_string();
        let reference =
            crate::host_database::Reference::capture(state, &permit.permit_id, &self.attempt_id)
                .map_err(invalid)?;
        if !reference.matches_node_identities([
            &self.identities[0],
            &self.identities[1],
            &self.identities[2],
        ]) {
            return Err("host_carry_target_invalid".into());
        }
        Ok(reference)
    }
}

/// The step the host agent last said it was in, for display only. Anything else says nothing.
pub(crate) fn step(state: &Path, permit: &Permit) -> Option<&'static str> {
    let mut text = String::new();
    std::fs::File::open(
        state
            .join("carry-forward")
            .join(&permit.permit_id)
            .join("progress"),
    )
    .ok()?
    .take(32)
    .read_to_string(&mut text)
    .ok()?;
    ["export", "restore", "verify"]
        .into_iter()
        .find(|name| *name == text.trim())
}

/// The reason the host agent gave for stopping, when it is one of the carry-forward codes.
pub(crate) fn agent_refusal(state: &Path) -> Option<String> {
    use std::io::{Seek, SeekFrom};
    let mut log = std::fs::File::open(state.join("agent.log")).ok()?;
    let length = log.metadata().ok()?.len();
    log.seek(SeekFrom::Start(length.saturating_sub(4096)))
        .ok()?;
    let mut tail = String::new();
    log.take(4096).read_to_string(&mut tail).ok()?;
    let last = tail.lines().rev().find(|line| !line.trim().is_empty())?;
    (last.starts_with("host_carry_")
        && last.len() <= 80
        && last
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte == b'_'))
    .then(|| last.to_owned())
}

/// Wait for one carry-forward step of the host agent and stop it. The agent does all of its
/// work before it reports ready, so ready is the step's success.
#[cfg(unix)]
pub(crate) fn run_step(
    mut process: crate::host_runtime::HostProcess,
    cancel: &std::sync::atomic::AtomicBool,
    state: &Path,
) -> Result<(), String> {
    // Longer than the agent's own two-hour limits for a dump and a restore together.
    match process.wait_ready_or_cancel(std::time::Duration::from_secs(5 * 60 * 60), cancel) {
        Ok(true) => process.stop(),
        Ok(false) => Err("host_carry_cancelled".into()),
        Err(error) => {
            let _ = process.stop();
            Err(agent_refusal(state).unwrap_or(error))
        }
    }
}

/// A plain note beside the carry-forward records naming the directory that is no longer used.
pub(crate) fn label_previous(state: &Path, permit: &Permit, database: &Path) {
    let text = format!(
        "Frameleaf moved this library to a new database folder on {} (seconds since 1970).\n\n\
         The folder below is the library's database as Postgres {} left it. Frameleaf no longer\n\
         uses it and has not changed it. It is kept so the move can be undone, and Frameleaf does\n\
         not delete it.\n\n{}\n",
        permit.switched_at.unwrap_or_default(),
        permit.previous.postgres_version,
        database.display()
    );
    let path = state
        .join("carry-forward")
        .join(&permit.permit_id)
        .join("PREVIOUS-DATABASE.txt");
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    if let Ok(mut file) = options.open(path) {
        let _ = file
            .write_all(text.as_bytes())
            .and_then(|()| file.sync_all());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn package(digit: &str, postgres: &str) -> PackageIdentity {
        PackageIdentity {
            manifest_sha256: digit.repeat(64),
            postgres_version: postgres.into(),
            pgvector_version: "0.8.7".into(),
        }
    }
    const LIBRARY: &str = "cccccccccccc";
    fn directory() -> std::path::PathBuf {
        let root = std::env::temp_dir()
            .canonicalize()
            .unwrap()
            .join(format!("frameleaf-carry-{}", uuid::Uuid::new_v4()));
        crate::runtime_store::private_directory(&root).unwrap();
        root
    }

    #[test]
    fn a_permit_is_durable_before_its_run_and_is_used_by_exactly_one_export() {
        let data = directory();
        let (previous, target) = (package("a", "18.7"), package("b", "19beta4"));
        assert_eq!(stored(&data), Stored::Absent);
        let mut permit = permit_for(stored(&data), LIBRARY, &previous, &target, 100).unwrap();
        assert_eq!((permit.stage, permit.export_runs), (Stage::Permitted, 0));
        // Nothing is on disk until it is saved, and a run is recorded before it starts.
        assert_eq!(stored(&data), Stored::Absent);
        permit.begin_export().unwrap();
        save(&data, &permit).unwrap();
        assert_eq!(stored(&data), Stored::Present(Box::new(permit.clone())));
        // A run that failed or was interrupted leaves the permit usable: the same one comes back.
        let mut again = permit_for(stored(&data), LIBRARY, &previous, &target, 200).unwrap();
        assert_eq!(again.permit_id, permit.permit_id);
        again.begin_export().unwrap();
        assert_eq!(again.export_runs, 2);
        // A completed export uses it: no further run can even be recorded.
        again.exported("d".repeat(64)).unwrap();
        save(&data, &again).unwrap();
        let mut used = permit_for(stored(&data), LIBRARY, &previous, &target, 300).unwrap();
        assert_eq!(used.stage, Stage::Exported);
        assert_eq!(used.begin_export().unwrap_err(), "host_carry_permit_used");
        assert_eq!(
            used.exported("e".repeat(64)).unwrap_err(),
            "host_carry_permit_used"
        );
        std::fs::remove_dir_all(data).unwrap();
    }

    #[test]
    fn a_permit_is_bound_to_its_library_previous_package_and_current_pins() {
        let (previous, target) = (package("a", "18.7"), package("b", "19beta4"));
        let unused = Permit::new(LIBRARY, &previous, &target, 1);
        let mut exported = unused.clone();
        exported.exported("d".repeat(64)).unwrap();
        // Another library's permit is never used or replaced.
        for permit in [unused.clone(), exported.clone()] {
            assert_eq!(
                permit_for(
                    Stored::Present(Box::new(permit)),
                    "dddddddddddd",
                    &previous,
                    &target,
                    2
                )
                .unwrap_err(),
                "host_carry_permit_mismatch"
            );
        }
        // The pins moved again before any export: the unused permit is void and a new one is made.
        let moved = package("f", "19.1");
        let fresh = permit_for(
            Stored::Present(Box::new(unused.clone())),
            LIBRARY,
            &previous,
            &moved,
            2,
        )
        .unwrap();
        assert_ne!(fresh.permit_id, unused.permit_id);
        assert_eq!(
            (fresh.target.clone(), fresh.stage),
            (moved.clone(), Stage::Permitted)
        );
        // With an export taken for other pins or another previous package, nothing proceeds.
        for (from, to) in [(&previous, &moved), (&moved, &target)] {
            assert_eq!(
                permit_for(
                    Stored::Present(Box::new(exported.clone())),
                    LIBRARY,
                    from,
                    to,
                    2
                )
                .unwrap_err(),
                "host_carry_permit_mismatch"
            );
        }
        // A record that cannot be read is never "no permit".
        assert_eq!(
            permit_for(Stored::Unreadable, LIBRARY, &previous, &target, 2).unwrap_err(),
            "host_carry_permit_unreadable"
        );
        // A finished move leaves room for the next one, from where it ended.
        let mut finished = exported.clone();
        finished.restored(uuid::Uuid::new_v4().to_string()).unwrap();
        finished.switched(5).unwrap();
        assert_eq!(finished.keep_until(), Some(5 + RETENTION_SECONDS));
        let next = permit_for(
            Stored::Present(Box::new(finished.clone())),
            LIBRARY,
            &target,
            &moved,
            9,
        )
        .unwrap();
        assert_eq!(
            (next.previous.clone(), next.stage),
            (target.clone(), Stage::Permitted)
        );
        assert_eq!(
            permit_for(
                Stored::Present(Box::new(finished)),
                LIBRARY,
                &previous,
                &moved,
                9
            )
            .unwrap_err(),
            "host_carry_permit_mismatch"
        );
    }

    #[test]
    fn stages_only_move_forward_and_a_record_that_skips_a_proof_is_unreadable() {
        let data = directory();
        let mut permit = Permit::new(LIBRARY, &package("a", "18.7"), &package("b", "19beta4"), 1);
        assert_eq!(
            permit.restored("x".into()).unwrap_err(),
            "host_carry_permit_mismatch"
        );
        assert_eq!(
            permit.switched(1).unwrap_err(),
            "host_carry_permit_mismatch"
        );
        assert_eq!(
            permit.confirmed().unwrap_err(),
            "host_carry_permit_mismatch"
        );
        permit.exported("d".repeat(64)).unwrap();
        assert_eq!(
            permit.switched(1).unwrap_err(),
            "host_carry_permit_mismatch"
        );
        // An attempt that is not an operation identity is not a restore.
        let mut wrong = permit.clone();
        assert_eq!(
            wrong.restored("../x".into()).unwrap_err(),
            "host_carry_permit_mismatch"
        );
        permit.restored(uuid::Uuid::new_v4().to_string()).unwrap();
        permit.switched(7).unwrap();
        permit.confirmed().unwrap();
        save(&data, &permit).unwrap();
        // Hand-edited records: a stage without what proves it, an unknown field, too large.
        let good = serde_json::to_value(&permit).unwrap();
        for change in [
            serde_json::json!({"exportSha256": null}),
            serde_json::json!({"attemptId": null}),
            serde_json::json!({"switchedAt": null}),
            serde_json::json!({"stage": "permitted"}),
            serde_json::json!({"schemaVersion": 2}),
            serde_json::json!({"extra": true}),
            serde_json::json!({"libraryId": "C".repeat(12)}),
        ] {
            let mut value = good.clone();
            value
                .as_object_mut()
                .unwrap()
                .extend(change.as_object().unwrap().clone());
            std::fs::write(data.join(RECORD), serde_json::to_vec(&value).unwrap()).unwrap();
            assert_eq!(stored(&data), Stored::Unreadable, "{change}");
        }
        std::fs::write(data.join(RECORD), vec![b' '; 5000]).unwrap();
        assert_eq!(stored(&data), Stored::Unreadable);
        std::fs::remove_dir_all(data).unwrap();
    }

    #[test]
    fn room_is_enough_short_or_unknown_and_unknown_is_never_enough() {
        const GIB: u64 = 1 << 30;
        assert_eq!(
            required_bytes(10 * GIB, Stage::Permitted),
            20 * GIB + (1792 << 20)
        );
        assert_eq!(
            required_bytes(10 * GIB, Stage::Exported),
            10 * GIB + (1536 << 20)
        );
        assert_eq!(required_bytes(10 * GIB, Stage::Restored), 0);
        assert_eq!(required_bytes(u64::MAX, Stage::Permitted), u64::MAX);
        assert_eq!(room(Ok(5), Ok(5)), Room::Enough);
        assert_eq!(room(Ok(5), Ok(4)), Room::Short);
        assert_eq!(room(Err("x".into()), Ok(u64::MAX)), Room::Unknown);
        assert_eq!(room(Ok(0), Err("x".into())), Room::Unknown);
        let root = directory();
        std::fs::create_dir(root.join("base")).unwrap();
        std::fs::write(root.join("base/1"), [0; 1000]).unwrap();
        std::fs::write(root.join("PG_VERSION"), "19\n").unwrap();
        assert_eq!(directory_bytes(&root), Ok(1003));
        assert_eq!(
            directory_bytes(&root.join("missing")).unwrap_err(),
            "host_carry_space_unknown"
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    fn write_record(state: &Path, permit: &Permit, name: &str, value: &serde_json::Value) {
        let directory = state.join("carry-forward").join(&permit.permit_id);
        for path in [state.join("carry-forward"), directory.clone()] {
            if !path.exists() {
                crate::runtime_store::private_directory(&path).unwrap();
            }
        }
        std::fs::write(directory.join(name), serde_json::to_vec(value).unwrap()).unwrap();
    }

    #[test]
    fn an_export_or_restore_record_counts_only_for_its_own_permit_and_packages() {
        let state = directory();
        let mut permit = Permit::new(LIBRARY, &package("a", "18.7"), &package("b", "19beta4"), 1);
        assert_eq!(read_export(&state, &permit), Ok(None));
        assert_eq!(read_restore(&state, &permit), Ok(None));
        let export = serde_json::json!({"schemaVersion":1,"permitId":permit.permit_id,"libraryId":LIBRARY,
            "source":{"manifestSha256":"a".repeat(64),"sourceRevision":"1".repeat(40),"postgresMajor":"18","postgresVersion":"18.7","vectorVersion":"0.8.7"},
            "target":{"manifestSha256":"b".repeat(64),"postgresVersion":"19beta4","vectorVersion":"0.8.7"},
            "checkpoint":{"operationId":permit.permit_id},"extensions":[],"tables":[{"name":"public.asset","rows":3}],"vectorIndexes":[]});
        write_record(&state, &permit, "export.json", &export);
        let digest = read_export(&state, &permit).unwrap().unwrap();
        assert!(crate::native_runtime::digest_valid(&digest, 64));
        for (pointer, value) in [
            (
                "/permitId",
                serde_json::json!(uuid::Uuid::new_v4().to_string()),
            ),
            ("/libraryId", serde_json::json!("dddddddddddd")),
            ("/source/manifestSha256", serde_json::json!("e".repeat(64))),
            ("/source/postgresMajor", serde_json::json!("17")),
            ("/target/manifestSha256", serde_json::json!("e".repeat(64))),
            ("/target/postgresVersion", serde_json::json!("19.1")),
            (
                "/checkpoint/operationId",
                serde_json::json!(uuid::Uuid::new_v4().to_string()),
            ),
            ("/tables", serde_json::json!([])),
            ("/schemaVersion", serde_json::json!(2)),
        ] {
            let mut changed = export.clone();
            *changed.pointer_mut(pointer).unwrap() = value;
            write_record(&state, &permit, "export.json", &changed);
            assert_eq!(
                read_export(&state, &permit).unwrap_err(),
                "host_carry_export_invalid",
                "{pointer}"
            );
        }
        std::fs::write(
            state
                .join("carry-forward")
                .join(&permit.permit_id)
                .join("export.json"),
            "{",
        )
        .unwrap();
        assert_eq!(
            read_export(&state, &permit).unwrap_err(),
            "host_carry_record_invalid"
        );

        let restore = serde_json::json!({"schemaVersion":1,"state":"carry-restored","permitId":permit.permit_id,
            "attemptId":uuid::Uuid::new_v4().to_string(),"profileIdentity":"1:2","targetIdentity":"1:3","databaseIdentity":"1:4",
            "exportSha256":digest,"validation":{"postgresMajor":19,"vectorVersion":"0.8.7","canonical":true,"executionStateReconstructed":true,
            "tables":1,"rows":3,"vectorIndexes":0,"vectorIndexesSearched":0,"offlineChecksums":true,"schemaValidated":true}});
        write_record(&state, &permit, "restore.json", &restore);
        // No export is recorded on the permit yet, so no restore can belong to it.
        assert_eq!(
            read_restore(&state, &permit).unwrap_err(),
            "host_carry_target_invalid"
        );
        permit.exported(digest.clone()).unwrap();
        let restored = read_restore(&state, &permit).unwrap().unwrap();
        assert_eq!((restored.tables, restored.rows), (1, 3));
        // The directory the receipt names does not exist: nothing can be selected.
        assert_eq!(
            restored.reference(&state, &permit).unwrap_err(),
            "host_carry_target_invalid"
        );
        for (pointer, value) in [
            ("/state", serde_json::json!("carry-restoring")),
            ("/exportSha256", serde_json::json!("f".repeat(64))),
            ("/validation/postgresMajor", serde_json::json!(18)),
            ("/validation/vectorVersion", serde_json::json!("0.8.6")),
            ("/validation/offlineChecksums", serde_json::json!(false)),
            ("/validation/schemaValidated", serde_json::json!(null)),
            ("/validation/canonical", serde_json::json!("true")),
            ("/attemptId", serde_json::json!("../../database")),
            ("/validation/rows", serde_json::json!(-1)),
        ] {
            let mut changed = restore.clone();
            *changed.pointer_mut(pointer).unwrap() = value;
            write_record(&state, &permit, "restore.json", &changed);
            assert_eq!(
                read_restore(&state, &permit).unwrap_err(),
                "host_carry_target_invalid",
                "{pointer}"
            );
        }
        std::fs::remove_dir_all(state).unwrap();
    }

    #[test]
    fn only_a_carry_forward_refusal_on_the_last_line_is_reported_as_the_reason() {
        let state = directory();
        assert_eq!(agent_refusal(&state), None);
        std::fs::write(
            state.join("agent.log"),
            "noise\nhost_carry_space_insufficient\n\n",
        )
        .unwrap();
        assert_eq!(
            agent_refusal(&state).as_deref(),
            Some("host_carry_space_insufficient")
        );
        for log in [
            "host_carry_counts_mismatch\nnative_host_failed\n",
            "host_carry_/etc/passwd\n",
            "host_restore_failed\n",
        ] {
            std::fs::write(state.join("agent.log"), log).unwrap();
            assert_eq!(agent_refusal(&state), None, "{log}");
        }
        let permit = Permit::new(LIBRARY, &package("a", "18.7"), &package("b", "19beta4"), 1);
        assert_eq!(step(&state, &permit), None);
        write_record(&state, &permit, "progress", &serde_json::json!(0));
        for (text, expected) in [
            ("verify", Some("verify")),
            ("restore\n", Some("restore")),
            ("rm -rf", None),
        ] {
            std::fs::write(
                state
                    .join("carry-forward")
                    .join(&permit.permit_id)
                    .join("progress"),
                text,
            )
            .unwrap();
            assert_eq!(step(&state, &permit), expected);
        }
        std::fs::remove_dir_all(state).unwrap();
    }
}
