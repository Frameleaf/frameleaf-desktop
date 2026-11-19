//! `frameleaf-repository` version 1: chunked, deduplicated, encrypted backups, byte for byte the format
//! of `packages/backup-core` in frameleaf-app (see its `FORMAT.md`). A repository written by either engine
//! is read by the other.
//!
//! The engine is synchronous: a caller in async code runs it on a blocking thread.

pub mod backup;
pub mod chunker;
pub mod escrow;
pub mod keys;
pub mod maintenance;
pub mod recovery;
pub mod repository;
pub mod restore;
pub mod s3;
pub mod snapshot_record;
pub mod store;
pub mod tree;

pub use backup::{backup, BackupOptions, BackupProblem, BackupResult, Progress};
pub use chunker::{chunks, cut_point, gear_table, ChunkerParams, DEFAULT_CHUNKER};
pub use keys::{blob_id, derive_keys, RepositoryKeys, FORMAT, VERSION};
pub use maintenance::{
    prune, retain, verify, PruneOptions, PruneReport, RetentionPolicy, VerifyReport,
};
pub use recovery::{parse_recovery_code, recovery_code, server_backup_vault_id};
pub use repository::{Location, Repository, RepositoryConfig, Snapshot, Stats, PACK_TARGET};
pub use restore::{find, list_folder, read_file, restore, RestoreResult};
pub use store::{ByteRange, DirStore, MemoryStore, Store, StoredObject};
pub use tree::{
    filter_source, fs_source, measure_source, mount_source, Entry, EntryType, Source, SourceEntry,
};

use std::fmt;

/// A blob id: HMAC-SHA256 of its plaintext under the repository's `id` key.
pub type Id = [u8; 32];

#[derive(Debug)]
pub enum Error {
    /// The key is wrong, or the stored bytes were changed. AES-GCM cannot tell the two apart.
    Unseal,
    /// A piece a backup needs is not stored.
    MissingBlob(String),
    /// Objects are written once; this name is taken.
    ObjectExists(String),
    /// The run was told to stop. What was stored is kept for the next run.
    Stopped,
    Io(std::io::Error),
    S3 {
        message: String,
        /// None when the provider could not be reached at all.
        status: Option<u16>,
        code: Option<String>,
    },
    Invalid(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Unseal => write!(
                f,
                "Could not open this data: the key is wrong or the data is damaged"
            ),
            Error::MissingBlob(id) => {
                write!(f, "A piece of this backup is missing from storage: {id}")
            }
            Error::ObjectExists(key) => write!(f, "This object is already stored: {key}"),
            Error::Stopped => write!(f, "The backup was stopped"),
            Error::Io(error) => write!(f, "{error}"),
            Error::S3 { message, .. } => write!(f, "{message}"),
            Error::Invalid(message) => write!(f, "{message}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(error: std::io::Error) -> Self {
        Error::Io(error)
    }
}

pub type Result<T> = std::result::Result<T, Error>;

pub(crate) fn invalid(message: impl Into<String>) -> Error {
    Error::Invalid(message.into())
}

/// Parses a 64-character hex blob id. Anything else is not stored, by definition.
pub(crate) fn parse_id(hex_id: &str) -> Result<Id> {
    let mut id = [0u8; 32];
    hex::decode_to_slice(hex_id, &mut id).map_err(|_| Error::MissingBlob(hex_id.to_string()))?;
    Ok(id)
}

/// `Date.prototype.toISOString`: UTC with milliseconds.
pub(crate) fn iso(time: time::OffsetDateTime) -> String {
    let time = time.to_offset(time::UtcOffset::UTC);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
        time.year(),
        u8::from(time.month()),
        time.day(),
        time.hour(),
        time.minute(),
        time.second(),
        time.millisecond()
    )
}
