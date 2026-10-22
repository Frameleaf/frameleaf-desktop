//! Bounded source-copy child messages; credentials and consent remain in the parent.

use serde::{Deserialize, Serialize};
const MAX_ORIGINAL_BYTES: u64 = 2 * 1024 * 1024 * 1024;
const CHUNK_BYTES: u64 = 65_536;
fn valid_cloud_path(path: &[u16]) -> bool {
    path.len() <= 32_768
        && path
            .split_last()
            .is_some_and(|(&last, name)| last == 0 && !name.is_empty() && !name.contains(&0))
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Request {
    version: u8,
    operation_id: String,
    root: String,
    root_identity: String,
    source_stamp: String,
    relative: String,
    staging: String,
    bytes: u64,
}
impl Request {
    fn validate(&self) -> Result<(), String> {
        let valid_path = |value: &str| {
            !value.is_empty() && !value.contains('\0') && value.encode_utf16().count() <= 32_767
        };
        let identity = self.root_identity.split_once(":file-id-v2:");
        let full_identity = identity.is_some_and(|(volume, id)| {
            volume
                .parse::<u64>()
                .is_ok_and(|value| value.to_string() == volume)
                && id.len() == 32
                && id
                    .bytes()
                    .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
                && id.bytes().any(|c| c != b'0')
        });
        let relative = self.relative.replace('\\', "/");
        if self.version != 1
            || self.bytes == 0
            || self.bytes > MAX_ORIGINAL_BYTES
            || !uuid::Uuid::parse_str(&self.operation_id)
                .is_ok_and(|id| !id.is_nil() && id.to_string() == self.operation_id)
            || !full_identity
            || version_metadata(&self.source_stamp, self.bytes).is_none()
            || !valid_path(&self.root)
            || !valid_path(&self.staging)
            || self.staging.replace('\\', "/").rsplit('/').next()
                != Some(self.operation_id.as_str())
            || !valid_path(&self.relative)
            || relative.contains(':')
            || super::relative_path(&relative).is_err()
        {
            return Err("source_child_request_invalid".into());
        }
        Ok(())
    }
}
#[derive(Serialize, Deserialize)]
#[serde(
    tag = "state",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
enum Event {
    Progress {
        operation_id: String,
        bytes: u64,
    },
    Complete {
        operation_id: String,
        bytes: u64,
        sha256: String,
        source_stamp: String,
        created_at_ms: i64,
        modified_at_ms: i64,
    },
    Error {
        operation_id: String,
        code: String,
    },
}
fn version_metadata(stamp: &str, bytes: u64) -> Option<(i64, i64)> {
    let parts: [&str; 6] = stamp.split(':').collect::<Vec<_>>().try_into().ok()?;
    let [version, volume, file_id, length, created, modified] = parts;
    if version != "cloud-file-v1"
        || volume.parse::<u64>().ok()?.to_string() != volume
        || file_id.len() != 32
        || !file_id
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
        || file_id.bytes().all(|c| c == b'0')
        || length != bytes.to_string()
    {
        return None;
    }
    let milliseconds = |ticks: &str| {
        let value = ticks.parse::<i64>().ok()?;
        if value < 0 || value.to_string() != ticks {
            return None;
        }
        i64::try_from((i128::from(value) - 116_444_736_000_000_000) / 10_000).ok()
    };
    Some((milliseconds(created)?, milliseconds(modified)?))
}
#[derive(Debug)]
struct Copied {
    bytes: u64,
    sha256: String,
    source_stamp: String,
    created_at_ms: i64,
    modified_at_ms: i64,
}
struct Progress {
    operation_id: String,
    expected: u64,
    source_stamp: String,
    copied: u64,
    finished: bool,
}
impl Progress {
    fn new(request: &Request) -> Self {
        Self {
            operation_id: request.operation_id.clone(),
            expected: request.bytes,
            source_stamp: request.source_stamp.clone(),
            copied: 0,
            finished: false,
        }
    }
    fn accept(&mut self, event: Event) -> Result<Option<Copied>, String> {
        let operation_id = match &event {
            Event::Progress { operation_id, .. }
            | Event::Complete { operation_id, .. }
            | Event::Error { operation_id, .. } => operation_id,
        };
        if self.finished || operation_id != &self.operation_id {
            return Err("source_copy_interrupted".into());
        }
        match event {
            Event::Progress { bytes, .. } => {
                let next = self.copied + CHUNK_BYTES.min(self.expected - self.copied);
                if bytes != next || bytes <= self.copied {
                    return Err("source_copy_interrupted".into());
                }
                self.copied = bytes;
                Ok(None)
            }
            Event::Complete {
                bytes,
                sha256,
                source_stamp,
                created_at_ms,
                modified_at_ms,
                ..
            } => {
                if bytes != self.expected
                    || self.copied != self.expected
                    || source_stamp != self.source_stamp
                    || sha256.len() != 64
                    || !sha256
                        .bytes()
                        .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
                    || !source_stamp.starts_with("cloud-file-v1:")
                    || source_stamp.len() > 256
                    || source_stamp.chars().any(char::is_control)
                    || version_metadata(&source_stamp, bytes)
                        != Some((created_at_ms, modified_at_ms))
                {
                    return Err("source_copy_interrupted".into());
                }
                self.finished = true;
                Ok(Some(Copied {
                    bytes,
                    sha256,
                    source_stamp,
                    created_at_ms,
                    modified_at_ms,
                }))
            }
            Event::Error { code, .. } => {
                self.finished = true;
                if let Some((api, hresult)) = code.split_once(':') {
                    if api == "source_item_changed"
                        && matches!(
                            hresult,
                            "admission"
                                | "parent-version"
                                | "protected-open"
                                | "oplock"
                                | "oplock-open"
                                | "oplock-first-read"
                                | "oplock-next-read"
                                | "oplock-complete"
                                | "before-read"
                                | "read-length"
                                | "after-read"
                                | "completion"
                                | "borrowed-handle"
                                | "unexpected-eof"
                        )
                    {
                        #[cfg(debug_assertions)]
                        eprintln!("source_reader/version-check:{hresult}");
                        return Err("source_item_changed".into());
                    }
                    if matches!(
                        api,
                        "source_cloud_open_failed" | "source_cloud_hydration_failed"
                    ) && hresult.len() == 8
                        && hresult
                            .bytes()
                            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
                    {
                        #[cfg(debug_assertions)]
                        eprintln!("source_reader/{api}:hresult={hresult}");
                        return Err("source_cloud_provider_unavailable".into());
                    }
                }
                match code.as_str() {
                    "source_item_changed"
                    | "source_root_changed"
                    | "source_item_invalid"
                    | "source_item_excluded"
                    | "source_identity_unavailable"
                    | "source_item_unavailable"
                    | "source_stage_write_failed"
                    | "source_cloud_provider_unavailable"
                    | "source_capacity_unavailable"
                    | "source_capacity_insufficient"
                    | "source_staging_overlap"
                    | "source_copy_budget_exceeded"
                    | "source_stage_invalid"
                    | "source_stage_unavailable" => Err(code),
                    _ => Err("source_copy_interrupted".into()),
                }
            }
        }
    }
}

#[cfg(windows)]
mod parent;
#[cfg(windows)]
mod platform;
#[cfg(windows)]
const MAX_REQUEST_BYTES: usize = 512 * 1024;
#[cfg(windows)]
pub(super) fn enabled() -> bool {
    cfg!(feature = "windows-cloud-copy")
}
#[cfg(windows)]
pub(super) fn approval_root(path: &std::path::Path) -> Result<cap_std::fs::Dir, String> {
    let (mut held, _) = platform::directories(path, true)?;
    held.pop().ok_or_else(|| "source_root_unavailable".into())
}
#[cfg(windows)]
pub(super) fn run_child() -> Result<(), String> {
    use std::io::{Read, Write};
    if !enabled() {
        return Err("source_cloud_copy_pending".into());
    }
    let mut input = Vec::new();
    std::io::stdin()
        .lock()
        .take(MAX_REQUEST_BYTES as u64 + 1)
        .read_to_end(&mut input)
        .map_err(|_| "source_child_request_invalid")?;
    if input.len() > MAX_REQUEST_BYTES {
        return Err("source_child_request_invalid".into());
    }
    let request: Request =
        serde_json::from_slice(&input).map_err(|_| "source_child_request_invalid")?;
    request.validate()?;
    let mut output = std::io::stdout().lock();
    let mut emit = |event: Event| {
        let bytes = serde_json::to_vec(&event).map_err(|_| "source_copy_interrupted")?;
        if bytes.len() >= 4096 {
            return Err("source_copy_interrupted".to_string());
        }
        output
            .write_all(&bytes)
            .and_then(|_| output.write_all(b"\n"))
            .and_then(|_| output.flush())
            .map_err(|_| "source_copy_interrupted".to_string())
    };
    match platform::copy(&request, &mut emit) {
        Ok(copied) => emit(Event::Complete {
            operation_id: request.operation_id,
            bytes: copied.bytes,
            sha256: copied.sha256,
            source_stamp: copied.source_stamp,
            created_at_ms: copied.created_at_ms,
            modified_at_ms: copied.modified_at_ms,
        }),
        Err(code) => {
            let _ = emit(Event::Error {
                operation_id: request.operation_id,
                code: code.clone(),
            });
            Err(code)
        }
    }
}
#[cfg(windows)]
#[allow(clippy::too_many_arguments)]
pub(super) fn stage(
    approval: &super::CopyApproval,
    identity: &crate::connection::DeviceIdentity,
    relative: &str,
    destination: &std::path::Path,
    stage_id: &str,
    expected: Option<u64>,
    cancelled: &std::sync::atomic::AtomicBool,
    gate: &(dyn Fn() -> Result<(), String> + Sync),
) -> Result<Option<super::StagedCopy>, String> {
    use std::io::Read;
    if !enabled() {
        return Ok(None);
    }
    crate::native_runtime::absolute_directory(destination)?;
    let mut source = platform::Source::open(
        &approval.scope.root,
        &approval.scope.root_identity,
        relative,
        expected,
    )?;
    let (destination_dirs, _) = platform::directories(destination, false)?;
    if source.overlaps(&destination_dirs)? {
        return Err("source_staging_overlap".into());
    }
    if !source.cloud {
        return Ok(None);
    }
    if source.version.bytes > approval.scope.max_item_bytes {
        return Err("source_copy_budget_exceeded".into());
    }
    crate::runtime_store::private_directory(destination)?;
    super::cancel(cancelled)?;
    gate()?;
    let path = destination.join(stage_id);
    crate::windows_protection::new_private_directory(&path)?;
    let mut cleanup = super::Partial(Some(path.clone()));
    crate::runtime_store::private_directory(&path)?;
    let (_staging_dirs, _) = platform::directories(&path, false)?;
    let request = Request {
        version: 1,
        operation_id: stage_id.into(),
        root: approval.scope.root.clone(),
        root_identity: approval.scope.root_identity.clone(),
        source_stamp: source.version.stamp(),
        relative: relative.into(),
        staging: path.to_str().ok_or("source_stage_invalid")?.into(),
        bytes: source.version.bytes,
    };
    source.release_leaf();
    let copied = match parent::run(&request, cancelled, gate) {
        Ok(copied) => copied,
        Err(code) => {
            if code == "source_copy_shutdown_unconfirmed" {
                cleanup.0.take();
            }
            return Err(code);
        }
    };
    let root = _staging_dirs.last().ok_or("source_stage_unavailable")?;
    let mut file = root
        .open_with("original", &super::no_follow_options(false))
        .map_err(|_| "source_stage_unavailable")?;
    let meta = file.metadata().map_err(|_| "source_stage_invalid")?;
    if !meta.is_file() || super::link(&meta) || meta.len() != request.bytes {
        return Err("source_stage_invalid".into());
    }
    crate::windows_protection::require_private_directory(&path)?;
    let mut bytes = 0;
    let mut hash = sha2::Sha256::new();
    let mut buffer = [0u8; 65_536];
    let mut next_gate = 0;
    use sha2::Digest;
    loop {
        super::cancel(cancelled)?;
        if bytes >= next_gate {
            gate()?;
            next_gate = bytes + 1024 * 1024;
        }
        let count = file.read(&mut buffer).map_err(|_| "source_stage_invalid")?;
        if count == 0 {
            break;
        }
        bytes += count as u64;
        if bytes > copied.bytes {
            return Err("source_stage_invalid".into());
        }
        hash.update(&buffer[..count]);
    }
    if bytes != copied.bytes || format!("{:x}", hash.finalize()) != copied.sha256 {
        return Err("source_stage_invalid".into());
    }
    super::cancel(cancelled)?;
    gate()?;
    let mut staged = super::StagedCopy {
        id: stage_id.into(),
        bytes,
        sha256: copied.sha256,
        file_created_at_ms: copied.created_at_ms,
        file_modified_at_ms: copied.modified_at_ms,
        source_signature: approval.signature.clone(),
        source_stamp: copied.source_stamp,
        relative: relative.into(),
        approval: approval.clone(),
        signature: String::new(),
    };
    staged.publish(identity, &path)?;
    cleanup.0.take();
    Ok(Some(staged))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cloud_paths_require_one_bounded_terminated_name_before_ffi() {
        assert!(valid_cloud_path(&[67, 58, 92, 26053, 0]));
        for path in [
            vec![],
            vec![0],
            vec![67, 58],
            vec![67, 0, 92, 0],
            vec![67; 32_769],
        ] {
            assert!(!valid_cloud_path(&path));
        }
    }
    fn request() -> Request {
        Request {
            version: 1,
            operation_id: "11111111-1111-4111-8111-111111111111".into(),
            root: r"C:\Users\Example\Selected Photos".into(),
            root_identity: "42:file-id-v2:0102030405060708090a0b0c0d0e0f10".into(),
            source_stamp: "cloud-file-v1:42:0102030405060708090a0b0c0d0e0f10:65553:116444736000010000:116444736000020000".into(),
            relative: "旅行/original.jpg".into(),
            staging: r"C:\Users\Example\Private\11111111-1111-4111-8111-111111111111".into(),
            bytes: 65_553,
        }
    }
    #[test]
    fn child_request_is_finite_and_contains_no_credentials_or_arbitrary_options() {
        let valid = request();
        valid.validate().unwrap();
        let mut raw = serde_json::to_value(&valid).unwrap();
        raw["accessToken"] = serde_json::json!("synthetic");
        assert!(serde_json::from_value::<Request>(raw).is_err());
        for count in [0, MAX_ORIGINAL_BYTES + 1] {
            let mut value = request();
            value.bytes = count;
            assert!(value.validate().is_err());
        }
        for relative in [
            "../outside.jpg",
            "/outside.jpg",
            "x\\..\\outside.jpg",
            "x:stream",
            "a\0b",
        ] {
            let mut value = request();
            value.relative = relative.into();
            assert!(value.validate().is_err(), "{relative:?}");
        }
        let mut value = request();
        value.root_identity = "42:0:123".into();
        assert!(value.validate().is_err());
        let mut value = request();
        value.root.push('\0');
        assert!(value.validate().is_err());
        let mut value = request();
        value.operation_id = "../outside".into();
        assert!(value.validate().is_err());
    }
    fn complete(request: &Request) -> Event {
        Event::Complete {
            operation_id: request.operation_id.clone(),
            bytes: request.bytes,
            sha256: "a".repeat(64),
            source_stamp: request.source_stamp.clone(),
            created_at_ms: 1,
            modified_at_ms: 2,
        }
    }
    #[test]
    fn progress_requires_exact_chunks_then_one_bound_complete_message() {
        let request = request();
        let mut state = Progress::new(&request);
        assert!(state
            .accept(Event::Progress {
                operation_id: request.operation_id.clone(),
                bytes: 65_536
            })
            .unwrap()
            .is_none());
        assert!(state
            .accept(Event::Progress {
                operation_id: request.operation_id.clone(),
                bytes: request.bytes
            })
            .unwrap()
            .is_none());
        let copied = state.accept(complete(&request)).unwrap().unwrap();
        assert_eq!(copied.bytes, request.bytes);
        assert_eq!(copied.sha256, "a".repeat(64));
        assert!(copied.source_stamp.starts_with("cloud-file-v1:"));
        assert_eq!((copied.created_at_ms, copied.modified_at_ms), (1, 2));
        assert!(state.accept(complete(&request)).is_err());
    }
    #[test]
    fn a_complete_message_cannot_invent_content_version_or_creation_metadata() {
        let request = request();
        for stamp in ["cloud-file-v1:", "cloud-file-v1:42:0102030405060708090a0b0c0d0e0f10:1:116444736000010000:116444736000020000", "cloud-file-v1:42:SHORT:65553:1:2"] {
            let mut state=Progress::new(&request);
            state.accept(Event::Progress {operation_id:request.operation_id.clone(),bytes:65_536}).unwrap();
            state.accept(Event::Progress {operation_id:request.operation_id.clone(),bytes:request.bytes}).unwrap();
            let mut event=complete(&request);
            if let Event::Complete{source_stamp,..}=&mut event { *source_stamp=stamp.into(); }
            assert!(state.accept(event).is_err(),"{stamp}");
        }
        let mut state = Progress::new(&request);
        state
            .accept(Event::Progress {
                operation_id: request.operation_id.clone(),
                bytes: 65_536,
            })
            .unwrap();
        state
            .accept(Event::Progress {
                operation_id: request.operation_id.clone(),
                bytes: request.bytes,
            })
            .unwrap();
        let mut event = complete(&request);
        if let Event::Complete { created_at_ms, .. } = &mut event {
            *created_at_ms = 999;
        }
        assert!(state.accept(event).is_err());
    }
    #[test]
    fn completion_must_match_the_admitted_original_identity() {
        let request = request();
        let mut state = Progress::new(&request);
        state
            .accept(Event::Progress {
                operation_id: request.operation_id.clone(),
                bytes: 65_536,
            })
            .unwrap();
        state
            .accept(Event::Progress {
                operation_id: request.operation_id.clone(),
                bytes: request.bytes,
            })
            .unwrap();
        let mut event = complete(&request);
        if let Event::Complete { source_stamp, .. } = &mut event {
            *source_stamp = source_stamp.replace(
                "0102030405060708090a0b0c0d0e0f10",
                "11111111111111111111111111111111",
            );
        }
        assert!(state.accept(event).is_err());
    }
    #[test]
    fn safe_api_diagnostics_do_not_escape_as_user_errors() {
        let request = request();
        for code in [
            "source_cloud_open_failed:80070020",
            "source_cloud_hydration_failed:80070057",
        ] {
            assert_eq!(
                Progress::new(&request)
                    .accept(Event::Error {
                        operation_id: request.operation_id.clone(),
                        code: code.into()
                    })
                    .unwrap_err(),
                "source_cloud_provider_unavailable"
            );
        }
        for code in [
            "source_cloud_open_failed:private path",
            "source_cloud_open_failed:80070020/secret",
            "source_cloud_open_failed:8007002",
            "unrecognized:80070020",
        ] {
            assert_eq!(
                Progress::new(&request)
                    .accept(Event::Error {
                        operation_id: request.operation_id.clone(),
                        code: code.into()
                    })
                    .unwrap_err(),
                "source_copy_interrupted"
            );
        }
    }

    #[test]
    fn version_diagnostics_accept_only_fixed_stages() {
        let request = request();
        for (code, expected) in [
            ("source_item_changed:admission", "source_item_changed"),
            ("source_item_changed:after-read", "source_item_changed"),
            ("source_item_changed:oplock", "source_item_changed"),
            ("source_item_changed:oplock-open", "source_item_changed"),
            (
                "source_item_changed:oplock-first-read",
                "source_item_changed",
            ),
            (
                "source_item_changed:oplock-next-read",
                "source_item_changed",
            ),
            ("source_item_changed:oplock-complete", "source_item_changed"),
            (
                "source_item_changed:private-path",
                "source_copy_interrupted",
            ),
            (
                "source_item_changed:after-read/secret",
                "source_copy_interrupted",
            ),
        ] {
            assert_eq!(
                Progress::new(&request)
                    .accept(Event::Error {
                        operation_id: request.operation_id.clone(),
                        code: code.into(),
                    })
                    .unwrap_err(),
                expected
            );
        }
    }

    #[test]
    fn incomplete_forged_or_oversized_progress_cannot_publish_a_copy() {
        let request = request();
        assert!(Progress::new(&request).accept(complete(&request)).is_err());
        for (operation_id, bytes) in [
            (request.operation_id.clone(), 1),
            (request.operation_id.clone(), request.bytes + 1),
            ("foreign".into(), 65_536),
        ] {
            assert!(Progress::new(&request)
                .accept(Event::Progress {
                    operation_id,
                    bytes
                })
                .is_err());
        }
        let mut state = Progress::new(&request);
        assert_eq!(
            state
                .accept(Event::Error {
                    operation_id: request.operation_id.clone(),
                    code: "private path or provider detail".into()
                })
                .unwrap_err(),
            "source_copy_interrupted"
        );
    }
}
