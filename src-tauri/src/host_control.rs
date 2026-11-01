//! Private owner-pipe bridge for Manager. No listener, server token, shell command or PID authority.
use crate::{native_runtime, release_policy};
use serde::Deserialize;
use serde_json::json;
use std::{
    fs::{File, OpenOptions},
    io::{BufRead, BufReader, Read, Write},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc, Arc,
    },
    time::Duration,
};
use zeroize::{Zeroize, Zeroizing};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Config {
    protocol_version: u32,
    installation_id: String,
    candidate: PathBuf,
    state: PathBuf,
    manifest_sha256: String,
    password: String,
    database_port: u16,
    api_port: u16,
}
impl Drop for Config {
    fn drop(&mut self) {
        self.password.zeroize();
    }
}
fn config(raw: &[u8]) -> Result<Config, String> {
    let config: Config = serde_json::from_slice(raw).map_err(|_| "host_control_config_invalid")?;
    if config.protocol_version != 1
        || !native_runtime::digest_valid(&config.installation_id, 12)
        || [&config.candidate, &config.state].iter().any(|path| {
            !path.is_absolute()
                || path
                    .components()
                    .any(|part| matches!(part, std::path::Component::ParentDir))
                || (cfg!(windows)
                    && path
                        .as_os_str()
                        .to_string_lossy()
                        .split(['\\', '/'])
                        .any(|part| part == ".."))
        })
        || !native_runtime::digest_valid(&config.manifest_sha256, 64)
        || !(24..=512).contains(&config.password.len())
        || config.password.contains(['\r', '\n', '\0'])
        || config.database_port == 0
        || config.api_port == 0
        || config.database_port == config.api_port
    {
        return Err("host_control_config_invalid".into());
    }
    Ok(config)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Inspection {
    protocol_version: u32,
    installation_id: String,
    candidate: PathBuf,
    state: PathBuf,
    manifest_sha256: String,
}
fn physical_id(path: &Path) -> Result<String, String> {
    let directory = cap_std::fs::Dir::from_std_file(crate::host_storage::directory(path)?);
    crate::copy_source::root_identity(&directory)
        .map_err(|_| "host_profile_identity_unavailable".into())
}
pub(crate) fn separate_paths(candidate: &Path, state: &Path) -> Result<(), String> {
    // Compare physical directory identities too: case aliases cannot bypass payload/state separation.
    let candidate_id = physical_id(candidate)?;
    let existing = if state.exists() {
        state
    } else {
        state.parent().ok_or("host_control_config_invalid")?
    };
    for ancestor in existing.ancestors() {
        if physical_id(ancestor)? == candidate_id {
            return Err("host_state_overlaps_runtime".into());
        }
    }
    if state.exists() {
        let state_id = physical_id(state)?;
        for ancestor in candidate.ancestors() {
            if physical_id(ancestor)? == state_id {
                return Err("host_state_overlaps_runtime".into());
            }
        }
    }
    Ok(())
}
fn verify_candidate(
    candidate: &Path,
    expected: &str,
) -> Result<crate::host_runtime::VerifiedHostRuntime, String> {
    native_runtime::absolute_directory(candidate)?;
    let raw = candidate_file(&candidate.join("manifest.json"), 16 * 1024 * 1024)?;
    let signature: [u8; 64] = candidate_file(&candidate.join("manifest.sig"), 64)?
        .try_into()
        .map_err(|_| "host_control_candidate_invalid")?;
    let runtime =
        release_policy::verify_host_runtime(&candidate.join("payload"), &raw, &signature)?;
    if runtime.manifest_sha256() != expected {
        return Err("host_control_candidate_changed".into());
    }
    Ok(runtime)
}

pub fn inspect_owner() -> Result<(), String> {
    let raw = line(&mut BufReader::new(std::io::stdin()), 16 * 1024)
        .map_err(|_| "host_control_config_invalid")?;
    let request: Inspection =
        serde_json::from_slice(&raw).map_err(|_| "host_control_config_invalid")?;
    if request.protocol_version != 1
        || !native_runtime::digest_valid(&request.installation_id, 12)
        || !native_runtime::digest_valid(&request.manifest_sha256, 64)
        || [&request.candidate, &request.state].iter().any(|path| {
            !path.is_absolute()
                || path
                    .components()
                    .any(|part| matches!(part, std::path::Component::ParentDir))
                || (cfg!(windows)
                    && path
                        .as_os_str()
                        .to_string_lossy()
                        .split(['\\', '/'])
                        .any(|part| part == ".."))
        })
    {
        return Err("host_control_config_invalid".into());
    }
    separate_paths(&request.candidate, &request.state)?;
    let mut owner = crate::host_state::Owner::acquire(&request.state, false)?;
    let runtime = verify_candidate(&request.candidate, &request.manifest_sha256)?;
    let marker = owner.inspect(&request.installation_id, &request.manifest_sha256)?;
    emit(
        json!({"protocolVersion":1,"state":"quiescent","installationId":marker.installation_id,
        "manifestSha256":runtime.manifest_sha256(),"sourceRevision":runtime.source_revision(),
        "certified":runtime.certified(),"profileIdentity":marker.profile_identity,"generation":marker.generation}),
    )
}

fn line(reader: &mut impl BufRead, limit: usize) -> Result<Zeroizing<Vec<u8>>, String> {
    let mut bytes = Zeroizing::new(Vec::new());
    Read::by_ref(reader)
        .take((limit + 1) as u64)
        .read_until(b'\n', &mut bytes)
        .map_err(|_| "host_control_input_invalid")?;
    if bytes.len() > limit || !bytes.ends_with(b"\n") {
        return Err("host_control_input_invalid".into());
    }
    Ok(bytes)
}

fn candidate_file(path: &Path, maximum: usize) -> Result<Vec<u8>, String> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.custom_flags(0x00200000); // FILE_FLAG_OPEN_REPARSE_POINT.
    }
    let file: File = options
        .open(path)
        .map_err(|_| "host_control_candidate_invalid")?;
    let metadata = file
        .metadata()
        .map_err(|_| "host_control_candidate_invalid")?;
    if !metadata.is_file() || metadata.len() > maximum as u64 {
        return Err("host_control_candidate_invalid".into());
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if metadata.file_attributes() & 0x400 != 0 {
            return Err("host_control_candidate_invalid".into());
        }
    }
    let mut bytes = Vec::new();
    file.take(maximum as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "host_control_candidate_invalid")?;
    if bytes.is_empty() || bytes.len() > maximum {
        return Err("host_control_candidate_invalid".into());
    }
    Ok(bytes)
}

fn emit(value: serde_json::Value) -> Result<(), String> {
    let mut output = std::io::stdout().lock();
    writeln!(output, "{value}")
        .and_then(|()| output.flush())
        .map_err(|_| "host_control_output_unavailable".into())
}
pub fn report_failure(code: &str) -> Result<(), String> {
    emit(json!({"protocolVersion":1,"state":"failed","code":code}))
}
fn stopped(invalid: &AtomicBool) -> Result<(), String> {
    if invalid.load(Ordering::Acquire) {
        return Err("host_control_command_invalid".into());
    }
    emit(json!({"protocolVersion":1,"state":"stopped"}))
}

pub fn run() -> Result<(), String> {
    let cancelled = Arc::new(AtomicBool::new(false));
    let invalid = Arc::new(AtomicBool::new(false));
    let (sender, receiver) = mpsc::sync_channel(1);
    let input_cancelled = cancelled.clone();
    let input_invalid = invalid.clone();
    std::thread::spawn(move || {
        let mut input = BufReader::new(std::io::stdin());
        let parsed = line(&mut input, 16 * 1024)
            .map_err(|_| "host_control_config_invalid".into())
            .and_then(|raw| config(&raw));
        let valid = parsed.is_ok();
        if sender.send(parsed).is_err() || !valid {
            return;
        }
        // A missing owner is a clean stop; a malformed command also stops, then reports failure.
        let mut bytes = Zeroizing::new(Vec::new());
        match Read::by_ref(&mut input)
            .take(65)
            .read_until(b'\n', &mut bytes)
        {
            Ok(0) => {}
            Ok(_) if bytes.as_slice() == b"stop\n" => {}
            _ => input_invalid.store(true, Ordering::Release),
        }
        input_cancelled.store(true, Ordering::Release);
    });
    let mut config = receiver
        .recv()
        .map_err(|_| "host_control_config_invalid")??;
    let password = Zeroizing::new(std::mem::take(&mut config.password));
    if cancelled.load(Ordering::Acquire) {
        return stopped(&invalid);
    }
    separate_paths(&config.candidate, &config.state)?;
    let mut owner = crate::host_state::Owner::acquire(&config.state, true)?;
    let runtime = verify_candidate(&config.candidate, &config.manifest_sha256)?;
    if cancelled.load(Ordering::Acquire) {
        return stopped(&invalid);
    }
    crate::host_storage::check(&config.state)?;
    owner.activate(&config.installation_id, &config.manifest_sha256)?;
    let mut process = runtime.start(
        &config.state,
        &password,
        config.database_port,
        config.api_port,
    )?;
    if !process.wait_ready_or_cancel(Duration::from_secs(240), &cancelled)? {
        owner.clean_stop()?;
        return stopped(&invalid);
    }
    if emit(
        json!({"protocolVersion":1,"state":"running", "manifestSha256":runtime.manifest_sha256(),
        "sourceRevision":runtime.source_revision(),"certified":runtime.certified()}),
    )
    .is_err()
    {
        process.stop()?;
        owner.clean_stop()?;
        return Err("host_control_output_unavailable".into());
    }
    while !cancelled.load(Ordering::Acquire) {
        if !process.is_running()? {
            return Err("host_process_exited".into());
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    process.stop()?;
    owner.clean_stop()?;
    stopped(&invalid)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_cannot_overlap_the_physical_runtime_tree_before_journal_creation() {
        let root = std::env::temp_dir()
            .canonicalize()
            .unwrap()
            .join(format!("frameleaf-separation-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&root).unwrap();
        let candidate = root.join("Candidate");
        std::fs::create_dir(&candidate).unwrap();
        for state in [candidate.clone(), candidate.join("state"), root.clone()] {
            assert_eq!(
                separate_paths(&candidate, &state).unwrap_err(),
                "host_state_overlaps_runtime"
            );
        }
        let alias = root.join("candidate");
        if alias.exists() {
            assert!(separate_paths(&candidate, &alias.join("state")).is_err());
        }
        assert!(separate_paths(&candidate, &root.join("state")).is_ok());
        assert!(!root.join("state").exists());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn controller_configuration_cannot_expand_authority_or_accept_invalid_identity() {
        let root = std::env::temp_dir().canonicalize().unwrap();
        let good = json!({"protocolVersion":1,"installationId":"a".repeat(12),"candidate":root.join("candidate"),"state":root.join("state"),
            "manifestSha256":"a".repeat(64),"password":"synthetic-password-long-enough",
            "databasePort":54321,"apiPort":54322});
        assert!(config(&serde_json::to_vec(&good).unwrap()).is_ok());
        // Joining a Windows verbatim path normalizes away the traversal before validation.
        let parent_path = |leaf: &str| {
            json!(format!(
                "{}{separator}parent{separator}..{separator}{leaf}",
                root.display(),
                separator = std::path::MAIN_SEPARATOR
            ))
        };
        for (field, value) in [
            ("protocolVersion", json!(2)),
            ("candidate", json!("relative")),
            ("state", json!("relative")),
            ("state", parent_path("state")),
            ("candidate", parent_path("candidate")),
            ("manifestSha256", json!("main")),
            ("password", json!("too-short")),
            ("password", json!("x".repeat(513))),
            ("password", json!("synthetic-password-with\ncontrol")),
            ("databasePort", json!(0)),
            ("apiPort", json!(54321)),
            ("trustedKeys", json!(["untrusted"])),
            ("command", json!("arbitrary command")),
        ] {
            let mut value_config = good.clone();
            value_config[field] = value;
            assert_eq!(
                config(&serde_json::to_vec(&value_config).unwrap())
                    .err()
                    .unwrap(),
                "host_control_config_invalid"
            );
        }
    }

    #[test]
    fn controller_lines_are_bounded_and_require_a_complete_message() {
        assert_eq!(&*line(&mut &b"stop\n"[..], 5).unwrap(), b"stop\n");
        for input in [&b"stop"[..], &b""[..], &b"stop\nx"[..]] {
            let result = line(&mut &input[..], 4);
            assert_eq!(result.err().unwrap(), "host_control_input_invalid");
        }
    }

    #[cfg(unix)]
    #[test]
    fn candidate_files_refuse_links_special_files_and_oversized_content() {
        use std::os::unix::ffi::OsStrExt;
        let root = std::env::temp_dir()
            .canonicalize()
            .unwrap()
            .join(format!("frameleaf-control-file-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&root).unwrap();
        let file = root.join("file");
        std::fs::write(&file, b"fixture").unwrap();
        assert_eq!(candidate_file(&file, 7).unwrap(), b"fixture");
        assert!(candidate_file(&file, 6).is_err());
        let alias = root.join("alias");
        std::os::unix::fs::symlink(&file, &alias).unwrap();
        assert!(candidate_file(&alias, 7).is_err());
        assert!(candidate_file(&root, 7).is_err());
        let fifo = root.join("fifo");
        let name = std::ffi::CString::new(fifo.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
        assert!(candidate_file(&fifo, 7).is_err());
        std::fs::remove_dir_all(root).unwrap();
    }
}
