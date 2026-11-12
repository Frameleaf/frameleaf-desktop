//! Native-only Manager owner. No caller-supplied command, browser credentials or stored PID authority.
use crate::{host_runtime::VerifiedHostRuntime, manager_tls::TlsIdentity};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    fs,
    io::{BufRead, BufReader, Read, Write},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

#[cfg(all(test, windows))]
#[path = "manager_host_windows_tests.rs"]
mod windows_tests;

#[cfg(target_os = "macos")]
pub(crate) fn no_acl(path: &Path) -> Result<(), String> {
    use std::os::fd::AsRawFd;
    unsafe extern "C" {
        fn acl_get_fd(fd: libc::c_int) -> *mut libc::c_void;
        fn acl_get_entry(
            acl: *mut libc::c_void,
            entry: libc::c_int,
            out: *mut *mut libc::c_void,
        ) -> libc::c_int;
        fn acl_free(acl: *mut libc::c_void) -> libc::c_int;
    }
    let file = fs::File::open(path).map_err(|_| "native_manager_unprotected")?;
    let acl = unsafe { acl_get_fd(file.as_raw_fd()) };
    if acl.is_null() {
        // Darwin reports ENOENT for an existing inode without an extended ACL.
        if std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT)
            && file.metadata().is_ok()
        {
            return Ok(());
        }
        return Err("native_manager_unprotected".into());
    }
    let mut entry = std::ptr::null_mut();
    let result = unsafe { acl_get_entry(acl, 0, &mut entry) };
    let error = std::io::Error::last_os_error().raw_os_error();
    unsafe {
        acl_free(acl);
    }
    if result != -1 || error != Some(libc::EINVAL) {
        return Err("native_manager_unprotected".into());
    }
    Ok(())
}
/// Root-owned physical ancestors and no write-granting ACLs keep verified code immutable through spawn.
pub(crate) fn protect(path: &Path, checked: &mut BTreeSet<PathBuf>) -> Result<(), String> {
    #[cfg(windows)]
    {
        crate::windows_protection::protect(path, checked)
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
    {
        let _ = (path, checked);
        Err("native_manager_protection_unavailable".into())
    }
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    {
        use std::os::unix::fs::MetadataExt;
        if !path.is_absolute()
            || path
                .components()
                .any(|c| matches!(c, std::path::Component::ParentDir))
        {
            return Err("native_manager_unprotected".into());
        }
        let mut ancestors: Vec<_> = path.ancestors().collect();
        ancestors.reverse();
        for current in ancestors {
            if checked.contains(current) {
                continue;
            }
            let meta = fs::symlink_metadata(current).map_err(|_| "native_manager_unprotected")?;
            if meta.uid() != 0
                || meta.mode() & 0o022 != 0
                || (!meta.is_file() && !meta.is_dir())
                || (current != path && !meta.is_dir())
            {
                return Err("native_manager_unprotected".into());
            }
            #[cfg(target_os = "macos")]
            no_acl(current)?;
            // Linux POSIX ACL write grants are constrained by the group mask checked above.
            checked.insert(current.to_owned());
        }
        Ok(())
    }
}

pub struct Programs<'a> {
    pub(crate) runtime: &'a VerifiedHostRuntime,
    pub(crate) root: PathBuf,
    pub(crate) node: PathBuf,
    pub(crate) main: PathBuf,
}
impl Programs<'_> {
    pub(crate) fn check(&self) -> Result<(), String> {
        let mut checked = BTreeSet::new();
        let mut pending = vec![self.root.clone()];
        while let Some(path) = pending.pop() {
            protect(&path, &mut checked)?;
            if fs::symlink_metadata(&path)
                .map_err(|_| "native_manager_unprotected")?
                .is_dir()
            {
                for entry in fs::read_dir(&path).map_err(|_| "native_manager_unprotected")? {
                    pending.push(entry.map_err(|_| "native_manager_unprotected")?.path());
                }
            }
        }
        self.runtime.check_files()
    }
}
/// Supplied only by reviewed native setup; not a Tauri/HTTP command or credential record.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Configuration {
    pub installation_id: String,
    pub name: String,
    pub release: String,
    pub controller: PathBuf,
    pub state: PathBuf,
    pub data: PathBuf,
    pub origin: String,
    pub database_port: u16,
    pub api_port: u16,
}
/// Manager accepts a changed package once, from the descriptor it last ran with.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Transition {
    pub operation_id: uuid::Uuid,
    pub from_fingerprint: String,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Binding<'a> {
    runtime: &'a str,
    id: &'a str,
    secure_installation_id: uuid::Uuid,
    controller: &'a Path,
    candidate: &'a Path,
    state: &'a Path,
    manifest_sha256: &'a str,
    source_revision: &'a str,
    certified: bool,
    database_port: u16,
    api_port: u16,
}
/// The installation part of the bootstrap and descriptor, in Manager's field order.
fn binding<'a>(
    config: &'a Configuration,
    candidate: &'a Path,
    runtime: &'a crate::host_runtime::VerifiedHostRuntime,
) -> Result<Binding<'a>, String> {
    Ok(Binding {
        runtime: "native",
        id: &config.installation_id,
        secure_installation_id: crate::host_state::secure_installation_id(&config.state)?,
        controller: &config.controller,
        candidate,
        state: &config.state,
        manifest_sha256: runtime.manifest_sha256(),
        source_revision: runtime.source_revision(),
        certified: runtime.certified(),
        database_port: config.database_port,
        api_port: config.api_port,
    })
}
/// Same fields and order as Manager's native descriptor, whose fingerprint is sha256(JSON).
#[cfg(unix)]
pub(crate) fn descriptor_fingerprint(
    config: &Configuration,
    candidate: &Path,
    runtime: &crate::host_runtime::VerifiedHostRuntime,
    controller_sha256: &str,
    certificate_pem: &str,
) -> Result<String, String> {
    fingerprint(
        binding(config, candidate, runtime)?,
        controller_sha256,
        runtime.backup_engine()?,
        &config.name,
        &config.release,
        format!("{:x}", Sha256::digest(certificate_pem.as_bytes())),
    )
}
/// sha256 of the compact JSON Manager computes for its stored descriptor.
#[cfg(unix)]
fn fingerprint(
    installation: Binding,
    controller_sha256: &str,
    backup_engine: crate::host_runtime::BackupEngine,
    name: &str,
    release: &str,
    tls_certificate_pem_sha256: String,
) -> Result<String, String> {
    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct Descriptor<'a> {
        protocol_version: u32,
        installation: Binding<'a>,
        controller_sha256: &'a str,
        backup_engine: crate::host_runtime::BackupEngine,
        name: &'a str,
        release: &'a str,
        tls_certificate_pem_sha256: String,
    }
    let descriptor = Descriptor {
        protocol_version: 2,
        installation,
        controller_sha256,
        backup_engine,
        name,
        release,
        tls_certificate_pem_sha256,
    };
    Ok(format!(
        "{:x}",
        Sha256::digest(
            serde_json::to_vec(&descriptor).map_err(|_| "native_manager_config_invalid")?
        )
    ))
}
fn protect_profile_parents(config: &Configuration) -> Result<Vec<fs::File>, String> {
    #[cfg(windows)]
    {
        crate::windows_host_profile::admit(&config.state, &config.data)
    }
    #[cfg(not(windows))]
    {
        let mut checked = BTreeSet::new();
        for path in [&config.state, &config.data] {
            protect(
                path.parent().ok_or("native_manager_config_invalid")?,
                &mut checked,
            )?;
        }
        Ok(Vec::new())
    }
}
pub(crate) fn validate_paths(candidate: &Path, state: &Path, data: &Path) -> Result<(), String> {
    for path in [state, data] {
        crate::native_runtime::absolute_directory(
            path.parent().ok_or("native_manager_config_invalid")?,
        )?;
        if path.file_name().is_none()
            || path
                .components()
                .any(|p| matches!(p, std::path::Component::ParentDir))
            || path.starts_with(candidate)
            || candidate.starts_with(path)
        {
            return Err("native_manager_config_invalid".into());
        }
        if path.exists() {
            crate::native_runtime::absolute_directory(path)?;
        }
    }
    if data.starts_with(state) || state.starts_with(data) {
        return Err("native_manager_config_invalid".into());
    }
    crate::host_control::separate_paths(candidate, state)?;
    crate::host_control::separate_paths(candidate, data)?;
    if state.exists() {
        crate::host_control::separate_paths(state, data)?;
    }
    if data.exists() {
        crate::host_control::separate_paths(data, state)?;
    }
    Ok(())
}
pub(crate) fn validate_configuration(config: &Configuration) -> Result<(), String> {
    let manager_port = local_origin(&config.origin)?;
    if !crate::native_runtime::digest_valid(&config.installation_id, 12)
        || config.name.trim().is_empty()
        || config.name.len() > 120
        || config.release.len() > 256
        || !config.release.starts_with("frameleaf-v")
        || config.database_port == 0
        || config.api_port == 0
        || config.database_port == config.api_port
        || [config.database_port, config.api_port].contains(&manager_port)
    {
        return Err("native_manager_config_invalid".into());
    }
    Ok(())
}
fn local_origin(origin: &str) -> Result<u16, String> {
    let url = url::Url::parse(origin).map_err(|_| "native_manager_config_invalid")?;
    let port = url.port().ok_or("native_manager_config_invalid")?;
    if url.scheme() != "https"
        || url.origin().ascii_serialization() != origin
        || !matches!(url.host_str(), Some("127.0.0.1" | "[::1]"))
        || !url.username().is_empty()
        || url.password().is_some()
        || url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
        || port < 1024
    {
        return Err("native_manager_config_invalid".into());
    }
    Ok(port)
}
/// What fallible evidence says about something of this library running. `Unknown` is its own
/// answer and is never read as `Clear`: only `Clear` permits what running would forbid.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Evidence {
    /// Proven not running.
    Clear,
    Running,
    Unknown,
}
/// Only an accepted connection proves a listener and only a refusal proves there is none; a
/// timeout or any other failure proves neither.
pub(crate) fn listener_evidence(attempt: std::io::Result<std::net::TcpStream>) -> Evidence {
    match attempt {
        Ok(_) => Evidence::Running,
        Err(error) if error.kind() == std::io::ErrorKind::ConnectionRefused => Evidence::Clear,
        Err(_) => Evidence::Unknown,
    }
}
pub(crate) fn listener(port: u16) -> Evidence {
    let address = std::net::SocketAddr::from(([127, 0, 0, 1], port));
    listener_evidence(std::net::TcpStream::connect_timeout(
        &address,
        Duration::from_millis(250),
    ))
}
/// Refuse with the port's number when a program already accepts connections on a local port.
pub(crate) fn foreign_listener(ports: &[u16]) -> Result<(), String> {
    for port in ports {
        if listener(*port) == Evidence::Running {
            return Err(format!("local_port_in_use_{port}"));
        }
    }
    Ok(())
}

/// The Manager this app started, recorded so a later launch can recognise it after a crash.
/// The record is written before Manager is spawned, as an intent that names no process yet,
/// and completed with the process once it exists. It is removed only when that Manager is
/// proven to have exited or was never spawned.
#[cfg(unix)]
const OWNED_PROCESS: &str = "desktop-manager-process.json";
#[cfg(unix)]
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct OwnedProcess {
    schema_version: u32,
    /// None: a launch was begun and its process is not known.
    #[serde(default)]
    process: Option<crate::process_tree::ProcessIdentity>,
}
#[cfg(unix)]
#[derive(Debug, PartialEq, Eq)]
enum Recorded {
    Nothing,
    /// A launch was begun; whether a Manager came of it is not known.
    Intent,
    Process(crate::process_tree::ProcessIdentity),
    Unreadable,
}
#[cfg(unix)]
fn recorded(data: &Path) -> Recorded {
    match fs::symlink_metadata(data.join(OWNED_PROCESS)) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Recorded::Nothing,
        Err(_) => return Recorded::Unreadable,
        Ok(_) => {}
    }
    let read = || -> Option<OwnedProcess> {
        let directory = cap_std::fs::Dir::from_std_file(crate::host_storage::directory(data).ok()?);
        let file = directory
            .open_with(OWNED_PROCESS, &crate::host_state::options(false))
            .ok()?
            .into_std();
        crate::host_state::valid_file(&file).ok()?;
        let mut bytes = Vec::new();
        file.take(4097).read_to_end(&mut bytes).ok()?;
        serde_json::from_slice(&bytes).ok()
    };
    match read() {
        Some(OwnedProcess {
            schema_version: 1,
            process,
        }) => process.map_or(Recorded::Intent, Recorded::Process),
        _ => Recorded::Unreadable,
    }
}
/// Replace the record in one step, so a crash leaves either the old one or the new one.
#[cfg(unix)]
fn write_record(
    data: &Path,
    process: Option<crate::process_tree::ProcessIdentity>,
) -> Result<(), String> {
    const TEMPORARY: &str = ".desktop-manager-process.json.tmp";
    let failed = |_: std::io::Error| "native_manager_state_unavailable".to_string();
    let bytes = serde_json::to_vec(&OwnedProcess {
        schema_version: 1,
        process,
    })
    .map_err(|_| "native_manager_state_unavailable")?;
    let directory = cap_std::fs::Dir::from_std_file(crate::host_storage::directory(data)?);
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
        .rename(TEMPORARY, &directory, OWNED_PROCESS)
        .map_err(failed)?;
    crate::host_storage::directory(data)?
        .sync_all()
        .map_err(failed)
}
/// Before Manager is spawned: from here on, a later run must assume one may be running.
#[cfg(unix)]
pub(crate) fn record_launch_intent(data: &Path) -> Result<(), String> {
    write_record(data, None)
}
/// Complete the record with the spawned process.
#[cfg(unix)]
pub(crate) fn record_owned_process(data: &Path, pid: u32) -> Result<(), String> {
    let process =
        crate::process_tree::ProcessIdentity::of(pid).ok_or("native_manager_state_unavailable")?;
    write_record(data, Some(process))
}
/// Only for a Manager proven to have exited, or never spawned.
#[cfg(unix)]
pub(crate) fn forget_owned_process(data: &Path) {
    if let Ok(directory) = crate::host_storage::directory(data) {
        let _ = cap_std::fs::Dir::from_std_file(directory).remove_file(OWNED_PROCESS);
    }
}
/// Whether this app's record names exactly the live process `pid`.
#[cfg(unix)]
pub(crate) fn owned_process_recorded(data: &Path, pid: u32) -> bool {
    crate::process_tree::ProcessIdentity::of(pid)
        .is_some_and(|live| recorded(data) == Recorded::Process(live))
}
/// For the update gate: whether a Manager recorded in `data` may still be running.
/// `Clear` only with no record, or a record whose exact process is gone or replaced by another.
/// A launch intent with no process, a record that cannot be read, and a process that cannot be
/// looked up are all `Unknown`.
#[cfg(unix)]
pub(crate) fn recorded_manager(
    data: &Path,
    lookup: impl FnOnce(u32) -> crate::process_tree::Presence,
) -> Evidence {
    use crate::process_tree::Presence;
    match recorded(data) {
        Recorded::Nothing => Evidence::Clear,
        Recorded::Intent | Recorded::Unreadable => Evidence::Unknown,
        Recorded::Process(process) => match lookup(process.pid) {
            Presence::Absent => Evidence::Clear,
            Presence::Present(live) if live == process => Evidence::Running,
            Presence::Present(_) => Evidence::Clear,
            Presence::Unknown => Evidence::Unknown,
        },
    }
}
/// Send the recorded process the same exit request `shutdown` makes. Returns false, without
/// signalling, when the process with that PID is no longer the recorded one.
///
/// Linux binds the signal to a process handle; see `request_exit_through`. Everywhere else
/// there is no such handle and `signal_after_recheck` is all the platform allows.
#[cfg(unix)]
fn request_exit(recorded: &crate::process_tree::ProcessIdentity) -> Result<bool, String> {
    #[cfg(target_os = "linux")]
    {
        request_exit_through(recorded, open_process_handle)
    }
    #[cfg(not(target_os = "linux"))]
    {
        signal_after_recheck(recorded)
    }
}
/// PID-based signal for platforms without a process handle. The identity is read immediately
/// before `kill`, which narrows the race but does not close it: if the process exits and its
/// PID is reused within those few instructions, the new holder receives SIGTERM.
#[cfg(unix)]
fn signal_after_recheck(recorded: &crate::process_tree::ProcessIdentity) -> Result<bool, String> {
    if crate::process_tree::ProcessIdentity::of(recorded.pid).as_ref() != Some(recorded) {
        return Ok(false);
    }
    match unsafe { libc::kill(recorded.pid as libc::pid_t, libc::SIGTERM) } {
        0 => Ok(true),
        _ if std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH) => Ok(false),
        _ => Err("native_manager_orphan_running".into()),
    }
}
/// A pidfd for `pid`, or the errno that refused it.
#[cfg(target_os = "linux")]
fn open_process_handle(pid: libc::pid_t) -> Result<std::os::fd::OwnedFd, i32> {
    use std::os::fd::FromRawFd;
    let flags: libc::c_uint = 0;
    let opened = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, flags) };
    if opened < 0 {
        return Err(std::io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(libc::EINVAL));
    }
    Ok(unsafe { std::os::fd::OwnedFd::from_raw_fd(opened as libc::c_int) })
}
/// The handle is opened first and the identity read afterwards, so a match proves the handle
/// names the recorded process and a later reuse of the PID cannot redirect the signal.
///
/// When no handle can be opened this fails closed, with one intentional exception: ENOSYS
/// means the kernel has no pidfd at all, and only then is the weaker `signal_after_recheck`
/// used. ESRCH means the process is already gone. Any other refusal sends no signal.
#[cfg(target_os = "linux")]
fn request_exit_through(
    recorded: &crate::process_tree::ProcessIdentity,
    open: impl FnOnce(libc::pid_t) -> Result<std::os::fd::OwnedFd, i32>,
) -> Result<bool, String> {
    use std::os::fd::AsRawFd;
    let handle = match open(recorded.pid as libc::pid_t) {
        Ok(handle) => handle,
        Err(libc::ESRCH) => return Ok(false),
        Err(libc::ENOSYS) => return signal_after_recheck(recorded),
        Err(_) => return Err("native_manager_orphan_running".into()),
    };
    if crate::process_tree::ProcessIdentity::of(recorded.pid).as_ref() != Some(recorded) {
        return Ok(false);
    }
    let flags: libc::c_uint = 0;
    let sent = unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            handle.as_raw_fd(),
            libc::SIGTERM,
            std::ptr::null::<libc::siginfo_t>(),
            flags,
        )
    };
    match sent {
        0 => Ok(true),
        _ if std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH) => Ok(false),
        _ => Err("native_manager_orphan_running".into()),
    }
}
/// Stop the Manager an earlier run of this app left behind. Returns whether one was stopped.
///
/// A recorded process that is gone, or whose PID now belongs to another process, is forgotten
/// and not signalled; see `request_exit` for how firmly each platform can hold that.
///
/// A record that names no process this app can identify (a launch intent that was never
/// completed, an unreadable record, a process that cannot be looked up) is never cleared here.
/// Starting local management is the explicit recovery for it: the start goes ahead only after
/// Manager's port has definitely refused connections for the whole of `timeout`, and the new
/// launch then replaces the record with its own. Anything else refuses the start.
#[cfg(unix)]
pub(crate) fn stop_orphaned_manager(
    data: &Path,
    timeout: Duration,
    cancel: &AtomicBool,
    listener: &dyn Fn() -> Evidence,
) -> Result<bool, String> {
    use crate::process_tree::{Presence, ProcessIdentity};
    let deadline = Instant::now() + timeout;
    let wait = || -> Result<(), String> {
        if cancel.load(Ordering::Acquire) {
            return Err("native_manager_start_cancelled".into());
        }
        if Instant::now() >= deadline {
            return Err("native_manager_orphan_running".into());
        }
        std::thread::sleep(Duration::from_millis(50));
        Ok(())
    };
    let unidentified = || -> Result<bool, String> {
        loop {
            if listener() != Evidence::Clear {
                return Err("native_manager_orphan_running".into());
            }
            if Instant::now() >= deadline {
                return Ok(false);
            }
            if cancel.load(Ordering::Acquire) {
                return Err("native_manager_start_cancelled".into());
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    };
    let process = match recorded(data) {
        Recorded::Nothing => return Ok(false),
        Recorded::Intent | Recorded::Unreadable => return unidentified(),
        Recorded::Process(process) => process,
    };
    // A record naming this app itself names no Manager.
    if process.pid == std::process::id() {
        forget_owned_process(data);
        return Ok(false);
    }
    let mut stopped = false;
    loop {
        match ProcessIdentity::lookup(process.pid) {
            Presence::Absent => break,
            Presence::Present(live) if live != process => break,
            Presence::Unknown if !stopped => return unidentified(),
            Presence::Unknown => wait()?,
            // Manager exits on this request and its controller then stops the database.
            Presence::Present(_) if !stopped => stopped = request_exit(&process)?,
            Presence::Present(_) => wait()?,
        }
    }
    forget_owned_process(data);
    Ok(stopped)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Ready {
    protocol_version: u32,
    state: String,
    installation_id: String,
    manifest_sha256: String,
    origin: String,
}
fn ready(bytes: &[u8], id: &str, hash: &str, origin: &str) -> Result<(), String> {
    if bytes.len() > 1024 || !bytes.ends_with(b"\n") || bytes[..bytes.len() - 1].contains(&b'\n') {
        return Err("native_manager_receipt_invalid".into());
    }
    let value: Ready =
        serde_json::from_slice(bytes).map_err(|_| "native_manager_receipt_invalid")?;
    if value.protocol_version != 2
        || value.state != "ready"
        || value.installation_id != id
        || value.manifest_sha256 != hash
        || value.origin != origin
    {
        return Err("native_manager_receipt_invalid".into());
    }
    Ok(())
}
pub struct NativeManager {
    child: Child,
    #[cfg(windows)]
    tree: crate::process_tree::ProcessTree,
    receipt: mpsc::Receiver<Result<Vec<u8>, String>>,
    #[cfg(all(test, windows))]
    stderr_diagnostic: Option<mpsc::Receiver<()>>,
    installation_id: String,
    manifest_sha256: String,
    origin: String,
    client: reqwest::Client,
    verified_ready: bool,
    startup_lease: Option<crate::host_state::Owner>,
    certificate_pem: String,
    _code_lease: Option<crate::package_lease::CodeLease>,
    _profile_pins: Vec<fs::File>,
}
#[derive(Default)]
struct Leases {
    code: Option<crate::package_lease::CodeLease>,
    startup: Option<crate::host_state::Owner>,
    profiles: Vec<fs::File>,
}
impl Programs<'_> {
    pub fn start_from_keystore(&self, config: &Configuration) -> Result<NativeManager, String> {
        validate_configuration(config)?;
        self.check()?;
        let _profile_pins = protect_profile_parents(config)?;
        protect(&config.controller, &mut BTreeSet::new())?;
        if self.root.file_name() != Some(std::ffi::OsStr::new("payload")) {
            return Err("native_manager_layout_invalid".into());
        }
        let candidate = self.root.parent().ok_or("native_manager_layout_invalid")?;
        validate_paths(candidate, &config.state, &config.data)?;
        let _code_lease = crate::package_lease::CodeLease::acquire(candidate)?;
        let profile = crate::manager_profile::Profile::from_keystore(
            config,
            candidate,
            self.runtime.manifest_sha256(),
        )?;
        let tls =
            TlsIdentity::from_keystore(&config.installation_id, &config.origin, profile.binding())?;
        profile.require_current(config)?;
        let lease = crate::host_state::Owner::acquire(&config.state, true)?;
        // This lease proves no controller of this library is running, so a listener on any of
        // its ports belongs to another program.
        foreign_listener(&[
            local_origin(&config.origin)?,
            config.api_port,
            config.database_port,
        ])?;
        let (password, backup_key) = (profile.password(), profile.backup_key()?);
        // Durable before the spawn: a crash from here on leaves a later run a record that says
        // a Manager may be running, even before one has bound its port.
        #[cfg(unix)]
        record_launch_intent(&config.data)?;
        let started = self.start_owned(
            config,
            &password,
            &backup_key,
            &tls,
            Some(lease),
            profile.installation_transition(),
        );
        #[cfg(unix)]
        match &started {
            // If this write fails the intent stays, which a later run reads as "may be running".
            Ok(manager) => {
                let _ = record_owned_process(&config.data, manager.process_id());
            }
            // Either nothing was spawned, or the child was killed and reaped when its owner
            // was dropped on the way out of `spawn`.
            Err(_) => forget_owned_process(&config.data),
        }
        started
    }
    /// Caller must persist the database password before use; it never enters argv/env/logs.
    pub fn start(
        &self,
        config: &Configuration,
        password: &Zeroizing<String>,
        backup_key: &Zeroizing<String>,
        tls: &TlsIdentity,
    ) -> Result<NativeManager, String> {
        self.start_owned(config, password, backup_key, tls, None, None)
    }
    fn start_owned(
        &self,
        config: &Configuration,
        password: &Zeroizing<String>,
        backup_key: &Zeroizing<String>,
        tls: &TlsIdentity,
        startup_lease: Option<crate::host_state::Owner>,
        transition: Option<&Transition>,
    ) -> Result<NativeManager, String> {
        validate_configuration(config)?;
        if !crate::manager_profile::valid_backup_key(backup_key) || backup_key == password {
            return Err("native_backup_key_invalid".into());
        }
        if !(24..=256).contains(&password.len()) || password.contains(['\r', '\n', '\0']) {
            return Err("native_manager_config_invalid".into());
        }
        if self.root.file_name() != Some(std::ffi::OsStr::new("payload")) {
            return Err("native_manager_layout_invalid".into());
        }
        let candidate = self.root.parent().ok_or("native_manager_layout_invalid")?;
        validate_paths(candidate, &config.state, &config.data)?;
        self.check()?;
        let profile_pins = protect_profile_parents(config)?;
        protect(&config.controller, &mut BTreeSet::new())?;
        let code_lease = crate::package_lease::CodeLease::acquire(candidate)?;
        let controller = crate::runtime_store::read_bounded(&config.controller, 256 * 1024 * 1024)?;
        let controller_hash = format!("{:x}", Sha256::digest(&controller));
        let client = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .tls_built_in_root_certs(false)
            .add_root_certificate(
                reqwest::Certificate::from_pem(tls.certificate().as_bytes())
                    .map_err(|_| "native_manager_tls_invalid")?,
            )
            .timeout(Duration::from_secs(2))
            .build()
            .map_err(|_| "native_manager_tls_invalid")?;
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct Bootstrap<'a> {
            protocol_version: u32,
            installation: Binding<'a>,
            controller_sha256: &'a str,
            backup_engine: crate::host_runtime::BackupEngine,
            name: &'a str,
            release: &'a str,
            password: &'a str,
            backup_key: &'a str,
            tls: crate::manager_tls::BootstrapTls<'a>,
            #[serde(skip_serializing_if = "Option::is_none")]
            installation_transition: Option<&'a Transition>,
        }
        let bootstrap = Bootstrap {
            protocol_version: 2,
            installation: binding(config, candidate, self.runtime)?,
            controller_sha256: &controller_hash,
            backup_engine: self.runtime.backup_engine()?,
            name: &config.name,
            release: &config.release,
            password,
            backup_key,
            tls: tls.wire(),
            installation_transition: transition,
        };
        let mut input = Zeroizing::new(
            serde_json::to_vec(&bootstrap).map_err(|_| "native_manager_config_invalid")?,
        );
        input.push(b'\n');
        if input.len() > 16 * 1024 {
            return Err("native_manager_config_invalid".into());
        }
        crate::runtime_store::private_directory(&config.data)?;
        validate_paths(candidate, &config.state, &config.data)?;
        let mut command = Command::new(&self.node);
        command
            .arg(&self.main)
            .current_dir(&self.root)
            .env_clear()
            .env("PATH", "")
            .env("MANAGER_RUNTIME", "native")
            .env("MANAGER_ORIGIN", &config.origin)
            .env("MANAGER_DATA", &config.data);
        #[cfg(windows)]
        command
            .env("NODE_OPTIONS", crate::windows_protection::NODE_PATH_OPTIONS)
            .env("SystemRoot", crate::windows_protection::system_root()?);
        let mut manager = NativeManager::spawn(
            &mut command,
            input,
            &config.installation_id,
            self.runtime.manifest_sha256(),
            &config.origin,
            client,
            Leases {
                code: Some(code_lease),
                startup: startup_lease,
                profiles: profile_pins,
            },
        )?;
        manager.certificate_pem = tls.certificate().into();
        Ok(manager)
    }
}
impl NativeManager {
    /// Start the owned Manager and send its bootstrap through private stdin.
    fn spawn(
        command: &mut Command,
        input: Zeroizing<Vec<u8>>,
        id: &str,
        hash: &str,
        origin: &str,
        client: reqwest::Client,
        leases: Leases,
    ) -> Result<Self, String> {
        #[cfg(windows)]
        crate::process_tree::configure(command);
        command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        #[cfg(all(test, windows))]
        if std::env::var("GITHUB_ACTIONS").as_deref() == Ok("true")
            && std::env::var("RUNNER_ENVIRONMENT").as_deref() == Ok("github-hosted")
            && std::env::var_os("FRAMELEAF_INSTALLED_HOST_MANIFEST").is_some()
        {
            command.stderr(Stdio::piped());
        }
        let child = match &leases.code {
            Some(lease) => lease.spawn(command),
            None => command.spawn(),
        }
        .map_err(|_| "native_manager_launch_failed")?;
        #[cfg(windows)]
        let (child, tree) = {
            let mut child = child;
            match crate::process_tree::ProcessTree::attach(&child) {
                Ok(tree) => (child, tree),
                Err(_) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err("native_manager_process_owner_failed".into());
                }
            }
        };
        let (receipt_tx, receipt) = mpsc::channel();
        let mut owner = Self {
            child,
            #[cfg(windows)]
            tree,
            receipt,
            #[cfg(all(test, windows))]
            stderr_diagnostic: None,
            installation_id: id.into(),
            manifest_sha256: hash.into(),
            origin: origin.into(),
            client,
            verified_ready: false,
            startup_lease: leases.startup,
            certificate_pem: String::new(),
            _code_lease: leases.code,
            _profile_pins: leases.profiles,
        };
        #[cfg(all(test, windows))]
        if let Some(mut stderr) = owner.child.stderr.take() {
            let (complete, diagnostic) = mpsc::channel();
            owner.stderr_diagnostic = Some(diagnostic);
            std::thread::spawn(move || {
                let mut bytes = Vec::new();
                let _ = stderr.by_ref().take(8192).read_to_end(&mut bytes);
                let output = String::from_utf8_lossy(&bytes);
                eprintln!("Installed Manager stderr prefix: bytes={}", bytes.len());
                // Print only known refusal codes and error categories, never child stderr or its paths.
                for code in [
                    "ZodError",
                    "TypeError",
                    "ReferenceError",
                    "SyntaxError",
                    "ERR_SQLITE_ERROR",
                    "EACCES",
                    "EPERM",
                    "ENOENT",
                    "EINVAL",
                    "native_installation_invalid",
                    "ERR_UNSUPPORTED_ESM_URL_SCHEME",
                    "ERR_INVALID_URL",
                    "ERR_WORKER_UNSUPPORTED_OPERATION",
                    "native_bootstrap_unavailable",
                    "native_bootstrap_invalid",
                    "native_controller_changed",
                    "native_controller_unprotected",
                    "native_backup_engine_changed",
                    "native_backup_destination_invalid",
                    "native_tls_invalid",
                    "native_installation_changed",
                    "ERR_MODULE_NOT_FOUND",
                    "ERR_INVALID_ARG_VALUE",
                    "ERR_INVALID_FILE_URL_HOST",
                    "ERR_INVALID_FILE_URL_PATH",
                    "native_library_identity_invalid",
                    "manager_runtime_changed",
                    "Frameleaf Manager could not start; check its mounted configuration.",
                ] {
                    if output.contains(code) {
                        eprintln!("Installed Manager diagnostic: {code}");
                    }
                }
                for file in [
                    "main.js:",
                    "native-service.js:",
                    "native.js:",
                    "store.js:",
                    "security.js:",
                    "backups.js:",
                    "releases.js:",
                ] {
                    let line = output
                        .match_indices(file)
                        .filter(|(index, _)| {
                            *index == 0
                                || matches!(
                                    output.as_bytes()[index - 1],
                                    b'/' | b'\\' | b' ' | b'('
                                )
                        })
                        .find_map(|(index, _)| {
                            output[index + file.len()..]
                                .split(':')
                                .next()?
                                .parse::<u32>()
                                .ok()
                        });
                    if let Some(line) = line {
                        eprintln!("Installed Manager frame: {file}{line}");
                    }
                }
                let _ = complete.send(());
                let _ = std::io::copy(&mut stderr, &mut std::io::sink());
            });
        }
        let stdout = owner
            .child
            .stdout
            .take()
            .ok_or("native_manager_launch_failed")?;
        let mut pipe = owner
            .child
            .stdin
            .take()
            .ok_or("native_manager_launch_failed")?;
        std::thread::spawn(move || {
            let mut bytes = Vec::new();
            let result = BufReader::new(stdout)
                .take(1025)
                .read_until(b'\n', &mut bytes)
                .map(|_| bytes)
                .map_err(|_| "native_manager_receipt_invalid".into());
            let _ = receipt_tx.send(result);
        });
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(
                pipe.write_all(&input)
                    .map_err(|_| "native_manager_bootstrap_failed"),
            );
        });
        rx.recv_timeout(Duration::from_secs(5))
            .map_err(|_| "native_manager_bootstrap_timeout")??;
        if owner
            .child
            .try_wait()
            .map_err(|_| "native_manager_state_unavailable")?
            .is_some()
        {
            return Err("native_manager_exited".into());
        }
        Ok(owner)
    }
    /// Cancellation applies until first verified readiness; use shutdown for an already-running Manager.
    pub async fn wait_ready(
        &mut self,
        timeout: Duration,
        cancel: &AtomicBool,
    ) -> Result<(), String> {
        if self.is_running()? {
            self.startup_lease.take();
            return Ok(());
        }
        let result = self.wait_ready_inner(timeout, cancel).await;
        if result.is_err() {
            self.verified_ready = false;
            #[cfg(windows)]
            self.cleanup_windows(Duration::from_secs(5))?;
            #[cfg(not(windows))]
            {
                let _ = self.child.kill();
                let _ = self.child.wait();
            }
        }
        self.startup_lease.take();
        result
    }

    async fn wait_ready_inner(
        &mut self,
        timeout: Duration,
        cancel: &AtomicBool,
    ) -> Result<(), String> {
        let deadline = Instant::now() + timeout;
        loop {
            if cancel.load(Ordering::Acquire) {
                return Err("native_manager_start_cancelled".into());
            }
            if self
                .child
                .try_wait()
                .map_err(|_| "native_manager_state_unavailable")?
                .is_some()
            {
                return Err("native_manager_exited".into());
            }
            match self.receipt.try_recv() {
                Ok(bytes) => {
                    let bytes = bytes?;
                    #[cfg(all(test, windows))]
                    if self.stderr_diagnostic.is_some() {
                        let value = serde_json::from_slice::<Ready>(&bytes);
                        eprintln!(
                            "Installed Manager receipt: bytes={}, newline={}, decoded={}, binding_matches={}",
                            bytes.len(),
                            bytes.ends_with(b"\n"),
                            value.is_ok(),
                            value.is_ok_and(|value| value.protocol_version == 2
                                && value.state == "ready"
                                && value.installation_id == self.installation_id
                                && value.manifest_sha256 == self.manifest_sha256
                                && value.origin == self.origin)
                        );
                    }
                    ready(
                        &bytes,
                        &self.installation_id,
                        &self.manifest_sha256,
                        &self.origin,
                    )?;
                    break;
                }
                Err(mpsc::TryRecvError::Disconnected) => {
                    return Err("native_manager_receipt_invalid".into())
                }
                Err(mpsc::TryRecvError::Empty) => {}
            }
            if Instant::now() >= deadline {
                return Err("native_manager_start_timeout".into());
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err("native_manager_start_timeout".into());
        }
        let response = self
            .client
            .get(format!("{}/manager-api/status", self.origin))
            .timeout(remaining.min(Duration::from_secs(2)))
            .send()
            .await
            .map_err(|_| "native_manager_https_unverified")?;
        let status: serde_json::Value = crate::transport::json_limit(response, 16 * 1024).await?;
        if !status["claimed"].is_boolean()
            || cancel.load(Ordering::Acquire)
            || self
                .child
                .try_wait()
                .map_err(|_| "native_manager_state_unavailable")?
                .is_some()
        {
            return Err("native_manager_https_unverified".into());
        }
        self.verified_ready = true;
        Ok(())
    }
    pub(crate) fn management_identity(
        &mut self,
        config: &Configuration,
    ) -> Result<crate::manager::CertificateTrust, String> {
        if config.installation_id != self.installation_id
            || config.origin != self.origin
            || !self.is_running()?
        {
            return Err("native_manager_not_ready".into());
        }
        Ok(crate::manager::CertificateTrust {
            pem: self.certificate_pem.clone(),
            sha256: crate::manager::certificate_fingerprint(&self.certificate_pem)?,
        })
    }
    pub(crate) async fn claimed(&mut self) -> Result<bool, String> {
        if !self.is_running()? {
            return Err("native_manager_not_ready".into());
        }
        let response = self
            .client
            .get(format!("{}/manager-api/status", self.origin))
            .send()
            .await
            .map_err(|_| "native_manager_https_unverified")?;
        let status: serde_json::Value = crate::transport::json_limit(response, 16 * 1024).await?;
        status["claimed"]
            .as_bool()
            .ok_or_else(|| "native_manager_receipt_invalid".into())
    }
    pub(crate) async fn claim_local(&mut self, password: &str, proof: &str) -> Result<(), String> {
        if !self.is_running()? || !crate::native_runtime::digest_valid(proof, 64) {
            return Err("native_manager_not_ready".into());
        }
        crate::manager::claim_local(
            &self.client,
            &self.origin,
            "Local administrator",
            password,
            proof,
        )
        .await
    }
    pub(crate) fn has_exited(&mut self) -> Result<bool, String> {
        self.child
            .try_wait()
            .map(|value| value.is_some())
            .map_err(|_| "native_manager_state_unavailable".into())
    }
    #[cfg(unix)]
    pub(crate) fn process_id(&self) -> u32 {
        self.child.id()
    }
    /// Whether Manager and everything it started under this owner have exited.
    pub(crate) fn tree_exited(&mut self) -> Result<bool, String> {
        if !self.has_exited()? {
            return Ok(false);
        }
        // The Windows job also holds the controller and database; they can outlive Manager.
        #[cfg(windows)]
        {
            self.tree
                .is_empty()
                .map_err(|_| "native_manager_state_unavailable".into())
        }
        #[cfg(not(windows))]
        {
            Ok(true)
        }
    }
    /// A stand-in child for lifecycle tests; it never reports readiness.
    #[cfg(all(test, unix))]
    pub(crate) fn test_child(command: &mut Command) -> Self {
        Self::spawn(
            command,
            Zeroizing::new(b"synthetic-private-input\n".to_vec()),
            "aaaaaaaaaaaa",
            &"b".repeat(64),
            "https://127.0.0.1:9443",
            reqwest::Client::new(),
            Leases::default(),
        )
        .unwrap()
    }
    pub fn is_running(&mut self) -> Result<bool, String> {
        Ok(self.verified_ready
            && self
                .child
                .try_wait()
                .map_err(|_| "native_manager_state_unavailable")?
                .is_none())
    }
    /// Database quiescence requires separate journal/lease proof before stopping the Manager.
    pub async fn shutdown(&mut self, timeout: Duration) -> Result<(), String> {
        self.verified_ready = false;
        #[cfg(windows)]
        {
            self.cleanup_windows(timeout)
        }
        #[cfg(not(windows))]
        {
            if self
                .child
                .try_wait()
                .map_err(|_| "native_manager_state_unavailable")?
                .is_some()
            {
                return Ok(());
            }
            #[cfg(unix)]
            if unsafe { libc::kill(self.child.id() as i32, libc::SIGTERM) } != 0 {
                return Err("native_manager_shutdown_unconfirmed".into());
            }
            #[cfg(not(unix))]
            self.child
                .kill()
                .map_err(|_| "native_manager_shutdown_unconfirmed")?;
            let deadline = Instant::now() + timeout;
            loop {
                if self
                    .child
                    .try_wait()
                    .map_err(|_| "native_manager_state_unavailable")?
                    .is_some()
                {
                    return Ok(());
                }
                if Instant::now() >= deadline {
                    return Err("native_manager_shutdown_unconfirmed".into());
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        }
    }
    #[cfg(windows)]
    fn cleanup_windows(&mut self, timeout: Duration) -> Result<(), String> {
        #[cfg(test)]
        windows_tests::cleanup_barrier();
        let deadline = Instant::now() + timeout;
        self.tree
            .terminate_confirmed(timeout)
            .map_err(|_| "native_manager_shutdown_unconfirmed")?;
        // An empty job can precede its leader's process handle becoming signaled.
        loop {
            if self
                .child
                .try_wait()
                .map_err(|_| "native_manager_shutdown_unconfirmed")?
                .is_some()
            {
                return Ok(());
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err("native_manager_shutdown_unconfirmed".into());
            }
            std::thread::sleep(remaining.min(Duration::from_millis(20)));
        }
    }
}
impl Drop for NativeManager {
    fn drop(&mut self) {
        #[cfg(windows)]
        {
            if self.cleanup_windows(Duration::from_secs(5)).is_err() {
                // Retain maintenance/startup exclusion until process exit if cleanup is unproven.
                std::mem::forget(self._code_lease.take());
                std::mem::forget(self.startup_lease.take());
                std::mem::forget(std::mem::take(&mut self._profile_pins));
                let _ = self.child.kill();
            }
        }
        #[cfg(all(test, windows))]
        if let Some(diagnostic) = self.stderr_diagnostic.take() {
            let _ = diagnostic.recv_timeout(Duration::from_secs(1));
        }
        #[cfg(not(windows))]
        if !matches!(self.child.try_wait(), Ok(Some(_))) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    /// Captured from a Library 1.2.3 Manager's stored native-installation binding (synthetic fixture).
    #[cfg(unix)]
    #[test]
    fn descriptor_fingerprint_matches_the_one_manager_stored() {
        let m = "2047575e52c6bf5f0f1c3a44a56fa7ef0e8982679c4b77848f2c6a3ebc2c6435";
        let controller = format!("/opt/frameleaf/Controllers/{m}/bf2c8b0fbb382066895f40f2e7e2e10832db9ba997f99dadf685ab826b5de68b/frameleaf-native-host");
        let candidate = format!("/opt/frameleaf/Runtimes/{m}");
        let installation = Binding {
            runtime: "native",
            id: "1d0ea3c5161e",
            secure_installation_id: "c6c6b19e-000f-88a2-9241-7571029303a6".parse().unwrap(),
            controller: Path::new(&controller),
            candidate: Path::new(&candidate),
            state: Path::new("/opt/frameleaf/Profiles/1001/state"),
            manifest_sha256: m,
            source_revision: "c64039743af7bb0d68b602ff842683906019de52",
            certified: false,
            database_port: 54329,
            api_port: 2283,
        };
        let backup = crate::host_runtime::BackupEngine {
            executable: format!("{candidate}/payload/backup/restic").into(),
            sha256: "01143daba61a1dc8afb0cb3d03ba83e6b118f55b6b146b27473a09efc3df13d6".into(),
        };
        assert_eq!(
            fingerprint(
                installation,
                "bf2c8b0fbb382066895f40f2e7e2e10832db9ba997f99dadf685ab826b5de68b",
                backup,
                "My Frameleaf library",
                "frameleaf-v1.2.3-native.c64039743af7-1",
                "9fdf3df9908cdfa7823ee232f00c28e749bd4a5f04cdec60429c3c232b496ec2".into(),
            )
            .unwrap(),
            "4960f7aabe867f695d52ba16515e8f382b6d5b680135a2a5e6904995e634cd86"
        );
    }
    #[cfg(target_os = "linux")]
    #[test]
    fn a_refused_process_handle_fails_closed_except_on_a_kernel_without_one() {
        use crate::process_tree::ProcessIdentity;
        use std::os::unix::process::ExitStatusExt;
        let mut child = Command::new("/bin/sleep").arg("30").spawn().unwrap();
        let live = ProcessIdentity::of(child.id()).unwrap();
        // Unexpected refusals must not fall back to signalling a bare PID.
        for errno in [
            libc::EMFILE,
            libc::ENFILE,
            libc::ENOMEM,
            libc::EINVAL,
            libc::EPERM,
        ] {
            assert_eq!(
                request_exit_through(&live, |_| Err(errno)).unwrap_err(),
                "native_manager_orphan_running"
            );
            assert!(
                child.try_wait().unwrap().is_none(),
                "errno {errno} signalled"
            );
        }
        // The process is already gone: nothing to signal, and that is not an error.
        assert!(!request_exit_through(&live, |_| Err(libc::ESRCH)).unwrap());
        assert!(child.try_wait().unwrap().is_none());
        // Even the one permitted fallback re-reads the identity first.
        let mut reused = live.clone();
        reused.started.push('9');
        assert!(!request_exit_through(&reused, |_| Err(libc::ENOSYS)).unwrap());
        assert!(child.try_wait().unwrap().is_none());
        // A kernel without process handles is the only case that signals by PID.
        assert!(request_exit_through(&live, |_| Err(libc::ENOSYS)).unwrap());
        assert_eq!(child.wait().unwrap().signal(), Some(libc::SIGTERM));
        // A real handle reaches the recorded process.
        let mut child = Command::new("/bin/sleep").arg("30").spawn().unwrap();
        let live = ProcessIdentity::of(child.id()).unwrap();
        assert!(request_exit_through(&live, open_process_handle).unwrap());
        assert_eq!(child.wait().unwrap().signal(), Some(libc::SIGTERM));
    }
    #[cfg(unix)]
    #[test]
    fn orphaned_manager_is_stopped_only_while_the_recorded_process_is_still_the_same_one() {
        use crate::process_tree::ProcessIdentity;
        use std::os::unix::{fs::OpenOptionsExt, process::ExitStatusExt};
        let data = std::env::temp_dir()
            .canonicalize()
            .unwrap()
            .join(format!("frameleaf-owned-manager-{}", uuid::Uuid::new_v4()));
        crate::runtime_store::private_directory(&data).unwrap();
        let record = data.join(OWNED_PROCESS);
        let write = |process: &ProcessIdentity| {
            let _ = fs::remove_file(&record);
            fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&record)
                .unwrap()
                .write_all(
                    &serde_json::to_vec(&serde_json::json!({"schemaVersion":1,"process":process}))
                        .unwrap(),
                )
                .unwrap();
        };
        let cancel = AtomicBool::new(false);
        let stop_with = |timeout: Duration, listener: &dyn Fn() -> Evidence| {
            stop_orphaned_manager(&data, timeout, &cancel, listener)
        };
        let stop = || stop_with(Duration::from_secs(10), &|| Evidence::Clear).unwrap();
        assert!(!stop(), "nothing was recorded");

        for pid in [0, 1, u32::MAX] {
            assert!(ProcessIdentity::of(pid).is_none());
        }
        let mut child = Command::new("/bin/sleep").arg("30").spawn().unwrap();
        let live = ProcessIdentity::of(child.id()).unwrap();
        assert_eq!(ProcessIdentity::of(child.id()).unwrap(), live);
        assert_ne!(ProcessIdentity::of(std::process::id()).unwrap(), live);

        // The recorded PID now belongs to a process that started at another time.
        let mut reused = live.clone();
        reused.started.push('9');
        write(&reused);
        assert!(!stop());
        assert!(!record.exists(), "a stale record is forgotten");
        // Same PID and start, but it runs a different program.
        let mut other = live.clone();
        other.program = "/bin/echo".into();
        write(&other);
        assert!(!stop());
        // A record naming this app itself is never acted on.
        write(&ProcessIdentity::of(std::process::id()).unwrap());
        assert!(!stop());
        // A record that is not private could have been written by anyone. The mode is set
        // outright so the check does not depend on the umask this test runs under.
        fs::write(
            &record,
            serde_json::to_vec(&serde_json::json!({"schemaVersion":1,"process":live})).unwrap(),
        )
        .unwrap();
        fs::set_permissions(&record, std::os::unix::fs::PermissionsExt::from_mode(0o644)).unwrap();
        assert!(crate::host_state::valid_file(&fs::File::open(&record).unwrap()).is_err());
        // Neither it nor a launch that recorded no process identifies a Manager to stop, and
        // neither is cleared. A start may go on only while the port definitely refuses.
        let brief = Duration::from_millis(200);
        for intent in [false, true] {
            if intent {
                record_launch_intent(&data).unwrap();
                assert_eq!(recorded(&data), Recorded::Intent);
            } else {
                assert_eq!(recorded(&data), Recorded::Unreadable);
            }
            assert_eq!(
                recorded_manager(&data, |_| panic!("no process is named")),
                Evidence::Unknown
            );
            for answering in [Evidence::Running, Evidence::Unknown] {
                assert_eq!(
                    stop_with(brief, &|| answering).unwrap_err(),
                    "native_manager_orphan_running"
                );
            }
            assert!(!stop_with(brief, &|| Evidence::Clear).unwrap());
            assert!(record.exists(), "an unidentified record is never cleared");
        }
        assert!(
            child.try_wait().unwrap().is_none(),
            "a process that is not the recorded one must never be signalled"
        );

        // The exact process this app recorded is asked to exit, and only then forgotten.
        record_owned_process(&data, child.id()).unwrap();
        assert_eq!(
            recorded_manager(&data, ProcessIdentity::lookup),
            Evidence::Running
        );
        assert_eq!(
            recorded_manager(&data, |_| crate::process_tree::Presence::Unknown),
            Evidence::Unknown
        );
        assert!(stop());
        assert_eq!(child.wait().unwrap().signal(), Some(libc::SIGTERM));
        assert!(!record.exists());
        // Its record outliving it changes nothing.
        write(&live);
        assert!(!stop());
        assert!(!record.exists());
        fs::remove_dir_all(data).unwrap();
    }
    #[test]
    fn readiness_is_bounded_and_bound_to_this_installation_manifest_and_origin() {
        let good = br#"{"protocolVersion":2,"state":"ready","installationId":"aaaaaaaaaaaa","manifestSha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","origin":"https://127.0.0.1:9443"}
"#;
        assert!(ready(
            good,
            "aaaaaaaaaaaa",
            &"b".repeat(64),
            "https://127.0.0.1:9443"
        )
        .is_ok());
        for bytes in [
            good.replace_bytes(b"ready", b"failed"),
            good.replace_bytes(b"aaaaaaaaaaaa", b"cccccccccccc"),
            good.replace_bytes(b"9443", b"9444"),
            good.replace_bytes(b"bbbbbbbb", b"cccccccc"),
            good.replace_bytes(b"\"protocolVersion\":2", b"\"protocolVersion\":1"),
            good.replace_bytes(b"\"state\"", b"\"unknown\""),
            vec![b'x'; 1025],
            good[..good.len() - 1].to_vec(),
        ] {
            assert!(ready(
                &bytes,
                "aaaaaaaaaaaa",
                &"b".repeat(64),
                "https://127.0.0.1:9443"
            )
            .is_err());
        }
    }
    trait ReplaceBytes {
        fn replace_bytes(&self, old: &[u8], new: &[u8]) -> Vec<u8>;
    }
    impl ReplaceBytes for [u8] {
        fn replace_bytes(&self, old: &[u8], new: &[u8]) -> Vec<u8> {
            String::from_utf8_lossy(self)
                .replace(
                    std::str::from_utf8(old).unwrap(),
                    std::str::from_utf8(new).unwrap(),
                )
                .into_bytes()
        }
    }
    #[cfg(unix)]
    #[test]
    fn installed_authority_rejects_user_owned_paths_but_accepts_a_protected_system_file() {
        let path = std::env::temp_dir()
            .canonicalize()
            .unwrap()
            .join(format!("frameleaf-authority-{}", uuid::Uuid::new_v4()));
        std::fs::write(&path, b"synthetic").unwrap();
        assert!(protect(&path, &mut std::collections::BTreeSet::new()).is_err());
        std::fs::remove_file(path).unwrap();
        protect(
            &std::fs::canonicalize("/bin/echo").unwrap(),
            &mut std::collections::BTreeSet::new(),
        )
        .unwrap();
    }
    #[test]
    fn local_origin_refuses_public_addresses_aliases_and_privileged_ports() {
        assert_eq!(local_origin("https://127.0.0.1:9443").unwrap(), 9443);
        assert_eq!(local_origin("https://[::1]:19443").unwrap(), 19443);
        for origin in [
            "https://localhost:9443",
            "https://127.1:9443",
            "https://0.0.0.0:9443",
            "http://127.0.0.1:9443",
            "https://127.0.0.1",
            "https://127.0.0.1:9443/",
            "https://user@127.0.0.1:9443",
            "https://127.0.0.1:9443?q",
        ] {
            assert!(local_origin(origin).is_err());
        }
    }
    #[cfg(target_os = "macos")]
    #[test]
    fn macos_extended_acl_is_refused_even_when_it_only_grants_read_access() {
        let path = std::env::temp_dir()
            .canonicalize()
            .unwrap()
            .join(format!("frameleaf-manager-acl-{}", uuid::Uuid::new_v4()));
        fs::write(&path, b"synthetic").unwrap();
        no_acl(&path).unwrap();
        let account = Command::new("/usr/bin/id").arg("-un").output().unwrap();
        assert!(account.status.success());
        let account = String::from_utf8(account.stdout).unwrap();
        let acl = format!("user:{} allow read", account.trim());
        assert!(Command::new("/bin/chmod")
            .args(["+a", &acl])
            .arg(&path)
            .status()
            .unwrap()
            .success());
        let refused = no_acl(&path).is_err();
        fs::remove_file(path).unwrap();
        assert!(refused);
    }
    #[cfg(unix)]
    #[tokio::test]
    async fn cancellation_timeout_and_bad_receipt_reap_only_the_owned_child() {
        for mode in ["cancel", "timeout", "bad-receipt"] {
            let mut command = Command::new(if mode == "bad-receipt" {
                "/bin/sh"
            } else {
                "/bin/sleep"
            });
            if mode != "bad-receipt" {
                command.arg("30");
            } else {
                command.args(["-c", "printf 'invalid\\n'; exec /bin/sleep 30"]);
            }
            let mut owner = NativeManager::spawn(
                &mut command,
                Zeroizing::new(b"synthetic-private-input\n".to_vec()),
                "aaaaaaaaaaaa",
                &"b".repeat(64),
                "https://127.0.0.1:9443",
                reqwest::Client::new(),
                Leases::default(),
            )
            .unwrap();
            let state = std::env::temp_dir()
                .canonicalize()
                .unwrap()
                .join(format!("frameleaf-startup-lease-{}", uuid::Uuid::new_v4()));
            owner.startup_lease = Some(crate::host_state::Owner::acquire(&state, true).unwrap());
            assert!(crate::host_state::Owner::acquire(&state, true).is_err());
            assert!(!owner.is_running().unwrap());
            let result = owner
                .wait_ready(
                    Duration::from_millis(60),
                    &AtomicBool::new(mode == "cancel"),
                )
                .await;
            assert_eq!(
                result.unwrap_err(),
                match mode {
                    "cancel" => "native_manager_start_cancelled",
                    "timeout" => "native_manager_start_timeout",
                    _ => "native_manager_receipt_invalid",
                }
            );
            assert!(owner.child.try_wait().unwrap().is_some());
            assert!(owner.startup_lease.is_none());
            drop(crate::host_state::Owner::acquire(&state, true).unwrap());
            fs::remove_dir_all(state).unwrap();
        }
    }
    #[cfg(unix)]
    #[tokio::test]
    #[ignore = "requires compiled Manager/private Node and new owned fixture directory; no installed authority or keychain claim"]
    async fn compiled_manager_runs_through_the_private_supervisor_owner() {
        compiled_manager_owner(false, false).await;
    }
    #[cfg(unix)]
    #[tokio::test]
    #[ignore = "requires compiled Manager/private Node and new owned fixture directory; no installed authority or keychain claim"]
    async fn compiled_manager_revokes_stale_device_grant() {
        compiled_manager_owner(true, false).await;
    }
    #[cfg(unix)]
    #[tokio::test]
    #[ignore = "requires compiled Manager/private Node and new owned fixture directory; no installed authority or keychain claim"]
    async fn compiled_manager_restore_review_is_scoped_and_refuses_unverified_execution() {
        compiled_manager_owner(false, true).await;
    }
    #[cfg(unix)]
    async fn compiled_manager_owner(revoke_only: bool, recovery: bool) {
        let node = PathBuf::from(std::env::var("FRAMELEAF_TEST_NODE").unwrap());
        let manager = PathBuf::from(std::env::var("FRAMELEAF_TEST_MANAGER").unwrap());
        let output = PathBuf::from(std::env::var("FRAMELEAF_TEST_OUTPUT").unwrap());
        assert!(node.is_absolute() && manager.is_absolute() && output.is_absolute());
        fs::create_dir_all(&output).unwrap();
        let output = output.join(if recovery {
            "recovery"
        } else if revoke_only {
            "device-revoke"
        } else {
            "full"
        });
        fs::create_dir(&output).unwrap();
        let data = output.join("data");
        crate::runtime_store::private_directory(&data).unwrap();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let origin = format!(
            "https://127.0.0.1:{}",
            listener.local_addr().unwrap().port()
        );
        drop(listener);
        let origin = origin.as_str();
        let tls =
            TlsIdentity::load_or_create("aaaaaaaaaaaa", origin, || Ok(None), |_| Ok(())).unwrap();
        let controller = fs::canonicalize("/bin/echo").unwrap();
        let mut input=Zeroizing::new(serde_json::to_vec(&serde_json::json!({
          "protocolVersion":2,"backupKey":"k".repeat(43),"installation":{"runtime":"native","id":"aaaaaaaaaaaa","controller":controller,"candidate":output.join("runtime"),"state":output.join("state"),"manifestSha256":"b".repeat(64),"sourceRevision":"c".repeat(40),"certified":false,"databasePort":54329,"apiPort":2283},
          "controllerSha256":format!("{:x}",Sha256::digest(fs::read(&controller).unwrap())),"backupEngine":{"executable":controller,"sha256":format!("{:x}",Sha256::digest(fs::read(&controller).unwrap()))},"name":"Synthetic owner fixture","release":"frameleaf-v3.0.0-1","password":"synthetic native database password","tls":tls.wire()
        })).unwrap());
        input.push(b'\n');
        let client = reqwest::Client::builder()
            .no_proxy()
            .tls_built_in_root_certs(false)
            .redirect(reqwest::redirect::Policy::none())
            .add_root_certificate(
                reqwest::Certificate::from_pem(tls.certificate().as_bytes()).unwrap(),
            )
            .timeout(Duration::from_secs(2))
            .build()
            .unwrap();
        let mut command = Command::new(node);
        command
            .arg(manager.join("build/main.js"))
            .env_clear()
            .env("PATH", "")
            .env("MANAGER_RUNTIME", "native")
            .env("MANAGER_ORIGIN", origin)
            .env("MANAGER_DATA", &data);
        // Exercise the real owner primitive with a development package; public Programs::start still refuses this unprotected payload.
        let mut owner = NativeManager::spawn(
            &mut command,
            input,
            "aaaaaaaaaaaa",
            &"b".repeat(64),
            origin,
            client,
            Leases::default(),
        )
        .unwrap();
        let state = output.join("state");
        owner.startup_lease = Some(crate::host_state::Owner::acquire(&state, true).unwrap());
        assert!(crate::host_state::Owner::acquire(&state, true).is_err());
        owner
            .wait_ready(Duration::from_secs(10), &AtomicBool::new(false))
            .await
            .unwrap();
        assert!(owner.is_running().unwrap());
        assert!(owner.startup_lease.is_none());
        drop(crate::host_state::Owner::acquire(&state, true).unwrap());
        owner
            .wait_ready(Duration::from_secs(1), &AtomicBool::new(false))
            .await
            .unwrap();
        owner.certificate_pem = tls.certificate().into();
        let configuration = Configuration {
            installation_id: "aaaaaaaaaaaa".into(),
            name: "Synthetic owner fixture".into(),
            release: "frameleaf-v3.0.0-1".into(),
            controller: fs::canonicalize("/bin/echo").unwrap(),
            state: state.clone(),
            data: data.clone(),
            origin: origin.into(),
            database_port: 54329,
            api_port: 2283,
        };
        let identity = crate::connection::DeviceIdentity::generate();
        let password = "synthetic local Manager password";
        if !revoke_only {
            let interrupted = crate::host_setup::authorize_owner(
                &mut owner,
                &configuration,
                &identity,
                Zeroizing::new(password.into()),
                false,
                None,
                |_| Err("credential_store_locked_or_unavailable".into()),
            )
            .await;
            assert_eq!(
                interrupted.err().unwrap(),
                "credential_store_locked_or_unavailable"
            );
            assert!(owner.claimed().await.unwrap());
            // Retry after a committed claim must not read or replace the original proof/password.
            fs::remove_file(data.join("claim-key")).unwrap();
        }
        let saved = std::cell::RefCell::new(None::<crate::manager::SavedManager>);
        let paired = crate::host_setup::authorize_owner(
            &mut owner,
            &configuration,
            &identity,
            Zeroizing::new(password.into()),
            recovery,
            None,
            |record| {
                let encoded = Zeroizing::new(serde_json::to_string(record).unwrap());
                *saved.borrow_mut() = Some(serde_json::from_str(&encoded).unwrap());
                Ok(())
            },
        )
        .await
        .unwrap();
        assert_eq!(paired.installation_id, configuration.installation_id);
        assert_eq!(
            paired.certificate_sha256,
            Some(crate::manager::certificate_fingerprint(tls.certificate()).unwrap())
        );
        let public = serde_json::to_string(&paired).unwrap();
        assert!(
            !public.contains(password)
                && !public.contains("token")
                && !public.contains("proof")
                && !public.contains("PRIVATE KEY")
        );
        let stored = saved.borrow_mut().take().unwrap();
        let encoded = Zeroizing::new(serde_json::to_string(&stored).unwrap());
        let status = crate::manager::send(&stored, &identity, crate::manager::Command::Status {})
            .await
            .unwrap();
        assert_eq!(status["manager"]["id"], paired.manager_id);
        assert_eq!(status["installation"]["id"], configuration.installation_id);
        if recovery {
            use crate::manager::{send, Command, Scope};
            assert!(paired.scopes.contains(&Scope::Restore));
            let key = uuid::Uuid::new_v4();
            let accepted = send(
                &stored,
                &identity,
                Command::ReviewRestore {
                    snapshot: "1".repeat(64),
                    key,
                },
            )
            .await
            .unwrap();
            assert_eq!(accepted["id"], key.to_string());
            let deadline = Instant::now() + Duration::from_secs(10);
            loop {
                let review = send(
                    &stored,
                    &identity,
                    Command::RestoreReview {
                        id: key,
                        snapshot: "1".repeat(64),
                    },
                )
                .await
                .unwrap();
                if review["state"] != "preparing" {
                    assert_eq!(review["state"], "failed");
                    break;
                }
                assert!(
                    Instant::now() < deadline,
                    "owned fixture review did not finish"
                );
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            // The fixture engine is echo: real Manager must reject absent readback before any host mutation.
            assert_eq!(
                send(
                    &stored,
                    &identity,
                    Command::Restore {
                        review_id: key,
                        key: uuid::Uuid::new_v4()
                    }
                )
                .await
                .err()
                .unwrap(),
                "native_restore_review_not_ready"
            );
            let status = send(&stored, &identity, Command::Status {}).await.unwrap();
            assert_eq!(status["operations"], serde_json::json!([]));
            owner.shutdown(Duration::from_secs(5)).await.unwrap();
            assert!(!owner.is_running().unwrap());
            return;
        }
        let photos =
            crate::host_setup::photos_owner(&mut owner, &configuration, &identity, &stored)
                .await
                .unwrap();
        assert_eq!(photos.as_str(), "http://127.0.0.1:2283/");
        if revoke_only {
            let old_grant = stored;
            let replacement_identity = crate::connection::DeviceIdentity::generate();
            assert!(old_grant.require_device(&replacement_identity).is_err());
            // An administrator can revoke the stale grant without its lost device key.
            crate::manager::disconnect(&old_grant, password.into())
                .await
                .unwrap();
            assert!(crate::manager::send(
                &old_grant,
                &identity,
                crate::manager::Command::Status {}
            )
            .await
            .is_err());
            owner.shutdown(Duration::from_secs(5)).await.unwrap();
            assert!(!owner.is_running().unwrap());
            return;
        }
        let again = crate::host_setup::authorize_owner(
            &mut owner,
            &configuration,
            &identity,
            Zeroizing::new(password.into()),
            false,
            Some(stored),
            |_| panic!("existing grant must not be replaced"),
        )
        .await
        .unwrap();
        assert_eq!(again.manager_id, paired.manager_id);
        for (field, value, expected) in [
            (
                "installationId",
                serde_json::json!("dddddddddddd"),
                "manager_already_paired",
            ),
            ("expiresAt", serde_json::json!(1), "manager_pairing_expired"),
            (
                "certificatePem",
                serde_json::Value::Null,
                "manager_already_paired",
            ),
            (
                "origin",
                serde_json::json!("https://nas.example"),
                "manager_already_paired",
            ),
            (
                "deviceId",
                serde_json::json!(uuid::Uuid::new_v4().to_string()),
                "manager_device_changed",
            ),
        ] {
            let mut record: serde_json::Value = serde_json::from_str(&encoded).unwrap();
            record[field] = value;
            let existing = serde_json::from_value(record).unwrap();
            assert_eq!(
                crate::host_setup::photos_owner(&mut owner, &configuration, &identity, &existing)
                    .await
                    .unwrap_err(),
                expected
            );
            let refused = crate::host_setup::authorize_owner(
                &mut owner,
                &configuration,
                &identity,
                Zeroizing::new(password.into()),
                false,
                Some(existing),
                |_| panic!("must preserve existing pairing"),
            )
            .await;
            assert_eq!(refused.err().unwrap(), expected);
        }
        owner.shutdown(Duration::from_secs(5)).await.unwrap();
        assert!(!owner.is_running().unwrap());
        assert!(!data.join("tls.key").exists() && !data.join("tls.crt").exists());
    }
    #[test]
    fn setup_storage_refuses_aliases_links_and_runtime_overlap() {
        let root = std::env::temp_dir()
            .canonicalize()
            .unwrap()
            .join(format!("frameleaf-setup-paths-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&root).unwrap();
        let candidate = root.join("runtime");
        fs::create_dir(&candidate).unwrap();
        let state = root.join("state");
        let data = root.join("data");
        validate_paths(&candidate, &state, &data).unwrap();
        fs::create_dir(&state).unwrap();
        fs::create_dir(&data).unwrap();
        validate_paths(&candidate, &state, &data).unwrap();
        for (state, data) in [(&candidate, &data), (&state, &state), (&root, &data)] {
            assert!(validate_paths(&candidate, state, data).is_err());
        }
        let alias = root.join("STATE");
        if alias.exists() {
            assert!(validate_paths(&candidate, &state, &alias).is_err());
        }
        #[cfg(unix)]
        {
            let link = root.join("linked-state");
            std::os::unix::fs::symlink(&state, &link).unwrap();
            assert!(validate_paths(&candidate, &link, &data).is_err());
        }
        fs::remove_dir_all(root).unwrap();
    }
    #[cfg(unix)]
    #[test]
    fn profile_parent_authority_refuses_home_style_paths_without_touching_system_folders() {
        let parent = std::env::temp_dir().canonicalize().unwrap();
        let mut config = Configuration {
            installation_id: "a".repeat(12),
            name: "Synthetic".into(),
            release: "frameleaf-v3.0.0-1".into(),
            controller: std::path::PathBuf::from("/bin/echo"),
            state: parent.join("state"),
            data: parent.join("data"),
            origin: "https://127.0.0.1:9443".into(),
            database_port: 54329,
            api_port: 2283,
        };
        assert!(protect_profile_parents(&config).is_err());
        let protected = std::fs::canonicalize("/usr/bin").unwrap();
        config.state = protected.join("synthetic-state-not-created");
        config.data = protected.join("synthetic-data-not-created");
        protect_profile_parents(&config).unwrap();
    }
}
