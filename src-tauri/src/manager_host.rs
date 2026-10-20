//! Native-only Manager owner. No caller-supplied command, browser credentials or stored PID authority.
use crate::{
    host_epochs::{HostEpochAuthority, HostExecution},
    host_runtime::VerifiedHostRuntime,
    manager_tls::TlsIdentity,
};
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

#[cfg(all(test, unix))]
#[path = "manager_host_unix_tests.rs"]
mod unix_tests;
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
    // Keep historical profile-account hashes stable; the bootstrap serializes UUID explicitly.
    #[serde(skip)]
    pub secure_installation_id: String,
    pub name: String,
    pub release: String,
    pub controller: PathBuf,
    pub state: PathBuf,
    pub data: PathBuf,
    pub origin: String,
    pub database_port: u16,
    pub api_port: u16,
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
        || !crate::host_state::valid_installation_id(&config.secure_installation_id)
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
    pub(crate) secure_installation_id: Option<String>,
    child: Child,
    tree: crate::process_tree::ProcessTree,
    shutdown_confirmed: bool,
    #[cfg(unix)]
    shutdown_signalled: bool,
    receipt: mpsc::Receiver<Result<Vec<u8>, String>>,
    installation_id: String,
    manifest_sha256: String,
    origin: String,
    client: reqwest::Client,
    verified_ready: bool,
    startup_lease: Option<crate::host_state::Owner>,
    certificate_pem: String,
    _code_lease: Option<crate::package_lease::CodeLease>,
    _profile_pins: Vec<fs::File>,
    _profile_guard: Option<crate::manager_profile::ProfileGuard>,
}
#[derive(Default)]
struct Leases<'a> {
    execution: Option<(&'a HostExecution<'a>, &'a VerifiedHostRuntime)>,
    code: Option<crate::package_lease::CodeLease>,
    startup: Option<crate::host_state::Owner>,
    profiles: Vec<fs::File>,
    profile: Option<crate::manager_profile::ProfileGuard>,
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
        let mut profile = crate::manager_profile::Profile::from_keystore(
            config,
            candidate,
            self.runtime.manifest_sha256(),
        )?;
        let tls =
            TlsIdentity::from_keystore(&config.installation_id, &config.origin, profile.binding())?;
        let authority = crate::credentials::CredentialEpochAuthority;
        authority.activate(&config.secure_installation_id, self.runtime, &mut || {
            profile.require_current(config)
        })?;
        let execution = HostExecution::new(&authority, &config.secure_installation_id)?;
        let lease = crate::host_state::Owner::acquire(
            &config.state,
            true,
            profile.installation_identity()?,
        )?;
        let password = profile.password();
        let backup_key = profile.backup_key()?;
        let guard = profile.take_guard()?;
        drop(profile);
        self.start_owned(
            config,
            &password,
            &backup_key,
            &tls,
            Leases {
                execution: Some((&execution, self.runtime)),
                startup: Some(lease),
                profile: Some(guard),
                ..Leases::default()
            },
        )
    }
    /// Caller must persist the database password before use; it never enters argv/env/logs.
    pub fn start(
        &self,
        config: &Configuration,
        password: &Zeroizing<String>,
        backup_key: &Zeroizing<String>,
        tls: &TlsIdentity,
        execution: &HostExecution<'_>,
    ) -> Result<NativeManager, String> {
        self.start_owned(
            config,
            password,
            backup_key,
            tls,
            Leases {
                execution: Some((execution, self.runtime)),
                ..Leases::default()
            },
        )
    }
    fn start_owned(
        &self,
        config: &Configuration,
        password: &Zeroizing<String>,
        backup_key: &Zeroizing<String>,
        tls: &TlsIdentity,
        mut leases: Leases<'_>,
    ) -> Result<NativeManager, String> {
        validate_configuration(config)?;
        let (execution, _) = leases.execution.ok_or("host_epoch_not_admitted")?;
        if execution.installation_id() != config.secure_installation_id {
            return Err("host_installation_identity_changed".into());
        }
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
        if leases.profile.is_none() {
            leases.profile = Some(crate::manager_profile::ProfileGuard::acquire(config)?);
        }
        validate_paths(candidate, &config.state, &config.data)?;
        crate::manager_profile::check_start(config)?;
        leases
            .profile
            .as_ref()
            .ok_or("native_profile_unavailable")?
            .require_current(config)?;
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
        struct Binding<'a> {
            runtime: &'a str,
            id: &'a str,
            secure_installation_id: &'a str,
            controller: &'a Path,
            candidate: &'a Path,
            state: &'a Path,
            manifest_sha256: &'a str,
            source_revision: &'a str,
            certified: bool,
            database_port: u16,
            api_port: u16,
        }
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
        }
        let bootstrap = Bootstrap {
            protocol_version: 2,
            installation: Binding {
                runtime: "native",
                id: &config.installation_id,
                secure_installation_id: &config.secure_installation_id,
                controller: &config.controller,
                candidate,
                state: &config.state,
                manifest_sha256: self.runtime.manifest_sha256(),
                source_revision: self.runtime.source_revision(),
                certified: self.runtime.certified(),
                database_port: config.database_port,
                api_port: config.api_port,
            },
            controller_sha256: &controller_hash,
            backup_engine: self.runtime.backup_engine()?,
            name: &config.name,
            release: &config.release,
            password,
            backup_key,
            tls: tls.wire(),
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
        command.env("NODE_OPTIONS", crate::windows_protection::NODE_PATH_OPTIONS);
        leases.code = Some(code_lease);
        leases.profiles = profile_pins;
        let mut manager = NativeManager::spawn(
            &mut command,
            input,
            &config.installation_id,
            self.runtime.manifest_sha256(),
            &config.origin,
            client,
            leases,
        )?;
        manager.certificate_pem = tls.certificate().into();
        Ok(manager)
    }
}
impl NativeManager {
    fn spawn(
        command: &mut Command,
        input: Zeroizing<Vec<u8>>,
        id: &str,
        hash: &str,
        origin: &str,
        client: reqwest::Client,
        leases: Leases<'_>,
    ) -> Result<Self, String> {
        #[cfg(unix)]
        let mut leases = leases;
        if let Some(lease) = &leases.code {
            lease.inherit(command);
        }
        #[cfg(not(test))]
        if leases.profile.is_none() {
            return Err("native_profile_unavailable".into());
        }
        #[cfg(unix)]
        if let Some(profile) = &leases.profile {
            profile.inherit(command);
        }
        crate::process_tree::configure(command);
        let launch = || {
            command
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn()
                .map_err(|_| "native_manager_launch_failed".to_string())
        };
        let child = match leases.execution {
            Some((execution, runtime)) => execution.spawn(runtime, launch)?,
            #[cfg(test)]
            None => {
                let mut launch = launch;
                launch()?
            }
            #[cfg(not(test))]
            None => return Err("host_epoch_not_admitted".into()),
        };
        #[cfg(unix)]
        if let Some(profile) = &mut leases.profile {
            profile.child_spawned();
        }
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
            secure_installation_id: leases
                .startup
                .as_ref()
                .and_then(|owner| owner.installation_identity())
                .map(str::to_owned),
            child,
            tree,
            shutdown_confirmed: false,
            #[cfg(unix)]
            shutdown_signalled: false,
            receipt,
            installation_id: id.into(),
            manifest_sha256: hash.into(),
            origin: origin.into(),
            client,
            verified_ready: false,
            startup_lease: leases.startup,
            certificate_pem: String::new(),
            _code_lease: leases.code,
            _profile_pins: leases.profiles,
            _profile_guard: leases.profile,
        };
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
        if owner.child_exited()? {
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
            self.cleanup_owned(Duration::from_secs(5))?;
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
            if self.child_exited()? {
                return Err("native_manager_exited".into());
            }
            match self.receipt.try_recv() {
                Ok(bytes) => {
                    ready(
                        &bytes?,
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
            || self.child_exited()?
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
    pub(crate) async fn create_administrator(
        &mut self,
        config: &Configuration,
        name: &str,
        password: &str,
    ) -> Result<(), String> {
        let name = name.trim();
        if name.is_empty()
            || name.encode_utf16().count() > 120
            || name.chars().any(char::is_control)
        {
            return Err("manager_account_details_invalid".into());
        }
        crate::host_setup::require_password(password)?;
        self.management_identity(config)?;
        if self.claimed().await? {
            return Err("manager_account_exists".into());
        }
        self.management_identity(config)?;
        #[derive(Serialize)]
        struct Account<'a> {
            name: &'a str,
            password: &'a str,
        }
        let response = self
            .client
            .post(format!("{}/manager-api/claim", self.origin))
            .header(reqwest::header::ORIGIN, &self.origin)
            .json(&Account { name, password })
            .send()
            .await
            .map_err(|_| "native_manager_https_unverified")?;
        if response.status() == reqwest::StatusCode::CONFLICT {
            return Err("manager_account_exists".into());
        }
        if !response.status().is_success() {
            return Err("manager_account_creation_failed".into());
        }
        let result: serde_json::Value = crate::transport::json_limit(response, 4096)
            .await
            .map_err(|_| "native_manager_receipt_invalid")?;
        if !result["csrf"]
            .as_str()
            .is_some_and(|value| crate::native_runtime::digest_valid(value, 64))
            || !self.claimed().await?
        {
            return Err("native_manager_receipt_invalid".into());
        }
        self.management_identity(config)?;
        Ok(())
    }
    pub(crate) async fn stop_idle(
        &mut self,
        config: &Configuration,
        manifest: &str,
        timeout: Duration,
    ) -> Result<(), String> {
        validate_configuration(config)?;
        if self.installation_id != config.installation_id
            || self.secure_installation_id.as_deref()
                != Some(config.secure_installation_id.as_str())
            || self.manifest_sha256 != manifest
            || self.origin != config.origin
        {
            return Err("native_manager_not_ready".into());
        }
        self._profile_guard
            .as_ref()
            .ok_or("native_profile_recovery_required")?
            .require_current(config)?;
        let check = |proof: &mut crate::host_state::Owner, allow_reserved: bool| {
            if proof.installation_identity() != Some(config.secure_installation_id.as_str()) {
                return Err("host_installation_identity_changed".into());
            }
            match proof.admit_idle(&config.installation_id, manifest) {
                Ok(()) => Ok(()),
                // Cleanup of an already stopped or retained owner never clears the update fence.
                Err(_) if allow_reserved => proof
                    .review_reserved_update(&config.installation_id, manifest)
                    .map(|_| ()),
                Err(error) => Err(error),
            }
        };
        if let Some(proof) = self.startup_lease.as_mut() {
            check(proof, true)?;
        } else {
            let mut proof = crate::host_state::Owner::acquire_update(
                &config.state,
                &config.secure_installation_id,
            )?;
            check(&mut proof, self.shutdown_confirmed)?;
            self.startup_lease = Some(proof);
        }
        self.shutdown(timeout).await?;
        self.startup_lease.take();
        Ok(())
    }
    /// Retain the Manager profile and controller exclusions through the durable update fence.
    pub async fn reserve_update(
        &mut self,
        source: &VerifiedHostRuntime,
        target: &VerifiedHostRuntime,
        config: &Configuration,
        execution: &HostExecution<'_>,
    ) -> Result<crate::host_runtime::HostUpdateReservation, String> {
        validate_configuration(config)?;
        if self.installation_id != config.installation_id
            || self.secure_installation_id.as_deref()
                != Some(config.secure_installation_id.as_str())
            || self.manifest_sha256 != source.manifest_sha256()
            || self.origin != config.origin
            || self._code_lease.is_none()
            || self.startup_lease.is_some()
            || !self.is_running()?
        {
            return Err("native_manager_not_ready".into());
        }
        self._profile_guard
            .as_ref()
            .ok_or("native_profile_recovery_required")?
            .require_current(config)?;
        // Refuse unsupported targets or active database owners before stopping the live Manager.
        source.update_candidate_paths(target, config)?;
        source.review_update(target, &config.state, &config.installation_id, execution)?;
        let mut owner =
            crate::host_state::Owner::acquire_update(&config.state, execution.installation_id())?;
        owner.admit_idle(&config.installation_id, source.manifest_sha256())?;
        // Keep this in the owner before awaiting: cancellation must retain controller exclusion too.
        self.startup_lease = Some(owner);
        self.shutdown(Duration::from_secs(10)).await?;
        let result = source.reserve_update_held(
            target,
            config,
            execution,
            self._profile_guard
                .as_ref()
                .ok_or("native_profile_recovery_required")?,
            self.startup_lease
                .as_mut()
                .ok_or("native_manager_not_ready")?,
        );
        if result.is_ok() {
            self.startup_lease.take();
        }
        result
    }
    pub(crate) fn has_exited(&mut self) -> Result<bool, String> {
        if self.shutdown_confirmed {
            return Ok(true);
        }
        let exited = self.child_exited()?;
        if exited {
            self.cleanup_owned(Duration::from_secs(5))?;
        }
        Ok(exited)
    }
    pub fn is_running(&mut self) -> Result<bool, String> {
        Ok(self.verified_ready && !self.has_exited()?)
    }
    /// Database quiescence requires separate journal/lease proof before stopping the Manager.
    pub async fn shutdown(&mut self, timeout: Duration) -> Result<(), String> {
        self.verified_ready = false;
        if self.shutdown_confirmed {
            return Ok(());
        }
        #[cfg(windows)]
        {
            self.cleanup_owned(timeout)
        }
        #[cfg(not(windows))]
        {
            if self.has_exited()? {
                return Ok(());
            }
            #[cfg(unix)]
            if unsafe { libc::kill(self.child.id() as i32, libc::SIGTERM) } != 0 {
                return Err("native_manager_shutdown_unconfirmed".into());
            }
            let deadline = Instant::now() + timeout;
            loop {
                if self.child_exited()? {
                    return self.cleanup_owned(timeout);
                }
                if Instant::now() >= deadline {
                    return Err("native_manager_shutdown_unconfirmed".into());
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        }
    }
    fn child_exited(&mut self) -> Result<bool, String> {
        #[cfg(windows)]
        return self
            .child
            .try_wait()
            .map(|status| status.is_some())
            .map_err(|_| "native_manager_state_unavailable".into());
        #[cfg(unix)]
        {
            if self.shutdown_confirmed {
                return Ok(true);
            }
            let mut info = std::mem::MaybeUninit::<libc::siginfo_t>::zeroed();
            let result = unsafe {
                libc::waitid(
                    libc::P_PID,
                    self.child.id(),
                    info.as_mut_ptr(),
                    libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
                )
            };
            if result != 0 {
                let error = std::io::Error::last_os_error();
                if error.raw_os_error() == Some(libc::EINTR) {
                    return Ok(false);
                }
                if error.raw_os_error() == Some(libc::ECHILD) {
                    self.shutdown_signalled = true;
                }
                return Err("native_manager_state_unavailable".into());
            }
            // Keep the leader unreaped until the owned group has received its final signal.
            Ok(unsafe { info.assume_init().si_pid() } != 0)
        }
    }
    fn cleanup_owned(&mut self, timeout: Duration) -> Result<(), String> {
        if self.shutdown_confirmed {
            return Ok(());
        }
        #[cfg(windows)]
        self.cleanup_windows(timeout)?;
        #[cfg(unix)]
        self.tree
            .terminate_child_confirmed(&mut self.child, &mut self.shutdown_signalled, timeout)
            .map_err(|_| "native_manager_shutdown_unconfirmed")?;
        self.shutdown_confirmed = true;
        Ok(())
    }
    #[cfg(windows)]
    fn cleanup_windows(&mut self, timeout: Duration) -> Result<(), String> {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::{
            Foundation::WAIT_OBJECT_0, System::Threading::WaitForSingleObject,
        };
        let deadline = Instant::now() + timeout;
        self.tree
            .terminate_confirmed(timeout)
            .map_err(|_| "native_manager_shutdown_unconfirmed")?;
        // Empty job accounting can precede the leader handle becoming signalled.
        let remaining = deadline.saturating_duration_since(Instant::now());
        let milliseconds = remaining.as_millis().min(u128::from(u32::MAX - 1)) as u32;
        if unsafe { WaitForSingleObject(self.child.as_raw_handle(), milliseconds) } != WAIT_OBJECT_0
        {
            return Err("native_manager_shutdown_unconfirmed".into());
        }
        match self.child.try_wait() {
            Ok(Some(_)) => Ok(()),
            _ => Err("native_manager_shutdown_unconfirmed".into()),
        }
    }
}
impl Drop for NativeManager {
    fn drop(&mut self) {
        if self.cleanup_owned(Duration::from_secs(5)).is_err() {
            // Unproven descendant shutdown must retain every exclusion until this supervisor exits.
            std::mem::forget(self._code_lease.take());
            std::mem::forget(self.startup_lease.take());
            std::mem::forget(self._profile_guard.take());
            std::mem::forget(std::mem::take(&mut self._profile_pins));
            #[cfg(windows)]
            let _ = self.child.kill();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
    #[test]
    fn session_identity_survives_startup_lease_release_without_credential_access() {
        let identity = "11111111-1111-4111-8111-111111111111";
        let state = std::env::temp_dir().canonicalize().unwrap().join(format!(
            "frameleaf-manager-identity-{}",
            uuid::Uuid::new_v4()
        ));
        let startup = crate::host_state::Owner::acquire(&state, true, identity).unwrap();
        let mut command = Command::new("/bin/sleep");
        command.arg("30");
        let mut manager = NativeManager::spawn(
            &mut command,
            Zeroizing::new(b"synthetic-private-input\n".to_vec()),
            "aaaaaaaaaaaa",
            &"b".repeat(64),
            "https://127.0.0.1:9443",
            reqwest::Client::new(),
            Leases {
                startup: Some(startup),
                ..Leases::default()
            },
        )
        .unwrap();
        assert_eq!(manager.secure_installation_id.as_deref(), Some(identity));
        manager.startup_lease.take();
        assert_eq!(manager.secure_installation_id.as_deref(), Some(identity));
        drop(crate::host_state::Owner::acquire(&state, true, identity).unwrap());
        drop(manager);
        fs::remove_dir_all(state).unwrap();
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
            owner.startup_lease = Some(
                crate::host_state::Owner::acquire(
                    &state,
                    true,
                    "11111111-1111-4111-8111-111111111111",
                )
                .unwrap(),
            );
            assert!(crate::host_state::Owner::acquire(
                &state,
                true,
                "11111111-1111-4111-8111-111111111111"
            )
            .is_err());
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
            drop(
                crate::host_state::Owner::acquire(
                    &state,
                    true,
                    "11111111-1111-4111-8111-111111111111",
                )
                .unwrap(),
            );
            fs::remove_dir_all(state).unwrap();
        }
    }
    #[cfg(unix)]
    #[tokio::test]
    async fn local_authorization_without_an_administrator_never_creates_an_account_or_grant() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        listener.set_nonblocking(true).unwrap();
        let server = std::thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(2);
            let mut stream = loop {
                match listener.accept() {
                    Ok((stream, _)) => break stream,
                    Err(error)
                        if error.kind() == std::io::ErrorKind::WouldBlock
                            && Instant::now() < deadline =>
                    {
                        std::thread::sleep(Duration::from_millis(5))
                    }
                    Err(error) => panic!("status request unavailable: {error}"),
                }
            };
            stream.set_nonblocking(false).unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(1)))
                .unwrap();
            let mut bytes = [0; 4096];
            let length = stream.read(&mut bytes).unwrap();
            let request = String::from_utf8(bytes[..length].to_vec()).unwrap();
            let body = r#"{"claimed":false}"#;
            write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", body.len(), body).unwrap();
            request
        });
        let mut command = Command::new("/bin/sleep");
        command.arg("30");
        let mut owner = NativeManager::spawn(
            &mut command,
            Zeroizing::new(b"synthetic input\n".to_vec()),
            "aaaaaaaaaaaa",
            &"b".repeat(64),
            &origin,
            reqwest::Client::builder()
                .no_proxy()
                .timeout(Duration::from_secs(1))
                .build()
                .unwrap(),
            Leases::default(),
        )
        .unwrap();
        owner.verified_ready = true;
        let wire: serde_json::Value =
            serde_json::from_str(include_str!("manager_wire.json")).unwrap();
        owner.certificate_pem = wire["certificatePem"].as_str().unwrap().into();
        let root = std::env::temp_dir().join(format!(
            "frameleaf-existing-account-{}",
            uuid::Uuid::new_v4()
        ));
        let configuration = Configuration {
            installation_id: "aaaaaaaaaaaa".into(),
            secure_installation_id: "11111111-1111-4111-8111-111111111111".into(),
            name: "Synthetic existing account".into(),
            release: "frameleaf-v3.0.0-1".into(),
            controller: fs::canonicalize("/bin/echo").unwrap(),
            state: root.join("state"),
            data: root.join("data"),
            origin,
            database_port: 54329,
            api_port: 2283,
        };
        let persisted = std::cell::Cell::new(false);
        let result = crate::host_setup::authorize_owner(
            &mut owner,
            &configuration,
            &crate::connection::DeviceIdentity::generate(),
            Zeroizing::new("synthetic existing password".into()),
            false,
            false,
            None,
            |_| {
                persisted.set(true);
                Ok(())
            },
        )
        .await;
        assert_eq!(result.err().unwrap(), "manager_initialization_required");
        assert!(!persisted.get());
        assert!(server
            .join()
            .unwrap()
            .starts_with("GET /manager-api/status HTTP/1.1\r\n"));
        assert!(!root.exists());
    }

    #[cfg(unix)]
    fn account_owner(origin: &str) -> (NativeManager, Configuration) {
        let mut command = Command::new("/bin/sleep");
        command.arg("30");
        let mut owner = NativeManager::spawn(
            &mut command,
            Zeroizing::new(b"synthetic input\n".to_vec()),
            "aaaaaaaaaaaa",
            &"b".repeat(64),
            origin,
            reqwest::Client::builder()
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(Duration::from_secs(1))
                .build()
                .unwrap(),
            Leases::default(),
        )
        .unwrap();
        owner.verified_ready = true;
        let wire: serde_json::Value =
            serde_json::from_str(include_str!("manager_wire.json")).unwrap();
        owner.certificate_pem = wire["certificatePem"].as_str().unwrap().into();
        let root = std::env::temp_dir().join(format!("frameleaf-account-{}", uuid::Uuid::new_v4()));
        let config = Configuration {
            installation_id: "aaaaaaaaaaaa".into(),
            secure_installation_id: "11111111-1111-4111-8111-111111111111".into(),
            name: "Synthetic owner".into(),
            release: "frameleaf-v3.0.0-1".into(),
            controller: fs::canonicalize("/bin/echo").unwrap(),
            state: root.join("state"),
            data: root.join("data"),
            origin: origin.into(),
            database_port: 54329,
            api_port: 2283,
        };
        (owner, config)
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn password_account_creation_uses_only_explicit_credentials_and_never_overwrites_an_account(
    ) {
        for (case, responses, expected) in [
            (
                "created",
                vec![
                    (200, r#"{"claimed":false}"#.to_string()),
                    (201, format!(r#"{{"csrf":"{}"}}"#, "a".repeat(64))),
                    (200, r#"{"claimed":true}"#.to_string()),
                ],
                None,
            ),
            (
                "exists",
                vec![(200, r#"{"claimed":true}"#.to_string())],
                Some("manager_account_exists"),
            ),
            (
                "raced",
                vec![
                    (200, r#"{"claimed":false}"#.to_string()),
                    (409, r#"{"code":"already_claimed"}"#.to_string()),
                ],
                Some("manager_account_exists"),
            ),
            (
                "legacy-refused",
                vec![
                    (200, r#"{"claimed":false}"#.to_string()),
                    (400, r#"{"code":"invalid_request"}"#.to_string()),
                ],
                Some("manager_account_creation_failed"),
            ),
            (
                "malformed-success",
                vec![
                    (200, r#"{"claimed":false}"#.to_string()),
                    (201, r#"{"csrf":"wrong"}"#.to_string()),
                ],
                Some("native_manager_receipt_invalid"),
            ),
            (
                "not-created",
                vec![
                    (200, r#"{"claimed":false}"#.to_string()),
                    (201, format!(r#"{{"csrf":"{}"}}"#, "a".repeat(64))),
                    (200, r#"{"claimed":false}"#.to_string()),
                ],
                Some("native_manager_receipt_invalid"),
            ),
        ] {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let origin = format!("http://{}", listener.local_addr().unwrap());
            listener.set_nonblocking(true).unwrap();
            let server = std::thread::spawn(move || {
                let mut requests = Vec::new();
                for (status, body) in responses {
                    let deadline = Instant::now() + Duration::from_secs(3);
                    let stream = loop {
                        match listener.accept() {
                            Ok((stream, _)) => break stream,
                            Err(error)
                                if error.kind() == std::io::ErrorKind::WouldBlock
                                    && Instant::now() < deadline =>
                            {
                                std::thread::sleep(Duration::from_millis(5))
                            }
                            Err(error) => panic!("account request missing: {error}"),
                        }
                    };
                    stream.set_nonblocking(false).unwrap();
                    stream
                        .set_read_timeout(Some(Duration::from_secs(1)))
                        .unwrap();
                    let mut reader = BufReader::new(stream);
                    let mut header = String::new();
                    let mut length = 0;
                    loop {
                        let mut line = String::new();
                        assert!(reader.read_line(&mut line).unwrap() > 0);
                        if line == "\r\n" {
                            break;
                        }
                        if let Some(value) =
                            line.to_ascii_lowercase().strip_prefix("content-length: ")
                        {
                            length = value.trim().parse::<usize>().unwrap();
                        }
                        header.push_str(&line);
                        assert!(header.len() < 8192);
                    }
                    assert!(length < 4096);
                    let mut payload = vec![0; length];
                    reader.read_exact(&mut payload).unwrap();
                    write!(reader.get_mut(), "HTTP/1.1 {status} Response\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",body.len()).unwrap();
                    requests.push((header, payload));
                }
                requests
            });
            let (mut owner, config) = account_owner(&origin);
            let result = owner
                .create_administrator(&config, "  Test owner  ", "synthetic new password")
                .await;
            assert_eq!(result.err().as_deref(), expected, "{case}");
            let requests = server.join().unwrap();
            assert!(requests[0]
                .0
                .starts_with("GET /manager-api/status HTTP/1.1\r\n"));
            if requests.len() > 1 {
                assert!(requests[1]
                    .0
                    .starts_with("POST /manager-api/claim HTTP/1.1\r\n"));
                assert!(requests[1]
                    .0
                    .to_ascii_lowercase()
                    .contains(&format!("origin: {origin}\r\n")));
                let payload: serde_json::Value = serde_json::from_slice(&requests[1].1).unwrap();
                assert_eq!(
                    payload,
                    serde_json::json!({"name":"Test owner","password":"synthetic new password"})
                );
            }
            assert!(!config.data.exists());
            owner.shutdown(Duration::from_secs(1)).await.unwrap();
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn password_account_creation_validates_details_and_owned_identity_before_network() {
        let (mut owner, mut config) = account_owner("http://127.0.0.1:1");
        for name in ["", "   ", "bad\nname", &"a".repeat(121), &"🌱".repeat(61)] {
            assert_eq!(
                owner
                    .create_administrator(&config, name, "synthetic new password")
                    .await
                    .err()
                    .as_deref(),
                Some("manager_account_details_invalid")
            );
        }
        assert_eq!(
            owner
                .create_administrator(&config, "Owner", "short")
                .await
                .err()
                .as_deref(),
            Some("manager_login_details_invalid")
        );
        config.installation_id = "cccccccccccc".into();
        assert_eq!(
            owner
                .create_administrator(&config, "Owner", "synthetic new password")
                .await
                .err()
                .as_deref(),
            Some("native_manager_not_ready")
        );
        owner.shutdown(Duration::from_secs(1)).await.unwrap();
    }

    #[cfg(unix)]
    #[tokio::test]
    #[ignore = "requires compiled Manager/private Node and new owned fixture directory; no installed authority or keychain claim"]
    async fn compiled_manager_runs_through_the_private_supervisor_owner() {
        compiled_manager_owner(false, false, false).await;
    }
    #[cfg(unix)]
    #[tokio::test]
    #[ignore = "requires compiled Manager/private Node and new owned fixture directory; no installed authority or keychain claim"]
    async fn compiled_manager_revokes_stale_device_grant() {
        compiled_manager_owner(true, false, false).await;
    }
    #[cfg(unix)]
    #[tokio::test]
    #[ignore = "requires compiled Manager/private Node and new owned fixture directory; no installed authority or keychain claim"]
    async fn compiled_manager_restore_review_is_scoped_and_refuses_unverified_execution() {
        compiled_manager_owner(false, true, false).await;
    }
    #[cfg(unix)]
    #[tokio::test]
    #[ignore = "requires compiled code-free Manager/private Node and new isolated fixture directory"]
    async fn compiled_manager_creates_password_only_account_then_pairs_and_retries_persistence() {
        compiled_manager_owner(false, false, true).await;
    }
    #[cfg(unix)]
    async fn compiled_manager_owner(revoke_only: bool, recovery: bool, create_account: bool) {
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
        let unicode_password = "🌱".repeat(128);
        let password = if create_account {
            unicode_password.as_str()
        } else {
            "synthetic local Manager password"
        };
        if !create_account {
            // The isolated fixture starts with an existing administrator, like a configured server.
            assert!(Command::new(&node)
            .args(["--input-type=module", "-e", r#"
              import {pathToFileURL} from 'node:url';
              import {scryptSync} from 'node:crypto';
              const {Store}=await import(pathToFileURL(process.argv[1]).href);
              const store=new Store(process.argv[2]);
              const salt='synthetic-fixture-salt';
              if(!store.createOnce('administrator',{name:'Synthetic owner',salt,hash:scryptSync(process.argv[3],salt,64).toString('hex')}))process.exit(2);
              store.db.close();
            "#])
            .arg(manager.join("build/store.js"))
            .arg(&data)
            .arg(password)
            .env_clear()
            .env("PATH", "")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status().unwrap().success());
        }
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
          "protocolVersion":2,"backupKey":"k".repeat(43),"installation":{"runtime":"native","id":"aaaaaaaaaaaa","secureInstallationId":"11111111-1111-4111-8111-111111111111","controller":controller,"candidate":output.join("runtime"),"state":output.join("state"),"manifestSha256":"b".repeat(64),"sourceRevision":"c".repeat(40),"certified":false,"databasePort":54329,"apiPort":2283},
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
        owner.startup_lease = Some(
            crate::host_state::Owner::acquire(&state, true, "11111111-1111-4111-8111-111111111111")
                .unwrap(),
        );
        assert!(crate::host_state::Owner::acquire(
            &state,
            true,
            "11111111-1111-4111-8111-111111111111"
        )
        .is_err());
        owner
            .wait_ready(Duration::from_secs(10), &AtomicBool::new(false))
            .await
            .unwrap();
        assert!(owner.is_running().unwrap());
        assert!(owner.startup_lease.is_none());
        drop(
            crate::host_state::Owner::acquire(&state, true, "11111111-1111-4111-8111-111111111111")
                .unwrap(),
        );
        owner
            .wait_ready(Duration::from_secs(1), &AtomicBool::new(false))
            .await
            .unwrap();
        owner.certificate_pem = tls.certificate().into();
        let configuration = Configuration {
            installation_id: "aaaaaaaaaaaa".into(),
            secure_installation_id: "11111111-1111-4111-8111-111111111111".into(),
            name: "Synthetic owner fixture".into(),
            release: "frameleaf-v3.0.0-1".into(),
            controller: fs::canonicalize("/bin/echo").unwrap(),
            state: state.clone(),
            data: data.clone(),
            origin: origin.into(),
            database_port: 54329,
            api_port: 2283,
        };
        if create_account {
            assert!(!owner.claimed().await.unwrap());
            owner
                .create_administrator(&configuration, "Synthetic owner", password)
                .await
                .unwrap();
            assert!(owner.claimed().await.unwrap());
            assert_eq!(
                owner
                    .create_administrator(&configuration, "Replacement", password)
                    .await
                    .err()
                    .as_deref(),
                Some("manager_account_exists")
            );
        }
        let identity = crate::connection::DeviceIdentity::generate();
        if !revoke_only {
            let interrupted = crate::host_setup::authorize_owner(
                &mut owner,
                &configuration,
                &identity,
                Zeroizing::new(password.into()),
                false,
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
            // A persistence retry authenticates the existing account without replacing it.
        }
        let saved = std::cell::RefCell::new(None::<crate::manager::SavedManager>);
        let paired = crate::host_setup::authorize_owner(
            &mut owner,
            &configuration,
            &identity,
            Zeroizing::new(password.into()),
            recovery,
            false,
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
        let existing = serde_json::from_str(&encoded).unwrap();
        let refused = crate::host_setup::authorize_owner(
            &mut owner,
            &configuration,
            &identity,
            Zeroizing::new(password.into()),
            false,
            true,
            Some(existing),
            |_| panic!("update permission must not replace an existing grant"),
        )
        .await;
        assert_eq!(refused.err().unwrap(), "manager_update_approval_required");
        let again = crate::host_setup::authorize_owner(
            &mut owner,
            &configuration,
            &identity,
            Zeroizing::new(password.into()),
            false,
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
            secure_installation_id: "11111111-1111-4111-8111-111111111111".into(),
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

#[cfg(all(test, unix))]
#[path = "manager_admission_tests.rs"]
mod admission_tests;

#[cfg(all(test, unix))]
#[path = "manager_session_tests.rs"]
mod session_tests;

#[cfg(all(test, unix))]
#[path = "manager_update_tests.rs"]
mod update_tests;
