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
        self.start_owned(
            config,
            &profile.password(),
            &profile.backup_key()?,
            &tls,
            Some(lease),
        )
    }
    /// Caller must persist the database password before use; it never enters argv/env/logs.
    pub fn start(
        &self,
        config: &Configuration,
        password: &Zeroizing<String>,
        backup_key: &Zeroizing<String>,
        tls: &TlsIdentity,
    ) -> Result<NativeManager, String> {
        self.start_owned(config, password, backup_key, tls, None)
    }
    fn start_owned(
        &self,
        config: &Configuration,
        password: &Zeroizing<String>,
        backup_key: &Zeroizing<String>,
        tls: &TlsIdentity,
        startup_lease: Option<crate::host_state::Owner>,
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
        struct Binding<'a> {
            runtime: &'a str,
            id: &'a str,
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
