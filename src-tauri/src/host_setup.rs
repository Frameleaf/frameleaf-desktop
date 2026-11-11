//! Only installed identities cross IPC; code, state paths and secrets stay native.
use crate::{
    host_install::Installation,
    manager_host::{Configuration, NativeManager},
};
use serde::Serialize;
#[cfg(any(target_os = "macos", target_os = "linux", windows))]
use sha2::{Digest, Sha256};
use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct View {
    state: String,
    code: Option<String>,
    installation: Option<Installation>,
    origin: Option<String>,
    pub background_active: bool,
    profile_setup_available: bool,
    profile_requires_authorization: bool,
    companion_platform: Option<&'static str>,
}
impl Default for View {
    fn default() -> Self {
        Self {
            state: "idle".into(),
            code: None,
            installation: None,
            origin: None,
            background_active: false,
            profile_setup_available: cfg!(any(target_os = "linux", windows)),
            profile_requires_authorization: cfg!(target_os = "linux"),
            companion_platform: match (std::env::consts::OS, std::env::consts::ARCH) {
                ("macos", "aarch64") => Some("mac"),
                ("windows", "x86_64") => Some("windows"),
                ("linux", "x86_64") => Some("linux"),
                _ => None,
            },
        }
    }
}
struct Running {
    manager: NativeManager,
    configuration: Configuration,
    installation: Installation,
}
#[derive(Default)]
pub(crate) struct HostSetup {
    owner: tokio::sync::Mutex<Option<Running>>,
    cancel: Arc<AtomicBool>,
    active: AtomicBool,
    view: Mutex<View>,
}
impl HostSetup {
    pub(crate) fn background_active(&self) -> bool {
        self.active.load(Ordering::Acquire)
    }
    pub(crate) fn lock_for_update(&self) -> Result<impl Drop + '_, String> {
        let owner = self.owner.try_lock().map_err(|_| "update_host_active")?;
        if owner.is_some() || self.background_active() {
            return Err("update_host_active".into());
        }
        Ok(owner)
    }
    fn set(&self, state: &str, code: Option<String>, installation: Option<Installation>) {
        *self.view.lock().unwrap_or_else(|error| error.into_inner()) = View {
            state: state.into(),
            code,
            origin: installation
                .as_ref()
                .map(|_| "https://127.0.0.1:9443".into()),
            installation,
            ..View::default()
        };
    }
    fn snapshot(&self) -> View {
        let mut view = self
            .view
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .clone();
        view.background_active = self.background_active();
        view
    }
    pub(crate) fn require_management_origin(&self, origin: &str) -> Result<(), String> {
        let view = self.snapshot();
        if view.origin.as_deref() == Some(origin)
            && matches!(
                view.state.as_str(),
                "starting" | "stopping" | "provisioning"
            )
        {
            return Err("native_host_busy".into());
        }
        Ok(())
    }
    pub(crate) fn cancel(&self) {
        self.cancel.store(true, Ordering::Release);
    }
    pub(crate) async fn status(&self) -> Result<View, String> {
        if let Ok(mut owner) = self.owner.try_lock() {
            if let Some(running) = owner.as_mut() {
                if running.manager.has_exited()? {
                    let record = Some(running.installation.clone());
                    self.set(
                        "needs-attention",
                        Some("native_manager_exited".into()),
                        record,
                    );
                }
            }
        }
        Ok(self.snapshot())
    }
    pub(crate) async fn provision(&self, manifest: String) -> Result<View, String> {
        #[cfg(target_os = "linux")]
        {
            let record = Installation::read(&manifest)?;
            self.provision_record(record, crate::profile_elevation::provision)
                .await
        }
        #[cfg(windows)]
        {
            let record = Installation::read(&manifest)?;
            self.provision_record(record, crate::windows_host_profile::prepare)
                .await
        }
        #[cfg(not(any(target_os = "linux", windows)))]
        {
            let _ = manifest;
            Err("host_install_platform_unsupported".into())
        }
    }
    #[cfg(any(target_os = "linux", windows, test))]
    async fn provision_record<F>(
        &self,
        installation: Installation,
        provision: F,
    ) -> Result<View, String>
    where
        F: FnOnce(&Installation) -> Result<(), String> + Send + 'static,
    {
        let owner = self.owner.try_lock().map_err(|_| "native_host_busy")?;
        if owner.is_some() {
            return Err("native_host_stop_required".into());
        }
        self.active.store(true, Ordering::Release);
        self.set("provisioning", None, Some(installation.clone()));
        let record = installation.clone();
        let result = tauri::async_runtime::spawn_blocking(move || provision(&record))
            .await
            .map_err(|_| "host_profile_prepare_failed".to_string())
            .and_then(|result| result);
        self.active.store(false, Ordering::Release);
        self.set(
            if result.is_ok() {
                "profile-ready"
            } else {
                "needs-attention"
            },
            result.as_ref().err().cloned(),
            Some(installation),
        );
        result?;
        Ok(self.snapshot())
    }
    pub(crate) async fn start(&self, manifest: String) -> Result<View, String> {
        let mut owner = self.owner.try_lock().map_err(|_| "native_host_busy")?;
        if let Some(running) = owner.as_mut() {
            if !running.manager.has_exited()? {
                return Err("native_manager_already_running".into());
            }
        }
        if !cfg!(any(target_os = "macos", target_os = "linux", windows)) {
            return Err("host_install_platform_unsupported".into());
        }
        // Validate the fixed identity before changing lifecycle state.
        let installation = Installation::read(&manifest)?;
        if owner
            .as_ref()
            .is_some_and(|running| running.installation != installation)
        {
            return Err("native_host_stop_required".into());
        }
        let attempted = installation.clone();
        self.cancel.store(false, Ordering::Release);
        self.active.store(true, Ordering::Release);
        self.set("starting", None, Some(installation.clone()));
        let cancel = self.cancel.clone();
        let result = tauri::async_runtime::spawn_blocking(move || launch(&installation, &cancel))
            .await
            .map_err(|_| "native_host_setup_failed".to_string())
            .and_then(|value| value);
        let result = match result {
            Ok(mut running) => match running
                .manager
                .wait_ready(Duration::from_secs(20), &self.cancel)
                .await
            {
                Ok(()) => Ok(running),
                Err(error) => Err(error),
            },
            Err(error) => Err(error),
        };
        match result {
            Ok(running) => {
                *owner = Some(running);
                self.set("manager-ready", None, self.snapshot().installation);
            }
            Err(error) => {
                self.startup_failed(
                    owner.as_ref().map(|running| running.installation.clone()),
                    attempted,
                    error.clone(),
                );
                return Err(error);
            }
        }
        Ok(self.snapshot())
    }
    fn startup_failed(
        &self,
        retained: Option<Installation>,
        attempted: Installation,
        error: String,
    ) {
        self.active.store(retained.is_some(), Ordering::Release);
        self.set("needs-attention", Some(error), retained.or(Some(attempted)));
    }
    pub(crate) async fn authorize(
        &self,
        password: zeroize::Zeroizing<String>,
        allow_recovery: bool,
    ) -> Result<crate::manager::View, String> {
        require_password(&password)?;
        let mut owner = self.owner.try_lock().map_err(|_| "native_host_busy")?;
        let running = owner.as_mut().ok_or("native_manager_not_ready")?;
        running
            .manager
            .management_identity(&running.configuration)?;
        let identity = crate::credentials::identity()?;
        let existing =
            crate::credentials::load::<crate::manager::SavedManager>(crate::manager::CREDENTIAL)?;
        // Confirm secure writes before claiming an administrator or issuing a grant.
        crate::credentials::save("manager-pairing-check", &true)?;
        crate::credentials::delete("manager-pairing-check")?;
        authorize_owner(
            &mut running.manager,
            &running.configuration,
            &identity,
            password,
            allow_recovery,
            existing,
            |saved| crate::credentials::save(crate::manager::CREDENTIAL, saved),
        )
        .await
    }
    pub(crate) async fn photos_url(&self) -> Result<url::Url, String> {
        let mut owner = self.owner.try_lock().map_err(|_| "native_host_busy")?;
        let running = owner.as_mut().ok_or("native_manager_not_ready")?;
        running
            .manager
            .management_identity(&running.configuration)?;
        let saved =
            crate::credentials::load::<crate::manager::SavedManager>(crate::manager::CREDENTIAL)?
                .ok_or("manager_pairing_required")?;
        photos_owner(
            &mut running.manager,
            &running.configuration,
            &crate::credentials::identity()?,
            &saved,
        )
        .await
    }
    pub(crate) async fn stop(&self) -> Result<View, String> {
        let mut owner = self.owner.try_lock().map_err(|_| "native_host_busy")?;
        let Some(running) = owner.as_mut() else {
            return Ok(self.snapshot());
        };
        let record = Some(running.installation.clone());
        self.set("stopping", None, record.clone());
        let result = async {
            let mut proof = crate::host_state::Owner::acquire(&running.configuration.state, true)?;
            proof.admit_idle(
                &running.configuration.installation_id,
                &running.installation.manifest_sha256,
            )?;
            running.manager.shutdown(Duration::from_secs(10)).await?;
            drop(proof);
            Ok::<(), String>(())
        }
        .await;
        if let Err(error) = result {
            self.set("needs-attention", Some(error.clone()), record);
            return Err(error);
        }
        *owner = None;
        self.active.store(false, Ordering::Release);
        self.set("idle", None, record);
        Ok(self.snapshot())
    }
}
fn local_photos_origin(port: u16) -> Result<url::Url, String> {
    if port == 0 {
        return Err("native_host_config_invalid".into());
    }
    url::Url::parse(&format!("http://127.0.0.1:{port}/"))
        .map_err(|_| "native_host_config_invalid".into())
}
pub(crate) async fn photos_owner(
    manager: &mut NativeManager,
    configuration: &Configuration,
    identity: &crate::connection::DeviceIdentity,
    saved: &crate::manager::SavedManager,
) -> Result<url::Url, String> {
    let certificate = manager.management_identity(configuration)?;
    local_grant(saved, identity, configuration, &certificate.sha256)?;
    crate::manager::send(saved, identity, crate::manager::Command::Status {}).await?;
    manager.management_identity(configuration)?;
    // This selects the owned server address; only the photo UI can establish account readiness.
    local_photos_origin(configuration.api_port)
}
fn require_password(password: &str) -> Result<(), String> {
    if password.chars().count() < 14
        || password.len() > 256
        || password.contains(['\r', '\n', '\0'])
    {
        return Err("manager_login_details_invalid".into());
    }
    Ok(())
}
fn claim_proof(path: &std::path::Path) -> Result<zeroize::Zeroizing<String>, String> {
    use std::io::Read;
    let directory = cap_std::fs::Dir::from_std_file(crate::host_storage::directory(path)?);
    let file = directory
        .open_with("claim-key", &crate::host_state::options(false))
        .map_err(|_| "manager_claim_proof_changed")?
        .into_std();
    crate::host_state::valid_file(&file).map_err(|_| "manager_claim_proof_changed")?;
    let mut bytes = zeroize::Zeroizing::new(Vec::new());
    file.take(65)
        .read_to_end(&mut bytes)
        .map_err(|_| "manager_claim_proof_changed")?;
    let text = std::str::from_utf8(&bytes).map_err(|_| "manager_claim_proof_changed")?;
    if !crate::native_runtime::digest_valid(text, 64) {
        return Err("manager_claim_proof_changed".into());
    }
    Ok(zeroize::Zeroizing::new(text.to_owned()))
}
fn local_grant(
    saved: &crate::manager::SavedManager,
    identity: &crate::connection::DeviceIdentity,
    configuration: &Configuration,
    certificate: &str,
) -> Result<crate::manager::View, String> {
    saved.require_device(identity)?;
    let view = saved.view();
    if view.origin != configuration.origin
        || view.installation_id != configuration.installation_id
        || view.certificate_sha256.as_deref() != Some(certificate)
    {
        return Err("manager_already_paired".into());
    }
    if view.expires_at <= crate::manager::clock()? {
        return Err("manager_pairing_expired".into());
    }
    Ok(view)
}
pub(crate) async fn authorize_owner(
    manager: &mut NativeManager,
    configuration: &Configuration,
    identity: &crate::connection::DeviceIdentity,
    password: zeroize::Zeroizing<String>,
    allow_recovery: bool,
    existing: Option<crate::manager::SavedManager>,
    persist: impl FnOnce(&crate::manager::SavedManager) -> Result<(), String>,
) -> Result<crate::manager::View, String> {
    require_password(&password)?;
    let certificate = manager.management_identity(configuration)?;
    if let Some(saved) = existing {
        let view = local_grant(&saved, identity, configuration, &certificate.sha256)?;
        if allow_recovery && !view.scopes.contains(&crate::manager::Scope::Restore) {
            return Err("manager_recovery_approval_required".into());
        }
        crate::manager::reauthenticate(&saved, password.to_string()).await?;
        crate::manager::send(&saved, identity, crate::manager::Command::Status {}).await?;
        manager.management_identity(configuration)?;
        return Ok(view);
    }
    if !manager.claimed().await? {
        let proof = claim_proof(&configuration.data)?;
        manager.claim_local(&password, &proof).await?;
    }
    let fingerprint = certificate.sha256.clone();
    crate::manager::pair(
        identity,
        &configuration.origin,
        password.to_string(),
        Some(certificate),
        allow_recovery,
        |saved| {
            manager.management_identity(configuration)?;
            local_grant(saved, identity, configuration, &fingerprint)?;
            persist(saved)
        },
    )
    .await
}

#[cfg(any(target_os = "macos", target_os = "linux", windows, all(test, unix)))]
pub(crate) fn require_leaf(path: &std::path::Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let required = if cfg!(target_os = "linux") {
            "host_install_linux_profile_required"
        } else {
            "host_install_profile_required"
        };
        let info = std::fs::symlink_metadata(path).map_err(|_| required.to_string())?;
        if !info.is_dir()
            || info.uid() != unsafe { libc::geteuid() }
            || info.mode() & 0o7777 != 0o700
        {
            return Err(required.into());
        }
        #[cfg(target_os = "macos")]
        crate::manager_host::no_acl(path)?;
        Ok(())
    }
    #[cfg(windows)]
    {
        crate::windows_protection::require_private_directory(path)
            .map_err(|_| "host_install_windows_profile_required".into())
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = path;
        Err("host_install_platform_unsupported".into())
    }
}
#[cfg(any(target_os = "macos", target_os = "linux", windows, test))]
fn native_release(version: &str, revision: &str) -> Result<String, String> {
    if version.split('.').count() != 3
        || !version.split('.').all(|part| {
            !part.is_empty() && part.len() <= 5 && part.bytes().all(|b| b.is_ascii_digit())
        })
        || !crate::native_runtime::digest_valid(revision, 40)
    {
        return Err("native_host_version_invalid".into());
    }
    Ok(format!("frameleaf-v{version}-native.{}-1", &revision[..12]))
}
#[cfg(windows)]
fn pin_profile_leaf(path: &std::path::Path) -> Result<Vec<std::fs::File>, String> {
    crate::windows_protection::pin_private_directory(path)
        .map_err(|_| "host_install_windows_profile_required".into())
}

/// Re-read an installed package record and verify its controller and signed runtime.
#[cfg(any(target_os = "macos", target_os = "linux", windows))]
fn verified(
    record: &Installation,
) -> Result<
    (
        crate::host_install::Layout,
        crate::host_runtime::VerifiedHostRuntime,
    ),
    String,
> {
    let current = Installation::read(&record.manifest_sha256)?;
    if &current != record {
        return Err("host_install_record_invalid".into());
    }
    let layout = record.layout()?;
    let controller = crate::runtime_store::read_bounded(&layout.controller, 256 * 1024 * 1024)?;
    if format!("{:x}", Sha256::digest(controller)) != record.controller_sha256 {
        return Err("host_install_controller_changed".into());
    }
    let raw = crate::runtime_store::read_bounded(
        &layout.runtime.join("manifest.json"),
        16 * 1024 * 1024,
    )?;
    let signature: [u8; 64] =
        crate::runtime_store::read_bounded(&layout.runtime.join("manifest.sig"), 64)?
            .try_into()
            .map_err(|_| "host_signature_invalid")?;
    let runtime = crate::release_policy::verify_host_runtime(
        &layout.runtime.join("payload"),
        &raw,
        &signature,
    )?;
    if runtime.manifest_sha256() != record.manifest_sha256 {
        return Err("host_install_runtime_changed".into());
    }
    Ok((layout, runtime))
}

/// The Manager configuration for a verified package and this account's profile paths.
#[cfg(any(target_os = "macos", target_os = "linux", windows))]
fn configuration<U: Serialize>(
    record: &Installation,
    layout: &crate::host_install::Layout,
    runtime: &crate::host_runtime::VerifiedHostRuntime,
    uid: &U,
    state: std::path::PathBuf,
    data: std::path::PathBuf,
) -> Result<Configuration, String> {
    let package: serde_json::Value = serde_json::from_slice(&crate::runtime_store::read_bounded(
        &layout.runtime.join("payload/server/package.json"),
        64 * 1024,
    )?)
    .map_err(|_| "native_host_version_invalid")?;
    let release = native_release(
        package["version"]
            .as_str()
            .ok_or("native_host_version_invalid")?,
        runtime.source_revision(),
    )?;
    let identity = serde_json::to_vec(&(record, uid)).map_err(|_| "native_host_setup_failed")?;
    Ok(Configuration {
        installation_id: format!("{:x}", Sha256::digest(identity))[..12].into(),
        name: "My Frameleaf library".into(),
        release,
        controller: layout.controller.clone(),
        state,
        data,
        origin: "https://127.0.0.1:9443".into(),
        database_port: 54329,
        api_port: 2283,
    })
}

/// A library keeps its first installation identity. Moving it to a newer signed package copies its
/// saved secrets and repoints its journals while it is cleanly stopped; downgrades are refused.
#[cfg(any(target_os = "macos", target_os = "linux"))]
fn carry_forward(
    record: &Installation,
    runtime: &crate::host_runtime::VerifiedHostRuntime,
    next: &mut Configuration,
    uid: u32,
) -> Result<(), String> {
    let Some(marker) = crate::host_state::Owner::peek(&next.state)? else {
        return Ok(());
    };
    next.installation_id = marker.installation_id.clone();
    if marker.manifest_sha256 == record.manifest_sha256 {
        return Ok(());
    }
    let previous_record = Installation::read(&marker.manifest_sha256)
        .map_err(|_| "host_upgrade_previous_package_missing")?;
    let (previous_layout, previous_runtime) = verified(&previous_record)?;
    if runtime.epoch() <= previous_runtime.epoch() {
        return Err("host_upgrade_downgrade_refused".into());
    }
    let mut previous = configuration(
        &previous_record,
        &previous_layout,
        &previous_runtime,
        &uid,
        next.state.clone(),
        next.data.clone(),
    )?;
    previous.installation_id = marker.installation_id.clone();
    let layout = record.layout()?;
    // Hold the previous package and the journal for the whole move.
    let _code = crate::package_lease::CodeLease::acquire(&previous_layout.runtime)?;
    let owner = crate::host_state::Owner::acquire(&next.state, true)?;
    // Manager accepts the new package only from the exact descriptor it last ran with.
    let old_binding = crate::manager_profile::Profile::binding_for(
        &previous,
        &previous_layout.runtime,
        &marker.manifest_sha256,
    )?;
    let transition = crate::manager_tls::TlsIdentity::saved_certificate(&old_binding)?
        .map(|certificate| -> Result<_, String> {
            Ok(crate::manager_host::Transition {
                operation_id: uuid::Uuid::new_v4(),
                from_fingerprint: crate::manager_host::descriptor_fingerprint(
                    &previous,
                    &previous_layout.runtime,
                    &previous_runtime,
                    &previous_record.controller_sha256,
                    &certificate,
                )?,
            })
        })
        .transpose()?;
    move_library(
        owner,
        Package {
            config: &previous,
            candidate: &previous_layout.runtime,
            manifest: &marker.manifest_sha256,
            revision: previous_runtime.source_revision(),
        },
        Package {
            config: next,
            candidate: &layout.runtime,
            manifest: &record.manifest_sha256,
            revision: runtime.source_revision(),
        },
        |previous, next| crate::manager_profile::Profile::carry_forward(previous, next, transition),
        crate::manager_tls::TlsIdentity::carry_forward,
    )
}

/// One side of a library move: the package's configuration, location and identity.
#[cfg(unix)]
struct Package<'a> {
    config: &'a Configuration,
    candidate: &'a std::path::Path,
    manifest: &'a str,
    revision: &'a str,
}

/// Every check runs before the first change; the journal write last commits the move.
#[cfg(unix)]
fn move_library(
    mut owner: crate::host_state::Owner,
    previous: Package,
    next: Package,
    profile: impl FnOnce(
        (&Configuration, &std::path::Path, &str),
        (&Configuration, &std::path::Path, &str),
    ) -> Result<(String, String), String>,
    tls: impl FnOnce(&str, &str) -> Result<(), String>,
) -> Result<(), String> {
    let id = &previous.config.installation_id;
    owner.check_movable(id, previous.manifest)?;
    host_state_package(
        &next.config.state,
        (previous.manifest, previous.revision),
        (next.manifest, next.revision),
    )?;
    let (old, new) = profile(
        (previous.config, previous.candidate, previous.manifest),
        (next.config, next.candidate, next.manifest),
    )?;
    tls(&old, &new)?;
    carry_host_state(
        &next.config.state,
        (previous.manifest, previous.revision),
        (next.manifest, next.revision),
    )?;
    owner.carry_forward(id, previous.manifest, next.manifest)
}

/// The exact bytes the host agent writes for a package's marker.
#[cfg(unix)]
fn host_state_marker((manifest, revision): (&str, &str)) -> Result<String, String> {
    if !crate::native_runtime::digest_valid(manifest, 64)
        || !crate::native_runtime::digest_valid(revision, 40)
    {
        return Err("host_state_invalid".into());
    }
    Ok(format!(
        r#"{{"schemaVersion":1,"manifestSha256":"{manifest}","sourceRevision":"{revision}","postgresMajor":"19"}}"#
    ))
}

#[cfg(unix)]
#[derive(Debug, PartialEq)]
enum HostStatePackage {
    /// The host never created its database; the agent starts it fresh for any package.
    Unclaimed,
    Previous,
    Next,
}

/// Read-only: which package the host agent's marker names.
#[cfg(unix)]
fn host_state_package(
    state: &std::path::Path,
    previous: (&str, &str),
    next: (&str, &str),
) -> Result<HostStatePackage, String> {
    use std::io::Read;
    let (previous, next) = (host_state_marker(previous)?, host_state_marker(next)?);
    let root = cap_std::fs::Dir::from_std_file(crate::host_storage::directory(state)?);
    let mut file = match root.open_with("host-state.json", &crate::host_state::options(false)) {
        Ok(file) => file.into_std(),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            for entry in root.entries().map_err(|_| "host_state_invalid")? {
                let name = entry.map_err(|_| "host_state_invalid")?.file_name();
                if !["lease.lock", "agent.log", "controller-state.json"]
                    .iter()
                    .any(|allowed| name == std::ffi::OsStr::new(allowed))
                {
                    return Err("host_update_requires_manager".into());
                }
            }
            return Ok(HostStatePackage::Unclaimed);
        }
        Err(_) => return Err("host_state_invalid".into()),
    };
    crate::host_state::valid_file(&file).map_err(|_| "host_state_invalid")?;
    let mut current = String::new();
    Read::by_ref(&mut file)
        .take(4097)
        .read_to_string(&mut current)
        .map_err(|_| "host_state_invalid")?;
    if current == next {
        Ok(HostStatePackage::Next)
    } else if current == previous {
        Ok(HostStatePackage::Previous)
    } else {
        Err("host_update_requires_manager".into())
    }
}

/// The host agent's package marker names the package that last ran this database.
#[cfg(unix)]
fn carry_host_state(
    state: &std::path::Path,
    previous: (&str, &str),
    next: (&str, &str),
) -> Result<(), String> {
    use std::io::Write;
    if host_state_package(state, previous, next)? != HostStatePackage::Previous {
        return Ok(());
    }
    let marker = host_state_marker(next)?;
    let root = cap_std::fs::Dir::from_std_file(crate::host_storage::directory(state)?);
    // A fixed name lets a retry replace what an interrupted move left behind.
    let temp = ".host-state.json.carry.tmp";
    match root.remove_file(temp) {
        Err(error) if error.kind() != std::io::ErrorKind::NotFound => {
            return Err("host_state_invalid".into())
        }
        _ => {}
    }
    let result = (|| -> Result<(), String> {
        let mut options = crate::host_state::options(true);
        options.create_new(true);
        let mut output = root
            .open_with(temp, &options)
            .map_err(|_| "host_state_invalid")?
            .into_std();
        output
            .write_all(marker.as_bytes())
            .and_then(|_| output.sync_all())
            .map_err(|_| "host_state_invalid")?;
        drop(output);
        root.rename(temp, &root, "host-state.json")
            .map_err(|_| "host_state_invalid")?;
        crate::host_storage::directory(state)?
            .sync_all()
            .map_err(|_| "host_state_invalid".to_string())
    })();
    if result.is_err() {
        let _ = root.remove_file(temp);
    }
    result
}

/// The Library version a package carries, for display only.
pub(crate) fn package_version(record: &Installation) -> Option<String> {
    let layout = record.layout().ok()?;
    let raw = crate::runtime_store::read_bounded(
        &layout.runtime.join("payload/server/package.json"),
        64 * 1024,
    )
    .ok()?;
    let version = serde_json::from_slice::<serde_json::Value>(&raw).ok()?["version"]
        .as_str()?
        .to_owned();
    (version.split('.').count() == 3
        && version.split('.').all(|part| {
            !part.is_empty() && part.len() <= 5 && part.bytes().all(|b| b.is_ascii_digit())
        }))
    .then_some(version)
}

/// The package this account's library last ran with, for display only.
pub(crate) fn library_package(records: &[Installation]) -> Option<String> {
    #[cfg(unix)]
    let state = records
        .first()?
        .layout()
        .ok()?
        .profiles
        .join(unsafe { libc::geteuid() }.to_string())
        .join("state");
    #[cfg(windows)]
    let state = {
        records.first()?;
        crate::windows_host_profile::paths().ok()?.0
    };
    crate::host_state::Owner::peek(&state)
        .ok()
        .flatten()
        .map(|marker| marker.manifest_sha256)
}

fn launch(record: &Installation, cancel: &AtomicBool) -> Result<Running, String> {
    #[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
    {
        let _ = (record, cancel);
        Err("host_install_platform_unsupported".into())
    }
    #[cfg(any(target_os = "macos", target_os = "linux", windows))]
    {
        let (layout, runtime) = verified(record)?;
        #[cfg(unix)]
        let uid = {
            let uid = unsafe { libc::geteuid() };
            let minimum_uid = if cfg!(target_os = "linux") { 1 } else { 501 };
            if uid < minimum_uid || unsafe { libc::getuid() } != uid {
                return Err("host_install_profile_required".into());
            }
            uid
        };
        #[cfg(windows)]
        let uid = crate::windows_protection::process_user_sid()?;
        #[cfg(unix)]
        let profile = layout.profiles.join(uid.to_string());
        #[cfg(unix)]
        let state = profile.join("state");
        #[cfg(unix)]
        let data = profile.join("manager");
        #[cfg(windows)]
        let (state, data) = crate::windows_host_profile::paths()?;
        // Downstream shared setup helpers may create missing leaves; keep both existing objects pinned.
        #[cfg(windows)]
        let _profiles = [pin_profile_leaf(&state)?, pin_profile_leaf(&data)?];
        require_leaf(&state)?;
        require_leaf(&data)?;
        #[allow(unused_mut)]
        let mut configuration = configuration(record, &layout, &runtime, &uid, state, data)?;
        #[cfg(any(target_os = "macos", target_os = "linux"))]
        carry_forward(record, &runtime, &mut configuration, uid)?;
        if cancel.load(Ordering::Acquire) {
            return Err("native_manager_start_cancelled".into());
        }
        let programs = runtime.manager_programs()?;
        if cancel.load(Ordering::Acquire) {
            return Err("native_manager_start_cancelled".into());
        }
        let manager = programs.start_from_keystore(&configuration)?;
        Ok(Running {
            manager,
            configuration,
            installation: record.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Run the released app as a client of a separate disposable signed Library.
    #[cfg(windows)]
    #[test]
    #[ignore = "requires an installed Desktop and signed companion on a fresh Windows runner"]
    fn disposable_runner_installed_desktop_watches_while_hidden() {
        use std::{
            io::Write,
            net::TcpListener,
            path::PathBuf,
            process::{Command, Stdio},
            time::Instant,
        };
        use zeroize::Zeroizing;

        assert_eq!(std::env::var("GITHUB_ACTIONS").as_deref(), Ok("true"));
        assert_eq!(
            std::env::var("RUNNER_ENVIRONMENT").as_deref(),
            Ok("github-hosted")
        );
        let runner = PathBuf::from(std::env::var_os("RUNNER_TEMP").unwrap())
            .canonicalize()
            .unwrap();
        let executable = PathBuf::from(std::env::var_os("FRAMELEAF_WATCH_DESKTOP_EXE").unwrap());
        let physical = executable.canonicalize().unwrap();
        assert!(executable.is_absolute() && physical.starts_with(&runner) && physical.is_file());
        assert_eq!(physical.file_name().unwrap(), "frameleaf-desktop.exe");
        let expected = std::env::var("FRAMELEAF_WATCH_DESKTOP_SHA256").unwrap();
        let bytes = crate::runtime_store::read_bounded(&physical, 256 * 1024 * 1024).unwrap();
        assert_eq!(format!("{:x}", Sha256::digest(bytes)), expected);

        let (state, _) = crate::windows_host_profile::paths().unwrap();
        assert!(
            !state.parent().unwrap().exists(),
            "requires a fresh native profile"
        );
        let local_data = crate::host_install::windows_local_app_data().unwrap();
        assert!(
            !local_data.join("app.frameleaf.desktop").exists(),
            "requires a fresh Desktop app data directory"
        );
        for account in [
            "connection",
            "installation",
            crate::manager::CREDENTIAL,
            crate::source_consent::CREDENTIAL,
        ] {
            assert!(
                crate::credentials::load::<serde_json::Value>(account)
                    .unwrap()
                    .is_none(),
                "requires a fresh Desktop credential store"
            );
        }
        let listener = TcpListener::bind(("127.0.0.1", 2283)).unwrap();
        let database = TcpListener::bind(("127.0.0.1", 54329)).unwrap();
        let manifest = std::env::var("FRAMELEAF_INSTALLED_HOST_MANIFEST").unwrap();
        let record =
            Installation::read(&manifest).expect("expected the approved installed companion");
        let (layout, runtime) = verified(&record).expect("installed companion verification failed");

        let scratch = crate::runtime_store::Staging::create(
            runner.join(format!("frameleaf-watch-library-{}", uuid::Uuid::new_v4())),
        )
        .unwrap();
        let source = crate::runtime_store::Staging::create(
            PathBuf::from(std::env::var_os("USERPROFILE").unwrap())
                .join(format!("frameleaf-watch-source-{}", uuid::Uuid::new_v4())),
        )
        .unwrap();
        let database_password = Zeroizing::new(format!("Synthetic-db-{}!", uuid::Uuid::new_v4()));
        let photo_password = Zeroizing::new(format!("Synthetic-photo-{}!", uuid::Uuid::new_v4()));
        drop((listener, database));
        let mut host = runtime
            .start(
                scratch.path(),
                &database_password,
                54329,
                2283,
                &layout.controller,
            )
            .expect("disposable signed Library did not start");
        host.wait_ready(Duration::from_secs(240)).unwrap();

        let tools = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../tools");
        let mut command = Command::new("powershell.exe");
        command
            .args(["-NoProfile", "-File"])
            .arg(tools.join("qualify_windows_welcome.ps1"))
            .arg("-Executable")
            .arg(&executable)
            .arg("-WatchedFolder")
            .arg(source.path())
            .env(
                "FRAMELEAF_SYNTHETIC_PHOTO_PASSWORD",
                photo_password.as_str(),
            );
        let mut smoke = command
            .spawn()
            .expect("Windows UI Automation could not start");
        let tree = crate::process_tree::ProcessTree::attach(&smoke).unwrap_or_else(|_| {
            let _ = smoke.kill();
            let _ = smoke.wait();
            panic!("could not own the Windows acceptance process tree");
        });
        smoke
            .stdin
            .take()
            .unwrap()
            .write_all(b"frameleaf-watch-smoke\r\n")
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(900);
        let result = loop {
            match smoke.try_wait() {
                Ok(Some(status)) => break status.success(),
                Ok(None) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(250))
                }
                _ => break false,
            }
        };
        tree.terminate_confirmed(Duration::from_secs(20)).unwrap();
        let stopped = host.stop();
        assert!(result, "installed Desktop watcher acceptance failed");
        stopped.expect("disposable Library shutdown failed");
    }

    #[cfg(windows)]
    #[tokio::test]
    #[ignore = "requires an installed companion on a disposable hosted runner"]
    async fn disposable_runner_diagnoses_installed_manager_start() {
        assert_eq!(std::env::var("GITHUB_ACTIONS").as_deref(), Ok("true"));
        assert_eq!(
            std::env::var("RUNNER_ENVIRONMENT").as_deref(),
            Ok("github-hosted")
        );
        let manifest = std::env::var("FRAMELEAF_INSTALLED_HOST_MANIFEST")
            .expect("expected the reviewed installed companion identity");
        let setup = HostSetup::default();
        let view = setup
            .start(manifest)
            .await
            .expect("installed Manager startup refused");
        assert_eq!(view.state, "manager-ready");
        setup
            .stop()
            .await
            .expect("installed Manager shutdown failed");
    }

    #[cfg(unix)]
    #[test]
    fn host_package_marker_moves_forward_once_and_refuses_unknown_packages() {
        let root = std::env::temp_dir()
            .canonicalize()
            .unwrap()
            .join(format!("frameleaf-host-marker-{}", uuid::Uuid::new_v4()));
        crate::runtime_store::private_directory(&root).unwrap();
        let path = root.join("host-state.json");
        let marker = |m: &str, r: &str| {
            format!(
                r#"{{"schemaVersion":1,"manifestSha256":"{m}","sourceRevision":"{r}","postgresMajor":"19"}}"#
            )
        };
        let (a, b, c) = ("a".repeat(64), "b".repeat(64), "c".repeat(64));
        let (ra, rb) = ("1".repeat(40), "2".repeat(40));
        let write = |text: &str| {
            use std::os::unix::fs::OpenOptionsExt;
            let _ = std::fs::remove_file(&path);
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&path)
                .unwrap();
            std::fs::write(&path, text).unwrap();
        };
        write(&marker(&a, &ra));
        carry_host_state(&root, (&a, &ra), (&b, &rb)).unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), marker(&b, &rb));
        carry_host_state(&root, (&a, &ra), (&b, &rb)).unwrap();
        assert_eq!(std::fs::read_dir(&root).unwrap().count(), 1);
        write(&marker(&c, &ra));
        assert_eq!(
            carry_host_state(&root, (&a, &ra), (&b, &rb)).unwrap_err(),
            "host_update_requires_manager"
        );
        assert_eq!(std::fs::read_to_string(&path).unwrap(), marker(&c, &ra));
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn library_move_checks_everything_before_its_first_change() {
        use crate::host_state::Owner;
        let (a, b, c) = ("a".repeat(64), "b".repeat(64), "c".repeat(64));
        let (ra, rb) = ("1".repeat(40), "2".repeat(40));
        let id = "aaaaaaaaaaaa";
        let setup = |active: bool, marker: Option<&str>, pending: bool| {
            let root = std::env::temp_dir()
                .canonicalize()
                .unwrap()
                .join(format!("frameleaf-library-move-{}", uuid::Uuid::new_v4()));
            let state = root.join("state");
            crate::runtime_store::private_directory(&root).unwrap();
            let mut owner = Owner::acquire(&state, true).unwrap();
            owner
                .activate(id, &a, crate::host_runtime::HostMode::Server)
                .unwrap();
            if !active {
                owner.clean_stop().unwrap();
            }
            drop(owner);
            if let Some(text) = marker {
                use std::os::unix::fs::OpenOptionsExt;
                let mut file = std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(state.join("host-state.json"))
                    .unwrap();
                std::io::Write::write_all(&mut file, text.as_bytes()).unwrap();
            }
            if pending {
                crate::runtime_store::private_directory(&state.join("checkpoints")).unwrap();
                crate::runtime_store::private_directory(&state.join("checkpoints/op")).unwrap();
            }
            (root, state)
        };
        let config = |state: &std::path::Path| Configuration {
            installation_id: id.into(),
            name: "Synthetic".into(),
            release: "frameleaf-v3.0.0-1".into(),
            controller: "/bin/echo".into(),
            state: state.into(),
            data: state.with_file_name("manager"),
            origin: "https://127.0.0.1:9443".into(),
            database_port: 54329,
            api_port: 2283,
        };
        let run = |state: &std::path::Path| {
            let config = config(state);
            let calls = std::cell::Cell::new(0);
            let owner = Owner::acquire(state, true);
            let result = owner.and_then(|owner| {
                move_library(
                    owner,
                    Package {
                        config: &config,
                        candidate: std::path::Path::new("/runtime/a"),
                        manifest: &a,
                        revision: &ra,
                    },
                    Package {
                        config: &config,
                        candidate: std::path::Path::new("/runtime/b"),
                        manifest: &b,
                        revision: &rb,
                    },
                    |_, _| {
                        calls.set(calls.get() + 1);
                        Ok(("d".repeat(64), "e".repeat(64)))
                    },
                    |_, _| Ok(()),
                )
            });
            (result, calls.get())
        };
        let previous = host_state_marker((&a, &ra)).unwrap();
        for (active, marker, pending, code) in [
            (
                true,
                Some(previous.clone()),
                false,
                "host_recovery_requires_manager",
            ),
            (
                false,
                Some(previous.clone()),
                true,
                "host_upgrade_operation_pending",
            ),
            (
                false,
                Some(host_state_marker((&c, &ra)).unwrap()),
                false,
                "host_update_requires_manager",
            ),
        ] {
            let (root, state) = setup(active, marker.as_deref(), pending);
            let before = std::fs::read(state.join("host-state.json")).unwrap();
            let (result, calls) = run(&state);
            assert_eq!(result.unwrap_err(), code);
            assert_eq!(calls, 0, "nothing changes before every check passes");
            assert_eq!(
                std::fs::read(state.join("host-state.json")).unwrap(),
                before
            );
            std::fs::remove_dir_all(root).unwrap();
        }
        let (root, state) = setup(false, Some(&previous), false);
        let (result, calls) = run(&state);
        result.unwrap();
        assert_eq!(calls, 1);
        assert_eq!(
            std::fs::read_to_string(state.join("host-state.json")).unwrap(),
            host_state_marker((&b, &rb)).unwrap()
        );
        assert_eq!(Owner::peek(&state).unwrap().unwrap().manifest_sha256, b);
        assert_eq!(
            run(&state).0.unwrap_err(),
            "host_controller_binding_changed"
        );
        std::fs::remove_dir_all(root).unwrap();
        // A host that never created its database moves without a marker to rewrite.
        let (root, state) = setup(false, None, false);
        run(&state).0.unwrap();
        assert!(!state.join("host-state.json").exists());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn update_excludes_local_host_operations() {
        let setup = HostSetup::default();
        let update = setup.lock_for_update().unwrap();
        assert!(setup.owner.try_lock().is_err());
        assert!(setup.lock_for_update().is_err());
        drop(update);
        setup.active.store(true, Ordering::Release);
        assert!(setup.lock_for_update().is_err());
        setup.active.store(false, Ordering::Release);
        assert!(setup.lock_for_update().is_ok());
    }

    #[cfg(windows)]
    #[test]
    fn pinned_profile_leaf_cannot_disappear_during_shared_startup_helpers() {
        let root =
            std::env::temp_dir().join(format!("frameleaf-setup-pin-{}", uuid::Uuid::new_v4()));
        crate::runtime_store::private_directory(&root).unwrap();
        let pin = pin_profile_leaf(&root).unwrap();
        assert!(std::fs::remove_dir(&root).is_err());
        assert!(std::fs::rename(&root, root.with_extension("moved")).is_err());
        require_leaf(&root).unwrap();
        crate::runtime_store::private_directory(&root).unwrap();
        drop(pin);
        std::fs::remove_dir(root).unwrap();
    }
    #[tokio::test]
    async fn uninstalled_identity_never_starts_a_manager_or_reads_credentials() {
        let setup = HostSetup::default();
        assert_eq!(
            setup.start("../escape".into()).await.err().unwrap(),
            "host_install_identity_invalid"
        );
        assert!(setup.owner.lock().await.is_none());
        assert!(!setup.background_active());
        assert_eq!(setup.snapshot().state, "idle");
    }
    #[cfg(windows)]
    #[test]
    fn windows_setup_never_creates_missing_or_adopts_inherited_profile_leaves() {
        let root = std::env::temp_dir().join(format!("frameleaf-setup-{}", uuid::Uuid::new_v4()));
        assert_eq!(
            require_leaf(&root).unwrap_err(),
            "host_install_windows_profile_required"
        );
        assert!(!root.exists());
        std::fs::create_dir(&root).unwrap();
        std::fs::write(root.join("retained"), b"synthetic only").unwrap();
        assert!(require_leaf(&root).is_err());
        assert_eq!(
            std::fs::read(root.join("retained")).unwrap(),
            b"synthetic only"
        );
        std::fs::remove_dir_all(&root).unwrap();
        crate::runtime_store::private_directory(&root).unwrap();
        require_leaf(&root).unwrap();
        std::fs::remove_dir(root).unwrap();
    }
    #[test]
    fn profile_setup_capability_survives_lifecycle_transitions() {
        let setup = HostSetup::default();
        for state in ["idle", "provisioning", "profile-ready", "needs-attention"] {
            setup.set(state, None, None);
            let view = serde_json::to_value(setup.snapshot()).unwrap();
            assert_eq!(
                view["profileSetupAvailable"],
                cfg!(any(target_os = "linux", windows))
            );
            assert_eq!(view["state"], state);
        }
    }
    #[tokio::test]
    async fn local_photos_requires_an_owned_manager_before_reading_credentials() {
        assert_eq!(
            HostSetup::default().photos_url().await.unwrap_err(),
            "native_manager_not_ready"
        );
    }
    #[test]
    fn local_photos_origin_is_only_the_configured_loopback_port() {
        let url = local_photos_origin(2283).unwrap();
        assert_eq!(url.as_str(), "http://127.0.0.1:2283/");
        assert!(local_photos_origin(0).is_err());
        for other in [
            "http://localhost:2283/",
            "https://127.0.0.1:2283/",
            "http://127.0.0.1:9443/",
            "https://nas.example/",
        ] {
            assert_ne!(url.origin(), url::Url::parse(other).unwrap().origin());
        }
        assert_eq!(url.origin(), url.join("auth/register").unwrap().origin());
    }
    #[test]
    fn native_prerelease_label_preserves_real_version_and_source_identity() {
        assert_eq!(
            native_release("3.2.0", &"a".repeat(40)).unwrap(),
            "frameleaf-v3.2.0-native.aaaaaaaaaaaa-1"
        );
        for version in ["", "3.2", "3.2.0/escape", "3.2.0.1", "3..0"] {
            assert!(native_release(version, &"a".repeat(40)).is_err());
        }
        assert!(native_release("3.2.0", "main").is_err());
    }
    #[test]
    fn lifecycle_management_gate_only_blocks_the_owned_origin_during_transitions() {
        let setup = HostSetup::default();
        let record: Installation = serde_json::from_value(serde_json::json!({"schemaVersion":1,"manifestSha256":"a".repeat(64),"controllerSha256":"b".repeat(64)})).unwrap();
        setup.active.store(true, Ordering::Release);
        setup.set("starting", None, Some(record.clone()));
        assert!(setup
            .require_management_origin("https://127.0.0.1:9443")
            .is_err());
        assert!(setup
            .require_management_origin("https://nas.example")
            .is_ok());
        setup.set("provisioning", None, Some(record.clone()));
        assert!(setup
            .require_management_origin("https://127.0.0.1:9443")
            .is_err());
        setup.cancel();
        assert!(setup.cancel.load(Ordering::Acquire));
        setup.set("manager-ready", None, Some(record));
        assert!(setup
            .require_management_origin("https://127.0.0.1:9443")
            .is_ok());
        assert!(setup.snapshot().background_active);
    }
    #[tokio::test]
    async fn profile_setup_serializes_authorization_and_never_starts_a_manager() {
        let setup = Arc::new(HostSetup::default());
        let record: Installation = serde_json::from_value(serde_json::json!({"schemaVersion":1,"manifestSha256":"a".repeat(64),"controllerSha256":"b".repeat(64)})).unwrap();
        let inspect = setup.clone();
        let view = setup
            .provision_record(record.clone(), move |_| {
                assert!(inspect.background_active());
                assert_eq!(inspect.snapshot().state, "provisioning");
                assert!(inspect.owner.try_lock().is_err());
                assert!(inspect
                    .require_management_origin("https://127.0.0.1:9443")
                    .is_err());
                Ok(())
            })
            .await
            .unwrap();
        assert_eq!(view.state, "profile-ready");
        assert_eq!(view.installation, Some(record.clone()));
        assert!(!view.background_active);
        assert!(setup.owner.lock().await.is_none());
        let held = setup.owner.lock().await;
        assert_eq!(
            setup
                .provision_record(record.clone(), |_| panic!(
                    "busy setup must not request authorization"
                ))
                .await
                .err()
                .unwrap(),
            "native_host_busy"
        );
        drop(held);
        assert_eq!(
            setup
                .provision_record(record.clone(), |_| Err(
                    "host_profile_authorization_cancelled".into()
                ))
                .await
                .err()
                .unwrap(),
            "host_profile_authorization_cancelled"
        );
        let view = setup.snapshot();
        assert_eq!(view.state, "needs-attention");
        assert_eq!(view.installation, Some(record));
        assert!(!view.background_active);
        assert!(setup.owner.lock().await.is_none());
    }
    #[cfg(unix)]
    #[test]
    fn setup_never_adopts_a_shared_or_linked_profile_leaf() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let root = std::env::temp_dir()
            .canonicalize()
            .unwrap()
            .join(format!("frameleaf-setup-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(require_leaf(&root).is_err());
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        require_leaf(&root).unwrap();
        let alias = root.with_extension("alias");
        symlink(&root, &alias).unwrap();
        assert!(require_leaf(&alias).is_err());
        std::fs::remove_file(alias).unwrap();
        std::fs::remove_dir(root).unwrap();
    }
    #[test]
    fn failed_or_cancelled_restart_retains_exit_protection_and_previous_installation() {
        let setup = HostSetup::default();
        let previous: Installation=serde_json::from_value(serde_json::json!({"schemaVersion":1,"manifestSha256":"a".repeat(64),"controllerSha256":"b".repeat(64)})).unwrap();
        let attempted: Installation=serde_json::from_value(serde_json::json!({"schemaVersion":1,"manifestSha256":"c".repeat(64),"controllerSha256":"d".repeat(64)})).unwrap();
        setup.startup_failed(
            Some(previous.clone()),
            attempted.clone(),
            "native_manager_start_cancelled".into(),
        );
        assert!(setup.background_active());
        assert_eq!(setup.snapshot().installation, Some(previous));
        setup.startup_failed(None, attempted.clone(), "native_host_setup_failed".into());
        assert!(!setup.background_active());
        assert_eq!(setup.snapshot().installation, Some(attempted));
    }
    #[test]
    fn local_authorization_password_is_bounded_before_credentials_or_network() {
        for password in [
            "",
            "short",
            "1234567890123",
            &"x".repeat(257),
            "long-password\ncontrol",
        ] {
            assert!(require_password(password).is_err());
        }
        require_password("12345678901234").unwrap();
    }
    #[test]
    fn local_claim_proof_is_private_bounded_and_never_follows_links() {
        use std::io::Write;
        let root = std::env::temp_dir()
            .canonicalize()
            .unwrap()
            .join(format!("frameleaf-claim-proof-{}", uuid::Uuid::new_v4()));
        crate::runtime_store::private_directory(&root).unwrap();
        let dir = cap_std::fs::Dir::from_std_file(crate::host_storage::directory(&root).unwrap());
        for value in [
            "a".repeat(64),
            "a".repeat(65),
            "A".repeat(64),
            "short".into(),
        ] {
            let mut file = dir
                .open_with("claim-key", &crate::host_state::options(true))
                .unwrap();
            file.write_all(value.as_bytes()).unwrap();
            drop(file);
            assert_eq!(claim_proof(&root).is_ok(), value == "a".repeat(64));
            dir.remove_file("claim-key").unwrap();
        }
        let mut file = dir
            .open_with("original", &crate::host_state::options(true))
            .unwrap();
        file.write_all("a".repeat(64).as_bytes()).unwrap();
        drop(file);
        std::fs::hard_link(root.join("original"), root.join("claim-key")).unwrap();
        assert!(claim_proof(&root).is_err());
        std::fs::remove_file(root.join("claim-key")).unwrap();
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(root.join("original"), root.join("claim-key")).unwrap();
            assert!(claim_proof(&root).is_err());
        }
        std::fs::remove_dir_all(root).unwrap();
    }
}
