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
    fn set(&self, state: &str, code: Option<String>, installation: Option<Installation>) {
        *self.view.lock().unwrap_or_else(|error| error.into_inner()) = View {
            state: state.into(),
            code,
            origin: installation
                .as_ref()
                .map(|_| "https://127.0.0.1:9443".into()),
            installation,
            background_active: false,
            profile_setup_available: cfg!(any(target_os = "linux", windows)),
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
            self.provision_record(record, crate::windows_profile_elevation::provision)
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
fn pin_profile_leaf(path: &std::path::Path) -> Result<std::fs::File, String> {
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_LIST_DIRECTORY,
        FILE_READ_ATTRIBUTES, READ_CONTROL,
    };
    let required = "host_install_windows_profile_required";
    let file = std::fs::OpenOptions::new()
        // Metadata-only handles do not participate in Windows sharing checks.
        .access_mode(READ_CONTROL | FILE_READ_ATTRIBUTES | FILE_LIST_DIRECTORY)
        .share_mode(3)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
        .map_err(|_| required)?;
    let info = file.metadata().map_err(|_| required)?;
    if !info.is_dir() || info.file_attributes() & 0x400 != 0 {
        return Err(required.into());
    }
    Ok(file)
}
fn launch(record: &Installation, cancel: &AtomicBool) -> Result<Running, String> {
    #[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
    {
        let _ = (record, cancel);
        Err("host_install_platform_unsupported".into())
    }
    #[cfg(any(target_os = "macos", target_os = "linux", windows))]
    {
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
        #[cfg(windows)]
        let profile = layout.profiles.join(&uid);
        let state = profile.join("state");
        let data = profile.join("manager");
        // Downstream shared setup helpers may create missing leaves; keep both existing objects pinned.
        #[cfg(windows)]
        let _profiles = [pin_profile_leaf(&state)?, pin_profile_leaf(&data)?];
        require_leaf(&state)?;
        require_leaf(&data)?;
        let package: serde_json::Value =
            serde_json::from_slice(&crate::runtime_store::read_bounded(
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
        let identity =
            serde_json::to_vec(&(record, uid)).map_err(|_| "native_host_setup_failed")?;
        let configuration = Configuration {
            installation_id: format!("{:x}", Sha256::digest(identity))[..12].into(),
            name: "My Frameleaf library".into(),
            release,
            controller: layout.controller,
            state,
            data,
            origin: "https://127.0.0.1:9443".into(),
            database_port: 54329,
            api_port: 2283,
        };
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
