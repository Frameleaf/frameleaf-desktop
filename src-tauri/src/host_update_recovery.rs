use super::*;

use crate::host_epochs::HostEpochAuthority;
use std::{io::Read, path::Path};

fn state_record(state: &Path, name: &str) -> Result<Option<Vec<u8>>, String> {
    if !matches!(name, "host-update.json" | "controller-state.json") {
        return Err("host_update_discovery_invalid".into());
    }
    match std::fs::symlink_metadata(state) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err("host_update_discovery_invalid".into()),
        Ok(_) => {}
    }
    require_leaf(state)?;
    let root = cap_std::fs::Dir::from_std_file(crate::host_storage::directory(state)?);
    match root.symlink_metadata(name) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err("host_update_discovery_invalid".into()),
        Ok(_) => {}
    }
    let path = Path::new(name);
    let mut file = crate::copy_source::staged_file(&root, path)?;
    crate::host_state::valid_file(
        &file
            .try_clone()
            .map_err(|_| "host_update_discovery_invalid")?
            .into_std(),
    )?;
    let stamp = crate::copy_source::opened_stamp(&file)?;
    let length = file
        .metadata()
        .map_err(|_| "host_update_discovery_invalid")?
        .len();
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(4097)
        .read_to_end(&mut bytes)
        .map_err(|_| "host_update_discovery_invalid")?;
    if bytes.is_empty() || bytes.len() > 4096 {
        return Err("host_update_discovery_invalid".into());
    }
    crate::copy_source::unchanged(&root, path, &file, &stamp, length, bytes.len() as u64)?;
    Ok(Some(bytes))
}
fn pending_at(state: &Path) -> Result<Option<PendingUpdate>, String> {
    let Some(bytes) = state_record(state, "host-update.json")? else {
        return Ok(None);
    };
    let value: serde_json::Value =
        serde_json::from_slice(&bytes).map_err(|_| "host_update_discovery_invalid")?;
    let field = |value: &serde_json::Value, key: &str| {
        value[key]
            .as_str()
            .map(str::to_owned)
            .ok_or_else(|| "host_update_discovery_invalid".to_string())
    };
    let hint = PendingUpdate {
        operation_id: field(&value, "operationId")?,
        phase: field(&value, "state")?,
        from_manifest_sha256: field(&value["review"], "fromManifestSha256")?,
        to_manifest_sha256: field(&value["review"], "toManifestSha256")?,
        installation_id: field(&value["review"], "installationId")?,
        secure_installation_id: field(&value["review"], "secureInstallationId")?,
        record_sha256: format!("{:x}", Sha256::digest(bytes)),
    };
    if value["protocolVersion"] != 1
        || !matches!(
            hint.phase.as_str(),
            "reserved" | "preparingCredentials" | "credentialsPrepared" | "approvalConsumed"
        )
        || !crate::host_runtime::checkpoint_operation_id(&hint.operation_id)
        || !crate::native_runtime::digest_valid(&hint.from_manifest_sha256, 64)
        || !crate::native_runtime::digest_valid(&hint.to_manifest_sha256, 64)
        || hint.from_manifest_sha256 == hint.to_manifest_sha256
        || !crate::native_runtime::digest_valid(&hint.installation_id, 12)
        || !crate::host_state::valid_installation_id(&hint.secure_installation_id)
    {
        return Err("host_update_discovery_invalid".into());
    }
    Ok(Some(hint))
}
fn profile_paths() -> Result<(std::path::PathBuf, std::path::PathBuf), String> {
    #[cfg(unix)]
    {
        let uid = unsafe { libc::geteuid() };
        let minimum = if cfg!(target_os = "linux") { 1 } else { 501 };
        if uid < minimum || unsafe { libc::getuid() } != uid {
            return Err("host_install_profile_required".into());
        }
        let profile = crate::host_install::Layout::new(&"0".repeat(64), &"0".repeat(64))?
            .profiles
            .join(uid.to_string());
        Ok((profile.join("state"), profile.join("manager")))
    }
    #[cfg(windows)]
    {
        crate::windows_host_profile::paths()
    }
}
pub(crate) fn discover_status(mut view: View) -> Result<View, String> {
    if view.background_active {
        return Ok(view);
    }
    let (state, _) = profile_paths()?;
    if let Some(hint) = pending_at(&state)? {
        view.installation = Some(Installation::read(&hint.from_manifest_sha256)?);
        view.state = "update-pending".into();
        view.pending_update = Some(hint);
        return Ok(view);
    }
    if let Some(bytes) = state_record(&state, "controller-state.json")? {
        let marker: serde_json::Value =
            serde_json::from_slice(&bytes).map_err(|_| "host_update_discovery_invalid")?;
        let manifest = marker["manifestSha256"]
            .as_str()
            .filter(|value| crate::native_runtime::digest_valid(value, 64))
            .ok_or("host_update_discovery_invalid")?;
        // An installed-package suggestion only; normal launch still verifies profile and epoch authority.
        view.installation = Some(Installation::read(manifest)?);
    }
    Ok(view)
}
/// Reopen a committed target using existing admission and profile identity.
pub(crate) fn require_admitted_profile(
    target: &VerifiedHostRuntime,
    execution: &HostExecution<'_>,
    state: &Path,
    data: &Path,
    secure: &str,
) -> Result<String, String> {
    execution.with_admitted(target, &mut || Ok(()))?;
    crate::manager_profile::configuration_id(state, data, secure)?
        .ok_or("host_update_discovery_invalid".into())
}

enum Admission {
    Source,
    Target,
}
fn admission(
    source: &VerifiedHostRuntime,
    target: &VerifiedHostRuntime,
    execution: &HostExecution<'_>,
) -> Result<Admission, String> {
    match execution.with_admitted(source, &mut || Ok(())) {
        Ok(()) => Ok(Admission::Source),
        Err(error) if error == "host_epoch_rollback" => {
            execution.with_admitted(target, &mut || Ok(()))?;
            Ok(Admission::Target)
        }
        Err(error) => Err(error),
    }
}
fn source_configuration(
    hint: &PendingUpdate,
    state: std::path::PathBuf,
    data: std::path::PathBuf,
    layout: &crate::host_install::Layout,
    runtime: &VerifiedHostRuntime,
    secure: &str,
) -> Result<Configuration, String> {
    if hint.secure_installation_id != secure {
        return Err("host_installation_identity_changed".into());
    }
    let base = Configuration {
        installation_id: hint.installation_id.clone(),
        secure_installation_id: secure.into(),
        name: "My Frameleaf library".into(),
        release: "frameleaf-v0.0.0-1".into(),
        controller: layout.controller.clone(),
        state,
        data,
        origin: "https://127.0.0.1:9443".into(),
        database_port: 54329,
        api_port: 2283,
    };
    update_configuration(&base, layout, runtime)
}
struct Activity<'a> {
    active: &'a AtomicBool,
    retain: bool,
}
impl<'a> Activity<'a> {
    fn new(active: &'a AtomicBool, retain: bool) -> Self {
        active.store(true, Ordering::Release);
        Self { active, retain }
    }
}
impl Drop for Activity<'_> {
    fn drop(&mut self) {
        self.active.store(self.retain, Ordering::Release);
    }
}
impl HostSetup {
    pub(crate) async fn recover_update(
        &self,
        manifest: String,
        cancel_update: bool,
    ) -> Result<View, String> {
        if !crate::native_runtime::digest_valid(&manifest, 64) {
            return Err("host_install_identity_invalid".into());
        }
        let mut owner = self.owner.try_lock().map_err(|_| "native_host_busy")?;
        let mut activity = Activity::new(&self.active, owner.is_some());
        self.cancel.store(false, Ordering::Release);
        let (state, data) = profile_paths()?;
        require_leaf(&state)?;
        require_leaf(&data)?;
        let hint = pending_at(&state)?;
        if cancel_update
            && hint
                .as_ref()
                .is_none_or(|hint| hint.phase == "approvalConsumed")
        {
            return Err("host_update_cancel_unsafe".into());
        }
        if hint
            .as_ref()
            .is_some_and(|hint| hint.to_manifest_sha256 != manifest)
        {
            return Err("host_update_reservation_changed".into());
        }
        if !cancel_update
            && hint
                .as_ref()
                .is_some_and(|hint| hint.phase != "approvalConsumed")
        {
            return Err("host_update_new_approval_required".into());
        }
        let authority = crate::credentials::CredentialEpochAuthority;
        let secure = authority.installation_id()?;
        let target_record = Installation::read(&manifest)?;
        let (target_layout, target) = installed_runtime(&target_record)?;
        let _target_code = crate::package_lease::CodeLease::acquire(&target_layout.runtime)?;
        if let Some(hint) = hint {
            let source_record = Installation::read(&hint.from_manifest_sha256)?;
            let (source_layout, source) = installed_runtime(&source_record)?;
            if source_layout.profiles != target_layout.profiles {
                return Err("host_install_profile_required".into());
            }
            let _source_code = crate::package_lease::CodeLease::acquire(&source_layout.runtime)?;
            let configuration =
                source_configuration(&hint, state, data, &source_layout, &source, &secure)?;
            let destination = update_configuration(&configuration, &target_layout, &target)?;
            source.update_candidate_paths(&target, &configuration)?;
            if let Some(running) = owner.as_mut() {
                if running.installation != source_record {
                    return Err("native_host_stop_required".into());
                }
                running
                    .manager
                    .stop_idle(
                        &configuration,
                        source.manifest_sha256(),
                        Duration::from_secs(10),
                    )
                    .await?;
            }
            drop(owner.take());
            activity.retain = false;
            self.active.store(true, Ordering::Release);
            self.set("updating", None, Some(source_record.clone()));
            let cancel = self.cancel.clone();
            let attempted = if cancel_update {
                source_record.clone()
            } else {
                target_record.clone()
            };
            let result = tauri::async_runtime::spawn_blocking(move || {
                if pending_at(&configuration.state)?.as_ref() != Some(&hint) {
                    return Err("host_update_reservation_changed".into());
                }
                if cancel.load(Ordering::Acquire) {
                    return Err("native_manager_start_cancelled".into());
                }
                let authority = crate::credentials::CredentialEpochAuthority;
                let execution = HostExecution::new(&authority, &secure)?;
                if cancel_update {
                    if hint.phase == "reserved" {
                        source.cancel_update_reservation(&target, &configuration, &execution)?;
                    } else {
                        source.prepare_update_credentials(
                            &target,
                            &configuration,
                            &destination,
                            &execution,
                        )?;
                        if cancel.load(Ordering::Acquire) {
                            return Err("native_manager_start_cancelled".into());
                        }
                        source.abort_prepared_update(
                            &target,
                            &configuration,
                            &destination,
                            &execution,
                        )?;
                    }
                    launch(&source_record, &cancel)
                } else {
                    let proof =
                        crate::host_state::Owner::acquire_update(&configuration.state, &secure)?;
                    let selected = proof.update_selection_evidence()?.is_some();
                    drop(proof);
                    if !selected {
                        match admission(&source, &target, &execution)? {
                            Admission::Source => {
                                source.begin_update_handover(
                                    &target,
                                    &configuration,
                                    &destination,
                                    &execution,
                                    &cancel,
                                )?;
                            }
                            Admission::Target => {
                                source.review_update_recovery(
                                    &target,
                                    &configuration,
                                    &destination,
                                    &execution,
                                )?;
                            }
                        }
                        source.select_update_candidate(
                            &target,
                            &configuration,
                            &destination,
                            &execution,
                            &cancel,
                        )?;
                    }
                    // Publication includes authenticated pointer recovery and accepts exact partial publication.
                    source.publish_update_selection(
                        &target,
                        &configuration,
                        &destination,
                        &execution,
                        &cancel,
                    )?;
                    source.finalize_update_selection(
                        &target,
                        &configuration,
                        &destination,
                        &execution,
                        &cancel,
                    )?;
                    launch(&target_record, &cancel)
                }
            })
            .await
            .map_err(|_| "native_host_update_failed".to_string())
            .and_then(|result| result);
            let result = self.finish_recovery(&mut owner, result, attempted).await;
            activity.retain = owner.is_some();
            return result;
        }
        // Commit ambiguity: require an ALREADY admitted target and an existing bound profile, never enroll.
        let execution = HostExecution::new(&authority, &secure)?;
        require_admitted_profile(&target, &execution, &state, &data, &secure)?;
        if let Some(running) = owner.as_mut() {
            if running.installation != target_record {
                return Err("native_host_stop_required".into());
            }
            running
                .manager
                .management_identity(&running.configuration)?;
            self.set("manager-ready", None, Some(target_record));
            return Ok(self.snapshot());
        }
        self.active.store(true, Ordering::Release);
        self.set("updating", None, Some(target_record.clone()));
        let cancel = self.cancel.clone();
        let attempted = target_record.clone();
        let result = tauri::async_runtime::spawn_blocking(move || launch(&target_record, &cancel))
            .await
            .map_err(|_| "native_host_update_failed".to_string())
            .and_then(|result| result);
        let result = self.finish_recovery(&mut owner, result, attempted).await;
        activity.retain = owner.is_some();
        result
    }
    async fn finish_recovery(
        &self,
        owner: &mut Option<Running>,
        result: Result<Running, String>,
        attempted: Installation,
    ) -> Result<View, String> {
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
                self.active.store(true, Ordering::Release);
                self.set("manager-ready", None, Some(attempted));
                Ok(self.snapshot())
            }
            Err(error) => {
                self.active.store(false, Ordering::Release);
                self.set("needs-attention", Some(error.clone()), Some(attempted));
                Err(error)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn recovery_activity_releases_preflight_failure_and_keeps_only_retained_manager_ownership() {
        let active = AtomicBool::new(false);
        let _ = std::panic::catch_unwind(|| {
            let _job = Activity::new(&active, false);
            assert!(active.load(Ordering::Acquire));
            panic!("synthetic preflight refusal");
        });
        assert!(!active.load(Ordering::Acquire));
        {
            let _job = Activity::new(&active, true);
        }
        assert!(active.load(Ordering::Acquire));
        {
            let mut job = Activity::new(&active, true);
            job.retain = false;
        }
        assert!(!active.load(Ordering::Acquire));
    }
    #[tokio::test]
    async fn malformed_recovery_target_refuses_before_profile_or_credential_access() {
        let setup = HostSetup::default();
        for cancel in [false, true] {
            assert!(
                matches!(setup.recover_update("bad".into(),cancel).await,Err(e) if e=="host_install_identity_invalid")
            );
            assert!(!setup.background_active());
        }
    }
    #[cfg(unix)]
    fn record() -> serde_json::Value {
        serde_json::json!({"protocolVersion":1,"state":"reserved","operationId":uuid::Uuid::new_v4(),"review":{"installationId":"a".repeat(12),"secureInstallationId":"11111111-1111-4111-8111-111111111111","fromManifestSha256":"b".repeat(64),"toManifestSha256":"c".repeat(64)}})
    }
    #[cfg(unix)]
    #[test]
    fn pending_update_hints_are_private_bounded_readonly_and_not_authorization() {
        use std::os::unix::fs::PermissionsExt;
        let root = std::env::temp_dir()
            .canonicalize()
            .unwrap()
            .join(format!("fl-update-hint-{}", uuid::Uuid::new_v4()));
        assert!(pending_at(&root).unwrap().is_none());
        assert!(!root.exists());
        crate::runtime_store::private_directory(&root).unwrap();
        let path = root.join("host-update.json");
        let mut value = record();
        for phase in [
            "reserved",
            "preparingCredentials",
            "credentialsPrepared",
            "approvalConsumed",
        ] {
            value["state"] = serde_json::json!(phase);
            std::fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
            let before = std::fs::read(&path).unwrap();
            let hint = pending_at(&root).unwrap().unwrap();
            let display = serde_json::to_value(&hint).unwrap();
            assert_eq!(display["phase"], phase);
            assert!(display.get("installationId").is_none());
            assert!(display.get("secureInstallationId").is_none());
            assert_eq!(std::fs::read(&path).unwrap(), before);
        }
        for fault in [
            "phase",
            "operation",
            "source",
            "configuration",
            "schema",
            "oversized",
            "symlink",
            "hardlink",
        ] {
            let mut value = record();
            match fault {
                "phase" => value["state"] = serde_json::json!("committed"),
                "operation" => value["operationId"] = serde_json::json!(uuid::Uuid::nil()),
                "source" => {
                    value["review"]["fromManifestSha256"] =
                        value["review"]["toManifestSha256"].clone()
                }
                "configuration" => value["review"]["installationId"] = serde_json::json!("bad"),
                "schema" => value["protocolVersion"] = serde_json::json!(2),
                _ => {}
            }
            std::fs::remove_file(&path).unwrap();
            let bytes = if fault == "oversized" {
                vec![b'x'; 4097]
            } else {
                serde_json::to_vec(&value).unwrap()
            };
            let original = root.join("retained");
            if matches!(fault, "symlink" | "hardlink") {
                std::fs::write(&original, &bytes).unwrap();
                std::fs::set_permissions(&original, std::fs::Permissions::from_mode(0o600))
                    .unwrap();
                if fault == "symlink" {
                    std::os::unix::fs::symlink(&original, &path).unwrap();
                } else {
                    std::fs::hard_link(&original, &path).unwrap();
                }
            } else {
                std::fs::write(&path, &bytes).unwrap();
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
            }
            assert!(pending_at(&root).is_err(), "accepted {fault}");
            assert_eq!(std::fs::read(&path).unwrap(), bytes);
            if original.exists() {
                std::fs::remove_file(original).unwrap();
            }
        }
        std::fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn recovery_routing_requires_actual_epoch_admission_and_never_treats_other_errors_as_handover()
    {
        use crate::host_epochs::{
            host_authority::{Authority, ID},
            host_fixture::Fixture,
            HostEpochAuthority, HostEpochs,
        };
        let source = Fixture::new();
        let mut target = Fixture::new();
        target.1["epoch"] = serde_json::json!(2);
        target.1["sourceRevision"] = serde_json::json!("b".repeat(40));
        let source = source.verify().unwrap();
        let target = target.verify().unwrap();
        let authority = Authority::admitted(&source);
        let before = serde_json::to_value(&authority.0.lock().unwrap().1).unwrap();
        assert!(matches!(
            admission(&source, &target, &authority.execution()).unwrap(),
            Admission::Source
        ));
        assert_eq!(
            serde_json::to_value(&authority.0.lock().unwrap().1).unwrap(),
            before
        );
        authority.activate(ID, &target, &mut || Ok(())).unwrap();
        assert!(matches!(
            admission(&source, &target, &authority.execution()).unwrap(),
            Admission::Target
        ));
        let empty = Authority(std::sync::Mutex::new((ID.into(), HostEpochs::default())));
        assert!(
            matches!(admission(&source,&target,&empty.execution()),Err(e) if e=="host_epoch_not_admitted")
        );
        authority.0.lock().unwrap().0 = "22222222-2222-4222-8222-222222222222".into();
        assert!(
            matches!(admission(&source,&target,&authority.execution()),Err(e) if e=="host_installation_identity_changed")
        );
    }
}
