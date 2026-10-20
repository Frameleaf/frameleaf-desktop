use super::*;

use crate::host_epochs::HostExecution;
use crate::host_runtime::VerifiedHostRuntime;
use zeroize::Zeroizing;

pub(crate) fn validate_update_request(
    manifest: &str,
    backup: uuid::Uuid,
    approved: bool,
) -> Result<(), String> {
    if !approved {
        return Err("manager_update_approval_required".into());
    }
    if !crate::native_runtime::digest_valid(manifest, 64) {
        return Err("host_install_identity_invalid".into());
    }
    if backup.is_nil() {
        return Err("manager_request_invalid".into());
    }
    Ok(())
}
fn update_configuration(
    source: &Configuration,
    layout: &crate::host_install::Layout,
    target: &VerifiedHostRuntime,
) -> Result<Configuration, String> {
    target.check_files()?;
    let package: serde_json::Value = serde_json::from_slice(&crate::runtime_store::read_bounded(
        &layout.runtime.join("payload/server/package.json"),
        64 * 1024,
    )?)
    .map_err(|_| "native_host_version_invalid")?;
    let configuration = Configuration {
        installation_id: source.installation_id.clone(),
        secure_installation_id: source.secure_installation_id.clone(),
        name: source.name.clone(),
        release: native_release(
            package["version"]
                .as_str()
                .ok_or("native_host_version_invalid")?,
            target.source_revision(),
        )?,
        controller: layout.controller.clone(),
        state: source.state.clone(),
        data: source.data.clone(),
        origin: source.origin.clone(),
        database_port: source.database_port,
        api_port: source.api_port,
    };
    crate::manager_host::validate_configuration(&configuration)?;
    Ok(configuration)
}
impl HostSetup {
    pub(crate) async fn update(
        &self,
        manifest: String,
        backup: uuid::Uuid,
        approved: bool,
    ) -> Result<View, String> {
        validate_update_request(&manifest, backup, approved)?;
        let mut owner = self.owner.try_lock().map_err(|_| "native_host_busy")?;
        let running = owner.as_mut().ok_or("native_manager_not_ready")?;
        self.cancel.store(false, Ordering::Release);
        let source_record = running.installation.clone();
        let source_copy = source_record.clone();
        let (source, target, layout, target_record) =
            tauri::async_runtime::spawn_blocking(move || {
                let (_, source) = installed_runtime(&source_copy)?;
                let record = Installation::read(&manifest)?;
                let (layout, target) = installed_runtime(&record)?;
                if source_copy.layout()?.profiles != layout.profiles {
                    return Err("host_install_profile_required".into());
                }
                Ok::<_, String>((source, target, layout, record))
            })
            .await
            .map_err(|_| "native_host_setup_failed".to_string())??;
        let _source_code =
            crate::package_lease::CodeLease::acquire(&source_record.layout()?.runtime)?;
        let _target_code = crate::package_lease::CodeLease::acquire(&layout.runtime)?;
        let destination = update_configuration(&running.configuration, &layout, &target)?;
        source.update_candidate_paths(&target, &running.configuration)?;
        let authority = crate::credentials::CredentialEpochAuthority;
        let execution =
            HostExecution::new(&authority, &running.configuration.secure_installation_id)?;
        source.review_update(
            &target,
            &running.configuration.state,
            &running.configuration.installation_id,
            &execution,
        )?;
        let identity = crate::credentials::identity()?;
        let saved =
            crate::credentials::load::<crate::manager::SavedManager>(crate::manager::CREDENTIAL)?
                .ok_or("manager_pairing_required")?;
        let certificate = running
            .manager
            .management_identity(&running.configuration)?;
        let grant = local_grant(
            &saved,
            &identity,
            &running.configuration,
            &certificate.sha256,
        )?;
        if !grant.scopes.contains(&crate::manager::Scope::Update) {
            return Err("manager_update_approval_required".into());
        }
        self.set("updating", None, Some(source_record.clone()));
        let result = async {
            if self.cancel.load(Ordering::Acquire) {
                return Err("native_manager_start_cancelled".into());
            }
            let mut reply = crate::manager::send(
                &saved,
                &identity,
                crate::manager::Command::ApproveUpdate {
                    backup_operation_id: backup,
                    target_manifest_sha256: target_record.manifest_sha256.clone(),
                    migrations_approved: true,
                    key: uuid::Uuid::new_v4(),
                },
            )
            .await?;
            running
                .manager
                .management_identity(&running.configuration)?;
            let token = match reply
                .as_object_mut()
                .and_then(|value| value.remove("approval"))
            {
                Some(serde_json::Value::String(token)) => Zeroizing::new(token),
                _ => return Err("manager_response_invalid".into()),
            };
            if self.cancel.load(Ordering::Acquire) {
                return Err("native_manager_start_cancelled".into());
            }
            running
                .manager
                .reserve_update(&source, &target, &running.configuration, &execution)
                .await?;
            Ok::<_, String>(token)
        }
        .await;
        let token = match result {
            Ok(token) => token,
            Err(error) => {
                self.set("needs-attention", Some(error.clone()), Some(source_record));
                return Err(error);
            }
        };
        // The durable reservation now excludes starts while the old Manager/profile guard is released.
        let retired = owner.take().ok_or("native_manager_not_ready")?;
        let Running {
            manager,
            configuration,
            installation: _,
        } = retired;
        drop(manager);
        let cancel = self.cancel.clone();
        let attempted = target_record.clone();
        let result = tauri::async_runtime::spawn_blocking(move || {
            let authority = crate::credentials::CredentialEpochAuthority;
            let execution = HostExecution::new(&authority, &configuration.secure_installation_id)?;
            if cancel.load(Ordering::Acquire) {
                return Err("native_manager_start_cancelled".into());
            }
            source.prepare_update_credentials(&target, &configuration, &destination, &execution)?;
            if cancel.load(Ordering::Acquire) {
                return Err("native_manager_start_cancelled".into());
            }
            source.consume_update_approval(
                &target,
                &configuration,
                &destination,
                &execution,
                &token,
            )?;
            source.begin_update_handover(
                &target,
                &configuration,
                &destination,
                &execution,
                &cancel,
            )?;
            source.select_update_candidate(
                &target,
                &configuration,
                &destination,
                &execution,
                &cancel,
            )?;
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
        })
        .await
        .map_err(|_| "native_host_update_failed".to_string())
        .and_then(|result| result);
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
                self.set("needs-attention", Some(error.clone()), Some(source_record));
                Err(error)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn update_request_refuses_missing_consent_invalid_identity_and_missing_owner_before_external_access(
    ) {
        let setup = HostSetup::default();
        for (manifest, backup, approved, expected) in [
            (
                "a".repeat(64),
                uuid::Uuid::new_v4(),
                false,
                "manager_update_approval_required",
            ),
            (
                "bad".into(),
                uuid::Uuid::new_v4(),
                true,
                "host_install_identity_invalid",
            ),
            (
                "a".repeat(64),
                uuid::Uuid::nil(),
                true,
                "manager_request_invalid",
            ),
            (
                "a".repeat(64),
                uuid::Uuid::new_v4(),
                true,
                "native_manager_not_ready",
            ),
        ] {
            assert!(matches!(setup.update(manifest,backup,approved).await,Err(e) if e==expected));
            assert!(!setup.background_active());
            assert_eq!(setup.snapshot().state, "idle");
        }
    }
    #[test]
    fn updating_blocks_concurrent_local_manager_actions_without_blocking_unrelated_origins() {
        let setup = HostSetup::default();
        let record:Installation=serde_json::from_value(serde_json::json!({"schemaVersion":1,"manifestSha256":"a".repeat(64),"controllerSha256":"b".repeat(64)})).unwrap();
        setup.set("updating", None, Some(record));
        assert_eq!(
            setup
                .require_management_origin("https://127.0.0.1:9443")
                .unwrap_err(),
            "native_host_busy"
        );
        setup
            .require_management_origin("https://nas.example:9443")
            .unwrap();
    }
    #[cfg(unix)]
    #[test]
    fn target_configuration_keeps_owned_library_and_identity_and_refuses_changed_signed_package() {
        use crate::host_epochs::host_fixture::Fixture;
        let mut fixture = Fixture::new();
        let package = br#"{"version":"3.1.0"}"#;
        std::fs::write(fixture.0.join("server/package.json"), package).unwrap();
        fixture.1["files"]["server/package.json"] = serde_json::json!({"bytes":package.len(),"sha256":format!("{:x}",Sha256::digest(package))});
        let runtime = fixture.verify().unwrap();
        let source = Configuration {
            installation_id: "a".repeat(12),
            secure_installation_id: "11111111-1111-4111-8111-111111111111".into(),
            name: "My original library".into(),
            release: "frameleaf-v3.0.0-1".into(),
            controller: "/bin/echo".into(),
            state: fixture.2.with_extension("state"),
            data: fixture.2.with_extension("manager"),
            origin: "https://127.0.0.1:9443".into(),
            database_port: 54329,
            api_port: 2283,
        };
        let layout = crate::host_install::Layout {
            runtime: fixture.2.clone(),
            controller: "/bin/sleep".into(),
            profiles: fixture.2.with_extension("profiles"),
        };
        let target = update_configuration(&source, &layout, &runtime).unwrap();
        assert_eq!(target.secure_installation_id, source.secure_installation_id);
        let mut expected = serde_json::to_value(&source).unwrap();
        expected["controller"] = serde_json::json!(layout.controller);
        expected["release"] = serde_json::json!("frameleaf-v3.1.0-native.aaaaaaaaaaaa-1");
        assert_eq!(serde_json::to_value(&target).unwrap(), expected);
        std::fs::write(
            fixture.0.join("server/package.json"),
            br#"{"version":"9.9.9"}"#,
        )
        .unwrap();
        assert!(update_configuration(&source, &layout, &runtime).is_err());
        assert!(!source.state.exists());
        assert!(!source.data.exists());
    }
}

#[path = "host_update_recovery.rs"]
pub(super) mod recovery;
