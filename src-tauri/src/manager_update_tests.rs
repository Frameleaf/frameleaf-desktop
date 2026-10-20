use super::*;
use crate::host_epochs::{host_authority::Authority, host_authority::ID, host_fixture::Fixture};
use crate::manager_profile::ProfileGuard;
use serde_json::json;
use std::sync::atomic::AtomicUsize;

struct Handover {
    source: Fixture,
    _target: Fixture,
    current: VerifiedHostRuntime,
    next: VerifiedHostRuntime,
    config: Configuration,
}
impl Handover {
    fn new() -> Self {
        let source = Fixture::new();
        let mut target = Fixture::new();
        target.1["epoch"] = json!(2);
        target.1["sourceRevision"] = json!("b".repeat(40));
        let current = source.verify().unwrap();
        let next = target.verify().unwrap();
        let state = source.2.with_extension("state");
        let data = source.2.with_extension("manager");
        let mut owner = crate::host_state::Owner::acquire(&state, true, ID).unwrap();
        owner
            .activate(
                "aaaaaaaaaaaa",
                current.manifest_sha256(),
                crate::host_runtime::HostMode::Server,
            )
            .unwrap();
        owner.clean_stop().unwrap();
        drop(owner);
        crate::runtime_store::private_directory(&state.join("database")).unwrap();
        crate::runtime_store::private_directory(&data).unwrap();
        fs::write(state.join("database/original"), b"retained original").unwrap();
        for (path, bytes) in [
            (data.join(".host-profile"), "c".repeat(64)),
            (state.join("host-state.json"), format!("{{\"schemaVersion\":1,\"manifestSha256\":\"{}\",\"sourceRevision\":\"{}\",\"postgresMajor\":\"19\"}}\n", current.manifest_sha256(), current.source_revision())),
        ] {
            use std::os::unix::fs::PermissionsExt;
            fs::write(&path, bytes).unwrap();
            fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        let config = Configuration {
            installation_id: "aaaaaaaaaaaa".into(),
            secure_installation_id: ID.into(),
            name: "Synthetic handover".into(),
            release: "frameleaf-v3.0.0-1".into(),
            controller: "/bin/echo".into(),
            state,
            data,
            origin: "https://127.0.0.1:9443".into(),
            database_port: 54329,
            api_port: 2283,
        };
        Self {
            source,
            _target: target,
            current,
            next,
            config,
        }
    }
    fn manager(&self, ignore_term: bool) -> NativeManager {
        let mut command = Command::new("/bin/sh");
        command
            .args([
                "-c",
                if ignore_term {
                    "trap '' TERM; read line; touch \"$1\"; exec /bin/sleep 20"
                } else {
                    "read line; touch \"$1\"; exec /bin/sleep 20"
                },
                "fixture",
            ])
            .arg(self.config.state.join("manager-ready"));
        let mut manager = NativeManager::spawn(
            &mut command,
            Zeroizing::new(b"synthetic\n".to_vec()),
            &self.config.installation_id,
            self.current.manifest_sha256(),
            &self.config.origin,
            reqwest::Client::new(),
            Leases {
                profile: Some(ProfileGuard::acquire(&self.config).unwrap()),
                code: Some(crate::package_lease::CodeLease::acquire(&self.source.2).unwrap()),
                startup: Some(
                    crate::host_state::Owner::acquire(&self.config.state, true, ID).unwrap(),
                ),
                ..Leases::default()
            },
        )
        .unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        while !self.config.state.join("manager-ready").exists() {
            assert!(Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(10));
        }
        // Synthetic process fixture only; actual HTTPS/installed readiness is a separate qualification.
        manager.verified_ready = true;
        manager.startup_lease.take();
        manager
    }
}
impl Drop for Handover {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.config.state);
        let _ = fs::remove_dir_all(&self.config.data);
    }
}
struct Probe<'a> {
    inner: Authority,
    config: &'a Configuration,
    pid: i32,
    reservations: AtomicUsize,
    refuse_reservation: bool,
}
impl HostEpochAuthority for Probe<'_> {
    fn installation_id(&self) -> Result<String, String> {
        self.inner.installation_id()
    }
    fn activate(
        &self,
        id: &str,
        runtime: &VerifiedHostRuntime,
        publish: &mut dyn FnMut() -> Result<(), String>,
    ) -> Result<(), String> {
        self.inner.activate(id, runtime, publish)
    }
    fn with_admitted(
        &self,
        id: &str,
        runtime: &VerifiedHostRuntime,
        operation: &mut dyn FnMut() -> Result<(), String>,
    ) -> Result<(), String> {
        self.inner.with_admitted(id,runtime,&mut || {
            if unsafe { libc::kill(self.pid,0) } != 0 {
                assert!(matches!(ProfileGuard::acquire(self.config),Err(e) if e=="native_profile_already_owned"));
                assert!(matches!(crate::host_state::Owner::acquire_update(&self.config.state,ID),Err(e) if e=="host_controller_already_owned"));
                assert!(!self.config.state.join("host-update.json").exists());
                self.reservations.fetch_add(1, Ordering::SeqCst);
                if self.refuse_reservation { return Err("fixture_reservation_refused".into()); }
            }
            operation()
        })
    }
}
#[tokio::test]
async fn live_manager_handover_keeps_profile_and_controller_owned_until_update_is_reserved() {
    let f = Handover::new();
    let mut manager = f.manager(false);
    let probe = Probe {
        inner: Authority::admitted(&f.current),
        config: &f.config,
        pid: manager.child.id() as i32,
        reservations: AtomicUsize::new(0),
        refuse_reservation: false,
    };
    let execution = HostExecution::new(&probe, ID).unwrap();
    let record = manager
        .reserve_update(&f.current, &f.next, &f.config, &execution)
        .await
        .unwrap();
    assert_eq!(serde_json::to_value(record).unwrap()["state"], "reserved");
    assert_eq!(probe.reservations.load(Ordering::SeqCst), 1);
    assert!(manager.shutdown_confirmed);
    assert!(matches!(ProfileGuard::acquire(&f.config),Err(e) if e=="native_profile_already_owned"));
    assert_eq!(
        fs::read(f.config.state.join("database/original")).unwrap(),
        b"retained original"
    );
    assert!(f.config.state.join("host-update.json").exists());
    drop(manager);
    drop(ProfileGuard::acquire(&f.config).unwrap());
    let mut competing = crate::host_state::Owner::acquire(&f.config.state, true, ID).unwrap();
    assert!(competing
        .activate(
            &f.config.installation_id,
            f.current.manifest_sha256(),
            crate::host_runtime::HostMode::Server
        )
        .is_err());
    drop(competing);
    f.current
        .cancel_update_reservation(&f.next, &f.config, &probe.inner.execution())
        .unwrap();
    drop(crate::host_state::Owner::acquire(&f.config.state, true, ID).unwrap());
}
#[tokio::test]
async fn live_manager_update_refuses_wrong_identity_or_active_controller_before_shutdown() {
    for fault in ["identity", "source", "profile", "active", "target-overlap"] {
        let mut f = Handover::new();
        if fault == "target-overlap" {
            let nested = f.config.data.join("target");
            fs::rename(&f._target.2, &nested).unwrap();
            f._target.0 = nested.join("payload");
            f._target.2 = nested;
            f.next = f._target.verify().unwrap();
        }
        let mut manager = f.manager(false);
        let authority = Authority::admitted(&f.current);
        let execution = authority.execution();
        match fault {
            "identity" => {
                manager.secure_installation_id = Some("22222222-2222-4222-8222-222222222222".into())
            }
            "source" => manager.manifest_sha256 = "f".repeat(64),
            "profile" => {
                manager._profile_guard.take();
            }
            "active" => {
                let mut owner =
                    crate::host_state::Owner::acquire(&f.config.state, true, ID).unwrap();
                owner
                    .activate(
                        &f.config.installation_id,
                        f.current.manifest_sha256(),
                        crate::host_runtime::HostMode::Server,
                    )
                    .unwrap();
            }
            "target-overlap" => {}
            _ => unreachable!(),
        }
        assert!(
            manager
                .reserve_update(&f.current, &f.next, &f.config, &execution)
                .await
                .is_err(),
            "{fault}"
        );
        assert!(
            !manager.shutdown_confirmed,
            "stopped before rejecting {fault}"
        );
        assert!(!manager.child_exited().unwrap());
        assert!(!f.config.state.join("host-update.json").exists());
    }
}

#[tokio::test]
async fn live_manager_handover_retains_all_exclusions_if_reservation_fails_after_shutdown() {
    let f = Handover::new();
    let mut manager = f.manager(false);
    let probe = Probe {
        inner: Authority::admitted(&f.current),
        config: &f.config,
        pid: manager.child.id() as i32,
        reservations: AtomicUsize::new(0),
        refuse_reservation: true,
    };
    let execution = HostExecution::new(&probe, ID).unwrap();
    assert_eq!(
        manager
            .reserve_update(&f.current, &f.next, &f.config, &execution)
            .await
            .unwrap_err(),
        "fixture_reservation_refused"
    );
    assert!(manager.shutdown_confirmed);
    assert!(manager.startup_lease.is_some());
    assert!(manager._code_lease.is_some());
    assert!(matches!(ProfileGuard::acquire(&f.config),Err(e) if e=="native_profile_already_owned"));
    assert!(
        matches!(crate::host_state::Owner::acquire_update(&f.config.state,ID),Err(e) if e=="host_controller_already_owned")
    );
    assert!(!f.config.state.join("host-update.json").exists());
    assert_eq!(
        fs::read(f.config.state.join("database/original")).unwrap(),
        b"retained original"
    );
    drop(manager);
    drop(ProfileGuard::acquire(&f.config).unwrap());
    drop(crate::host_state::Owner::acquire_update(&f.config.state, ID).unwrap());
}

#[tokio::test]
async fn live_manager_handover_cancellation_retains_controller_and_profile_until_cleanup() {
    let f = Handover::new();
    let mut manager = f.manager(true);
    let authority = Authority::admitted(&f.current);
    let execution = authority.execution();
    assert!(tokio::time::timeout(
        Duration::from_millis(50),
        manager.reserve_update(&f.current, &f.next, &f.config, &execution)
    )
    .await
    .is_err());
    assert!(!manager.shutdown_confirmed);
    assert!(!manager.child_exited().unwrap());
    assert!(manager.startup_lease.is_some());
    assert!(matches!(ProfileGuard::acquire(&f.config),Err(e) if e=="native_profile_already_owned"));
    assert!(
        matches!(crate::host_state::Owner::acquire_update(&f.config.state,ID),Err(e) if e=="host_controller_already_owned")
    );
    assert!(!f.config.state.join("host-update.json").exists());
    drop(manager);
    drop(ProfileGuard::acquire(&f.config).unwrap());
    drop(crate::host_state::Owner::acquire_update(&f.config.state, ID).unwrap());
}

#[tokio::test]
async fn desktop_stop_recovers_retained_update_failure_without_reacquiring_its_controller_lock() {
    let f = Handover::new();
    let mut manager = f.manager(false);
    let probe = Probe {
        inner: Authority::admitted(&f.current),
        config: &f.config,
        pid: manager.child.id() as i32,
        reservations: AtomicUsize::new(0),
        refuse_reservation: true,
    };
    let execution = HostExecution::new(&probe, ID).unwrap();
    assert!(manager
        .reserve_update(&f.current, &f.next, &f.config, &execution)
        .await
        .is_err());
    assert!(manager.startup_lease.is_some());
    manager
        .stop_idle(
            &f.config,
            f.current.manifest_sha256(),
            Duration::from_secs(1),
        )
        .await
        .unwrap();
    assert!(manager.shutdown_confirmed);
    assert!(manager.startup_lease.is_none());
    assert_eq!(
        fs::read(f.config.state.join("database/original")).unwrap(),
        b"retained original"
    );
    drop(manager);
    drop(ProfileGuard::acquire(&f.config).unwrap());
    drop(crate::host_state::Owner::acquire_update(&f.config.state, ID).unwrap());
}
#[tokio::test]
async fn desktop_stop_preserves_pending_update_fence_and_rejects_active_database() {
    for state in ["normal", "active", "reserved"] {
        let f = Handover::new();
        let mut manager = f.manager(false);
        let authority = Authority::admitted(&f.current);
        let execution = authority.execution();
        if state == "reserved" {
            manager
                .reserve_update(&f.current, &f.next, &f.config, &execution)
                .await
                .unwrap();
            let fence = fs::read(f.config.state.join("host-update.json")).unwrap();
            manager
                .stop_idle(
                    &f.config,
                    f.current.manifest_sha256(),
                    Duration::from_secs(1),
                )
                .await
                .unwrap();
            assert_eq!(
                fs::read(f.config.state.join("host-update.json")).unwrap(),
                fence
            );
        } else if state == "active" {
            let mut owner = crate::host_state::Owner::acquire(&f.config.state, true, ID).unwrap();
            owner
                .activate(
                    &f.config.installation_id,
                    f.current.manifest_sha256(),
                    crate::host_runtime::HostMode::Server,
                )
                .unwrap();
            drop(owner);
            assert!(manager
                .stop_idle(
                    &f.config,
                    f.current.manifest_sha256(),
                    Duration::from_secs(1)
                )
                .await
                .is_err());
            assert!(!manager.shutdown_confirmed);
            assert!(!manager.child_exited().unwrap());
        } else {
            manager
                .stop_idle(
                    &f.config,
                    f.current.manifest_sha256(),
                    Duration::from_secs(1),
                )
                .await
                .unwrap();
            assert!(manager.shutdown_confirmed);
            assert!(manager.startup_lease.is_none());
            assert!(!f.config.state.join("host-update.json").exists());
        }
    }
}
#[tokio::test]
async fn desktop_stop_timeout_and_cancel_keep_controller_owned_until_confirmed_cleanup() {
    for cancelled in [false, true] {
        let f = Handover::new();
        let mut manager = f.manager(true);
        if cancelled {
            assert!(tokio::time::timeout(
                Duration::from_millis(50),
                manager.stop_idle(
                    &f.config,
                    f.current.manifest_sha256(),
                    Duration::from_secs(1)
                )
            )
            .await
            .is_err());
        } else {
            assert!(manager
                .stop_idle(
                    &f.config,
                    f.current.manifest_sha256(),
                    Duration::from_millis(50)
                )
                .await
                .is_err());
        }
        assert!(manager.startup_lease.is_some());
        assert!(!manager.shutdown_confirmed);
        assert!(
            matches!(crate::host_state::Owner::acquire_update(&f.config.state,ID),Err(e) if e=="host_controller_already_owned")
        );
        manager.cleanup_owned(Duration::from_secs(1)).unwrap();
        manager
            .stop_idle(
                &f.config,
                f.current.manifest_sha256(),
                Duration::from_secs(1),
            )
            .await
            .unwrap();
        assert!(manager.startup_lease.is_none());
        drop(manager);
        drop(crate::host_state::Owner::acquire_update(&f.config.state, ID).unwrap());
    }
}

#[tokio::test]
async fn desktop_stop_checks_owned_identity_before_stopping_or_taking_controller() {
    for fault in ["identity", "manifest", "profile"] {
        let f = Handover::new();
        let mut manager = f.manager(false);
        let manifest = if fault == "manifest" {
            "f".repeat(64)
        } else {
            f.current.manifest_sha256().to_string()
        };
        if fault == "identity" {
            manager.secure_installation_id = Some("22222222-2222-4222-8222-222222222222".into());
        }
        if fault == "profile" {
            manager._profile_guard.take();
        }
        assert!(manager
            .stop_idle(&f.config, &manifest, Duration::from_secs(1))
            .await
            .is_err());
        assert!(!manager.shutdown_confirmed);
        assert!(!manager.child_exited().unwrap());
        assert!(manager.startup_lease.is_none());
        drop(crate::host_state::Owner::acquire_update(&f.config.state, ID).unwrap());
    }
}
