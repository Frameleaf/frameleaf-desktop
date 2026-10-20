use super::*;
use crate::host_epochs::{host_authority, host_fixture};
use host_authority::{Authority, ID};
use host_fixture::Fixture;

#[cfg(unix)]
#[test]
fn retained_manager_runtime_checks_authority_at_spawn_and_retains_owned_leases() {
    let fixture = Fixture::new();
    let runtime = fixture.verify().unwrap();
    let programs = Programs {
        runtime: &runtime,
        root: fixture.0.clone(),
        node: fixture.0.join("node"),
        main: fixture.0.join("manager/app/build/main.js"),
    };
    let authority = Authority::admitted(&runtime);
    let execution = authority.execution();
    let state = fixture.2.join("state");
    let startup = crate::host_state::Owner::acquire(&state, true, ID).unwrap();
    let mut command = Command::new("/bin/sleep");
    command.arg("30");
    let mut manager = NativeManager::spawn(
        &mut command,
        Zeroizing::new(b"private\n".to_vec()),
        "aaaaaaaaaaaa",
        runtime.manifest_sha256(),
        "https://127.0.0.1:9443",
        reqwest::Client::new(),
        Leases {
            execution: Some((&execution, programs.runtime)),
            startup: Some(startup),
            code: Some(crate::package_lease::CodeLease::acquire(&fixture.2).unwrap()),
            profiles: Vec::new(),
            profile: None,
        },
    )
    .unwrap();
    assert_eq!(manager.secure_installation_id.as_deref(), Some(ID));
    assert!(crate::host_state::Owner::acquire(&state, true, ID).is_err());
    manager.startup_lease.take();
    assert_eq!(manager.secure_installation_id.as_deref(), Some(ID));
    drop(crate::host_state::Owner::acquire(&state, true, ID).unwrap());
    drop(manager);
    let sentinel = fixture.2.join("unexpected-spawn");
    let mut higher = Fixture::new();
    higher.1["epoch"] = serde_json::json!(2);
    let higher = higher.verify().unwrap();
    authority.activate(ID, &higher, &mut || Ok(())).unwrap();
    for changed_identity in [false, true] {
        if changed_identity {
            authority.0.lock().unwrap().0 = "22222222-2222-4222-8222-222222222222".into();
        }
        let mut command = Command::new("/bin/sh");
        command
            .args(["-c", "echo leaked > \"$1\"; exec /bin/sleep 30", "fixture"])
            .arg(&sentinel);
        let result = NativeManager::spawn(
            &mut command,
            Zeroizing::new(b"private\n".to_vec()),
            "aaaaaaaaaaaa",
            runtime.manifest_sha256(),
            "https://127.0.0.1:9443",
            reqwest::Client::new(),
            Leases {
                execution: Some((&execution, programs.runtime)),
                ..Leases::default()
            },
        );
        let expected = if changed_identity {
            "host_installation_identity_changed"
        } else {
            "host_epoch_rollback"
        };
        assert!(matches!(result,Err(e) if e==expected));
        assert!(!sentinel.exists());
    }
}

#[cfg(unix)]
#[test]
fn manager_bootstrap_releases_authority_before_waiting_for_child_input() {
    use std::sync::Arc;
    let fixture = Fixture::new();
    let runtime = fixture.verify().unwrap();
    struct Probe {
        inner: Arc<Authority>,
        gate: PathBuf,
    }
    impl HostEpochAuthority for Probe {
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
            self.inner.with_admitted(id, runtime, &mut || {
                operation()?;
                let authority = self.inner.clone();
                let gate = self.gate.clone();
                std::thread::spawn(move || {
                    authority.installation_id().unwrap();
                    fs::write(gate, b"unlocked").unwrap();
                });
                Ok(())
            })
        }
    }
    let gate = fixture.2.join("credential-read-complete");
    let probe = Probe {
        inner: Arc::new(Authority::admitted(&runtime)),
        gate: gate.clone(),
    };
    let execution = HostExecution::new(&probe, ID).unwrap();
    let mut command = Command::new("/bin/sh");
    command.args(["-c","while [ ! -f \"$1\" ]; do /bin/sleep 0.01; done; /bin/cat >/dev/null; exec /bin/sleep 30","fixture"]).arg(&gate);
    // Exceed the pipe capacity: bootstrap cannot complete until the child obtains authority.
    let owner = NativeManager::spawn(
        &mut command,
        Zeroizing::new(vec![b'x'; 1024 * 1024]),
        "aaaaaaaaaaaa",
        runtime.manifest_sha256(),
        "https://127.0.0.1:9443",
        reqwest::Client::new(),
        Leases {
            execution: Some((&execution, &runtime)),
            ..Leases::default()
        },
    )
    .unwrap();
    assert!(gate.exists());
    drop(owner);
}
