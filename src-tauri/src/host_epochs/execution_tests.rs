use super::*;
use crate::{
    host_epochs::{host_authority, host_fixture, HostEpochAuthority},
    host_runtime::VerifiedHostRuntime,
};
use host_authority::{Authority, ID};
use host_fixture::Fixture;

#[test]
fn retained_execution_rechecks_actual_runtime_identity_and_files_before_spawn() {
    let fixture = Fixture::new();
    let runtime = fixture.verify().unwrap();
    let authority = Authority::admitted(&runtime);
    assert!(HostExecution::new(&authority, "bad").is_err());
    let execution = authority.execution();
    let mut higher = Fixture::new();
    higher.1["epoch"] = serde_json::json!(2);
    let next = higher.verify().unwrap();
    assert!(
        matches!(execution.spawn(&next, || panic!("unadmitted spawn")), Err(e) if e == "host_epoch_not_admitted")
    );
    authority.activate(ID, &next, &mut || Ok(())).unwrap();
    assert!(
        matches!(execution.spawn(&runtime, || panic!("stale spawn")), Err(e) if e == "host_epoch_rollback")
    );
    let mut reused = Fixture::new();
    reused.1["epoch"] = serde_json::json!(2);
    reused.1["sourceRevision"] = serde_json::json!("b".repeat(40));
    let reused = reused.verify().unwrap();
    assert!(
        matches!(execution.spawn(&reused, || panic!("reused spawn")), Err(e) if e == "host_epoch_reused")
    );
    authority.0.lock().unwrap().0 = "22222222-2222-4222-8222-222222222222".into();
    assert!(
        matches!(execution.spawn(&next, || panic!("foreign identity spawn")), Err(e) if e == "host_installation_identity_changed")
    );
    authority.0.lock().unwrap().0 = ID.into();
    std::fs::write(higher.0.join("node"), b"changed").unwrap();
    assert!(execution
        .spawn(&next, || panic!("changed payload spawn"))
        .is_err());
}

#[cfg(unix)]
#[test]
fn authority_is_released_before_bootstrap_and_child_is_reaped_after_failed_admission() {
    use std::process::{Command, Stdio};
    let fixture = Fixture::new();
    let runtime = fixture.verify().unwrap();
    let authority = Authority::admitted(&runtime);
    let execution = authority.execution();
    let mut child = execution
        .spawn(&runtime, || {
            assert!(
                authority.0.try_lock().is_err(),
                "spawn must own authority lock"
            );
            Command::new("/bin/sleep")
                .arg("30")
                .stdin(Stdio::piped())
                .spawn()
                .map_err(|_| "test_spawn".into())
        })
        .unwrap();
    assert!(
        authority.0.try_lock().is_ok(),
        "child bootstrap must not own authority lock"
    );
    assert!(child.try_wait().unwrap().is_none());
    child.kill().unwrap();
    child.wait().unwrap();

    struct Broken {
        mode: u8,
    }
    impl HostEpochAuthority for Broken {
        fn installation_id(&self) -> Result<String, String> {
            panic!("constructor must not read")
        }
        fn activate(
            &self,
            _: &str,
            _: &VerifiedHostRuntime,
            _: &mut dyn FnMut() -> Result<(), String>,
        ) -> Result<(), String> {
            unreachable!()
        }
        fn with_admitted(
            &self,
            _: &str,
            _: &VerifiedHostRuntime,
            operation: &mut dyn FnMut() -> Result<(), String>,
        ) -> Result<(), String> {
            match self.mode {
                0 => Ok(()),
                1 => {
                    operation()?;
                    Err("post_spawn_failure".into())
                }
                _ => {
                    operation()?;
                    let _ = operation();
                    Ok(())
                }
            }
        }
    }
    for mode in 0..3 {
        let broken = Broken { mode };
        assert!(HostExecution::new(&broken, "bad").is_err());
        let execution = HostExecution::new(&broken, ID).unwrap();
        let mut spawned = None;
        let result = execution.spawn(&runtime, || {
            let child = Command::new("/bin/sleep").arg("30").spawn().unwrap();
            spawned = Some(child.id());
            Ok(child)
        });
        assert!(result.is_err());
        if let Some(pid) = spawned {
            assert_eq!(
                unsafe { libc::kill(pid as i32, 0) },
                -1,
                "failed admission leaked owned child"
            );
        } else {
            assert_eq!(mode, 0);
        }
    }
}

#[test]
fn mismatched_execution_keeps_owned_controller_journal_unchanged() {
    let fixture = Fixture::new();
    let runtime = fixture.verify().unwrap();
    let authority = Authority::admitted(&runtime);
    let execution = authority.execution();
    let state = fixture.2.join("state");
    let mut owner =
        crate::host_state::Owner::acquire(&state, true, "22222222-2222-4222-8222-222222222222")
            .unwrap();
    owner
        .activate(
            "aaaaaaaaaaaa",
            runtime.manifest_sha256(),
            crate::host_runtime::HostMode::Server,
        )
        .unwrap();
    drop(owner);
    let journal = std::fs::read(state.join("controller-state.json")).unwrap();
    let mut owner =
        crate::host_state::Owner::acquire(&state, true, "22222222-2222-4222-8222-222222222222")
            .unwrap();
    let password = zeroize::Zeroizing::new("synthetic-host-password-with-enough-length".into());
    let result = runtime.start_mode(
        &state,
        &password,
        (54321, 54322),
        crate::host_runtime::HostMode::Server,
        Some(&mut owner),
        &execution,
    );
    assert!(matches!(result,Err(e) if e=="host_installation_identity_changed"));
    drop(owner);
    assert_eq!(
        std::fs::read(state.join("controller-state.json")).unwrap(),
        journal
    );
    assert!(!state.join("agent.log").exists());
}

#[test]
fn host_handover_callback_order_is_single_use_locked_and_fail_closed_for_unsupported_authorities() {
    struct Provider {
        mode: u8,
        lock: std::sync::Mutex<()>,
    }
    impl HostEpochAuthority for Provider {
        fn installation_id(&self) -> Result<String, String> {
            Ok(ID.into())
        }
        fn with_admitted(
            &self,
            _: &str,
            _: &VerifiedHostRuntime,
            _: &mut dyn FnMut() -> Result<(), String>,
        ) -> Result<(), String> {
            panic!("no split transaction fallback")
        }
        fn activate(
            &self,
            _: &str,
            _: &VerifiedHostRuntime,
            _: &mut dyn FnMut() -> Result<(), String>,
        ) -> Result<(), String> {
            panic!("no split activation fallback")
        }
        fn transition(
            &self,
            _: &str,
            _: [&VerifiedHostRuntime; 2],
            prepare: &mut dyn FnMut() -> Result<(), String>,
            publish: &mut dyn FnMut() -> Result<(), String>,
        ) -> Result<(), String> {
            let _held = self.lock.lock().unwrap();
            match self.mode {
                0 => Ok(()),
                1 => publish(),
                2 => {
                    prepare()?;
                    let _ = prepare();
                    publish()
                }
                3 => {
                    prepare()?;
                    publish()?;
                    let _ = publish();
                    Ok(())
                }
                4 => {
                    prepare()?;
                    publish()?;
                    Err("post publication failure".into())
                }
                6 => {
                    let _ = prepare();
                    let _ = publish();
                    Ok(())
                }
                _ => {
                    prepare()?;
                    publish()
                }
            }
        }
    }
    let source_fixture = Fixture::new();
    let source = source_fixture.verify().unwrap();
    let mut target_fixture = Fixture::new();
    target_fixture.1["epoch"] = serde_json::json!(2);
    let target = target_fixture.verify().unwrap();
    for mode in 0..7 {
        let authority = Provider {
            mode,
            lock: std::sync::Mutex::new(()),
        };
        let execution = HostExecution::new(&authority, ID).unwrap();
        let calls = std::cell::RefCell::new(Vec::new());
        let result = execution.transition(
            &source,
            &target,
            || {
                assert!(authority.lock.try_lock().is_err());
                calls.borrow_mut().push("prepare");
                if mode == 6 {
                    return Err("preparation refused".into());
                }
                Ok(())
            },
            || {
                assert!(authority.lock.try_lock().is_err());
                calls.borrow_mut().push("publish");
                Ok(())
            },
        );
        assert_eq!(result.is_ok(), mode == 5);
        assert!(calls.borrow().iter().filter(|c| **c == "prepare").count() <= 1);
        assert!(calls.borrow().iter().filter(|c| **c == "publish").count() <= 1);
        if matches!(mode, 2 | 6) {
            assert_eq!(
                *calls.borrow(),
                vec!["prepare"],
                "contract violation published work"
            );
        }
        if mode == 1 {
            assert!(calls.borrow().is_empty(), "out-of-order publication ran");
        }
    }
    let authority = Authority::admitted(&source);
    let history = serde_json::to_vec(&authority.0.lock().unwrap().1).unwrap();
    assert!(authority
        .execution()
        .transition(
            &source,
            &target,
            || panic!("unsupported prepare"),
            || panic!("unsupported publish")
        )
        .is_err());
    assert_eq!(
        serde_json::to_vec(&authority.0.lock().unwrap().1).unwrap(),
        history
    );
}
