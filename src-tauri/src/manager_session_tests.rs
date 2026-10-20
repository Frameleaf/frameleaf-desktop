use super::*;
use crate::manager_profile::ProfileGuard;

fn config(root: &Path) -> Configuration {
    Configuration {
        installation_id: "a".repeat(12),
        secure_installation_id: "11111111-1111-4111-8111-111111111111".into(),
        name: "Synthetic session".into(),
        release: "frameleaf-v3.0.0-1".into(),
        controller: "/bin/echo".into(),
        state: root.join("state"),
        data: root.join("manager"),
        origin: "https://127.0.0.1:9443".into(),
        database_port: 54329,
        api_port: 2283,
    }
}
struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir()
            .canonicalize()
            .unwrap()
            .join(format!("frameleaf-session-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&root).unwrap();
        Self(root)
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn wait_for(mut predicate: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while !predicate() {
        assert!(Instant::now() < deadline, "session fixture timed out");
        std::thread::sleep(Duration::from_millis(10));
    }
}
fn start(config: &Configuration) -> NativeManager {
    let mut command = Command::new("node");
    command.args(["-e", r#"
const fs = require('node:fs');
const held = fs.fstatSync(Number(process.env.FRAMELEAF_MANAGER_PROFILE_FD));
if (!held.isFile() || held.size !== 0) throw Error('invalid fixture lease');
process.stdin.once('data', () => { fs.writeFileSync(process.argv[1], 'ready'); console.log('ready'); });
process.stdin.resume();
setInterval(() => {}, 1000);
setTimeout(() => process.exit(0), 15000);
"#]).arg(config.data.parent().unwrap().join("ready"));
    NativeManager::spawn(
        &mut command,
        Zeroizing::new(b"synthetic\n".to_vec()),
        &config.installation_id,
        &"b".repeat(64),
        &config.origin,
        reqwest::Client::new(),
        Leases {
            profile: Some(ProfileGuard::acquire(config).unwrap()),
            startup: Some(
                crate::host_state::Owner::acquire(
                    &config.state,
                    true,
                    &config.secure_installation_id,
                )
                .unwrap(),
            ),
            ..Leases::default()
        },
    )
    .unwrap()
}
#[test]
fn manager_retains_profile_exclusion_until_owned_child_is_reaped() {
    let fixture = Fixture::new();
    let config = config(&fixture.0);
    let mut manager = start(&config);
    wait_for(|| fixture.0.join("ready").exists());
    assert!(manager.startup_lease.take().is_some());
    drop(
        crate::host_state::Owner::acquire(&config.state, true, &config.secure_installation_id)
            .unwrap(),
    );
    assert!(
        matches!(ProfileGuard::acquire(&config), Err(e) if e == "native_profile_already_owned")
    );
    drop(manager);
    drop(ProfileGuard::acquire(&config).unwrap());
}
#[test]
fn failed_manager_spawn_does_not_leave_an_inherited_lock() {
    let fixture = Fixture::new();
    let config = config(&fixture.0);
    let guard = ProfileGuard::acquire(&config).unwrap();
    let mut command = Command::new(fixture.0.join("missing-program"));
    let result = NativeManager::spawn(
        &mut command,
        Zeroizing::new(Vec::new()),
        &config.installation_id,
        &"b".repeat(64),
        &config.origin,
        reqwest::Client::new(),
        Leases {
            profile: Some(guard),
            ..Leases::default()
        },
    );
    assert!(matches!(result, Err(e) if e == "native_manager_launch_failed"));
    drop(ProfileGuard::acquire(&config).unwrap());
}
#[test]
fn nonempty_profile_lease_is_refused_without_truncation() {
    let fixture = Fixture::new();
    let config = config(&fixture.0);
    drop(ProfileGuard::acquire(&config).unwrap());
    let path = config.data.join(".setup.lock");
    fs::write(&path, b"unexpected").unwrap();
    assert!(
        matches!(ProfileGuard::acquire(&config), Err(e) if e == "native_profile_binding_changed")
    );
    assert_eq!(fs::read(path).unwrap(), b"unexpected");
}
#[test]
fn session_helper() {
    let Ok(root) = std::env::var("FRAMELEAF_SESSION_TEST_ROOT") else {
        return;
    };
    let config = config(Path::new(&root));
    if std::env::var("FRAMELEAF_SESSION_TEST_MODE").as_deref() == Ok("closed-stdio") {
        unsafe {
            libc::close(0);
            libc::close(1);
            libc::close(2);
        }
        let manager = start(&config);
        wait_for(|| Path::new(&root).join("ready").exists());
        drop(manager);
        drop(ProfileGuard::acquire(&config).unwrap());
        std::process::exit(0);
    }
    let manager = start(&config);
    wait_for(|| Path::new(&root).join("ready").exists());
    println!("OWNED_NODE_PID={}", manager.child.id());
    std::io::stdout().flush().unwrap();
    // Intentionally bypass Drop to model abrupt supervisor loss.
    std::process::exit(0);
}
fn helper(fixture: &Fixture, mode: &str) -> Command {
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args([
            "--exact",
            "manager_host::session_tests::session_helper",
            "--nocapture",
            "--test-threads=1",
        ])
        .env("FRAMELEAF_SESSION_TEST_ROOT", &fixture.0)
        .env("FRAMELEAF_SESSION_TEST_MODE", mode);
    command
}
#[test]
fn manager_surviving_supervisor_loss_retains_profile_exclusion() {
    struct Orphan(u32);
    impl Drop for Orphan {
        fn drop(&mut self) {
            unsafe {
                libc::kill(self.0 as i32, libc::SIGKILL);
            }
        }
    }
    let fixture = Fixture::new();
    let output = helper(&fixture, "crash").output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    let pid = stdout
        .lines()
        .find_map(|line| line.split_once("OWNED_NODE_PID=").map(|(_, pid)| pid))
        .unwrap()
        .parse()
        .unwrap();
    let orphan = Orphan(pid);
    let config = config(&fixture.0);
    assert_eq!(unsafe { libc::kill(pid as i32, 0) }, 0);
    assert!(
        matches!(ProfileGuard::acquire(&config), Err(e) if e == "native_profile_already_owned")
    );
    assert_eq!(unsafe { libc::kill(pid as i32, libc::SIGTERM) }, 0);
    wait_for(|| ProfileGuard::acquire(&config).is_ok());
    drop(orphan);
}
#[test]
fn closed_standard_descriptors_do_not_overwrite_the_child_profile_lease() {
    let fixture = Fixture::new();
    let output = helper(&fixture, "closed-stdio").output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(fixture.0.join("ready").exists());
    drop(ProfileGuard::acquire(&config(&fixture.0)).unwrap());
}

#[test]
fn dropping_supervisor_guard_does_not_unlock_the_live_manager_child() {
    let fixture = Fixture::new();
    let config = config(&fixture.0);
    let mut manager = start(&config);
    wait_for(|| fixture.0.join("ready").exists());
    drop(manager._profile_guard.take());
    assert!(
        matches!(ProfileGuard::acquire(&config), Err(e) if e == "native_profile_already_owned")
    );
    drop(manager);
    drop(ProfileGuard::acquire(&config).unwrap());
}
#[test]
fn post_spawn_authority_failure_releases_profile_only_after_child_cleanup() {
    use crate::host_epochs::{host_authority::Authority, host_fixture::Fixture as RuntimeFixture};
    struct RejectAfter(Authority);
    impl HostEpochAuthority for RejectAfter {
        fn installation_id(&self) -> Result<String, String> {
            self.0.installation_id()
        }
        fn with_admitted(
            &self,
            id: &str,
            runtime: &VerifiedHostRuntime,
            operation: &mut dyn FnMut() -> Result<(), String>,
        ) -> Result<(), String> {
            self.0.with_admitted(id, runtime, operation)?;
            Err("synthetic_post_spawn_failure".into())
        }
        fn activate(
            &self,
            id: &str,
            runtime: &VerifiedHostRuntime,
            publish: &mut dyn FnMut() -> Result<(), String>,
        ) -> Result<(), String> {
            self.0.activate(id, runtime, publish)
        }
    }
    let fixture = Fixture::new();
    let config = config(&fixture.0);
    let runtime_fixture = RuntimeFixture::new();
    let runtime = runtime_fixture.verify().unwrap();
    let authority = RejectAfter(Authority::admitted(&runtime));
    let execution = HostExecution::new(&authority, &config.secure_installation_id).unwrap();
    let mut command = Command::new("/bin/sleep");
    command.arg("30");
    let result = NativeManager::spawn(
        &mut command,
        Zeroizing::new(Vec::new()),
        &config.installation_id,
        &"b".repeat(64),
        &config.origin,
        reqwest::Client::new(),
        Leases {
            profile: Some(ProfileGuard::acquire(&config).unwrap()),
            execution: Some((&execution, &runtime)),
            ..Leases::default()
        },
    );
    assert!(matches!(result, Err(e) if e == "synthetic_post_spawn_failure"));
    drop(ProfileGuard::acquire(&config).unwrap());
}
