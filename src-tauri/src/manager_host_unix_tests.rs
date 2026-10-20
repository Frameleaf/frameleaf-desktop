use super::*;
use std::{io::BufRead, os::unix::fs::PermissionsExt};
const TEST: &str =
    "manager_host::unix_tests::manager_shutdown_confirms_descendants_before_releasing_ownership";
const ROLE: &str = "FRAMELEAF_MANAGER_UNIX_ROLE";
const ROOT: &str = "FRAMELEAF_MANAGER_UNIX_ROOT";
fn command(role: &str, root: &Path) -> Command {
    let mut cmd = Command::new(std::env::current_exe().unwrap());
    cmd.args(["--exact", TEST, "--nocapture", "--test-threads=2"])
        .env(ROLE, role)
        .env(ROOT, root);
    cmd
}
struct Fixture(std::path::PathBuf);
impl Drop for Fixture {
    fn drop(&mut self) {
        // Disposable fixture observation only; production cleanup uses the live Child and owned group.
        if let Ok(raw) = fs::read_to_string(self.0.join("leaf")) {
            if let Ok(pid) = raw.parse::<i32>() {
                if pid > 1 {
                    unsafe {
                        libc::kill(pid, libc::SIGKILL);
                    }
                }
            }
        }
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn alive(pid: i32) -> bool {
    unsafe { libc::kill(pid, 0) == 0 }
}
fn wait_for(path: &Path) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while !path.exists() {
        assert!(Instant::now() < deadline, "fixture did not become ready");
        std::thread::sleep(Duration::from_millis(10));
    }
}
#[tokio::test]
async fn manager_shutdown_confirms_descendants_before_releasing_ownership() {
    if let Ok(role) = std::env::var(ROLE) {
        let root = std::path::PathBuf::from(std::env::var_os(ROOT).unwrap());
        if role == "leaf" {
            fs::write(root.join("leaf-pending"), std::process::id().to_string()).unwrap();
            fs::rename(root.join("leaf-pending"), root.join("leaf")).unwrap();
            std::thread::sleep(Duration::from_secs(20));
            return;
        }
        let mut input = String::new();
        std::io::stdin().lock().read_line(&mut input).unwrap();
        assert_eq!(input, "synthetic-bootstrap\n");
        #[allow(clippy::zombie_processes)]
        // A surviving child is intentional; the test supervisor owns its cleanup.
        let _leaf = command("leaf", &root)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        wait_for(&root.join("leaf"));
        if role == "exited" {
            wait_for(&root.join("exit-now"));
            return;
        }
        // The test harness header is the deliberately invalid readiness frame; further writes would SIGPIPE.

        std::thread::sleep(Duration::from_secs(20));
        return;
    }
    for action in ["shutdown", "exited", "drop", "cancel", "bad-receipt"] {
        let root = std::env::temp_dir()
            .canonicalize()
            .unwrap()
            .join(format!("fl-manager-descendants-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let fixture = Fixture(root);
        let worker = if action == "exited" {
            "exited"
        } else if action == "bad-receipt" {
            "bad-receipt"
        } else {
            "worker"
        };
        let mut owner = NativeManager::spawn(
            &mut command(worker, &fixture.0),
            Zeroizing::new(b"synthetic-bootstrap\n".to_vec()),
            &"a".repeat(12),
            &"b".repeat(64),
            "http://127.0.0.1:1",
            reqwest::Client::new(),
            Leases::default(),
        )
        .unwrap();
        wait_for(&fixture.0.join("leaf"));
        let leaf = fs::read_to_string(fixture.0.join("leaf"))
            .unwrap()
            .parse::<i32>()
            .unwrap();
        assert!(alive(leaf));
        let group = owner.child.id() as i32;
        assert_eq!(unsafe { libc::getpgid(group) }, group);
        assert_eq!(unsafe { libc::getpgid(leaf) }, group);
        assert_ne!(unsafe { libc::getpgrp() }, group);
        if action == "exited" {
            fs::write(fixture.0.join("exit-now"), []).unwrap();
        }
        if action == "drop" {
            drop(owner);
        } else {
            if action == "exited" {
                let deadline = Instant::now() + Duration::from_secs(5);
                while !owner.child_exited().unwrap() {
                    assert!(Instant::now() < deadline);
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
                // Observation must leave the leader unreaped, reserving the group ID until cleanup.
                assert!(owner.child_exited().unwrap());
                assert!(!owner.shutdown_signalled);
                while !owner.has_exited().unwrap() {
                    assert!(Instant::now() < deadline);
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            }
            if action == "cancel" || action == "bad-receipt" {
                assert_eq!(
                    owner
                        .wait_ready(Duration::from_secs(1), &AtomicBool::new(action == "cancel"))
                        .await
                        .unwrap_err(),
                    if action == "cancel" {
                        "native_manager_start_cancelled"
                    } else {
                        "native_manager_receipt_invalid"
                    }
                );
            } else {
                owner.shutdown(Duration::from_secs(5)).await.unwrap();
                owner.shutdown(Duration::from_secs(5)).await.unwrap();
                assert!(!owner.is_running().unwrap());
            }
            assert!(owner.shutdown_signalled);
            drop(owner);
        }
        let deadline = Instant::now() + Duration::from_secs(3);
        while alive(leaf) && Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(!alive(leaf), "{action} left a Manager descendant running");
        fs::remove_file(fixture.0.join("leaf")).unwrap();
    }
}
