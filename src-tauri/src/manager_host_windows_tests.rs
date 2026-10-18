use super::*;
use std::{
    io::BufRead,
    os::windows::{
        io::{AsRawHandle, FromRawHandle, OwnedHandle},
        process::CommandExt,
    },
    thread::sleep,
};
use windows_sys::Win32::{
    Foundation::{WAIT_OBJECT_0, WAIT_TIMEOUT},
    System::Threading::{
        OpenProcess, TerminateProcess, WaitForSingleObject, DETACHED_PROCESS,
        PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE, PROCESS_TERMINATE,
    },
};

const TEST: &str =
    "manager_host::windows_tests::manager_owns_descendants_through_shutdown_and_owner_loss";
const ROLE: &str = "FRAMELEAF_MANAGER_TEST_ROLE";
const ROOT: &str = "FRAMELEAF_MANAGER_TEST_ROOT";

fn command(role: &str, root: &Path) -> Command {
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args(["--exact", TEST, "--nocapture"])
        .env(ROLE, role)
        .env(ROOT, root)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    command
}

fn wait_for(path: &Path) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !path.exists() {
        assert!(
            Instant::now() < deadline,
            "Manager fixture did not become ready"
        );
        sleep(Duration::from_millis(20));
    }
}

fn record(root: &Path, name: &str, pid: u32) {
    let temporary = root.join(format!(".{name}"));
    fs::write(&temporary, pid.to_string()).unwrap();
    fs::rename(temporary, root.join(name)).unwrap();
}

async fn role(role: &str, root: &Path) {
    match role {
        "owner" => {
            let mut worker = command("worker", root);
            let mut owner = NativeManager::spawn(
                &mut worker,
                Zeroizing::new(b"synthetic-bootstrap\n".to_vec()),
                "aaaaaaaaaaaa",
                &"b".repeat(64),
                "https://127.0.0.1:9443",
                reqwest::Client::new(),
                Leases {
                    code: Some(
                        crate::package_lease::CodeLease::acquire(&root.join("code")).unwrap(),
                    ),
                    startup: Some(
                        crate::host_state::Owner::acquire(&root.join("state"), true).unwrap(),
                    ),
                    profiles: Vec::new(),
                },
            )
            .unwrap();
            record(root, "worker", owner.child.id());
            fs::write(root.join("owner-ready"), b"ready").unwrap();
            wait_for(&root.join("action"));
            match fs::read(root.join("action")).unwrap().as_slice() {
                b"shutdown" => owner.shutdown(Duration::from_secs(5)).await.unwrap(),
                action @ (b"cancel" | b"bad-receipt") => {
                    let cancelled = action == b"cancel";
                    let error = owner
                        .wait_ready(Duration::from_secs(5), &AtomicBool::new(cancelled))
                        .await
                        .unwrap_err();
                    assert_eq!(
                        error,
                        if cancelled {
                            "native_manager_start_cancelled"
                        } else {
                            "native_manager_receipt_invalid"
                        }
                    );
                    assert!(owner.startup_lease.is_none());
                }
                _ => {}
            }
            drop(owner);
        }
        "worker" => {
            let mut input = String::new();
            std::io::stdin().lock().read_line(&mut input).unwrap();
            assert_eq!(input, "synthetic-bootstrap\n");
            let mut command = command("browser", root);
            command.creation_flags(DETACHED_PROCESS);
            let mut browser = command.spawn().unwrap();
            record(root, "browser", browser.id());
            browser.wait().unwrap();
        }
        "browser" => {
            let mut leaf = command("leaf", root).spawn().unwrap();
            record(root, "leaf", leaf.id());
            leaf.wait().unwrap();
        }
        "leaf" => {
            fs::write(root.join("ready"), b"ready").unwrap();
            sleep(Duration::from_secs(60));
        }
        _ => panic!("unknown Manager fixture role"),
    }
}

struct Fixture {
    root: PathBuf,
    handles: Vec<OwnedHandle>,
    owner: Option<Child>,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        if let Some(owner) = &mut self.owner {
            let _ = owner.kill();
            let _ = owner.wait();
        }
        for handle in &self.handles {
            unsafe {
                TerminateProcess(handle.as_raw_handle(), 1);
                WaitForSingleObject(handle.as_raw_handle(), 5000);
            }
        }
        let _ = fs::remove_dir_all(&self.root);
    }
}

#[tokio::test]
async fn manager_owns_descendants_through_shutdown_and_owner_loss() {
    if let Ok(value) = std::env::var(ROLE) {
        role(&value, &PathBuf::from(std::env::var_os(ROOT).unwrap())).await;
        return;
    }
    for mode in [
        "drop",
        "leader-first",
        "shutdown",
        "cancel",
        "bad-receipt",
        "owner-loss",
    ] {
        let started = Instant::now();
        let root = std::env::temp_dir()
            .canonicalize()
            .unwrap()
            .join(format!("frameleaf-manager-job-{}", uuid::Uuid::new_v4()));
        let mut fixture = Fixture {
            root,
            handles: Vec::new(),
            owner: None,
        };
        crate::runtime_store::private_directory(&fixture.root).unwrap();
        fs::create_dir(fixture.root.join("code")).unwrap();
        eprintln!("manager_owner_case={mode}");
        fixture.owner = Some(
            command("owner", &fixture.root)
                .stderr(Stdio::inherit())
                .spawn()
                .unwrap(),
        );
        wait_for(&fixture.root.join("owner-ready"));
        wait_for(&fixture.root.join("ready"));
        for name in ["worker", "browser", "leaf"] {
            wait_for(&fixture.root.join(name));
            let pid = fs::read_to_string(fixture.root.join(name))
                .unwrap()
                .parse()
                .unwrap();
            let raw = unsafe {
                OpenProcess(
                    PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE | PROCESS_TERMINATE,
                    0,
                    pid,
                )
            };
            assert!(!raw.is_null(), "Manager fixture process is missing");
            fixture
                .handles
                .push(unsafe { OwnedHandle::from_raw_handle(raw) });
        }
        let lease = fs::File::open(fixture.root.join("code/.runtime-lease")).unwrap();
        assert!(
            lease.try_lock().is_err(),
            "live Manager must exclude maintenance"
        );
        assert!(crate::host_state::Owner::acquire(&fixture.root.join("state"), true).is_err());
        for handle in &fixture.handles {
            assert_eq!(
                unsafe { WaitForSingleObject(handle.as_raw_handle(), 0) },
                WAIT_TIMEOUT
            );
        }
        if mode == "leader-first" {
            assert_ne!(
                unsafe { TerminateProcess(fixture.handles[0].as_raw_handle(), 1) },
                0
            );
            assert_eq!(
                unsafe { WaitForSingleObject(fixture.handles[0].as_raw_handle(), 5000) },
                WAIT_OBJECT_0
            );
        }
        assert!(
            started.elapsed() < Duration::from_secs(15),
            "fixture startup exhausted its cleanup window"
        );
        if mode == "owner-loss" {
            fixture.owner.as_mut().unwrap().kill().unwrap();
        } else {
            fs::write(fixture.root.join("action"), mode.as_bytes()).unwrap();
        }
        for handle in &fixture.handles {
            assert_eq!(
                unsafe { WaitForSingleObject(handle.as_raw_handle(), 5000) },
                WAIT_OBJECT_0,
                "Manager left a descendant running: {mode}"
            );
        }
        assert!(
            started.elapsed() < Duration::from_secs(30),
            "natural fixture expiry cannot prove cleanup"
        );
        let status = fixture.owner.as_mut().unwrap().wait().unwrap();
        assert!(
            mode == "owner-loss" || status.success(),
            "Manager owner failed in {mode}: {status}"
        );
        lease.try_lock().unwrap();
        lease.unlock().unwrap();
        drop(crate::host_state::Owner::acquire(&fixture.root.join("state"), true).unwrap());
    }
}
