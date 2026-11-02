use super::*;
use std::{
    fs,
    io::{Read, Write},
    os::windows::{
        io::{AsRawHandle, FromRawHandle, OwnedHandle},
        process::CommandExt,
    },
    path::{Path, PathBuf},
    process::Stdio,
    thread::sleep,
    time::{Duration, Instant},
};
use windows_sys::Win32::{
    Foundation::{WAIT_OBJECT_0, WAIT_TIMEOUT},
    System::{
        JobObjects::IsProcessInJob,
        Threading::{
            OpenProcess, TerminateProcess, WaitForSingleObject, DETACHED_PROCESS,
            PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE, PROCESS_TERMINATE,
        },
    },
};

const TEST: &str = "process_tree::windows_tests::detached_descendants_remain_owned_until_termination_or_owner_loss";
const ROLE: &str = "FRAMELEAF_JOB_TEST_ROLE";
const ROOT: &str = "FRAMELEAF_JOB_TEST_ROOT";

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

/// Spawn detached descendants only after the worker is assigned to its owner job.
fn probe(role: &str, root: &Path) {
    if role == "worker" {
        let mut gate = [0];
        std::io::stdin().read_exact(&mut gate).unwrap();
        assert_eq!(gate, [1]);
        let mut child = command("browser", root);
        child.creation_flags(DETACHED_PROCESS);
        let mut browser = child.spawn().unwrap();
        record(root, "browser", browser.id());
        browser.wait().unwrap();
    } else if role == "browser" {
        let mut leaf = command("leaf", root).spawn().unwrap();
        record(root, "leaf", leaf.id());
        leaf.wait().unwrap();
    } else {
        assert_eq!(role, "leaf");
        fs::write(root.join("ready"), b"ready").unwrap();
        // Bound fixture lifetime even if the ownership implementation regresses.
        sleep(Duration::from_secs(30));
    }
}

fn record(root: &Path, name: &str, pid: u32) {
    let temporary = root.join(format!(".{name}"));
    fs::write(&temporary, pid.to_string()).unwrap();
    fs::rename(temporary, root.join(name)).unwrap();
}

struct Fixture {
    root: PathBuf,
    processes: Vec<OwnedHandle>,
}
impl Drop for Fixture {
    /// Bound cleanup even when a membership or shutdown assertion fails.
    fn drop(&mut self) {
        for process in &self.processes {
            unsafe {
                TerminateProcess(process.as_raw_handle(), 1);
                WaitForSingleObject(process.as_raw_handle(), 5000);
            }
        }
        let _ = fs::remove_dir_all(&self.root);
    }
}

/// Check both shutdown paths before natural fixture expiry can hide a leaked process.
#[test]
fn detached_descendants_remain_owned_until_termination_or_owner_loss() {
    if let Ok(role) = std::env::var(ROLE) {
        probe(&role, &PathBuf::from(std::env::var_os(ROOT).unwrap()));
        return;
    }
    for close_owner in [false, true] {
        let mut fixture = Fixture {
            root: std::env::temp_dir().join(format!("frameleaf-job-{}", uuid::Uuid::new_v4())),
            processes: Vec::new(),
        };
        fs::create_dir(&fixture.root).unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut command = command("worker", &fixture.root);
        configure(&mut command);
        command.stdin(Stdio::piped());
        let mut child = command.spawn().unwrap();
        let tree = ProcessTree::attach(&child).unwrap();
        child.stdin.take().unwrap().write_all(&[1]).unwrap();
        while ["ready", "browser", "leaf"]
            .iter()
            .any(|name| !fixture.root.join(name).exists())
        {
            assert!(
                Instant::now() < deadline,
                "detached fixture did not become ready"
            );
            sleep(Duration::from_millis(20));
        }
        let pids = [
            child.id(),
            fs::read_to_string(fixture.root.join("browser"))
                .unwrap()
                .parse()
                .unwrap(),
            fs::read_to_string(fixture.root.join("leaf"))
                .unwrap()
                .parse()
                .unwrap(),
        ];
        for pid in pids {
            let raw = unsafe {
                OpenProcess(
                    PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE | PROCESS_TERMINATE,
                    0,
                    pid,
                )
            };
            assert!(!raw.is_null(), "owned fixture process unavailable");
            let handle = unsafe { OwnedHandle::from_raw_handle(raw) };
            let mut member = 0;
            assert_ne!(
                unsafe { IsProcessInJob(raw, tree.0.as_raw_handle(), &mut member) },
                0
            );
            assert_ne!(member, 0, "detached descendant escaped the Frameleaf job");
            fixture.processes.push(handle);
        }
        // Natural fixture expiry must never satisfy the shutdown assertion.
        assert!(
            Instant::now() < deadline,
            "fixture startup exceeded its qualification window"
        );
        for process in &fixture.processes {
            assert_eq!(
                unsafe { WaitForSingleObject(process.as_raw_handle(), 0) },
                WAIT_TIMEOUT
            );
        }
        if close_owner {
            drop(tree);
        } else {
            tree.terminate();
        }
        for process in &fixture.processes {
            assert_eq!(
                unsafe { WaitForSingleObject(process.as_raw_handle(), 5000) },
                WAIT_OBJECT_0,
                "job shutdown left an owned process running (close_owner={close_owner})"
            );
        }
        assert!(
            Instant::now() < deadline + Duration::from_secs(10),
            "job shutdown exceeded its qualification window"
        );
        child.wait().unwrap();
    }
}
