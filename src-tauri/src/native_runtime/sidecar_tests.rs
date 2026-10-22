use super::*;
use std::{
    io::BufRead,
    process::{Command, Stdio},
    sync::Arc,
    time::{Duration, Instant},
};

struct Fixture {
    root: PathBuf,
    group: i32,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::write(self.root.join("exit"), []);
        let _ = fs::write(self.root.join("leader-exit"), []);
        let deadline = Instant::now() + Duration::from_secs(5);
        while unsafe { libc::kill(-self.group, 0) } == 0 && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        if unsafe { libc::kill(-self.group, 0) } == -1
            && std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH)
        {
            let _ = fs::remove_dir_all(&self.root);
        }
    }
}
fn fixture() -> (Fixture, NativeSidecar) {
    let root = std::env::temp_dir()
        .canonicalize()
        .unwrap()
        .join(format!("frameleaf-sidecar-stop-{}", uuid::Uuid::new_v4()));
    crate::runtime_store::private_directory(&root).unwrap();
    let scratch = root.join("scratch");
    crate::runtime_store::private_directory(&scratch).unwrap();
    fs::write(scratch.join("retained"), b"synthetic staging").unwrap();
    let mut command = Command::new("python3");
    command.args(["-I", "-B", "-c", r#"
import pathlib, subprocess, sys, time
root=pathlib.Path(sys.argv[1])
leaf="""import pathlib,sys,time
p=pathlib.Path(sys.argv[1])
while not (p / 'exit').exists(): time.sleep(0.01)
"""
child=subprocess.Popen([sys.executable, '-I', '-B', '-c', leaf, str(root)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
print(child.pid, flush=True)
while not (root / 'leader-exit').exists(): time.sleep(0.01)
"#]).arg(&root).stdout(Stdio::piped()).stderr(Stdio::null()).stdin(Stdio::null());
    crate::process_tree::configure(&mut command);
    let child = command.spawn().unwrap();
    let tree = crate::process_tree::ProcessTree::attach(&child).unwrap();
    let group = child.id() as i32;
    let fixture = Fixture { root, group };
    let mut sidecar = NativeSidecar {
        child,
        tree,
        scratch,
        token: zeroize::Zeroizing::new("synthetic".into()),
        stopped: false,
        shutdown_signalled: false,
        exit_status: None,
        lease: None,
    };
    let mut line = String::new();
    std::io::BufReader::new(sidecar.child.stdout.take().unwrap())
        .read_line(&mut line)
        .unwrap();
    let leaf: i32 = line.trim().parse().unwrap();
    assert_eq!(unsafe { libc::getpgid(leaf) }, group);
    (fixture, sidecar)
}

#[test]
fn unconfirmed_sidecar_shutdown_keeps_staging_and_runtime_lease() {
    let (fixture, mut sidecar) = fixture();
    let lease = Arc::new(File::create(fixture.root.join("lease")).unwrap());
    sidecar.lease = Some(lease.clone());
    // Simulate an external reaper while a known descendant keeps the fixture's group ID reserved.
    assert_eq!(unsafe { libc::kill(fixture.group, libc::SIGKILL) }, 0);
    let mut status = 0;
    assert_eq!(
        unsafe { libc::waitpid(fixture.group, &mut status, 0) },
        fixture.group
    );
    assert!(sidecar.is_running().is_err());
    assert!(sidecar.stop().is_err());
    drop(sidecar);
    assert!(fixture.root.join("scratch/retained").is_file());
    assert_eq!(Arc::strong_count(&lease), 2);
}

#[test]
fn sidecar_stop_confirms_the_group_and_preserves_natural_exit_status() {
    for natural in [false, true] {
        let (fixture, mut sidecar) = fixture();
        if natural {
            fs::write(fixture.root.join("leader-exit"), []).unwrap();
            let deadline = Instant::now() + Duration::from_secs(5);
            while sidecar.is_running().unwrap() {
                assert!(Instant::now() < deadline);
                std::thread::sleep(Duration::from_millis(10));
            }
            assert!(sidecar.exit_status.unwrap().success());
        }
        sidecar.stop().unwrap();
        sidecar.stop().unwrap();
        assert!(!sidecar.is_running().unwrap());
        assert_eq!(unsafe { libc::kill(-fixture.group, 0) }, -1);
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::ESRCH)
        );
        drop(sidecar);
        assert!(!fixture.root.join("scratch").exists());
    }
}
