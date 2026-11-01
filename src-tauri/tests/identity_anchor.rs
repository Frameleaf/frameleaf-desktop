#![cfg(all(unix, test))]

#[path = "../src/identity_anchor.rs"]
mod identity_anchor;

use std::{fs, os::unix::fs::PermissionsExt, path::PathBuf};

mod credential_lock {
    std::thread_local! {
        pub static ROOT: std::cell::RefCell<Option<std::path::PathBuf>> = const { std::cell::RefCell::new(None) };
    }
    pub fn directory() -> Result<std::path::PathBuf, String> {
        ROOT.with(|root| root.borrow().clone().ok_or("fixture_missing".into()))
    }
}

mod runtime_store {
    pub fn read_bounded(path: &std::path::Path, max: u64) -> Result<Vec<u8>, String> {
        let bytes = std::fs::read(path).map_err(|_| "fixture_read_failed")?;
        if bytes.len() as u64 > max {
            return Err("fixture_read_failed".into());
        }
        Ok(bytes)
    }
}

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("frameleaf-anchor-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        credential_lock::ROOT.with(|root| *root.borrow_mut() = Some(path.clone()));
        Self(path)
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn failed_write_does_not_publish_a_partial_anchor() {
    let fixture = Fixture::new();
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "file_size_failure_child", "--ignored"])
        .env("FRAMELEAF_ANCHOR_PROBE", &fixture.0)
        .output()
        .unwrap();
    assert!(output.status.success(), "{:?}", output);
    assert!(!fixture.0.join("installation.json").exists());
    assert_eq!(fs::read_dir(&fixture.0).unwrap().count(), 0);
}

#[test]
#[ignore = "child-only file-size failure injection"]
fn file_size_failure_child() {
    let root = PathBuf::from(std::env::var_os("FRAMELEAF_ANCHOR_PROBE").unwrap());
    credential_lock::ROOT.with(|value| *value.borrow_mut() = Some(root));
    let mut previous = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    unsafe {
        assert_eq!(libc::getrlimit(libc::RLIMIT_FSIZE, &mut previous), 0);
        let signal = libc::signal(libc::SIGXFSZ, libc::SIG_IGN);
        let limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: previous.rlim_max,
        };
        assert_eq!(libc::setrlimit(libc::RLIMIT_FSIZE, &limit), 0);
        let result = identity_anchor::write(&uuid::Uuid::new_v4().to_string());
        assert_eq!(libc::setrlimit(libc::RLIMIT_FSIZE, &previous), 0);
        libc::signal(libc::SIGXFSZ, signal);
        assert!(result.is_err());
    }
}

#[test]
fn publication_is_private_and_never_replaces_an_existing_anchor() {
    let fixture = Fixture::new();
    let value = uuid::Uuid::new_v4().to_string();
    identity_anchor::write(&value).unwrap();
    assert_eq!(identity_anchor::read().unwrap(), Some(value.clone()));
    let path = fixture.0.join("installation.json");
    let bytes = fs::read(&path).unwrap();
    assert_eq!(serde_json::from_slice::<String>(&bytes).unwrap(), value);
    assert_eq!(
        fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert!(identity_anchor::write(&uuid::Uuid::new_v4().to_string()).is_err());
    assert_eq!(fs::read(&path).unwrap(), bytes);
    assert_eq!(fs::read_dir(&fixture.0).unwrap().count(), 1);
}

#[test]
fn refused_publication_preserves_an_existing_directory() {
    let fixture = Fixture::new();
    fs::create_dir(fixture.0.join("installation.json")).unwrap();
    assert!(identity_anchor::write(&uuid::Uuid::new_v4().to_string()).is_err());
    assert!(fixture.0.join("installation.json").is_dir());
    assert_eq!(fs::read_dir(&fixture.0).unwrap().count(), 1);
}
