//! These ignored fixtures own a fresh identity only inside a disposable hosted runner.
use super::*;
use crate::{
    native_runtime::VerifiedRuntime, runtime_epochs::EpochAuthority, runtime_store::RuntimeStore,
};
use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha256};
use std::{
    fs,
    path::Path,
    process::Command,
    sync::Arc,
    time::{Duration, Instant},
};

fn require_runner() {
    disposable(
        &std::env::var("GITHUB_ACTIONS").unwrap_or_default(),
        &std::env::var("RUNNER_ENVIRONMENT").unwrap_or_default(),
        &std::env::var("FRAMELEAF_TEST_DISPOSABLE_KEYSTORE").unwrap_or_default(),
    )
    .unwrap();
}
fn manifest(epoch: u64) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "schemaVersion":1,"protocolVersion":1,"epoch":epoch,
        "platform":std::env::consts::OS,"architecture":std::env::consts::ARCH,
        "provider":"CPUExecutionProvider","python":"python","sourceRevision":"a".repeat(40),
        "files":{"python":{"sha256":format!("{:x}",Sha256::digest(b"fixture")),"bytes":7}}
    }))
    .unwrap()
}

#[test]
fn disposable_runner_guard_refuses_ordinary_sessions() {
    for (github, environment, opt_in) in [
        ("", "", ""),
        ("true", "self-hosted", "1"),
        ("true", "github-hosted", ""),
        ("false", "github-hosted", "1"),
    ] {
        assert!(disposable(github, environment, opt_in).is_err());
    }
    assert!(disposable("true", "github-hosted", "1").is_ok());
}

#[test]
fn controller_credential_receipt_exposes_only_public_identity_and_runtime_history() {
    let identity = DeviceIdentity::generate();
    let receipt = controller_access_receipt(&identity, &identity.installation_id).unwrap();
    let mut keys: Vec<_> = receipt
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort();
    assert_eq!(
        keys,
        [
            "installationId",
            "protocolVersion",
            "publicKey",
            "runtimeEpochs"
        ]
    );
    assert_eq!(receipt["publicKey"], identity.public_key());
    assert_eq!(
        receipt["runtimeEpochs"],
        serde_json::json!({"accepted": {}})
    );
    assert!(controller_access_receipt(&identity, &uuid::Uuid::new_v4().to_string()).is_err());
    assert!(controller_access_receipt(&identity, "not-an-identity").is_err());
}

#[test]
#[ignore = "requires a fresh disposable hosted runner and a real unlocked OS credential store"]
fn disposable_runner_epoch_persistence() {
    require_runner();
    let controller = std::path::PathBuf::from(
        std::env::var_os("FRAMELEAF_TEST_CONTROLLER").expect("compiled controller is required"),
    );
    assert!(
        controller.is_absolute()
            && fs::symlink_metadata(&controller)
                .unwrap()
                .file_type()
                .is_file()
    );
    {
        let _lock = installation_lock().unwrap();
        assert!(
            load_record::<DeviceIdentity>("installation")
                .unwrap()
                .is_none(),
            "refuse an existing identity"
        );
        assert!(
            crate::identity_anchor::read().unwrap().is_none(),
            "refuse an existing enrollment"
        );
    }
    let enrolled = identity().unwrap();
    let installation_id = enrolled.installation_id.clone();
    let public_key = enrolled.public_key();
    let root = std::env::temp_dir()
        .canonicalize()
        .unwrap()
        .join(format!("frameleaf-keystore-{}", uuid::Uuid::new_v4()));
    struct Scratch(std::path::PathBuf);
    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    crate::runtime_store::private_directory(&root).unwrap();
    let scratch = Scratch(root);
    let candidate = scratch.0.join("candidate");
    crate::runtime_store::private_directory(&candidate).unwrap();
    fs::write(candidate.join("python"), b"fixture").unwrap();
    let key = SigningKey::from_bytes(&[42; 32]);
    let authority = Arc::new(CredentialEpochAuthority);
    for epoch in [2, 3] {
        let store = RuntimeStore::new(
            &scratch.0.join(format!("store-{epoch}")),
            vec![key.verifying_key()],
            1,
            authority.clone(),
        )
        .unwrap();
        let raw = manifest(epoch);
        store
            .install_and_activate(&candidate, &raw, &key.sign(&raw).to_bytes())
            .unwrap();
    }
    let fourth = manifest(4);
    let runtime = VerifiedRuntime::verify(
        &candidate,
        &fourth,
        &key.sign(&fourth).to_bytes(),
        &[key.verifying_key()],
        1,
    )
    .unwrap();
    assert_eq!(
        authority
            .activate(&installation_id, &runtime, &mut || Err(
                "interrupted_publish".into()
            ))
            .unwrap_err(),
        "interrupted_publish"
    );
    let expected_receipt = {
        let _lock = installation_lock().unwrap();
        controller_access_receipt(&runtime_identity().unwrap(), &installation_id).unwrap()
    };
    let output = scratch.0.join("controller-credential-receipt.json");
    let file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&output)
        .unwrap();
    let mut controller_child = Command::new(&controller)
        .args(["--qualify-credential-access", &installation_id])
        .stdout(file)
        .stderr(std::process::Stdio::inherit())
        .spawn()
        .unwrap();
    let status = wait_for_child(&mut controller_child, "separate-controller");
    let actual: serde_json::Value =
        serde_json::from_slice(&crate::runtime_store::read_bounded(&output, 8192).unwrap())
            .unwrap();
    assert_eq!(
        actual, expected_receipt,
        "separate controller must read the same key and saved rollback floor"
    );
    assert!(status.success(), "controller credential access failed");
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "credentials::qualification::child_reload",
            "--ignored",
        ])
        .env("FRAMELEAF_TEST_EPOCH_ROOT", &scratch.0)
        .env("FRAMELEAF_TEST_EPOCH_PUBLIC_KEY", public_key)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    assert!(
        wait_for_child(&mut child, "same-test-binary").success(),
        "credential reload child failed"
    );
    let store = RuntimeStore::new(
        &scratch.0.join("store-4"),
        vec![key.verifying_key()],
        1,
        authority,
    )
    .unwrap();
    store
        .install_and_activate(&candidate, &fourth, &key.sign(&fourth).to_bytes())
        .unwrap();
    assert!(store.load_active().unwrap().is_some());
    delete("installation").unwrap();
    assert_eq!(
        identity().err().as_deref(),
        Some("runtime_epoch_credential_missing")
    );
    assert_eq!(
        RuntimeStore::new(
            &scratch.0.join("fresh-root"),
            vec![key.verifying_key()],
            1,
            Arc::new(CredentialEpochAuthority)
        )
        .err()
        .as_deref(),
        Some("runtime_epoch_credential_missing")
    );
    let _lock = installation_lock().unwrap();
    assert!(load_record::<DeviceIdentity>("installation")
        .unwrap()
        .is_none());
    assert_eq!(
        crate::identity_anchor::read().unwrap().as_deref(),
        Some(installation_id.as_str())
    );
    remove_owned_marker();
}

#[test]
#[ignore = "child-only real credential reload; invoked by the disposable runner fixture"]
fn child_reload() {
    require_runner();
    let root = std::env::var_os("FRAMELEAF_TEST_EPOCH_ROOT").expect("missing parent fixture");
    let root = Path::new(&root);
    let identity = identity().unwrap();
    assert_eq!(
        identity.public_key(),
        std::env::var("FRAMELEAF_TEST_EPOCH_PUBLIC_KEY").unwrap()
    );
    let key = SigningKey::from_bytes(&[42; 32]);
    for epoch in [2, 3, 4] {
        let store = RuntimeStore::new(
            &root.join(format!("store-{epoch}")),
            vec![key.verifying_key()],
            1,
            Arc::new(CredentialEpochAuthority),
        )
        .unwrap();
        let loaded = store.load_active();
        if epoch < 4 {
            assert_eq!(loaded.err().as_deref(), Some("runtime_epoch_rollback"));
        } else {
            assert!(loaded.unwrap().is_none());
        }
    }
}

#[cfg(unix)]
fn remove_owned_marker() {
    fs::remove_file(
        crate::credential_lock::directory()
            .unwrap()
            .join("installation.json"),
    )
    .unwrap();
}
#[cfg(windows)]
fn remove_owned_marker() {
    use windows_sys::Win32::System::Registry::*;
    let name: Vec<u16> = "Software\\Frameleaf\\DesktopSecurity\0"
        .encode_utf16()
        .collect();
    let value: Vec<u16> = "InstallationId\0".encode_utf16().collect();
    let mut key = std::ptr::null_mut();
    assert_eq!(
        unsafe {
            RegOpenKeyExW(
                HKEY_CURRENT_USER,
                name.as_ptr(),
                0,
                KEY_SET_VALUE | KEY_QUERY_VALUE,
                &mut key,
            )
        },
        0
    );
    let removed = unsafe { RegDeleteValueW(key, value.as_ptr()) };
    let flushed = unsafe { RegFlushKey(key) };
    unsafe {
        RegCloseKey(key);
    }
    assert_eq!(removed, 0);
    assert_eq!(flushed, 0);
}

fn wait_for_child(child: &mut std::process::Child, phase: &str) -> std::process::ExitStatus {
    eprintln!("credential_fixture_phase={phase}");
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            return status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("credential reload child timed out: {phase}");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}
