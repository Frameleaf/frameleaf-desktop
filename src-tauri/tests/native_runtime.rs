use ed25519_dalek::{Signer, SigningKey};
use frameleaf_desktop::native_runtime::VerifiedRuntime;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, fs, path::PathBuf};
use uuid::Uuid;

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir()
            .canonicalize()
            .unwrap()
            .join(format!("frameleaf-pack-{}", Uuid::new_v4()));
        fs::create_dir(&root).unwrap();
        Self(root)
    }
    fn manifest(&self) -> Vec<u8> {
        serde_json::to_vec(&json!({
            "schemaVersion":1,"protocolVersion":1,"epoch":7,
            "platform":std::env::consts::OS,"architecture":std::env::consts::ARCH,
            "provider":"CPUExecutionProvider","python":"python", "sourceRevision":"a".repeat(40),
            "files":BTreeMap::from([("python",json!({"sha256":format!("{:x}",Sha256::digest(b"fixture")),"bytes":7}))])
        })).unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn key() -> SigningKey {
    SigningKey::from_bytes(&[42; 32])
}

#[test]
fn only_trusted_current_platform_signed_complete_packs_are_accepted() {
    let root = Fixture::new();
    fs::write(root.0.join("python"), b"fixture").unwrap();
    let raw = root.manifest();
    let signing = key();
    let signature = signing.sign(&raw).to_bytes();
    assert!(
        VerifiedRuntime::verify(&root.0, &raw, &signature, &[signing.verifying_key()], 7).is_ok()
    );
    assert!(VerifiedRuntime::verify(&root.0, &raw, &signature, &[], 7).is_err());
    assert!(
        VerifiedRuntime::verify(&root.0, &raw, &signature, &[signing.verifying_key()], 8).is_err()
    );
    let mut changed = raw.clone();
    changed.push(b' ');
    assert!(
        VerifiedRuntime::verify(&root.0, &changed, &signature, &[signing.verifying_key()], 7)
            .is_err()
    );
    fs::write(root.0.join("extra.py"), b"unapproved").unwrap();
    assert!(
        VerifiedRuntime::verify(&root.0, &raw, &signature, &[signing.verifying_key()], 7).is_err()
    );
    fs::remove_file(root.0.join("extra.py")).unwrap();
    fs::write(root.0.join("python"), b"changed").unwrap();
    assert!(
        VerifiedRuntime::verify(&root.0, &raw, &signature, &[signing.verifying_key()], 7).is_err()
    );
}

#[test]
fn signed_manifest_cannot_traverse_or_select_wrong_platform_or_protocol() {
    let root = Fixture::new();
    fs::write(root.0.join("python"), b"fixture").unwrap();
    for (field, value) in [
        ("python", json!("../python")),
        ("platform", json!("wrong")),
        ("protocolVersion", json!(2)),
        ("provider", json!("InventedProvider")),
    ] {
        let mut spec: serde_json::Value = serde_json::from_slice(&root.manifest()).unwrap();
        spec[field] = value;
        let raw = serde_json::to_vec(&spec).unwrap();
        let signing = key();
        assert!(VerifiedRuntime::verify(
            &root.0,
            &raw,
            &signing.sign(&raw).to_bytes(),
            &[signing.verifying_key()],
            7
        )
        .is_err());
    }
}

#[cfg(unix)]
#[test]
fn pack_symlinks_are_never_followed() {
    use std::os::unix::fs::symlink;
    let root = Fixture::new();
    let outside = Fixture::new();
    fs::write(outside.0.join("python"), b"fixture").unwrap();
    symlink(outside.0.join("python"), root.0.join("python")).unwrap();
    let raw = root.manifest();
    let signing = key();
    assert!(VerifiedRuntime::verify(
        &root.0,
        &raw,
        &signing.sign(&raw).to_bytes(),
        &[signing.verifying_key()],
        7
    )
    .is_err());
}

#[test]
fn owned_runtime_clears_ambient_credentials_and_stops_on_drop() {
    use std::{
        process::Command,
        time::{Duration, Instant},
    };
    let root = Fixture::new();
    let workspace = Fixture::new();
    let cache = Fixture::new();
    let source = workspace.0.join("fixture.rs");
    fs::write(&source, r#"
use std::{env,fs,io::{self,Read},thread,time::Duration};
fn main(){
 let mut gate=[0;23];io::stdin().read_exact(&mut gate).unwrap();assert_eq!(&gate,b"frameleaf-native-start\n");
 let args:Vec<_>=env::args().collect();assert_eq!(args[1],"-I");assert_eq!(args[2],"-B");assert_eq!(args[3],"-c");assert_eq!(args[5],"immich_ml.native_runtime");
 let token=env::var("FRAMELEAF_ML_AUTH_TOKEN").unwrap();assert_eq!(token.len(),64);
 assert!(env::var("HOME").is_err());assert!(env::var("PYTHONPATH").is_err());assert!(env::var("AWS_SECRET_ACCESS_KEY").is_err());
 fs::write("ready",b"ready").unwrap();loop{thread::sleep(Duration::from_millis(20));}
}
"#).unwrap();
    let executable = if cfg!(windows) {
        "python.exe"
    } else {
        "python"
    };
    assert!(Command::new("rustc")
        .args(["--edition=2021"])
        .arg(&source)
        .arg("-o")
        .arg(source.parent().unwrap().join(executable))
        .status()
        .unwrap()
        .success());
    fs::copy(
        source.parent().unwrap().join(executable),
        root.0.join(executable),
    )
    .unwrap();
    let bytes = fs::read(root.0.join(executable)).unwrap();
    let mut spec: serde_json::Value = serde_json::from_slice(&root.manifest()).unwrap();
    spec["python"] = json!(executable);
    spec["files"] =
        json!({executable:{"sha256":format!("{:x}",Sha256::digest(&bytes)),"bytes":bytes.len()}});
    let raw = serde_json::to_vec(&spec).unwrap();
    let signing = key();
    let pack = VerifiedRuntime::verify(
        &root.0,
        &raw,
        &signing.sign(&raw).to_bytes(),
        &[signing.verifying_key()],
        7,
    )
    .unwrap();
    let mut runtime = pack.start_sidecar(&cache.0, &workspace.0, 19999).unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    while !runtime.working_dir().join("ready").is_file() {
        assert!(Instant::now() < deadline);
        assert!(runtime.is_running().unwrap());
        std::thread::sleep(Duration::from_millis(10));
    }
    let scratch = runtime.working_dir().to_path_buf();
    runtime.stop().unwrap();
    assert!(!runtime.is_running().unwrap());
    drop(runtime);
    assert!(!scratch.exists());
    fs::write(root.0.join(executable), b"tampered").unwrap();
    assert!(pack.start_sidecar(&cache.0, &workspace.0, 19999).is_err());
}

#[test]
fn qualification_rejects_bad_binding_and_preexisting_cancellation_before_launch() {
    use std::sync::atomic::AtomicBool;
    let root = Fixture::new();
    let work = Fixture::new();
    let cache = Fixture::new();
    fs::write(root.0.join("python"), b"fixture").unwrap();
    let raw = root.manifest();
    let signing = key();
    let pack = VerifiedRuntime::verify(
        &root.0,
        &raw,
        &signing.sign(&raw).to_bytes(),
        &[signing.verifying_key()],
        7,
    )
    .unwrap();
    let spec=serde_json::to_vec(&json!({"protocolVersion":1,"modelKey":"approved","provider":"CPUExecutionProvider","fixtureFile":"fixture.txt","fixtureSha256":format!("{:x}",Sha256::digest(b"fixture")),"preprocessingSha256":"a".repeat(64),"deadlineSeconds":1})).unwrap();
    assert!(pack
        .qualify(
            &cache.0,
            &work.0,
            &spec,
            b"changed",
            &AtomicBool::new(false)
        )
        .is_err());
    assert!(pack
        .qualify(&cache.0, &work.0, &spec, b"fixture", &AtomicBool::new(true))
        .is_err());
    assert_eq!(fs::read_dir(&work.0).unwrap().count(), 0);
}

#[test]
fn qualifier_checks_exit_report_binding_deadline_and_cancellation() {
    use std::{
        process::Command,
        sync::{
            atomic::{AtomicBool, Ordering},
            Arc,
        },
        time::Duration,
    };
    let root = Fixture::new();
    let work = Fixture::new();
    let cache = Fixture::new();
    let spec=serde_json::to_vec(&json!({"protocolVersion":1,"modelKey":"approved","provider":"CPUExecutionProvider","fixtureFile":"fixture.txt","fixtureSha256":format!("{:x}",Sha256::digest(b"fixture")),"preprocessingSha256":"a".repeat(64),"deadlineSeconds":1})).unwrap();
    let binding = format!("{:x}", Sha256::digest(&spec));
    let report=serde_json::to_string(&json!({"protocolVersion":1,"modelKey":"approved","provider":"CPUExecutionProvider","fixtureSha256":format!("{:x}",Sha256::digest(b"fixture")),"preprocessingSha256":"a".repeat(64),"bindingSha256":binding,"runtimeFingerprint":"b".repeat(64),"state":"ready-cpu","reason":null,"coldMilliseconds":1.5,"warmMilliseconds":0.5,"execution":[{"state":"ready-cpu","reason":null,"nodes":{"CPUExecutionProvider":3}}]})).unwrap();
    let source = work.0.join("fixture.rs");
    fs::write(&source,format!(r#"
use std::{{env,fs,io::{{self,Read}},thread,time::Duration}};
fn main(){{
 let mut gate=[0;23];io::stdin().read_exact(&mut gate).unwrap();assert_eq!(&gate,b"frameleaf-native-start\n");
 let args:Vec<_>=env::args().collect();assert_eq!(args[5],"immich_ml.native_qualification");
 let argument=|name:&str|args[args.iter().position(|v|v==name).unwrap()+1].clone();
 let mode=fs::read_to_string(std::path::Path::new(&argument("--cache-dir")).join("mode")).unwrap_or_default();
 let report={report:?};
 if mode=="block"{{thread::sleep(Duration::from_secs(10));}}
 if mode=="exit"{{std::process::exit(11);}}
 let bytes=if mode=="wrong"{{report.replace("approved","other").into_bytes()}}else if mode=="oversize"{{vec![b'x';4*1024*1024+1]}}else{{report.as_bytes().to_vec()}};
 fs::write(argument("--output"),bytes).unwrap();
}}
"#)).unwrap();
    let executable = if cfg!(windows) {
        "python.exe"
    } else {
        "python"
    };
    assert!(Command::new("rustc")
        .arg("--edition=2021")
        .arg(&source)
        .arg("-o")
        .arg(source.parent().unwrap().join(executable))
        .status()
        .unwrap()
        .success());
    fs::copy(
        source.parent().unwrap().join(executable),
        root.0.join(executable),
    )
    .unwrap();
    let bytes = fs::read(root.0.join(executable)).unwrap();
    let mut manifest: serde_json::Value = serde_json::from_slice(&root.manifest()).unwrap();
    manifest["python"] = json!(executable);
    manifest["files"] =
        json!({executable:{"sha256":format!("{:x}",Sha256::digest(&bytes)),"bytes":bytes.len()}});
    let raw = serde_json::to_vec(&manifest).unwrap();
    let signing = key();
    let pack = VerifiedRuntime::verify(
        &root.0,
        &raw,
        &signing.sign(&raw).to_bytes(),
        &[signing.verifying_key()],
        7,
    )
    .unwrap();
    let result = pack
        .qualify(
            &cache.0,
            &work.0,
            &spec,
            b"fixture",
            &AtomicBool::new(false),
        )
        .unwrap();
    assert_eq!(result.report()["bindingSha256"], binding);
    assert_eq!(result.manifest_sha256(), pack.manifest_sha256());
    for mode in ["wrong", "oversize", "exit", "block"] {
        fs::write(cache.0.join("mode"), mode).unwrap();
        assert!(
            pack.qualify(
                &cache.0,
                &work.0,
                &spec,
                b"fixture",
                &AtomicBool::new(false)
            )
            .is_err(),
            "accepted {mode}"
        );
    }
    let cancel = Arc::new(AtomicBool::new(false));
    let signal = cancel.clone();
    let trigger = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(100));
        signal.store(true, Ordering::Release);
    });
    assert!(pack
        .qualify(&cache.0, &work.0, &spec, b"fixture", &cancel)
        .is_err());
    trigger.join().unwrap();
    assert!(fs::read_dir(&work.0).unwrap().all(|entry| !entry
        .unwrap()
        .file_name()
        .to_string_lossy()
        .starts_with("inference-")));
}
