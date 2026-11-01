//! Opt-in real database proof; fixture signing never changes release trust.
use super::*;
use crate::host_runtime::{HostMode, HostProcess, VerifiedHostRuntime};
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{json, Value};
use std::fs;
use std::{
    io::Write,
    net::TcpListener,
    process::{Command, Stdio},
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

fn event(process: &mut HostProcess, expected: &str) -> Value {
    let deadline = Instant::now() + Duration::from_secs(240);
    loop {
        if let Some(value) = process.poll_checkpoint().expect("owned restore response") {
            assert_eq!(value["state"], expected, "unexpected restore response");
            return value;
        }
        assert!(Instant::now() < deadline, "restore response timed out");
        std::thread::sleep(Duration::from_millis(100));
    }
}
fn helper(node: &Path, config: &Value, mode: &str) -> Value {
    let mut config = config.clone();
    config["mode"] = json!(mode);
    let script =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../tools/seed_host_restore_fixture.mjs");
    let mut command = Command::new(node);
    command.arg(script).env_clear();
    #[cfg(windows)]
    if let Some(system_root) = std::env::var_os("SystemRoot") {
        command.env("SystemRoot", system_root);
    }
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(serde_json::to_string(&config).unwrap().as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    // Fixture output contains synthetic paths only; never log its credential-bearing input.
    assert!(
        output.status.success(),
        "fixture {mode} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stdout.len() <= 64 * 1024);
    serde_json::from_slice(&output.stdout).expect("bounded fixture receipt")
}
fn verified(
    runtime: &VerifiedHostRuntime,
    owner: &mut Owner,
    state: &Path,
    password: &Zeroizing<String>,
    ports: (u16, u16),
    prepared: &PreparedRestore,
) -> VerifiedRestore {
    owner
        .activate(
            &prepared.binding.installation_id,
            runtime.manifest_sha256(),
            HostMode::RestorePrepare,
        )
        .unwrap();
    let mut process = runtime
        .start_mode(
            state,
            password,
            ports.0,
            ports.1,
            HostMode::RestorePrepare,
            Some(owner),
        )
        .unwrap();
    process.wait_ready(Duration::from_secs(30)).unwrap();
    process.request_verify_restore(prepared).unwrap();
    let response = event(&mut process, "restore-verified");
    process.stop().unwrap();
    owner.clean_stop().unwrap();
    process
        .take_verified_restore(
            &prepared.binding.operation_id,
            response["verificationId"].as_str().unwrap(),
        )
        .unwrap()
}

#[test]
#[ignore = "requires a complete measured test candidate, compiled Manager, and a new synthetic fixture root; no installed or release-signing claim"]
fn actual_postgres_restore_selection_finalization_and_writer_admission() {
    let pack =
        PathBuf::from(std::env::var_os("FRAMELEAF_TEST_HOST_PACK").expect("measured test pack"))
            .canonicalize()
            .unwrap();
    let root =
        PathBuf::from(std::env::var_os("FRAMELEAF_TEST_RESTORE_ROOT").expect("new owned root"));
    assert!(!root.exists(), "never adopt an existing profile");
    crate::runtime_store::private_directory(&root).unwrap();
    let root = root.canonicalize().unwrap();
    let state = root.join("profile");
    crate::runtime_store::private_directory(&state).unwrap();
    let raw = fs::read(pack.join("manifest.json")).unwrap();
    let manifest: Value = serde_json::from_slice(&raw).unwrap();
    let key = SigningKey::from_bytes(&[42; 32]);
    let runtime = VerifiedHostRuntime::verify(
        &pack.join("payload"),
        &raw,
        &key.sign(&raw).to_bytes(),
        &[key.verifying_key()],
        2,
    )
    .unwrap();
    let password = Zeroizing::new(format!("synthetic-{}", Uuid::new_v4()));
    let a = TcpListener::bind("127.0.0.1:0").unwrap();
    let b = TcpListener::bind("127.0.0.1:0").unwrap();
    let ports = (
        a.local_addr().unwrap().port(),
        b.local_addr().unwrap().port(),
    );
    drop((a, b));
    let id = "a".repeat(12);
    let mut owner = Owner::acquire(&state, true).unwrap();
    owner
        .activate(&id, runtime.manifest_sha256(), HostMode::Server)
        .unwrap();
    let config = json!({"root":root,"state":state,"runtime":pack.join("payload"),
        "manager":pack.join("payload/manager/app/build"), "password":password.as_str(),
        "manifestSha256":runtime.manifest_sha256(),"sourceRevision":runtime.source_revision(),
        "postgresMajor":"19","databasePort":ports.0,"apiPort":ports.1,"entryPoints":manifest["entryPoints"]});
    let node = pack
        .join("payload")
        .join(manifest["entryPoints"]["node"].as_str().unwrap());
    let seed = helper(&node, &config, "seed");
    let binding = serde_json::from_value(seed["binding"].clone()).unwrap();
    let safety: SafetySnapshot = serde_json::from_value(seed["safety"].clone()).unwrap();
    owner.clean_stop().unwrap();
    owner
        .activate(&id, runtime.manifest_sha256(), HostMode::RestorePrepare)
        .unwrap();
    let mut process = runtime
        .start_mode(
            &state,
            &password,
            ports.0,
            ports.1,
            HostMode::RestorePrepare,
            Some(&mut owner),
        )
        .unwrap();
    process.wait_ready(Duration::from_secs(30)).unwrap();
    process.request_restore(&binding).unwrap();
    let prepared: PreparedRestore =
        serde_json::from_value(event(&mut process, "restore-prepared")).unwrap();
    process.request_verify_restore(&prepared).unwrap();
    let response = event(&mut process, "restore-verified");
    process.stop().unwrap();
    owner.clean_stop().unwrap();
    let proof = process
        .take_verified_restore(
            &prepared.binding.operation_id,
            response["verificationId"].as_str().unwrap(),
        )
        .unwrap();
    owner.select_restore(proof, safety.clone()).unwrap();
    assert!(
        owner
            .inspect(&id, runtime.manifest_sha256())
            .unwrap()
            .restore_pending
    );
    assert!(state.join(ACTIVATION).is_file());
    assert!(owner
        .activate(&id, runtime.manifest_sha256(), HostMode::Server)
        .is_err());
    let proof = verified(&runtime, &mut owner, &state, &password, ports, &prepared);
    owner.finalize_restore(proof, safety.clone()).unwrap();
    assert!(
        !owner
            .inspect(&id, runtime.manifest_sha256())
            .unwrap()
            .restore_pending
    );
    assert!(!state.join(ACTIVATION).exists());
    let target = state
        .join("restore-targets")
        .join(&prepared.binding.operation_id)
        .join(&prepared.attempt_id);
    let intent = fs::read(target.join("activation-intent.json")).unwrap();
    assert_eq!(
        intent,
        fs::read(target.join("activation-complete.json")).unwrap()
    );
    let selected = owner.read().unwrap().unwrap().database_reference;
    let recovery = state
        .join("restore-safety")
        .join(&prepared.binding.operation_id)
        .join("recovery.json");
    let backup = fs::read(&recovery).unwrap();
    // Lost acknowledgements revalidate and finalize without repeating selection or the safety backup.
    let proof = verified(&runtime, &mut owner, &state, &password, ports, &prepared);
    owner.finalize_restore(proof, safety.clone()).unwrap();
    let final_state = owner.read().unwrap().unwrap();
    assert_eq!(final_state.database_reference, selected);
    assert!(!final_state.restore_pending);
    assert!(!state.join(ACTIVATION).exists());
    assert_eq!(
        fs::read(target.join("activation-intent.json")).unwrap(),
        intent
    );
    assert_eq!(
        fs::read(target.join("activation-complete.json")).unwrap(),
        intent
    );
    assert_eq!(fs::read(&recovery).unwrap(), backup);
    safety.verify_readback(&owner.root, &prepared).unwrap();
    owner
        .activate(&id, runtime.manifest_sha256(), HostMode::Server)
        .unwrap();
    let mut process = runtime
        .start_mode(
            &state,
            &password,
            ports.0,
            ports.1,
            HostMode::Server,
            Some(&mut owner),
        )
        .unwrap();
    process.wait_ready(Duration::from_secs(240)).unwrap();
    assert_eq!(helper(&node, &config, "selected")["selectedRows"], true);
    process.stop().unwrap();
    owner.clean_stop().unwrap();
    assert_eq!(helper(&node, &config, "original")["originalRows"], true);
    let receipt = json!({"actualPostgres":true,"compiledController":true,"sealedProof":true,
        "selectionFenced":true,"independentFinalization":true,"lostAcknowledgementRetry":true,
        "selectedWriterReady":true,"originalRowsRetained":true,"installedAcceptance":false,
        "sourceRevision":runtime.source_revision(),"manifestSha256":runtime.manifest_sha256()});
    fs::write(
        root.join("qualification.json"),
        serde_json::to_vec_pretty(&receipt).unwrap(),
    )
    .unwrap();
    println!("{receipt}");
}
