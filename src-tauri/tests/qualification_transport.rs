use base64::{engine::general_purpose::STANDARD, Engine};
use ed25519_dalek::{Signer, SigningKey};
use frameleaf_desktop::{
    ml_transport::{AcceptedQualification, QualificationChallenge},
    model_catalogue::{approved_profile, ApprovedProfile},
    runtime_store::{InstalledRuntime, RuntimeStore},
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{fs, path::PathBuf};
use uuid::Uuid;

fn worker() -> frameleaf_desktop::worker::SavedWorker {
    serde_json::from_value(
        json!({"serverId":"server","accountId":"account","deviceId":"device",
        "sessionId":"session","authorizationEpoch":2,"workerToken":"a".repeat(64),
        "expiresAt":"2099-01-01T00:00:00Z","nextSequence":1}),
    )
    .unwrap()
}
struct Fixture {
    root: PathBuf,
    store: RuntimeStore,
    installed: InstalledRuntime,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}
fn profile() -> ApprovedProfile {
    let catalogue: Value =
        serde_json::from_str(include_str!("../../runtime/model-catalogue.json")).unwrap();
    let p = &catalogue["profiles"][0];
    approved_profile(
        p["modelName"].as_str().unwrap(),
        &p["spec"]["entries"],
        p["runtimeSourceRevision"].as_str().unwrap(),
        p["spec"]["provider"].as_str().unwrap(),
    )
    .unwrap()
    .unwrap()
}
fn fixture() -> Fixture {
    let root = std::env::temp_dir()
        .canonicalize()
        .unwrap()
        .join(format!("frameleaf-challenge-{}", Uuid::new_v4()));
    fs::create_dir(&root).unwrap();
    let payload = root.join("payload");
    fs::create_dir(&payload).unwrap();
    fs::write(payload.join("python"), b"fixture").unwrap();
    let key = SigningKey::from_bytes(&[42; 32]);
    let p = profile();
    let raw = serde_json::to_vec(&json!({"schemaVersion":1,"protocolVersion":1,"epoch":2,
        "platform":std::env::consts::OS,"architecture":std::env::consts::ARCH,"provider":"CPUExecutionProvider",
        "python":"python","sourceRevision":p.runtime_source_revision(),
        "files":{"python":{"sha256":format!("{:x}",Sha256::digest(b"fixture")),"bytes":7}}})).unwrap();
    let store = RuntimeStore::new(&root.join("store"), vec![key.verifying_key()], 1).unwrap();
    store
        .install_and_activate(&payload, &raw, &key.sign(&raw).to_bytes())
        .unwrap();
    let installed = store.load_active().unwrap().unwrap();
    Fixture {
        root,
        store,
        installed,
    }
}
fn response(p: &ApprovedProfile, manifest: &str) -> Value {
    let id = "d621bd72-ad35-4199-95ab-76300756a38e";
    let (spec, fixture) = p.challenge(id).unwrap();
    json!({"id":id,"modelKey":p.model_key(),"specJson":String::from_utf8(spec.clone()).unwrap(),
        "bindingSha256":format!("{:x}",Sha256::digest(spec)),"fixtureBase64":STANDARD.encode(fixture),
        "manifestSha256":manifest,"expiresAt":"2026-10-15T20:10:00Z","reportSha256":null})
}
#[test]
fn accepts_only_the_compiled_profile_and_verified_factory_runtime_identity() {
    let f = fixture();
    let p = profile();
    let attestation = f.store.attestation(&f.installed).unwrap();
    let value = response(&p, f.installed.manifest_sha256());
    let bound = QualificationChallenge::bind(
        &worker(),
        &p,
        &attestation,
        &serde_json::to_vec(&value).unwrap(),
        1_792_094_400_000,
    )
    .unwrap();
    assert_eq!(bound.id(), value["id"].as_str().unwrap());
    assert_eq!(bound.specification(), p.challenge(bound.id()).unwrap().0);
    assert_eq!(bound.fixture(), p.challenge(bound.id()).unwrap().1);
    assert!(bound.report_sha256().is_none());
}
#[test]
fn rejects_changed_specs_fixtures_models_manifests_deadlines_and_unknown_fields() {
    let f = fixture();
    let p = profile();
    let attestation = f.store.attestation(&f.installed).unwrap();
    let original = response(&p, f.installed.manifest_sha256());
    for (field, value) in [
        ("modelKey", json!("other")),
        ("specJson", json!("{}")),
        ("fixtureBase64", json!("dGFtcGVyZWQ=")),
        ("bindingSha256", json!("b".repeat(64))),
        ("manifestSha256", json!("b".repeat(64))),
        ("expiresAt", json!("2026-10-15T19:00:00Z")),
        ("expiresAt", json!("2099-01-01T00:00:00Z")),
        ("reportSha256", json!("invalid")),
        ("id", json!("../elsewhere")),
        ("extra", json!(true)),
    ] {
        let mut changed = original.clone();
        changed[field] = value;
        assert!(
            QualificationChallenge::bind(
                &worker(),
                &p,
                &attestation,
                &serde_json::to_vec(&changed).unwrap(),
                1_792_094_400_000
            )
            .is_err(),
            "{field}"
        );
    }
}

#[test]
#[ignore = "requires a private factory-signed CPU pack and staged approved default model"]
fn actual_factory_runtime_qualifies_the_bound_challenge_and_refuses_nonce_replay() {
    use std::{
        sync::atomic::AtomicBool,
        time::{SystemTime, UNIX_EPOCH},
    };
    let root = std::env::temp_dir()
        .canonicalize()
        .unwrap()
        .join(format!("frameleaf-real-challenge-{}", Uuid::new_v4()));
    fs::create_dir(&root).unwrap();
    let pack = PathBuf::from(std::env::var("FRAMELEAF_FACTORY_TEST_PACK").unwrap());
    let cache = PathBuf::from(std::env::var("FRAMELEAF_FACTORY_MODEL_CACHE").unwrap());
    let store = frameleaf_desktop::release_policy::open_runtime_store(&root.join("store")).unwrap();
    let raw = fs::read(pack.join("manifest.json")).unwrap();
    let signature: [u8; 64] = fs::read(pack.join("manifest.sig"))
        .unwrap()
        .try_into()
        .unwrap();
    store
        .install_and_activate(&pack.join("payload"), &raw, &signature)
        .unwrap();
    let installed = store.load_active().unwrap().unwrap();
    let f = Fixture {
        root,
        store,
        installed,
    };
    let p = profile();
    let attestation = f.store.attestation(&f.installed).unwrap();
    let clock = || {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64
    };
    let ends = time::OffsetDateTime::now_utc() + time::Duration::minutes(10);
    let expires = format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        ends.year(),
        ends.month() as u8,
        ends.day(),
        ends.hour(),
        ends.minute(),
        ends.second()
    );
    let id = Uuid::new_v4().to_string();
    let (spec, fixture) = p.challenge(&id).unwrap();
    let wire = json!({"id":id,"modelKey":p.model_key(),"specJson":String::from_utf8(spec.clone()).unwrap(),
        "bindingSha256":format!("{:x}",Sha256::digest(&spec)),"fixtureBase64":STANDARD.encode(&fixture),
        "manifestSha256":attestation.manifest_sha256(),"expiresAt":expires,"reportSha256":null});
    let challenge = QualificationChallenge::bind(
        &worker(),
        &p,
        &attestation,
        &serde_json::to_vec(&wire).unwrap(),
        clock(),
    )
    .unwrap();
    let qualified = f
        .installed
        .qualify(
            &cache,
            &f.root,
            challenge.specification(),
            challenge.fixture(),
            &AtomicBool::new(false),
        )
        .unwrap();
    challenge
        .validate_submission(&worker(), &qualified, clock())
        .unwrap();
    assert_eq!(qualified.report()["state"], "ready-cpu");
    let accepted_at = time::OffsetDateTime::now_utc();
    let expiry = accepted_at + time::Duration::hours(1);
    let stamp = |date: time::OffsetDateTime| {
        format!(
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
            date.year(),
            date.month() as u8,
            date.day(),
            date.hour(),
            date.minute(),
            date.second()
        )
    };
    let spec: Value = serde_json::from_slice(&spec).unwrap();
    let accepted = json!({"id":id,"deviceId":worker().device_id,"sessionId":worker().session_id,"authorizationEpoch":2,
        "modelKey":p.model_key(),"configSha256":format!("{:x}",Sha256::digest(serde_json_canonicalizer::to_vec(&spec["entries"]).unwrap())),
        "inputKind":"text","bindingSha256":wire["bindingSha256"],"manifestSha256":attestation.manifest_sha256(),
        "runtimeFingerprint":qualified.report()["runtimeFingerprint"],"reportSha256":format!("{:x}",Sha256::digest(serde_json_canonicalizer::to_vec(qualified.report()).unwrap())),
        "qualifiedAt":stamp(accepted_at),"expiresAt":stamp(expiry)});
    let accepted = AcceptedQualification::bind(
        &worker(),
        &p,
        &qualified,
        &serde_json::to_vec(&accepted).unwrap(),
        clock(),
    )
    .unwrap();
    accepted.validate_runtime(&qualified, clock()).unwrap();
    let mut renewed = worker();
    renewed.worker_token = "b".repeat(64);
    accepted.validate_authority(&renewed, clock()).unwrap();
    assert!(accepted
        .validate_runtime(&qualified, clock() + 3_600_000)
        .is_err());

    let mut other = wire;
    let id2 = Uuid::new_v4().to_string();
    let (spec2, _) = p.challenge(&id2).unwrap();
    other["id"] = json!(id2);
    other["specJson"] = json!(String::from_utf8(spec2.clone()).unwrap());
    other["bindingSha256"] = json!(format!("{:x}", Sha256::digest(spec2)));
    let replaced = QualificationChallenge::bind(
        &worker(),
        &p,
        &attestation,
        &serde_json::to_vec(&other).unwrap(),
        clock(),
    )
    .unwrap();
    assert!(replaced
        .validate_submission(&worker(), &qualified, clock())
        .is_err());
    assert!(challenge
        .validate_submission(&worker(), &qualified, clock() + 720_000)
        .is_err());
    eprintln!("PASS: installed factory runtime qualified the approved default model; old-nonce and expired submissions refused");
}

#[test]
fn refuses_a_challenge_on_another_connection_or_credential_generation() {
    let f = fixture();
    let p = profile();
    let attestation = f.store.attestation(&f.installed).unwrap();
    let raw = serde_json::to_vec(&response(&p, f.installed.manifest_sha256())).unwrap();
    let challenge =
        QualificationChallenge::bind(&worker(), &p, &attestation, &raw, 1_792_094_400_000).unwrap();
    let original: frameleaf_desktop::worker::SavedWorker = serde_json::from_value(json!({
        "serverId":"server","accountId":"account","deviceId":"device","sessionId":"session",
        "authorizationEpoch":2,"workerToken":"a".repeat(64),"expiresAt":"2099-01-01T00:00:00Z","nextSequence":1
    })).unwrap();
    assert!(challenge.validate_authority(&original).is_ok());
    let mut advanced = original.clone();
    advanced.next_sequence += 1;
    assert!(challenge.validate_authority(&advanced).is_ok());
    for (field, value) in [
        ("serverId", json!("other")),
        ("accountId", json!("other")),
        ("deviceId", json!("other")),
        ("sessionId", json!("other")),
        ("authorizationEpoch", json!(3)),
        ("workerToken", json!("b".repeat(64))),
    ] {
        let mut changed = serde_json::to_value(&original).unwrap();
        changed[field] = value;
        let changed = serde_json::from_value(changed).unwrap();
        assert!(challenge.validate_authority(&changed).is_err(), "{field}");
    }
}
