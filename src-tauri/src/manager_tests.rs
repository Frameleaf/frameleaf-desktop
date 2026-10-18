use super::*;
use crate::connection::DeviceIdentity;
use base64::{engine::general_purpose::STANDARD, Engine};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde_json::json;

fn identity() -> DeviceIdentity {
    serde_json::from_value(
        json!({"installation_id":"11111111-1111-4111-8111-111111111111", "secret":vec![7u8;32]}),
    )
    .unwrap()
}
fn saved() -> SavedManager {
    serde_json::from_value(json!({
        "origin":"https://manager.test:9443", "managerId":"22222222-2222-4222-8222-222222222222",
        "deviceId":identity().installation_id, "installationId":"aaaaaaaaaaaa", "publicKey":identity().public_key(),
        "id":"33333333-3333-4333-8333-333333333333", "token":"b".repeat(64),
        "scopes":["status","start","stop","restart","backup"], "expiresAt":1702592000000u64,"recentUntil":1700000300000u64,
        "certificatePem":null
    })).unwrap()
}
#[test]
fn binds_request_bytes_device_and_scopes_without_exposing_grant_in_view() {
    let identity = identity();
    let saved = saved();
    let command = Command::Control {
        action: Action::Stop,
        key: uuid::Uuid::parse_str("44444444-4444-4444-8444-444444444444").unwrap(),
    };
    let prepared = prepare(
        &saved,
        &identity,
        &command,
        1700000000000,
        "55555555-5555-4555-8555-555555555555",
    )
    .unwrap();
    assert_eq!(prepared.path, "/manager-api/desktop/control");
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&prepared.body).unwrap()["action"],
        "stop"
    );
    let proof: serde_json::Value =
        serde_json::from_slice(&STANDARD.decode(&prepared.proof).unwrap()).unwrap();
    assert_eq!(proof["deviceId"], identity.installation_id);
    let message = request_message(&saved, &proof, "stop", prepared.path, &prepared.body).unwrap();
    let signature = STANDARD
        .decode(proof["signature"].as_str().unwrap())
        .unwrap();
    let key = STANDARD.decode(identity.public_key()).unwrap();
    VerifyingKey::from_bytes(&key.try_into().unwrap())
        .unwrap()
        .verify(
            message.as_bytes(),
            &Signature::from_slice(&signature).unwrap(),
        )
        .unwrap();
    assert!(!serde_json::to_string(&saved.view())
        .unwrap()
        .contains(&saved.token));
    let replacement = DeviceIdentity::generate();
    assert_eq!(
        prepare(
            &saved,
            &replacement,
            &command,
            1700000000000,
            "55555555-5555-4555-8555-555555555555"
        )
        .err()
        .unwrap(),
        "manager_device_changed"
    );
}
#[test]
fn rejects_expired_grants_untrusted_origins_extra_commands_and_invalid_pins() {
    let saved = saved();
    assert_eq!(
        prepare(
            &saved,
            &identity(),
            &Command::Status {},
            1702592000000,
            "55555555-5555-4555-8555-555555555555"
        )
        .err()
        .unwrap(),
        "manager_pairing_expired"
    );
    assert!(serde_json::from_value::<Command>(
        json!({"kind":"control","action":"shell","key":uuid::Uuid::new_v4()})
    )
    .is_err());
    assert!(
        serde_json::from_value::<Command>(json!({"kind":"status","url":"https://evil.test"}))
            .is_err()
    );
    assert_eq!(
        certificate_fingerprint("private data").unwrap_err(),
        "manager_certificate_invalid"
    );
    assert!(manager_client(Some("private data"), Some(&"a".repeat(64))).is_err());
}
#[test]
fn accepts_only_bounded_public_operation_and_status_records() {
    let saved = saved();
    let operation = json!({"id":uuid::Uuid::new_v4(),"kind":"stop","state":"complete","step":null,"completed":["stop"],"error":null,"createdAt":1700000000000u64,"updatedAt":1700000000000u64});
    assert!(validate_reply(
        &saved,
        &Command::Operation {
            id: uuid::Uuid::new_v4()
        },
        operation.clone()
    )
    .is_err());
    let id = uuid::Uuid::parse_str(operation["id"].as_str().unwrap()).unwrap();
    assert!(validate_reply(&saved, &Command::Operation { id }, operation.clone()).is_ok());
    let mut untrusted = operation;
    untrusted["token"] = json!("private protocol data");
    assert!(validate_reply(&saved, &Command::Operation { id }, untrusted).is_err());
}

#[test]
fn javascript_golden_messages_signatures_and_certificate_fingerprint_match() {
    let fixture: Value = serde_json::from_str(include_str!("manager_wire.json")).unwrap();
    let approval: Pairing = serde_json::from_value(fixture["pairing"].clone()).unwrap();
    validate_pairing(
        &approval,
        &identity(),
        "https://manager.test:9443",
        1700000000000,
        &SCOPES,
    )
    .unwrap();
    assert_eq!(pairing_message(&approval), fixture["pairingMessage"]);
    assert_eq!(
        identity().sign(&pairing_message(&approval)),
        fixture["pairingSignature"]
    );
    let command = Command::Control {
        action: Action::Stop,
        key: Uuid::parse_str("44444444-4444-4444-8444-444444444444").unwrap(),
    };
    let request = prepare(
        &saved(),
        &identity(),
        &command,
        1700000000000,
        "55555555-5555-4555-8555-555555555555",
    )
    .unwrap();
    assert_eq!(
        String::from_utf8(request.body.clone()).unwrap(),
        fixture["body"]
    );
    let proof: Value = serde_json::from_slice(&STANDARD.decode(request.proof).unwrap()).unwrap();
    assert_eq!(
        request_message(&saved(), &proof, "stop", request.path, &request.body).unwrap(),
        fixture["requestMessage"]
    );
    assert_eq!(proof["signature"], fixture["requestSignature"]);
    let pem = fixture["certificatePem"].as_str().unwrap();
    let hash = fixture["certificateSha256"].as_str().unwrap();
    assert_eq!(certificate_fingerprint(pem).unwrap(), hash);
    assert!(manager_client(Some(pem), Some(hash)).is_ok());
    assert_eq!(
        manager_client(Some(pem), Some(&"0".repeat(64)))
            .err()
            .unwrap(),
        "manager_certificate_approval_changed"
    );
    assert!(manager_client(Some(pem), None).is_err());
}

#[test]
fn pairing_and_response_validation_refuse_changed_authority_and_unknown_fields() {
    let fixture: Value = serde_json::from_str(include_str!("manager_wire.json")).unwrap();
    for (field, value) in [
        ("managerId", json!("invalid")),
        ("origin", json!("https://other.test:9443")),
        ("deviceId", json!(Uuid::new_v4())),
        ("publicKey", json!(DeviceIdentity::generate().public_key())),
        ("installationId", json!("../host")),
        ("scopes", json!(["status", "restore"])),
    ] {
        let mut data = fixture["pairing"].clone();
        data[field] = value;
        let approval: Pairing = serde_json::from_value(data).unwrap();
        assert!(validate_pairing(
            &approval,
            &identity(),
            "https://manager.test:9443",
            1700000000000,
            &SCOPES,
        )
        .is_err());
    }
    let mut approval: Pairing = serde_json::from_value(fixture["pairing"].clone()).unwrap();
    approval.expires_at = 1700000000000;
    assert!(validate_pairing(
        &approval,
        &identity(),
        "https://manager.test:9443",
        1700000000000,
        &SCOPES,
    )
    .is_err());
    for origin in [
        "http://manager.test",
        "https://manager.test/path",
        "https://user@manager.test",
        "https://manager.test?q=1",
    ] {
        assert!(canonical_origin(origin).is_err());
    }
    let data = json!({"manager":{"id":saved().manager_id,"origin":"https://manager.test:9443"},"installation":{"id":"bbbbbbbbbbbb","name":"Fixture","release":"frameleaf-v3.0.0-1","port":2283},"operations":[]});
    assert_eq!(
        validate_reply(&saved(), &Command::Status {}, data)
            .err()
            .unwrap(),
        "manager_installation_changed"
    );
}

#[test]
#[ignore = "requires an owned live compiled Manager HTTPS fixture; no OS-keystore access"]
fn actual_compiled_manager_pairs_signs_reauthenticates_and_cleans_failed_persistence() {
    tauri::async_runtime::block_on(async {
        let root = std::path::PathBuf::from(
            std::env::var_os("FRAMELEAF_TEST_MANAGER_ROOT").expect("owned fixture root"),
        );
        let pem = std::fs::read_to_string(root.join("manager/tls.crt")).unwrap();
        let certificate = CertificateTrust {
            sha256: certificate_fingerprint(&pem).unwrap(),
            pem,
        };
        let identity = DeviceIdentity::generate();
        let origin = "https://127.0.0.1:9443";
        let password = "synthetic compiled Manager HTTPS password";
        let record = std::sync::Mutex::new(None);
        let view = pair(
            &identity,
            origin,
            password.into(),
            Some(certificate.clone()),
            false,
            |saved| {
                *record.lock().unwrap() = Some(
                    serde_json::from_value::<SavedManager>(serde_json::to_value(saved).unwrap())
                        .unwrap(),
                );
                Ok(())
            },
        )
        .await
        .unwrap();
        assert_eq!(view.installation_id, "aaaaaaaaaaaa");
        let saved = record.lock().unwrap().take().unwrap();
        let status = send(&saved, &identity, Command::Status {}).await.unwrap();
        assert_eq!(status["installation"]["id"], "aaaaaaaaaaaa");
        reauthenticate(&saved, password.into()).await.unwrap();
        // Separate scenarios reset only this opt-in fixture's rate bucket, never production policy.
        let reset = std::process::Command::new(
            std::env::var_os("FRAMELEAF_TEST_NODE").expect("fixture Node"),
        )
        .arg(root.join("reset-rate.mjs"))
        .status()
        .unwrap();
        assert!(reset.success());
        let failed = std::sync::Mutex::new(String::new());
        assert_eq!(
            pair(
                &identity,
                origin,
                password.into(),
                Some(certificate),
                false,
                |value| {
                    *failed.lock().unwrap() = value.id.clone();
                    Err("credential_store_locked_or_unavailable".into())
                }
            )
            .await
            .err()
            .unwrap(),
            "credential_store_locked_or_unavailable"
        );
        let client = saved_client(&saved).unwrap();
        let session = login(&client, origin, password).await.unwrap();
        let list: Value = reply(
            client
                .get(format!("{origin}/manager-api/desktop-grants"))
                .header("cookie", &session.cookie)
                .send()
                .await
                .unwrap(),
        )
        .await
        .unwrap();
        assert!(!list["grants"]
            .as_array()
            .unwrap()
            .iter()
            .any(|grant| grant["id"].as_str() == Some(failed.lock().unwrap().as_str())));
        let _: Value = browser(&client, origin, &session, "logout", json!({}))
            .await
            .unwrap();
        disconnect(&saved, password.into()).await.unwrap();
        assert_eq!(
            send(&saved, &identity, Command::Status {})
                .await
                .unwrap_err(),
            "manager_pair_again"
        );
    });
}

#[test]
fn a_private_token_in_an_operation_error_never_reaches_the_webview() {
    let id = Uuid::new_v4();
    let operation = json!({"id":id,"kind":"stop","state":"failed","step":"stop","completed":[],"error":saved().token,"createdAt":1700000000000u64,"updatedAt":1700000000000u64});
    let reply = validate_reply(&saved(), &Command::Operation { id }, operation.clone()).unwrap();
    assert_eq!(reply["error"], "manager_operation_failed");
    let status = json!({"manager":{"id":saved().manager_id,"origin":saved().origin},"installation":{"id":saved().installation_id,"name":"Fixture","release":"frameleaf-v3.0.0-1","port":2283},"operations":[operation]});
    let reply = validate_reply(&saved(), &Command::Status {}, status).unwrap();
    assert!(!reply.to_string().contains(&saved().token));
}

#[test]
fn backup_review_commands_require_explicit_scope_and_bind_request_and_reply() {
    let request_id = Uuid::new_v4();
    let commands = [
        json!({"kind":"backups"}),
        json!({"kind":"review-restore","snapshot":"a".repeat(64),"key":request_id}),
        json!({"kind":"restore-review","id":request_id,"snapshot":"a".repeat(64)}),
    ];
    let mut owner = saved();
    for value in commands {
        let command: Command = serde_json::from_value(value).unwrap();
        assert_eq!(
            prepare(
                &owner,
                &identity(),
                &command,
                1700000000000,
                &Uuid::new_v4().to_string()
            )
            .err()
            .unwrap(),
            "manager_scope_denied"
        );
        owner.scopes.push(Scope::Restore);
        let request = prepare(
            &owner,
            &identity(),
            &command,
            1700000000000,
            &Uuid::new_v4().to_string(),
        )
        .unwrap();
        let body: Value = serde_json::from_slice(&request.body).unwrap();
        assert!(request.path.starts_with("/manager-api/desktop/"));
        assert!(body
            .get("snapshot")
            .is_none_or(|v| v == &json!("a".repeat(64))));
        owner.scopes.retain(|scope| *scope != Scope::Restore);
    }
    let command: Command = serde_json::from_value(
        json!({"kind":"review-restore","snapshot":"a".repeat(64),"key":request_id}),
    )
    .unwrap();
    let accepted = json!({"id":request_id,"snapshot":"a".repeat(64),"installationId":owner.installation_id,"state":"preparing"});
    assert!(validate_reply(&owner, &command, accepted.clone()).is_ok());
    let mut changed = accepted;
    changed["snapshot"] = json!("b".repeat(64));
    assert!(validate_reply(&owner, &command, changed).is_err());
    let command: Command = serde_json::from_value(
        json!({"kind":"restore-review","id":request_id,"snapshot":"a".repeat(64)}),
    )
    .unwrap();
    let status = json!({"id":request_id,"snapshot":"a".repeat(64),"installationId":owner.installation_id,"expires":1700000900000u64,"state":"prepared","libraryId":"a".repeat(12),"release":"frameleaf-v3.0.0-1","targetRelease":"frameleaf-v3.0.0-1","createdAt":1234,"mediaIncluded":false,"requiresRuntimeChange":false});
    assert!(validate_reply(&owner, &command, status.clone()).is_ok());
    for (key, value) in [
        ("mediaIncluded", json!(true)),
        ("installationId", json!("b".repeat(12))),
        ("privatePath", json!("/private/data")),
    ] {
        let mut changed = status.clone();
        changed[key] = value;
        assert!(validate_reply(&owner, &command, changed).is_err());
    }
}

#[test]
fn backup_list_rejects_malformed_or_private_metadata() {
    let entry = json!({"id":"a".repeat(64),"time":"2026-10-18T09:00:00Z"});
    assert!(validate_reply(&saved(), &Command::Backups {}, json!([entry.clone()])).is_ok());
    for (key, value) in [
        ("id", json!("short")),
        ("time", json!("invalid")),
        ("privatePath", json!("/private/data")),
    ] {
        let mut changed = entry.clone();
        changed[key] = value;
        assert!(validate_reply(&saved(), &Command::Backups {}, json!([changed])).is_err());
    }
    assert!(validate_reply(&saved(), &Command::Backups {}, json!(vec![entry; 1001])).is_err());
}

#[test]
fn recovery_pairing_accepts_only_the_explicitly_requested_permission_set() {
    let fixture: Value = serde_json::from_str(include_str!("manager_wire.json")).unwrap();
    let mut approval: Pairing = serde_json::from_value(fixture["pairing"].clone()).unwrap();
    approval.scopes.push(Scope::Restore);
    assert!(validate_pairing(
        &approval,
        &identity(),
        "https://manager.test:9443",
        1700000000000,
        &SCOPES
    )
    .is_err());
    let mut requested = SCOPES.to_vec();
    requested.push(Scope::Restore);
    assert!(validate_pairing(
        &approval,
        &identity(),
        "https://manager.test:9443",
        1700000000000,
        &requested
    )
    .is_ok());
    approval.scopes.push(Scope::Update);
    assert!(validate_pairing(
        &approval,
        &identity(),
        "https://manager.test:9443",
        1700000000000,
        &requested
    )
    .is_err());
}
