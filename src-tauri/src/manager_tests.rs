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
    assert!(manager_client(
        "https://manager.test:9443",
        Some("private data"),
        Some(&"a".repeat(64))
    )
    .is_err());
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
    assert!(manager_client("https://manager.test:9443", Some(pem), Some(hash)).is_ok());
    assert_eq!(
        manager_client(
            "https://manager.test:9443",
            Some(pem),
            Some(&"0".repeat(64))
        )
        .err()
        .unwrap(),
        "manager_certificate_approval_changed"
    );
    assert!(manager_client("https://manager.test:9443", Some(pem), None).is_err());
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
        "ftp://manager.test",
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
                .header("cookie", &session.credential)
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

#[test]
fn restore_execution_uses_explicit_scope_and_accepts_only_bound_public_restore_operations() {
    let id = Uuid::new_v4();
    let key = Uuid::new_v4();
    let mut owner = saved();
    for value in [
        json!({"kind":"restore","reviewId":id,"key":key}),
        json!({"kind":"restore-operation","id":id}),
        json!({"kind":"resume-restore","id":id}),
    ] {
        let command: Command = serde_json::from_value(value).unwrap();
        assert!(prepare(
            &owner,
            &identity(),
            &command,
            1700000000000,
            &Uuid::new_v4().to_string()
        )
        .is_err());
        owner.scopes.push(Scope::Restore);
        assert!(prepare(
            &owner,
            &identity(),
            &command,
            1700000000000,
            &Uuid::new_v4().to_string()
        )
        .is_ok());
        owner.scopes.retain(|v| *v != Scope::Restore);
    }
    let command: Command =
        serde_json::from_value(json!({"kind":"restore-operation","id":id})).unwrap();
    let operation = json!({"id":id,"kind":"restore","state":"running","step":"native-restore-verify","completed":vec!["native-backup-verified";40],"error":null,"createdAt":1,"updatedAt":2});
    assert!(validate_reply(&owner, &command, operation.clone()).is_ok());
    for (field, value) in [
        ("kind", json!("stop")),
        ("id", json!(key)),
        ("receipts", json!({"private":"secret"})),
        ("completed", json!(vec!["step"; 65])),
    ] {
        let mut changed = operation.clone();
        changed[field] = value;
        assert!(validate_reply(&owner, &command, changed).is_err());
    }
}

#[test]
fn manager_http_origins_preserve_validation_and_reject_certificate_pinning() {
    for origin in [
        "http://192.168.1.20:2282",
        "http://tower.local:2282",
        "https://manager.test:9443",
    ] {
        assert_eq!(canonical_origin(origin).unwrap(), origin);
        assert!(manager_client(origin, None, None).is_ok());
    }
    for origin in [
        "http://user:pass@tower.local",
        "http://tower.local/path",
        "http://tower.local?x=1",
        "http://tower.local#x",
        "http://tower.local\\path",
        "file:///tmp/manager",
    ] {
        assert!(normalize_manager(origin).is_err(), "{origin}");
    }
    for origin in ["http:tower.local:2282", "http:/tower.local:2282"] {
        assert_eq!(
            normalize_manager(origin)
                .unwrap()
                .origin()
                .ascii_serialization(),
            "http://tower.local:2282"
        );
    }
    assert!(crate::connection::normalize_server("http://tower.local").is_ok());
    assert!(manager_client(
        "http://tower.local",
        Some("certificate"),
        Some("fingerprint")
    )
    .is_err());
}

#[test]
fn manager_http_login_and_browser_calls_use_an_explicit_session_header() {
    use std::io::{Read, Write};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let server = std::thread::spawn(move || {
        for step in 0..3 {
            let (mut socket, _) = listener.accept().unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut request = [0; 4096];
            let length = socket.read(&mut request).unwrap();
            assert!(length > 0);
            if step == 1 {
                let headers = String::from_utf8_lossy(&request[..length]).to_lowercase();
                assert!(headers.contains(&format!(
                    "\r\nx-frameleaf-manager-session: {}\r\n",
                    "a".repeat(64)
                )));
                assert!(!headers.contains("\r\ncookie:"));
            }
            let body = json!({"csrf":"c".repeat(64)}).to_string();
            let credential = if step == 2 {
                format!(
                    "Set-Cookie: frameleaf-manager={}; Path=/; HttpOnly; SameSite=Strict",
                    "a".repeat(64)
                )
            } else {
                format!("X-Frameleaf-Manager-Session: {}", "a".repeat(64))
            };
            write!(socket, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n{}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", credential, body.len(), body).unwrap();
        }
    });
    tauri::async_runtime::block_on(async {
        let client = manager_client(&origin, None, None).unwrap();
        let session = login(&client, &origin, "synthetic password").await.unwrap();
        assert_eq!(session.credential, "a".repeat(64));
        browser::<Value>(&client, &origin, &session, "logout", json!({}))
            .await
            .unwrap();
        assert!(login(&client, &origin, "synthetic password").await.is_err());
    });
    server.join().unwrap();
}

/// Answers one local HTTP connection per raw response, then stops.
fn serve(responses: Vec<String>) -> (String, std::thread::JoinHandle<()>) {
    use std::io::{Read, Write};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let server = std::thread::spawn(move || {
        for response in responses {
            let (mut socket, _) = listener.accept().unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut request = [0; 4096];
            assert!(socket.read(&mut request).unwrap() > 0);
            // A client that stops at its size limit may close before the whole body is written.
            let _ = socket.write_all(response.as_bytes());
        }
    });
    (origin, server)
}
fn http(status: &str, headers: &str, body: &str) -> String {
    format!(
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\n{headers}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
}
async fn answer<T: DeserializeOwned>(response: String, limit: usize) -> Result<T, String> {
    let (origin, server) = serve(vec![response]);
    let received = manager_client(&origin, None, None)
        .unwrap()
        .post(&origin)
        .send()
        .await
        .unwrap();
    let result = reply_limit(received, limit).await;
    server.join().unwrap();
    result
}

#[test]
fn removing_a_pairing_clears_local_state_even_when_manager_is_unreachable() {
    let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let unreachable = format!("http://{}", closed.local_addr().unwrap());
    drop(closed);
    tauri::async_runtime::block_on(async {
        let forgotten = std::cell::Cell::new(0);
        let forget = || {
            forgotten.set(forgotten.get() + 1);
            Ok(())
        };
        let mut stale = saved();
        stale.origin = unreachable;
        assert_eq!(
            remove(Some(stale), "synthetic password".into(), forget).await,
            Ok(false)
        );
        // Without a password, or with a record that could not be read, removal stays local.
        assert_eq!(
            remove(Some(saved()), String::new(), forget).await,
            Ok(false)
        );
        assert_eq!(
            remove(None, "synthetic password".into(), forget).await,
            Ok(false)
        );
        assert_eq!(forgotten.get(), 3);

        let session = format!("X-Frameleaf-Manager-Session: {}\r\n", "a".repeat(64));
        let (origin, server) = serve(vec![
            http(
                "200 OK",
                &session,
                &json!({"csrf":"c".repeat(64)}).to_string(),
            ),
            http("200 OK", "", r#"{"revoked":true}"#),
            http("200 OK", "", "{}"),
        ]);
        let mut reachable = saved();
        reachable.origin = origin;
        assert_eq!(
            remove(Some(reachable), "synthetic password".into(), forget).await,
            Ok(true)
        );
        server.join().unwrap();
        assert_eq!(forgotten.get(), 4);

        // Only a credential store that cannot delete the record keeps the pairing.
        assert_eq!(
            remove(Some(saved()), String::new(), || Err(
                "credential_store_locked_or_unavailable".into()
            ))
            .await
            .unwrap_err(),
            "credential_store_locked_or_unavailable"
        );
    });
}

#[test]
fn pairing_requires_https_only_for_a_manager_beyond_the_home_network() {
    for origin in [
        "http://203.0.113.10",
        "http://203.0.113.10:2282",
        "http://manager.example.com:2282",
        "http://localhost.example.test",
        "http://[2001:db8::1]:2282",
    ] {
        assert_eq!(
            require_encrypted(origin).unwrap_err(),
            "manager_https_required",
            "{origin}"
        );
    }
    for origin in [
        "http://127.0.0.1",
        "http://127.0.0.1:2282",
        "http://[::1]:2282",
        "http://localhost:2282",
        // The home network: no certificate can be issued for these.
        "http://192.168.1.10",
        "http://192.168.1.10:2282",
        "http://10.0.0.5:2282",
        "http://172.16.4.2:2282",
        "http://169.254.10.20:2282",
        "http://100.100.20.30:2282",
        "http://tower.local:2282",
        "http://tower:2282",
        "http://nas.lan:2282",
        "http://nas.home.arpa:2282",
        "http://tower.tailnet.ts.net:2282",
        "http://[fd12:3456::1]:2282",
        "http://127.0.0.2:2282",
        "https://192.168.1.10",
        "https://manager.test:9443",
    ] {
        assert_eq!(require_encrypted(origin), Ok(()), "{origin}");
    }
    let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let loopback = format!("http://{}", closed.local_addr().unwrap());
    drop(closed);
    tauri::async_runtime::block_on(async {
        let attempt = |origin: String| async move {
            pair(
                &identity(),
                &origin,
                "synthetic password".into(),
                None,
                false,
                |_| panic!("nothing is saved"),
            )
            .await
            .err()
            .unwrap()
        };
        // Refused before any password leaves this computer.
        assert_eq!(
            attempt("http://203.0.113.10".into()).await,
            "manager_https_required"
        );
        assert_eq!(
            attempt(loopback).await,
            "manager_unreachable_or_certificate_invalid"
        );
    });
}

#[test]
fn an_unknown_operation_kind_does_not_hide_the_rest_of_the_status() {
    let saved = saved();
    let operation = |kind: &str| json!({"id":Uuid::new_v4(),"kind":kind,"state":"running","step":null,"completed":[],"error":null,"createdAt":1700000000000u64,"updatedAt":1700000000000u64});
    let status = json!({"manager":{"id":saved.manager_id,"origin":saved.origin},"installation":{"id":saved.installation_id,"name":"Fixture","release":"frameleaf-v3.0.0-1","port":2283},"operations":[operation("move-library"),operation("stop")]});
    let reply = validate_reply(&saved, &Command::Status {}, status).unwrap();
    assert_eq!(reply["operations"][0]["kind"], "other");
    assert_eq!(reply["operations"][1]["kind"], "stop");
    assert_eq!(reply["installation"]["name"], "Fixture");
}

#[test]
fn manager_error_codes_pass_through_without_private_text() {
    let id = Uuid::new_v4();
    let failed = |error: &str| {
        let operation = json!({"id":id,"kind":"backup","state":"failed","step":null,"completed":[],"error":error,"createdAt":1700000000000u64,"updatedAt":1700000000000u64});
        validate_reply(&saved(), &Command::Operation { id }, operation).unwrap()["error"].clone()
    };
    assert_eq!(failed("repository_locked"), "repository_locked");
    assert_eq!(failed("recovery_key_required"), "recovery_key_required");
    assert_eq!(failed(&"c".repeat(40)), "manager_operation_failed");
    tauri::async_runtime::block_on(async {
        let refused = |code: &str| {
            let body = json!({ "code": code }).to_string();
            async move {
                answer::<Value>(http("409 Conflict", "", &body), REPLY_LIMIT)
                    .await
                    .unwrap_err()
            }
        };
        assert_eq!(
            refused("desktop_operation_not_authorized").await,
            "desktop_operation_not_authorized"
        );
        assert_eq!(
            refused("operation_in_progress").await,
            "manager_operation_in_progress"
        );
        // Desktop's own codes drive its interface, and free text is never shown.
        for code in ["manager_device_changed", "Read /private/data failed", ""] {
            assert_eq!(refused(code).await, "manager_request_failed", "{code}");
        }
    });
}

#[test]
fn clock_skew_is_reported_as_clock_skew() {
    let fixture: Value = serde_json::from_str(include_str!("manager_wire.json")).unwrap();
    let approval: Pairing = serde_json::from_value(fixture["pairing"].clone()).unwrap();
    // The approval is valid from 1700000000000 for five minutes.
    for now in [1700000000000 - WINDOW - 1, 1700000300000] {
        assert_eq!(
            validate_pairing(
                &approval,
                &identity(),
                "https://manager.test:9443",
                now,
                &SCOPES
            )
            .unwrap_err(),
            "manager_clock_skew"
        );
    }
    let date = Some("Thu, 01 Jan 2015 00:00:00 GMT");
    assert!(clock_skewed(date, 1420070400000 + WINDOW));
    assert!(clock_skewed(date, 1420070400000 - WINDOW));
    assert!(!clock_skewed(date, 1420070400000 + 30_000));
    assert!(!clock_skewed(None, 1420070400000));
    tauri::async_runtime::block_on(async {
        let refused = |headers: &'static str| async move {
            let body = r#"{"code":"desktop_grant_invalid"}"#;
            answer::<Value>(http("401 Unauthorized", headers, body), REPLY_LIMIT)
                .await
                .unwrap_err()
        };
        assert_eq!(
            refused("Date: Thu, 01 Jan 2015 00:00:00 GMT\r\n").await,
            "manager_clock_skew"
        );
        assert_eq!(refused("").await, "manager_pair_again");
    });
}

#[test]
fn list_and_status_replies_may_exceed_the_small_reply_limit() {
    let body = json!("a".repeat(200_000)).to_string();
    tauri::async_runtime::block_on(async {
        assert_eq!(
            answer::<Value>(http("200 OK", "", &body), REPLY_LIMIT)
                .await
                .unwrap_err(),
            "manager_response_too_large"
        );
        assert!(answer::<Value>(http("200 OK", "", &body), LIST_LIMIT)
            .await
            .is_ok());
        let body = json!("a".repeat(LIST_LIMIT)).to_string();
        assert_eq!(
            answer::<Value>(http("200 OK", "", &body), LIST_LIMIT)
                .await
                .unwrap_err(),
            "manager_response_too_large"
        );
    });
}

#[test]
fn the_runtime_request_is_bound_to_its_nonce_and_never_comes_from_the_interface() {
    let nonce = uuid::Uuid::parse_str("66666666-6666-4666-8666-666666666666").unwrap();
    let prepared = prepare(
        &saved(),
        &identity(),
        &Command::Runtime { nonce },
        1700000000000,
        "55555555-5555-4555-8555-555555555555",
    )
    .unwrap();
    assert_eq!(prepared.path, "/manager-api/desktop/runtime");
    assert_eq!(
        serde_json::from_slice::<Value>(&prepared.body).unwrap(),
        json!({"nonce":"66666666-6666-4666-8666-666666666666"})
    );
    assert_eq!(
        prepare(
            &saved(),
            &identity(),
            &Command::Runtime {
                nonce: uuid::Uuid::nil()
            },
            1700000000000,
            "55555555-5555-4555-8555-555555555555",
        )
        .err()
        .unwrap(),
        "manager_request_invalid"
    );
    assert!(serde_json::from_value::<Command>(
        json!({"kind":"runtime","nonce":"66666666-6666-4666-8666-666666666666"})
    )
    .is_err());

    let command = Command::Runtime { nonce };
    let reply = |patch: &dyn Fn(&mut Value)| {
        let mut value = json!({
            "protocolVersion":1,"nonce":nonce.to_string(),"installationId":"aaaaaaaaaaaa",
            "capabilities":["runtime-status","ports","tls-rotation"],
            "ports":{"manager":9443,"api":2283,"database":54329},
            "photoServer":{"state":"running"}
        });
        patch(&mut value);
        validate_reply(&saved(), &command, value)
    };
    assert!(reply(&|_| {}).is_ok());
    // A later Manager may say more; what is read stays exact.
    assert!(reply(&|value| value["later"] = json!({"anything":true})).is_ok());
    assert!(reply(&|value| value["photoServer"] =
        json!({"state":"unknown","code":"native_database_maintenance"}))
    .is_ok());
    for patch in [
        (&|value: &mut Value| value["nonce"] = json!("77777777-7777-4777-8777-777777777777"))
            as &dyn Fn(&mut Value),
        &|value| value["installationId"] = json!("bbbbbbbbbbbb"),
        &|value| value["protocolVersion"] = json!(2),
        &|value| value["photoServer"]["state"] = json!("serving"),
        &|value| value["photoServer"] = json!({"state":"unknown","code":"A sentence, not a code."}),
        &|value| value["ports"]["api"] = json!(0),
        &|value| value["ports"]["api"] = json!(70000),
        &|value| {
            value.as_object_mut().unwrap().remove("photoServer");
        },
        &|value| {
            value.as_object_mut().unwrap().remove("ports");
        },
        &|value| {
            value.as_object_mut().unwrap().remove("nonce");
        },
        &|value| value["capabilities"] = json!("ports"),
    ] {
        assert_eq!(reply(patch).err().unwrap(), "manager_response_invalid");
    }
}

#[test]
fn a_saved_grant_follows_only_its_own_local_manager_to_a_new_port_or_certificate() {
    let fixture: Value = serde_json::from_str(include_str!("manager_wire.json")).unwrap();
    let pem = fixture["certificatePem"].as_str().unwrap();
    let mint = || {
        crate::manager_tls::TlsIdentity::load_or_create(
            "aaaaaaaaaaaa",
            "https://127.0.0.1:9443",
            || Ok(None),
            |_| Ok(()),
        )
        .unwrap()
        .certificate()
        .to_owned()
    };
    let (renewed, stranger) = (mint(), mint());
    let local = |origin: &str, certificate: Option<&str>| -> SavedManager {
        let mut value = serde_json::to_value(saved()).unwrap();
        value["origin"] = json!(origin);
        value["certificatePem"] = json!(certificate);
        serde_json::from_value(value).unwrap()
    };
    let default = "https://127.0.0.1:9443";
    // A moved port, same certificate.
    let mut grant = local(default, Some(pem));
    assert!(grant.follow_local("aaaaaaaaaaaa", "https://127.0.0.1:9444", pem, None));
    assert_eq!(grant.view().origin, "https://127.0.0.1:9444");
    assert_eq!(
        grant.view().certificate_sha256,
        Some(certificate_fingerprint(pem).unwrap())
    );
    // A renewed certificate, only when it replaced the pinned one.
    let mut grant = local(default, Some(pem));
    assert!(grant.follow_local("aaaaaaaaaaaa", default, &renewed, Some(pem)));
    assert_eq!(
        grant.view().certificate_sha256,
        Some(certificate_fingerprint(&renewed).unwrap())
    );
    // Already in step: nothing to write.
    assert!(!grant.follow_local("aaaaaaaaaaaa", default, &renewed, Some(pem)));
    assert!(!grant.follow_local("aaaaaaaaaaaa", default, &renewed, None));
    // Never: another installation, a certificate that did not replace the pinned one, a
    // grant with no pinned certificate, or an origin that is not this computer's loopback.
    for (mut grant, installation, origin, certificate, replaced) in [
        (
            local(default, Some(pem)),
            "bbbbbbbbbbbb",
            "https://127.0.0.1:9444",
            pem,
            None,
        ),
        (
            local(default, Some(pem)),
            "aaaaaaaaaaaa",
            default,
            renewed.as_str(),
            None,
        ),
        (
            local(default, Some(pem)),
            "aaaaaaaaaaaa",
            default,
            renewed.as_str(),
            Some(stranger.as_str()),
        ),
        (
            local(default, None),
            "aaaaaaaaaaaa",
            "https://127.0.0.1:9444",
            pem,
            None,
        ),
        (
            local("https://manager.test:9443", Some(pem)),
            "aaaaaaaaaaaa",
            "https://127.0.0.1:9444",
            pem,
            None,
        ),
        (
            local("https://192.168.1.20:9443", Some(pem)),
            "aaaaaaaaaaaa",
            "https://127.0.0.1:9443",
            pem,
            None,
        ),
        (
            local(default, Some(pem)),
            "aaaaaaaaaaaa",
            "https://[::1]:9443",
            pem,
            None,
        ),
        (
            local(default, Some(pem)),
            "aaaaaaaaaaaa",
            "http://127.0.0.1:9444",
            pem,
            None,
        ),
        (
            local(default, Some(pem)),
            "aaaaaaaaaaaa",
            "https://127.0.0.1:9444",
            "not a certificate",
            None,
        ),
    ] {
        let before = serde_json::to_value(&grant).unwrap();
        assert!(!grant.follow_local(installation, origin, certificate, replaced));
        assert_eq!(serde_json::to_value(&grant).unwrap(), before);
    }
}
