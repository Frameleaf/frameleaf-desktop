use base64::{engine::general_purpose::STANDARD, Engine};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use frameleaf_desktop::{
    connection::DeviceIdentity,
    worker::{session_request, worker_message, WorkerProof},
};

fn identity() -> DeviceIdentity {
    serde_json::from_value(serde_json::json!({"installation_id":"fixture", "secret":vec![7u8;32]}))
        .unwrap()
}
#[test]
fn session_signature_binds_server_account_and_device() {
    let identity = identity();
    let request = session_request(&identity, "server", "account", "device").unwrap();
    let enrollment = identity
        .enrollment("server", "account", "Fixture", "client-worker")
        .unwrap();
    let key = VerifyingKey::from_bytes(
        &STANDARD
            .decode(enrollment.public_key)
            .unwrap()
            .try_into()
            .unwrap(),
    )
    .unwrap();
    let signature = Signature::from_slice(&STANDARD.decode(&request.signature).unwrap()).unwrap();
    let message = format!(
        "frameleaf-desktop/session/v1\nserver\naccount\ndevice\n{}\n{}",
        request.request_id, request.timestamp
    );
    assert!(key.verify(message.as_bytes(), &signature).is_ok());
    assert!(key
        .verify(message.replace("account", "other").as_bytes(), &signature)
        .is_err());
}
#[test]
fn request_message_uses_utf8_sha256_and_binds_every_authority_field() {
    let proof = WorkerProof {
        session_id: "session".into(),
        sequence: 2,
        timestamp: 100,
        signature: String::new(),
    };
    let message = worker_message("server", 3, "token", &proof, "claim", "{\"name\":\"été\"}");
    assert_eq!(message, "frameleaf-desktop/request/v1\nserver\nsession\n3\n2\n100\nclaim\n8c30d66008a6ca268ddecf90c9bd57efe675508f1121bfe0fa49d6a22b8f0f14\n3c469e9d6c5875d37a43f353d4f88e61fcf812c66eee3457465a40b0da4153e0");
}

#[test]
fn reserves_request_counter_durably_before_exposing_a_signed_request() {
    use frameleaf_desktop::worker::{reserve_proof, SavedWorker};
    let mut worker = SavedWorker {
        server_id: "server".into(),
        account_id: "account".into(),
        device_id: "device".into(),
        session_id: "session".into(),
        authorization_epoch: 3,
        worker_token: "a".repeat(64),
        expires_at: "2026-10-15T20:00:00Z".into(),
        next_sequence: 1,
    };
    let identity = identity();
    assert!(
        reserve_proof(&mut worker, &identity, "claim", "{}", |_| Err(
            "locked".into()
        ))
        .is_err()
    );
    assert_eq!(worker.next_sequence, 1);
    let proof = reserve_proof(&mut worker, &identity, "claim", "{}", |saved| {
        assert_eq!(saved.next_sequence, 2);
        Ok(())
    })
    .unwrap();
    assert_eq!(proof.sequence, 1);
    assert_eq!(worker.next_sequence, 2);
    worker.next_sequence = 2_147_483_648;
    assert!(
        reserve_proof(&mut worker, &identity, "claim", "{}", |_| panic!(
            "must not persist invalid counter"
        ))
        .is_err()
    );
}

#[test]
fn worker_session_response_is_bound_locally_and_cannot_expand_scope() {
    use frameleaf_desktop::connection::SavedConnection;
    use frameleaf_desktop::worker::{bind_session, SessionResponse};
    let saved = SavedConnection {
        server: "https://nas.example/".into(),
        server_id: "server".into(),
        account_id: "account".into(),
        name: "Fixture".into(),
        token: "photo-token".into(),
        device_name: "Fixture".into(),
        mode: "client-worker".into(),
        device_id: Some("445bc2b6-f4cd-439e-b8bb-7e84d7ee0550".into()),
    };
    let mut response: SessionResponse = serde_json::from_value(serde_json::json!({"sessionId":"1117c1ca-0495-46e9-b579-f321520c2b1a", "authorizationEpoch":3, "workerToken":"a".repeat(64), "expiresAt":"2026-10-15T20:00:00Z", "scopes":["library-inference"], "modelKeys":[]})).unwrap();
    let bound = bind_session(&saved, &response).unwrap();
    assert_eq!(bound.server_id, "server");
    assert_eq!(bound.account_id, "account");
    assert_eq!(bound.device_id, saved.device_id.as_ref().unwrap().as_str());
    assert_eq!(bound.next_sequence, 1);
    response.scopes.push("admin".into());
    assert!(bind_session(&saved, &response).is_err());
    response.scopes.pop();
    response.worker_token = "photo-token".into();
    assert!(bind_session(&saved, &response).is_err());
}
