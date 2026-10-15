use frameleaf_desktop::ml_transport::ClaimedTask;
use frameleaf_desktop::worker::SavedWorker;
use sha2::{Digest, Sha256};

#[test]
fn accepts_only_current_scoped_hashed_tasks_and_bounded_input() {
    let saved = SavedWorker {
        server_id: "server".into(),
        account_id: "account".into(),
        device_id: "445bc2b6-f4cd-439e-b8bb-7e84d7ee0550".into(),
        session_id: "1117c1ca-0495-46e9-b579-f321520c2b1a".into(),
        authorization_epoch: 2,
        worker_token: "a".repeat(64),
        expires_at: "2026-10-15T21:00:00Z".into(),
        next_sequence: 1,
    };
    let mut task: ClaimedTask=serde_json::from_value(serde_json::json!({"id":"d621bd72-ad35-4199-95ab-76300756a38e","taskId":"c39d4385-84f8-4c37-a643-1b98fc12df93","deviceId":saved.device_id,"sessionId":saved.session_id,"authorizationEpoch":2,"generation":1,"modelKey":"approved","configJson":"{\"model\":\"été\"}","configSha256":format!("{:x}",Sha256::digest("{\"model\":\"été\"}".as_bytes())),"inputSha256":format!("{:x}",Sha256::digest(b"input")),"inputKind":"text","maxInputBytes":16_777_216,"expiresAt":"2026-10-15T20:01:00Z","executionDeadline":"2026-10-15T20:03:00Z"})).unwrap();
    let now = 1_792_094_400_000i64;
    assert!(task.validate_at(&saved, &["approved".into()], now).is_ok());
    assert!(task.validate_at(&saved, &["other".into()], now).is_err());
    assert!(task
        .validate_at(&saved, &["approved".into()], now + 120_000)
        .is_err());
    assert!(task
        .validate_result_at(&saved, &["approved".into()], now + 120_000)
        .is_ok());
    assert!(task
        .validate_result_at(&saved, &["approved".into()], now + 600_000)
        .is_err());
    assert!(task.verify_input(b"input").is_ok());
    assert!(task.verify_input(b"changed").is_err());
    task.config_json.push(' ');
    assert!(task.validate_at(&saved, &["approved".into()], now).is_err());
    task.config_json.pop();
    task.authorization_epoch = 3;
    assert!(task.validate_at(&saved, &["approved".into()], now).is_err());
    task.authorization_epoch = 2;
    task.session_id = saved.device_id.clone();
    assert!(task.validate_at(&saved, &["approved".into()], now).is_err());
    task.session_id = saved.session_id.clone();
    task.max_input_bytes = 16_777_217;
    assert!(task.validate_at(&saved, &["approved".into()], now).is_err());
    task.max_input_bytes = 16_777_216;
    assert!(task
        .validate_at(&saved, &["approved".into()], now + 600_000)
        .is_err());
}

#[test]
fn applies_server_renewal_without_extending_past_the_execution_deadline() {
    let mut task: ClaimedTask = serde_json::from_value(serde_json::json!({"id":"d621bd72-ad35-4199-95ab-76300756a38e","taskId":"c39d4385-84f8-4c37-a643-1b98fc12df93","deviceId":"445bc2b6-f4cd-439e-b8bb-7e84d7ee0550","sessionId":"1117c1ca-0495-46e9-b579-f321520c2b1a","authorizationEpoch":2,"generation":1,"modelKey":"approved","configJson":"{}","configSha256":"a".repeat(64),"inputSha256":"b".repeat(64),"inputKind":"image","maxInputBytes":1024,"expiresAt":"2026-10-15T20:01:00Z","executionDeadline":"2026-10-15T20:03:00Z"})).unwrap();
    assert!(task
        .renew_lease("2026-10-15T20:02:59Z", 1_792_094_450_000)
        .is_ok());
    assert_eq!(task.expires_at, "2026-10-15T20:02:59Z");
    assert!(task
        .renew_lease("2026-10-15T20:03:01Z", 1_792_094_450_000)
        .is_err());
    assert_eq!(task.expires_at, "2026-10-15T20:02:59Z");
}
