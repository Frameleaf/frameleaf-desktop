use super::*;
#[test]
fn resource_location_is_exactly_one_same_origin_upload_uuid() {
    let base = url::Url::parse("https://nas.test:2283/").unwrap();
    let id = "11111111-1111-4111-8111-111111111111";
    assert_eq!(
        resource_id(&base, &format!("/api/assets/uploads/{id}")).unwrap(),
        id
    );
    assert_eq!(
        resource_id(
            &base,
            &format!("https://nas.test:2283/api/assets/uploads/{id}")
        )
        .unwrap(),
        id
    );
    for bad in [
        format!("https://evil.test/api/assets/uploads/{id}"),
        format!("http://nas.test:2283/api/assets/uploads/{id}"),
        format!("https://nas.test/api/assets/uploads/{id}"),
        format!("//evil.test/api/assets/uploads/{id}"),
        format!("/api/assets/uploads/{id}?token=secret"),
        format!("/api/assets/uploads/{id}#x"),
        format!("/api/assets/uploads/{id}/result"),
        format!("/api/assets/uploads/%31{id}"),
        format!("/api/assets/../assets/uploads/{id}"),
        format!("https://user@nas.test:2283/api/assets/uploads/{id}"),
        format!("/api/assets/uploads/{id}\\evil"),
    ] {
        assert!(resource_id(&base, &bad).is_err(), "accepted {bad}");
    }
}

use crate::{
    connection::{DeviceIdentity, SavedConnection},
    copy_source::CopyApproval,
};
use std::{
    collections::VecDeque,
    io::{Read, Write},
    net::TcpListener,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread,
    time::{Duration, Instant},
};
const RESOURCE: &str = "11111111-1111-4111-8111-111111111111";
type CapturedRequests = Vec<(String, Vec<u8>)>;
pub(crate) struct Server {
    pub(crate) base: url::Url,
    pub(crate) requests: Arc<Mutex<CapturedRequests>>,
    stop: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
}
impl Server {
    pub(crate) fn new(replies: Vec<String>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let base = url::Url::parse(&format!("http://{}/", listener.local_addr().unwrap())).unwrap();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let captured = requests.clone();
        let stop = Arc::new(AtomicBool::new(false));
        let stopped = stop.clone();
        let handle = thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(15);
            let mut replies: VecDeque<_> = replies.into();
            while !stopped.load(Ordering::Acquire) && Instant::now() < deadline {
                let Ok((mut socket, _)) = listener.accept() else {
                    thread::sleep(Duration::from_millis(5));
                    continue;
                };
                socket.set_nonblocking(false).unwrap();
                socket
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                let mut headers = Vec::new();
                while !headers.ends_with(b"\r\n\r\n") {
                    let mut byte = [0];
                    if socket.read_exact(&mut byte).is_err() {
                        return;
                    }
                    headers.push(byte[0]);
                    assert!(headers.len() < 16384);
                }
                let headers = String::from_utf8(headers).unwrap();
                let length = headers
                    .lines()
                    .find_map(|line| {
                        line.to_lowercase()
                            .strip_prefix("content-length: ")
                            .map(str::to_string)
                    })
                    .map(|x| x.parse::<usize>().unwrap())
                    .unwrap_or(0);
                let mut body = vec![0; length];
                socket.read_exact(&mut body).unwrap();
                captured.lock().unwrap().push((headers, body));
                let response = replies.pop_front().expect("unexpected HTTP request");
                socket.write_all(response.as_bytes()).unwrap();
            }
        });
        Self {
            base,
            requests,
            stop,
            handle: Some(handle),
        }
    }
}
impl Drop for Server {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        self.handle.take().unwrap().join().unwrap();
    }
}
fn reply(status: u16, headers: &str, body: &str) -> String {
    format!(
        "HTTP/1.1 {status} Test\r\nConnection: close\r\nContent-Length: {}\r\n{headers}\r\n{body}",
        body.len()
    )
}
pub(crate) fn protocol(status: u16, extra: &str, body: &str) -> String {
    reply(
        status,
        &format!("Upload-Draft-Interop-Version: 9\r\n{extra}"),
        body,
    )
}
pub(crate) fn preflight() -> Vec<String> {
    vec![
        reply(
            200,
            "Content-Type: application/json\r\n",
            r#"{"protocolVersion":1,"serverId":"nas","features":{"enrollment":true,"worker":true,"sources":false,"nativeHost":false}}"#,
        ),
        reply(
            200,
            "Content-Type: application/json\r\n",
            r#"{"id":"owner"}"#,
        ),
        protocol(
            204,
            "Upload-Limit: max-size=100000, max-append-size=4, max-age=86400, min-size=1\r\n",
            "",
        ),
    ]
}
struct Fixture {
    root: std::path::PathBuf,
    saved: SavedConnection,
    identity: DeviceIdentity,
    copy: crate::copy_source::StagedCopy,
}
impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!("frameleaf-upload-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(root.join("source")).unwrap();
        std::fs::create_dir(root.join("stage")).unwrap();
        let root = std::fs::canonicalize(root).unwrap();
        std::fs::write(root.join("source/旅行.jpg"), b"abcdefghij").unwrap();
        let saved = SavedConnection {
            server: "https://nas.test/".into(),
            server_id: "nas".into(),
            account_id: "owner".into(),
            name: "Fixture".into(),
            token: "synthetic-token".into(),
            device_name: "Fixture".into(),
            mode: "client-worker".into(),
            device_id: Some("device".into()),
        };
        let identity = DeviceIdentity::generate();
        let copy = CopyApproval::approve(&saved, &identity, &root.join("source"), 1024, true)
            .unwrap()
            .stage(
                &saved,
                &identity,
                "旅行.jpg",
                &root.join("stage"),
                &AtomicBool::new(false),
            )
            .unwrap();
        Self {
            root,
            saved,
            identity,
            copy,
        }
    }
    fn binding(&self) -> FolderUploadBinding {
        FolderUploadBinding::new(
            &self.copy,
            "22222222-2222-4222-8222-222222222222",
            "33333333-3333-4333-8333-333333333333",
        )
        .unwrap()
    }
    async fn run(
        &self,
        server: &Server,
        journal: &mut Option<UploadSession>,
        mut persist: impl FnMut(&UploadSession) -> Result<(), String>,
    ) -> Result<UploadOutcome, String> {
        transfer(
            &crate::transport::client().unwrap(),
            &server.base,
            &self.saved,
            &self.identity,
            &self.copy,
            &self.binding(),
            &self.root.join("stage"),
            journal,
            |session, _| persist(session),
            &AtomicBool::new(false),
            &|| Ok(()),
        )
        .await
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}
#[test]
fn transfers_staged_bytes_with_signed_restart_and_strict_result_validation() {
    tauri::async_runtime::block_on(async {
        let fixture = Fixture::new();
        let mut responses = preflight();
        responses.push(protocol(201,&format!("Location: /api/assets/uploads/{RESOURCE}\r\nUpload-Offset: 0\r\nUpload-Complete: ?0\r\n"),""));
        for offset in [4, 8, 10] {
            responses.push(protocol(
                204,
                &format!("Upload-Offset: {offset}\r\nUpload-Complete: ?0\r\n"),
                "",
            ));
        }
        responses.push(protocol(
            200,
            "",
            &format!(
                r#"{{"id":"{RESOURCE}","status":"created","sha256":"{}"}}"#,
                fixture.copy.sha256
            ),
        ));
        let server = Server::new(responses);
        let mut journal = None;
        let mut checkpoints = 0;
        let result = fixture
            .run(&server, &mut journal, |session| {
                checkpoints += 1;
                assert!(!serde_json::to_string(session)
                    .unwrap()
                    .contains("synthetic-token"));
                Ok(())
            })
            .await
            .unwrap();
        assert!(matches!(result, UploadOutcome::Ingested { .. }));
        assert!(checkpoints >= 1);
        let requests = server.requests.lock().unwrap().clone();
        assert_eq!(requests.len(), 8);
        assert!(requests[3].0.starts_with("POST /api/assets/uploads "));
        assert!(requests[3].1.is_empty());
        let metadata = requests[3]
            .0
            .lines()
            .find_map(|x| x.strip_prefix("asset-metadata: "))
            .unwrap();
        let value: serde_json::Value = serde_json::from_slice(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(metadata)
                .unwrap(),
        )
        .unwrap();
        assert_eq!(value["filename"], "旅行.jpg");
        assert_eq!(
            value["sourceIdentity"],
            serde_json::to_value(fixture.binding()).unwrap()
        );
        let sent: Vec<_> = requests
            .iter()
            .filter(|(h, _)| h.starts_with("PATCH "))
            .flat_map(|(_, b)| b.clone())
            .collect();
        assert_eq!(sent, b"abcdefghij");
        assert!(requests[6].0.contains("upload-complete: ?1"));
        drop(requests);
        drop(server);
        let serialized = serde_json::to_vec(&journal).unwrap();
        let mut restored = serde_json::from_slice(&serialized).unwrap();
        let mut responses = preflight();
        responses.push(protocol(
            204,
            "Upload-Offset: 10\r\nUpload-Complete: ?1\r\n",
            "",
        ));
        responses.push(protocol(
            200,
            "",
            &format!(
                r#"{{"id":"{RESOURCE}","status":"duplicate","sha256":"{}"}}"#,
                fixture.copy.sha256
            ),
        ));
        let server = Server::new(responses);
        assert!(matches!(
            fixture
                .run(&server, &mut restored, |_| Ok(()))
                .await
                .unwrap(),
            UploadOutcome::Ingested { .. }
        ));
        assert!(!server
            .requests
            .lock()
            .unwrap()
            .iter()
            .any(|(h, _)| h.starts_with("POST ") || h.starts_with("PATCH ")));
    });
}
#[test]
fn cannot_append_without_durable_checkpoint_or_after_account_change() {
    tauri::async_runtime::block_on(async {
        let mut fixture = Fixture::new();
        let mut responses = preflight();
        responses.push(protocol(201,&format!("Location: /api/assets/uploads/{RESOURCE}\r\nUpload-Offset: 0\r\nUpload-Complete: ?0\r\n"),""));
        let server = Server::new(responses);
        let mut journal = None;
        assert_eq!(
            fixture
                .run(&server, &mut journal, |_| Err("disk_full".into()))
                .await
                .err()
                .as_deref(),
            Some("disk_full")
        );
        assert_eq!(server.requests.lock().unwrap().len(), 4);
        drop(server);
        fixture.saved.account_id = "another".into();
        let server = Server::new(vec![]);
        assert!(fixture
            .run(&server, &mut journal, |_| Ok(()))
            .await
            .is_err());
        assert!(server.requests.lock().unwrap().is_empty());
    });
}
#[test]
fn resume_uses_server_offset_after_interrupted_append_and_never_recreates() {
    tauri::async_runtime::block_on(async {
        let fixture = Fixture::new();
        let mut responses = preflight();
        responses.push(protocol(201,&format!("Location: /api/assets/uploads/{RESOURCE}\r\nUpload-Offset: 0\r\nUpload-Complete: ?0\r\n"),""));
        responses.push(protocol(
            409,
            "Upload-Offset: 4\r\nUpload-Complete: ?0\r\n",
            "",
        ));
        let server = Server::new(responses);
        let mut journal = None;
        assert!(fixture
            .run(&server, &mut journal, |_| Ok(()))
            .await
            .is_err());
        drop(server);
        let mut responses = preflight();
        responses.push(protocol(
            204,
            "Upload-Offset: 4\r\nUpload-Complete: ?0\r\n",
            "",
        ));
        responses.push(protocol(
            204,
            "Upload-Offset: 8\r\nUpload-Complete: ?0\r\n",
            "",
        ));
        responses.push(protocol(
            202,
            "Upload-Offset: 10\r\nUpload-Complete: ?0\r\n",
            "",
        ));
        responses.push(protocol(202, "", ""));
        let server = Server::new(responses);
        assert!(matches!(
            fixture
                .run(&server, &mut journal, |_| Ok(()))
                .await
                .unwrap(),
            UploadOutcome::Pending
        ));
        let requests = server.requests.lock().unwrap().clone();
        assert_eq!(requests[4].1, b"efgh");
        assert_eq!(requests[5].1, b"ij");
        assert!(!requests.iter().any(|(h, _)| h.starts_with("POST ")));
    });
}

#[test]
fn live_identity_mismatch_and_redirects_stop_before_filename_disclosure() {
    tauri::async_runtime::block_on(async {
        let fixture = Fixture::new();
        for (responses, count) in [
            (
                vec![reply(
                    200,
                    "Content-Type: application/json\r\n",
                    r#"{"protocolVersion":1,"serverId":"replacement","features":{"enrollment":false,"worker":false,"sources":false,"nativeHost":false}}"#,
                )],
                1,
            ),
            (
                vec![
                    preflight()[0].clone(),
                    reply(
                        200,
                        "Content-Type: application/json\r\n",
                        r#"{"id":"other-account"}"#,
                    ),
                ],
                2,
            ),
            (vec![reply(307, "Location: https://evil.test/\r\n", "")], 1),
        ] {
            let server = Server::new(responses);
            let mut journal = None;
            assert!(fixture
                .run(&server, &mut journal, |_| Ok(()))
                .await
                .is_err());
            let requests = server.requests.lock().unwrap().clone();
            assert_eq!(requests.len(), count);
            assert!(requests
                .iter()
                .all(|(headers, bytes)| !headers.contains("asset-metadata") && bytes.is_empty()));
        }
    });
}
#[test]
fn tampered_session_and_mismatched_digest_are_never_accepted() {
    tauri::async_runtime::block_on(async {
        let fixture = Fixture::new();
        let session = UploadSession {
            resource_id: RESOURCE.into(),
            stage_id: fixture.copy.id.clone(),
            binding: fixture.binding(),
            signature: session_signature(
                &fixture.saved,
                &fixture.identity,
                &fixture.copy,
                RESOURCE,
                &fixture.binding(),
            )
            .unwrap(),
        };
        let mut forged = serde_json::to_value(&session).unwrap();
        forged["resourceId"] = serde_json::json!("22222222-2222-4222-8222-222222222222");
        let mut journal = Some(serde_json::from_value(forged).unwrap());
        let server = Server::new(vec![]);
        assert_eq!(
            fixture
                .run(&server, &mut journal, |_| Ok(()))
                .await
                .err()
                .as_deref(),
            Some("source_upload_journal_invalid")
        );
        assert!(server.requests.lock().unwrap().is_empty());
        drop(server);
        let mut responses = preflight();
        responses.push(protocol(
            204,
            "Upload-Offset: 10\r\nUpload-Complete: ?1\r\n",
            "",
        ));
        responses.push(protocol(
            200,
            "",
            &format!(
                r#"{{"id":"{RESOURCE}","status":"created","sha256":"{}"}}"#,
                "0".repeat(64)
            ),
        ));
        let server = Server::new(responses);
        let mut journal = Some(session);
        assert_eq!(
            fixture
                .run(&server, &mut journal, |_| Ok(()))
                .await
                .err()
                .as_deref(),
            Some("source_upload_receipt_invalid")
        );
    });
}
#[test]
fn invalid_server_offsets_and_capacity_never_send_bytes() {
    tauri::async_runtime::block_on(async {
        let fixture = Fixture::new();
        for extra in [
            "Upload-Offset: 11\r\nUpload-Complete: ?0\r\n",
            "Upload-Offset: 01\r\nUpload-Complete: ?0\r\n",
            "Upload-Offset: 4\r\nUpload-Complete: ?1\r\n",
            "Upload-Offset: 0\r\nUpload-Offset: 4\r\nUpload-Complete: ?0\r\n",
        ] {
            let mut journal = Some(UploadSession {
                resource_id: RESOURCE.into(),
                stage_id: fixture.copy.id.clone(),
                binding: fixture.binding(),
                signature: session_signature(
                    &fixture.saved,
                    &fixture.identity,
                    &fixture.copy,
                    RESOURCE,
                    &fixture.binding(),
                )
                .unwrap(),
            });
            let mut responses = preflight();
            responses.push(protocol(204, extra, ""));
            let server = Server::new(responses);
            let error = fixture
                .run(&server, &mut journal, |_| Ok(()))
                .await
                .unwrap_err();
            assert_eq!(
                server.requests.lock().unwrap().len(),
                4,
                "{extra:?}: {error}"
            );
        }
        let mut responses = preflight();
        responses[2] = protocol(204, "Upload-Limit: max-size=9, max-append-size=4\r\n", "");
        let server = Server::new(responses);
        assert_eq!(
            fixture
                .run(&server, &mut None, |_| Ok(()))
                .await
                .err()
                .as_deref(),
            Some("source_upload_capacity_exceeded")
        );
        assert_eq!(server.requests.lock().unwrap().len(), 3);
    });
}
#[test]
fn cancellation_aborts_an_inflight_request_without_waiting_for_network_timeout() {
    tauri::async_runtime::block_on(async {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let cancelled = Arc::new(AtomicBool::new(false));
        let cancel = cancelled.clone();
        let handle = thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut bytes = Vec::new();
            while !bytes.ends_with(b"\r\n\r\n") {
                let mut byte = [0];
                socket.read_exact(&mut byte).unwrap();
                bytes.push(byte[0]);
            }
            cancel.store(true, Ordering::Release);
            thread::sleep(Duration::from_millis(250));
        });
        let now = Instant::now();
        assert_eq!(
            send(
                crate::transport::client()
                    .unwrap()
                    .get(format!("http://{address}/")),
                &cancelled
            )
            .await
            .err()
            .as_deref(),
            Some("source_copy_cancelled")
        );
        assert!(now.elapsed() < Duration::from_secs(2));
        handle.join().unwrap();
    });
}

#[test]
fn a_resume_journal_cannot_be_rebound_to_a_different_source_run_or_item() {
    tauri::async_runtime::block_on(async {
        let fixture = Fixture::new();
        let session = UploadSession {
            resource_id: RESOURCE.into(),
            stage_id: fixture.copy.id.clone(),
            binding: fixture.binding(),
            signature: session_signature(
                &fixture.saved,
                &fixture.identity,
                &fixture.copy,
                RESOURCE,
                &fixture.binding(),
            )
            .unwrap(),
        };
        for field in ["sourceId", "runId", "itemId", "kind"] {
            let mut forged = serde_json::to_value(&session).unwrap();
            forged["binding"][field] = serde_json::json!("44444444-4444-4444-8444-444444444444");
            let mut journal = Some(serde_json::from_value(forged).unwrap());
            let server = Server::new(vec![]);
            assert_eq!(
                fixture
                    .run(&server, &mut journal, |_| Ok(()))
                    .await
                    .err()
                    .as_deref(),
                Some("source_upload_journal_invalid")
            );
            assert!(server.requests.lock().unwrap().is_empty());
        }
        let mut legacy = serde_json::to_value(&session).unwrap();
        legacy.as_object_mut().unwrap().remove("binding");
        assert!(serde_json::from_value::<UploadSession>(legacy).is_err());
        assert!(FolderUploadBinding::new(&fixture.copy, "invalid", RESOURCE).is_err());
    });
}
