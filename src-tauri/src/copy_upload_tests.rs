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
        let mut replies: VecDeque<_> = replies.into();
        Self::handle(move |_, _| replies.pop_front().expect("unexpected HTTP request"))
    }
    /// Answers each request from its headers and body, for parallel parts that arrive in any order.
    pub(crate) fn handle(mut reply: impl FnMut(&str, &[u8]) -> String + Send + 'static) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let base = url::Url::parse(&format!("http://{}/", listener.local_addr().unwrap())).unwrap();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let captured = requests.clone();
        let stop = Arc::new(AtomicBool::new(false));
        let stopped = stop.clone();
        let handle = thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(15);
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
                        break;
                    }
                    headers.push(byte[0]);
                    assert!(headers.len() < 16384);
                }
                // A request the client abandoned (a dropped part) is skipped, not answered.
                if !headers.ends_with(b"\r\n\r\n") {
                    continue;
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
                // A client that abandons a part mid-body is not a fixture failure.
                if socket.read_exact(&mut body).is_err() {
                    continue;
                }
                let response = reply(&headers, &body);
                captured.lock().unwrap().push((headers, body));
                let _ = socket.write_all(response.as_bytes());
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
        let joined = self.handle.take().unwrap().join();
        // A server-thread panic fails the test, but never as a second panic while one unwinds:
        // that aborts the whole test binary (0xc0000409 on Windows) and hides the first failure.
        if !thread::panicking() {
            joined.unwrap();
        }
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

fn parts_options() -> String {
    protocol(
        204,
        "Upload-Limit: max-size=100000, max-append-size=4, max-age=86400, min-size=1\r\nUpload-Parts: max-parallel=6\r\n",
        "",
    )
}
fn header_value<'a>(headers: &'a str, name: &str) -> Option<&'a str> {
    headers
        .lines()
        .find_map(|line| line.strip_prefix(&format!("{name}: ")))
}
/// A parts-capable server: preflight, create, a parts listing, then `on_part` for each PUT.
fn parts_server(
    create: bool,
    mut listing: impl FnMut() -> String + Send + 'static,
    mut on_part: impl FnMut(u64, &[u8]) -> String + Send + 'static,
    result: String,
) -> Server {
    let mut preflight: VecDeque<_> = preflight().into();
    preflight.pop_back();
    preflight.push_back(parts_options());
    if create {
        preflight.push_back(protocol(201,&format!("Location: /api/assets/uploads/{RESOURCE}\r\nUpload-Offset: 0\r\nUpload-Complete: ?0\r\n"),""));
    }
    Server::handle(move |headers, body| {
        let line = headers.lines().next().unwrap();
        if line.starts_with(&format!("GET /api/assets/uploads/{RESOURCE}/parts ")) {
            protocol(200, "Content-Type: application/json\r\n", &listing())
        } else if line.starts_with(&format!("PUT /api/assets/uploads/{RESOURCE}/parts ")) {
            assert_eq!(
                header_value(headers, "content-type"),
                Some("application/octet-stream")
            );
            assert_eq!(
                header_value(headers, "content-length")
                    .unwrap()
                    .parse::<usize>()
                    .unwrap(),
                body.len()
            );
            on_part(
                header_value(headers, "upload-offset")
                    .unwrap()
                    .parse()
                    .unwrap(),
                body,
            )
        } else if line.starts_with(&format!("GET /api/assets/uploads/{RESOURCE}/result ")) {
            result.clone()
        } else {
            assert!(
                !line.starts_with("PATCH ") && !line.starts_with("HEAD "),
                "{line}"
            );
            preflight
                .pop_front()
                .unwrap_or_else(|| panic!("unexpected {line}"))
        }
    })
}
fn parts_received(server: &Server) -> Vec<(u64, Vec<u8>)> {
    let mut parts: Vec<_> = server
        .requests
        .lock()
        .unwrap()
        .iter()
        .filter(|(h, _)| h.starts_with("PUT "))
        .map(|(h, b)| {
            (
                header_value(h, "upload-offset").unwrap().parse().unwrap(),
                b.clone(),
            )
        })
        .collect();
    parts.sort();
    parts
}
fn result_json(copy: &crate::copy_source::StagedCopy) -> String {
    protocol(
        200,
        "Content-Type: application/json\r\n",
        &format!(
            r#"{{"id":"{RESOURCE}","status":"created","sha256":"{}"}}"#,
            copy.sha256
        ),
    )
}
#[test]
fn parallel_parts_cover_the_file_and_the_completing_part_carries_the_result() {
    tauri::async_runtime::block_on(async {
        let fixture = Fixture::new();
        let mut received = 0;
        let done = result_json(&fixture.copy);
        let server = parts_server(
            true,
            move || r#"{"offset":0,"size":10,"parts":[]}"#.to_string(),
            move |_, body| {
                received += body.len();
                if received == 10 {
                    done.clone()
                } else {
                    protocol(204, "Upload-Offset: 0\r\nUpload-Complete: ?0\r\n", "")
                }
            },
            String::new(),
        );
        let mut journal = None;
        let mut admitted = 0;
        let outcome = transfer(
            &crate::transport::client().unwrap(),
            &server.base,
            &fixture.saved,
            &fixture.identity,
            &fixture.copy,
            &fixture.binding(),
            &fixture.root.join("stage"),
            &mut journal,
            |_, bytes| {
                admitted += bytes;
                Ok(())
            },
            &AtomicBool::new(false),
            &|| Ok(()),
        )
        .await
        .unwrap();
        assert!(matches!(
            outcome,
            UploadOutcome::Ingested {
                duplicate: false,
                ..
            }
        ));
        assert_eq!(admitted, 10);
        // max-append-size=4 caps the 256 MiB Wi-Fi part: three parts, the last one short.
        assert_eq!(
            parts_received(&server),
            [
                (0, b"abcd".to_vec()),
                (4, b"efgh".to_vec()),
                (8, b"ij".to_vec())
            ]
        );
        let requests = server.requests.lock().unwrap();
        let create = requests
            .iter()
            .find(|(h, _)| h.starts_with("POST "))
            .unwrap();
        assert_eq!(header_value(&create.0, "upload-length"), Some("10"));
        assert!(create.1.is_empty());
        assert!(!requests.iter().any(|(h, _)| h.contains("/result ")));
    });
}
#[test]
fn resumed_parallel_upload_sends_only_the_gaps_and_retries_incomplete_or_throttled_parts() {
    tauri::async_runtime::block_on(async {
        let fixture = Fixture::new();
        let mut journal = None;
        // The first attempt dies on a server error after the resource exists.
        let server = parts_server(
            true,
            move || r#"{"offset":0,"size":10,"parts":[]}"#.to_string(),
            |_, _| protocol(500, "", ""),
            String::new(),
        );
        assert_eq!(
            fixture
                .run(&server, &mut journal, |_| Ok(()))
                .await
                .unwrap_err(),
            "source_upload_http_500"
        );
        drop(server);
        assert!(journal.is_some());
        let mut attempts = 0;
        let server = parts_server(
            false,
            move || r#"{"offset":4,"size":10,"parts":[{"offset":8,"size":2}]}"#.to_string(),
            move |offset, body| {
                assert_eq!((offset, body), (4, &b"efgh"[..]));
                attempts += 1;
                match attempts {
                    1 => protocol(400, "", ""),
                    2 => protocol(429, "", ""),
                    _ => protocol(204, "Upload-Offset: 10\r\nUpload-Complete: ?0\r\n", ""),
                }
            },
            result_json(&fixture.copy),
        );
        let outcome = fixture
            .run(&server, &mut journal, |_| Ok(()))
            .await
            .unwrap();
        assert!(matches!(outcome, UploadOutcome::Ingested { .. }));
        assert_eq!(parts_received(&server).len(), 3);
        let requests = server.requests.lock().unwrap();
        assert!(!requests.iter().any(|(h, _)| h.starts_with("POST ")));
        assert!(requests.iter().any(|(h, _)| h.contains("/result ")));
    });
}
#[test]
fn servers_without_upload_parts_keep_the_sequential_patch_path() {
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
        responses.push(result_json(&fixture.copy));
        let server = Server::new(responses);
        let mut journal = None;
        fixture
            .run(&server, &mut journal, |_| Ok(()))
            .await
            .unwrap();
        let requests = server.requests.lock().unwrap();
        assert_eq!(
            requests
                .iter()
                .filter(|(h, _)| h.starts_with("PATCH "))
                .count(),
            3
        );
        assert!(!requests
            .iter()
            .any(|(h, _)| h.starts_with("PUT ") || h.contains("/parts")));
    });
}

fn puts(server: &Server) -> Vec<(u64, usize)> {
    parts_received(server)
        .into_iter()
        .map(|(offset, body)| (offset, body.len()))
        .collect()
}
fn count(server: &Server, needle: &str) -> usize {
    server
        .requests
        .lock()
        .unwrap()
        .iter()
        .filter(|(h, _)| h.lines().next().unwrap().contains(needle))
        .count()
}
fn conflict(message: &str) -> String {
    protocol(
        409,
        "Content-Type: application/json\r\n",
        &format!(r#"{{"message":"{message}","error":"Conflict","statusCode":409}}"#),
    )
}
fn stored() -> String {
    protocol(204, "Upload-Offset: 0\r\nUpload-Complete: ?0\r\n", "")
}
async fn run_parts(fixture: &Fixture, server: &Server) -> Result<UploadOutcome, String> {
    let mut journal = None;
    fixture.run(server, &mut journal, |_| Ok(())).await
}
/// Runs a fresh upload and returns the bytes admitted against the run budget.
async fn run_admitted(fixture: &Fixture, server: &Server) -> (Result<UploadOutcome, String>, u64) {
    let mut admitted = 0;
    let mut journal = None;
    let result = transfer(
        &crate::transport::client().unwrap(),
        &server.base,
        &fixture.saved,
        &fixture.identity,
        &fixture.copy,
        &fixture.binding(),
        &fixture.root.join("stage"),
        &mut journal,
        |_, bytes| {
            admitted += bytes;
            Ok(())
        },
        &AtomicBool::new(false),
        &|| Ok(()),
    )
    .await;
    (result, admitted)
}
#[test]
fn an_overlap_conflict_rereads_the_listing_and_resends_only_the_missing_bytes() {
    tauri::async_runtime::block_on(async {
        let fixture = Fixture::new();
        let mut listings = 0;
        let mut conflicted = false;
        let server = parts_server(
            true,
            move || {
                listings += 1;
                // After the conflict, the server reports [4, 6) already received.
                if listings == 1 {
                    r#"{"offset":0,"size":10,"parts":[]}"#
                } else {
                    r#"{"offset":0,"size":10,"parts":[{"offset":4,"size":2}]}"#
                }
                .to_string()
            },
            move |offset, _| {
                if offset == 4 && !conflicted {
                    conflicted = true;
                    conflict("Part overlaps a different received part")
                } else {
                    stored()
                }
            },
            result_json(&fixture.copy),
        );
        assert!(matches!(
            run_parts(&fixture, &server).await.unwrap(),
            UploadOutcome::Ingested { .. }
        ));
        assert_eq!(puts(&server), [(0, 4), (4, 4), (6, 2), (8, 2)]);
        assert_eq!(count(&server, "/parts "), 6);
    });
}
#[test]
fn a_conflict_whose_listing_is_complete_goes_straight_to_the_result() {
    tauri::async_runtime::block_on(async {
        let fixture = Fixture::new();
        let mut listings = 0;
        let server = parts_server(
            true,
            move || {
                listings += 1;
                if listings == 1 {
                    r#"{"offset":0,"size":10,"parts":[]}"#
                } else {
                    r#"{"offset":10,"size":10,"parts":[]}"#
                }
                .to_string()
            },
            |offset, _| {
                if offset == 0 {
                    conflict("Upload is no longer accepting bytes")
                } else {
                    stored()
                }
            },
            result_json(&fixture.copy),
        );
        assert!(matches!(
            run_parts(&fixture, &server).await.unwrap(),
            UploadOutcome::Ingested { .. }
        ));
        // One snapshot: dropped parts may still be recorded after the upload returns.
        let requests = server.requests.lock().unwrap().clone();
        let lines = |needle: &str| {
            requests
                .iter()
                .filter(|(h, _)| h.lines().next().unwrap().contains(needle))
                .count()
        };
        let offsets: Vec<u64> = requests
            .iter()
            .filter(|(h, _)| h.starts_with("PUT "))
            .map(|(h, _)| header_value(h, "upload-offset").unwrap().parse().unwrap())
            .collect();
        assert_eq!(lines("/parts"), offsets.len() + 2);
        assert_eq!(offsets.iter().filter(|o| **o == 0).count(), 1);
        assert_eq!(lines("/result "), 1);
    });
}
#[test]
fn a_busy_part_waits_and_retries_without_rereading_the_listing() {
    tauri::async_runtime::block_on(async {
        let fixture = Fixture::new();
        let mut busy = 0;
        let server = parts_server(
            true,
            move || r#"{"offset":0,"size":10,"parts":[]}"#.to_string(),
            move |offset, _| {
                if offset == 0 && busy < 3 {
                    busy += 1;
                    match busy {
                        // A body larger than one 4 KiB read still shows its message.
                        1 => conflict(&format!(
                            "Upload has an active request\",\"detail\":\"{}",
                            "x".repeat(8192)
                        )),
                        2 => conflict("Upload admission expired"),
                        _ => conflict("Upload has an active request"),
                    }
                } else {
                    stored()
                }
            },
            result_json(&fixture.copy),
        );
        let (outcome, admitted) = run_admitted(&fixture, &server).await;
        assert!(matches!(outcome.unwrap(), UploadOutcome::Ingested { .. }));
        // Turned away at admission, the busy part's resends reuse its first charge.
        assert_eq!(admitted, 10);
        assert_eq!(puts(&server).iter().filter(|(o, _)| *o == 0).count(), 4);
        assert_eq!(
            count(
                &server,
                "GET /api/assets/uploads/11111111-1111-4111-8111-111111111111/parts "
            ),
            1
        );
    });
}
#[test]
fn an_accepted_part_awaiting_ingestion_polls_the_result() {
    tauri::async_runtime::block_on(async {
        let fixture = Fixture::new();
        let server = parts_server(
            true,
            move || r#"{"offset":0,"size":10,"parts":[]}"#.to_string(),
            |_, _| protocol(202, "Upload-Offset: 10\r\nUpload-Complete: ?0\r\n", ""),
            result_json(&fixture.copy),
        );
        assert!(matches!(
            run_parts(&fixture, &server).await.unwrap(),
            UploadOutcome::Ingested { .. }
        ));
        assert_eq!(count(&server, "/result "), 1);
    });
}
#[test]
fn an_interrupted_part_is_sent_again() {
    tauri::async_runtime::block_on(async {
        let fixture = Fixture::new();
        let mut dropped = false;
        let server = parts_server(
            true,
            move || r#"{"offset":0,"size":10,"parts":[]}"#.to_string(),
            move |offset, _| {
                if offset == 8 && !dropped {
                    dropped = true;
                    // Close without a response, as a lost connection would.
                    String::new()
                } else {
                    stored()
                }
            },
            result_json(&fixture.copy),
        );
        assert!(matches!(
            run_parts(&fixture, &server).await.unwrap(),
            UploadOutcome::Ingested { .. }
        ));
        assert_eq!(puts(&server), [(0, 4), (4, 4), (8, 2), (8, 2)]);
    });
}
// Unix only: on Windows the verified staged file stays open with read-only sharing, so no
// writer can shrink it mid-upload and this test cannot provoke the read failure.
#[cfg(unix)]
#[test]
fn a_staged_file_that_shrinks_mid_upload_is_a_staging_error_not_a_retry() {
    tauri::async_runtime::block_on(async {
        let fixture = Fixture::new();
        let original = fixture
            .root
            .join("stage")
            .join(&fixture.copy.id)
            .join("original");
        let server = parts_server(
            true,
            move || {
                // Verification already passed; now the staged bytes disappear under the upload.
                let mut permissions = std::fs::metadata(&original).unwrap().permissions();
                #[allow(clippy::permissions_set_readonly_false)]
                permissions.set_readonly(false);
                std::fs::set_permissions(&original, permissions).unwrap();
                std::fs::OpenOptions::new()
                    .write(true)
                    .open(&original)
                    .unwrap()
                    .set_len(0)
                    .unwrap();
                r#"{"offset":0,"size":10,"parts":[]}"#.to_string()
            },
            |_, _| stored(),
            String::new(),
        );
        let mut admitted = 0;
        let mut journal = None;
        let error = transfer(
            &crate::transport::client().unwrap(),
            &server.base,
            &fixture.saved,
            &fixture.identity,
            &fixture.copy,
            &fixture.binding(),
            &fixture.root.join("stage"),
            &mut journal,
            |_, bytes| {
                admitted += bytes;
                Ok(())
            },
            &AtomicBool::new(false),
            &|| Ok(()),
        )
        .await
        .unwrap_err();
        assert_eq!(error, "source_stage_changed");
        // Only the first wave was admitted; nothing was retried.
        assert!(admitted <= 10, "{admitted}");
    });
}
#[test]
fn resent_bytes_are_charged_only_when_the_server_read_the_body() {
    tauri::async_runtime::block_on(async {
        let fixture = Fixture::new();
        let mut attempts = 0;
        let server = parts_server(
            true,
            move || r#"{"offset":0,"size":10,"parts":[]}"#.to_string(),
            move |offset, _| {
                if offset != 0 {
                    return stored();
                }
                attempts += 1;
                match attempts {
                    // Throttled before the body was read: no new charge.
                    1 => protocol(429, "", ""),
                    // The server read an incomplete body: the resend is charged again.
                    2 => protocol(400, "", ""),
                    _ => stored(),
                }
            },
            result_json(&fixture.copy),
        );
        let (outcome, admitted) = run_admitted(&fixture, &server).await;
        assert!(matches!(outcome.unwrap(), UploadOutcome::Ingested { .. }));
        assert_eq!(admitted, 10 + 4);
    });
}
#[test]
fn parts_failing_together_spend_one_retry_per_wave_even_when_short() {
    tauri::async_runtime::block_on(async {
        let fixture = Fixture::new();
        // Three short parts fail three times each, in waves. Counting every failure would pass
        // the six-failure budget; counting one per wave spends three.
        let mut attempts = std::collections::HashMap::new();
        let server = parts_server(
            true,
            move || r#"{"offset":0,"size":10,"parts":[]}"#.to_string(),
            move |offset, _| {
                let n = attempts.entry(offset).or_insert(0);
                *n += 1;
                if *n <= 3 {
                    protocol(400, "", "")
                } else {
                    stored()
                }
            },
            result_json(&fixture.copy),
        );
        let (outcome, _) = run_admitted(&fixture, &server).await;
        assert!(matches!(outcome.unwrap(), UploadOutcome::Ingested { .. }));
        assert_eq!(puts(&server).len(), 12);
    });
}
#[test]
fn upload_mime_reads_only_a_real_extension() {
    assert_eq!(upload_mime("clip.MOV"), "video/quicktime");
    assert_eq!(upload_mime("clip.m4v"), "video/mp4");
    assert_eq!(upload_mime("IMG_0001.HEIC"), "image/heic");
    assert_eq!(upload_mime("photo.JPG"), "image/jpeg");
    // Unknown or missing extensions still pass the server's media Content-Type check.
    assert_eq!(upload_mime("RAW_0001.CR3"), "image/octet-stream");
    assert_eq!(upload_mime("mov"), "image/octet-stream");
    assert_eq!(upload_mime(".mp4"), "image/octet-stream");
    let media = |value: &str| {
        let (kind, sub) = value.split_once('/').unwrap();
        matches!(kind, "image" | "video" | "audio")
            && sub
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || ".+-".contains(c))
    };
    for name in ["a.mov", "a.mp4", "a.heic", "a.dng", "noext"] {
        assert!(media(upload_mime(name)), "{name}");
    }
}
