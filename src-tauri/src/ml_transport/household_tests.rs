//! A stand-in for the household server (FL-1484) speaking the worker's HTTP protocol, and the
//! worker transport's reactions to its refusals. It fences a computer the way the server does: a
//! household change gives that device a new authorization epoch, deletes its worker session and
//! gives the household list a new revision, which every lease granted under the old one loses.
use super::*;
use serde_json::{json, Value};
use std::{
    collections::{HashMap, HashSet, VecDeque},
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    sync::{Arc, Mutex as StdMutex},
    time::Duration,
};

const INPUT: &[u8] = b"fixture input";
const MODEL: &str = "fixture-model";

fn stamp(seconds: i64) -> String {
    let d = OffsetDateTime::now_utc() + time::Duration::seconds(seconds);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        d.year(),
        u8::from(d.month()),
        d.day(),
        d.hour(),
        d.minute(),
        d.second()
    )
}

struct Session {
    id: String,
    token: String,
    sequence: u32,
    qualification: String,
    qualification_expires: String,
}
#[derive(Default)]
struct State {
    epochs: HashMap<String, u32>,
    revoked: HashSet<String>,
    sessions: HashMap<String, Session>,
    issued: HashMap<String, u32>,
    revision: u32,
    queued: HashMap<String, u32>,
    /// attempt id → (device, household revision the lease was granted under)
    leases: HashMap<String, (String, u32)>,
    /// device → (path fragment, status, body) answered once instead of the normal reply
    forced: HashMap<String, VecDeque<(String, u16, String)>>,
    /// device → every result or failure report that passed authentication
    reports: HashMap<String, Vec<&'static str>>,
    completed: HashMap<String, u32>,
}

fn refuse(status: u16, message: &str) -> (u16, Vec<u8>) {
    let body = json!({"message":message,"statusCode":status});
    (status, body.to_string().into_bytes())
}
fn reply(value: Value) -> (u16, Vec<u8>) {
    (200, value.to_string().into_bytes())
}

impl State {
    fn respond(
        &mut self,
        method: &str,
        path: &str,
        authorization: Option<String>,
        proof: Option<String>,
        body: &[u8],
    ) -> (u16, Vec<u8>) {
        let body: Value = serde_json::from_slice(body).unwrap_or(Value::Null);
        if (method, path) == ("POST", "/api/desktop/devices/session") {
            let device = body["deviceId"].as_str().unwrap_or_default().to_owned();
            let Some(epoch) = self
                .epochs
                .get(&device)
                .copied()
                .filter(|_| !self.revoked.contains(&device))
            else {
                return refuse(401, "desktop_worker_credential_invalid");
            };
            let session = Session {
                id: Uuid::new_v4().to_string(),
                token: format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple()),
                sequence: 0,
                qualification: Uuid::new_v4().to_string(),
                qualification_expires: stamp(600),
            };
            let response = json!({"sessionId":session.id,"workerToken":session.token,
                "authorizationEpoch":epoch,"expiresAt":stamp(3600),
                "scopes":["library-inference"],"modelKeys":[]});
            // As on the server: a new session ends everything the device held under the old one.
            self.leases.retain(|_, (owner, _)| owner != &device);
            self.sessions.insert(device.clone(), session);
            *self.issued.entry(device).or_default() += 1;
            return reply(response);
        }
        let token = authorization
            .as_deref()
            .and_then(|value| value.strip_prefix("Bearer "))
            .unwrap_or_default();
        let proof: Option<crate::worker::WorkerProof> = proof
            .and_then(|header| STANDARD.decode(header).ok())
            .and_then(|bytes| serde_json::from_slice(&bytes).ok());
        let Some((device, session)) = proof.and_then(|proof| {
            self.sessions.iter_mut().find_map(|(device, session)| {
                (session.id == proof.session_id
                    && session.token == token
                    && proof.sequence > session.sequence)
                    .then(|| {
                        session.sequence = proof.sequence;
                        (device.clone(), session.id.clone())
                    })
            })
        }) else {
            return refuse(401, "desktop_worker_credential_invalid");
        };
        if let Some(queue) = self.forced.get_mut(&device) {
            if let Some(index) = queue.iter().position(|(part, _, _)| path.contains(part)) {
                let (_, status, body) = queue.remove(index).unwrap();
                return (status, body.into_bytes());
            }
        }
        let payload: Value = body["payload"]
            .as_str()
            .and_then(|payload| serde_json::from_str(payload).ok())
            .unwrap_or(Value::Null);
        let task = path
            .strip_prefix("/api/desktop/tasks/")
            .and_then(|rest| rest.split_once('/'));
        let held = |leases: &HashMap<String, (String, u32)>, id: &str| {
            leases
                .get(id)
                .filter(|(owner, _)| owner == &device)
                .map(|(_, revision)| *revision)
        };
        match (method, path, task) {
            ("POST", "/api/desktop/worker/claim", _) => {
                let waiting = self.queued.entry(device.clone()).or_default();
                if *waiting == 0 {
                    return reply(json!({"task":null}));
                }
                *waiting -= 1;
                let id = Uuid::new_v4().to_string();
                self.leases
                    .insert(id.clone(), (device.clone(), self.revision));
                let live = &self.sessions[&device];
                reply(json!({"task":{"id":id,"taskId":Uuid::new_v4().to_string(),
                    "deviceId":device,"sessionId":session,
                    "authorizationEpoch":self.epochs[&device],"generation":1,
                    "qualificationId":live.qualification,
                    "qualificationExpiresAt":live.qualification_expires,
                    "modelKey":MODEL,"configJson":"{}","configSha256":hash(b"{}"),
                    "inputSha256":hash(INPUT),"inputKind":"image","maxInputBytes":1024,
                    "expiresAt":stamp(60),"executionDeadline":stamp(120)}}))
            }
            ("POST", "/api/desktop/worker/heartbeat", _) => {
                let id = payload["id"].as_str().unwrap_or_default();
                if held(&self.leases, id) == Some(self.revision) {
                    reply(json!({"accepted":true,"expiresAt":stamp(60)}))
                } else {
                    reply(json!({"accepted":false,"expiresAt":null}))
                }
            }
            ("GET", _, Some((id, "input"))) => match held(&self.leases, id) {
                None => refuse(401, "desktop_lease_invalid"),
                Some(revision) if revision != self.revision => {
                    refuse(409, "desktop_pool_policy_changed")
                }
                Some(_) => (200, INPUT.to_vec()),
            },
            ("POST", _, Some((id, kind @ ("result" | "fail")))) => {
                let kind = if kind == "result" { "result" } else { "fail" };
                self.reports.entry(device.clone()).or_default().push(kind);
                match held(&self.leases, id) {
                    None => reply(json!({"accepted":false})),
                    Some(revision) if revision != self.revision => {
                        refuse(409, "desktop_pool_policy_changed")
                    }
                    Some(_) => {
                        self.leases.remove(id);
                        if kind == "result" {
                            *self.completed.entry(device).or_default() += 1;
                        }
                        reply(json!({"accepted":true}))
                    }
                }
            }
            _ => refuse(404, "Not Found"),
        }
    }
}

fn serve(mut stream: TcpStream, state: &StdMutex<State>) -> Option<()> {
    stream.set_read_timeout(Some(Duration::from_secs(5))).ok()?;
    let mut bytes = Vec::new();
    let end = loop {
        let mut part = [0; 4096];
        let count = stream.read(&mut part).ok().filter(|count| *count > 0)?;
        bytes.extend_from_slice(&part[..count]);
        if let Some(end) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&bytes[..end]).to_ascii_lowercase();
            let length: usize = head
                .lines()
                .find_map(|line| line.strip_prefix("content-length: "))
                .map_or(0, |value| value.trim().parse().unwrap());
            if bytes.len() >= end + 4 + length {
                break end;
            }
        }
    };
    let head = String::from_utf8_lossy(&bytes[..end]).into_owned();
    let mut request = head.lines().next()?.split(' ');
    let (method, path) = (request.next()?, request.next()?);
    let header = |name: &str| {
        head.lines().skip(1).find_map(|line| {
            let (key, value) = line.split_once(':')?;
            key.eq_ignore_ascii_case(name)
                .then(|| value.trim().to_owned())
        })
    };
    let (status, body) = state.lock().unwrap().respond(
        method,
        path,
        header("authorization"),
        header("x-frameleaf-desktop-proof"),
        &bytes[end + 4..],
    );
    let head = format!(
        "HTTP/1.1 {status} Fixture\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(head.as_bytes()).ok()?;
    stream.write_all(&body).ok()
}

pub(crate) struct FakeServer {
    url: String,
    state: Arc<StdMutex<State>>,
}
pub(crate) struct Device {
    id: String,
    identity: DeviceIdentity,
    saved: SavedConnection,
}
impl FakeServer {
    pub(crate) fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/", listener.local_addr().unwrap());
        let state = Arc::new(StdMutex::new(State::default()));
        let shared = state.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let state = shared.clone();
                std::thread::spawn(move || serve(stream, &state));
            }
        });
        Self { url, state }
    }
    /// A computer enrolled and approved for AI work, with its own installation key.
    pub(crate) fn enrol(&self) -> Device {
        let id = Uuid::new_v4().to_string();
        self.state.lock().unwrap().epochs.insert(id.clone(), 1);
        Device {
            saved: SavedConnection {
                server: self.url.clone(),
                server_id: "fixture-server".into(),
                account_id: "fixture-account".into(),
                name: "Fixture".into(),
                token: "fixture".into(),
                device_name: "Fixture".into(),
                mode: "client-worker".into(),
                device_id: Some(id.clone()),
            },
            identity: DeviceIdentity::generate(),
            id,
        }
    }
    /// Issue a worker session the way `transport::issue_worker_session` does, with this device's key.
    pub(crate) async fn session(&self, device: &Device) -> Result<WorkerTransport, String> {
        let saved = &device.saved;
        let request = crate::worker::session_request(
            &device.identity,
            &saved.server_id,
            &saved.account_id,
            &device.id,
        )?;
        let client = transport::client()?;
        let response: SessionResponse = transport::json(
            client
                .post(format!("{}api/desktop/devices/session", self.url))
                .json(&request)
                .send()
                .await
                .map_err(|_| "worker_session_setup_interrupted")?,
        )
        .await?;
        Ok(WorkerTransport(Mutex::new(Connection {
            client,
            base: normalize_server(&saved.server)?,
            worker: crate::worker::bind_session(saved, &response)?,
            identity: serde_json::from_value(serde_json::to_value(&device.identity).unwrap())
                .unwrap(),
            checkpoint: |_, _| Ok(()),
        })))
    }
    /// The qualification the server holds for this worker's session, as `prepare` would obtain it.
    pub(crate) async fn qualification(&self, worker: &WorkerTransport) -> AcceptedQualification {
        let connection = worker.0.lock().await;
        let state = self.state.lock().unwrap();
        // A session the server has since deleted has no qualification; its claims are refused anyway.
        let (id, expires) = state
            .sessions
            .get(&connection.worker.device_id)
            .filter(|session| session.id == connection.worker.session_id)
            .map_or((Uuid::new_v4().to_string(), stamp(600)), |session| {
                (
                    session.qualification.clone(),
                    session.qualification_expires.clone(),
                )
            });
        AcceptedQualification {
            authority: ChallengeAuthority::from_worker(&connection.worker),
            id,
            model_key: MODEL.into(),
            config_sha256: hash(b"{}"),
            input_kind: InputKind::Image,
            binding_sha256: "a".repeat(64),
            manifest_sha256: "b".repeat(64),
            runtime_fingerprint: "c".repeat(64),
            report_sha256: "d".repeat(64),
            expires_at: millis(&expires).unwrap(),
        }
    }
    /// `setHousehold` on the server: a new epoch for this device, its session deleted, and a new
    /// household revision for everyone.
    pub(crate) fn toggle_household(&self, device: &Device) {
        let mut state = self.state.lock().unwrap();
        *state.epochs.get_mut(&device.id).unwrap() += 1;
        state.sessions.remove(&device.id);
        state.revision += 1;
    }
    pub(crate) fn revoke(&self, device: &Device) {
        let mut state = self.state.lock().unwrap();
        state.revoked.insert(device.id.clone());
        state.sessions.remove(&device.id);
    }
    pub(crate) fn queue(&self, device: &Device, tasks: u32) {
        *self
            .state
            .lock()
            .unwrap()
            .queued
            .entry(device.id.clone())
            .or_default() += tasks;
    }
    /// Answer this device's next request whose path contains `path` with exactly this reply.
    pub(crate) fn respond_next(&self, device: &Device, path: &str, status: u16, body: Value) {
        self.state
            .lock()
            .unwrap()
            .forced
            .entry(device.id.clone())
            .or_default()
            .push_back((path.into(), status, body.to_string()));
    }
    pub(crate) fn completed(&self, device: &Device) -> u32 {
        let state = self.state.lock().unwrap();
        state.completed.get(&device.id).copied().unwrap_or(0)
    }
    pub(crate) fn sessions_issued(&self, device: &Device) -> u32 {
        let state = self.state.lock().unwrap();
        state.issued.get(&device.id).copied().unwrap_or(0)
    }
    /// Every result or failure report from this device that the server authenticated, in order.
    pub(crate) fn reports(&self, device: &Device) -> Vec<&'static str> {
        let state = self.state.lock().unwrap();
        state.reports.get(&device.id).cloned().unwrap_or_default()
    }
}

#[test]
fn only_named_refusals_are_translated_for_the_worker_loop() {
    for (status, message, expected) in [
        (
            401,
            "desktop_worker_credential_invalid",
            "worker_session_rejected",
        ),
        (401, "desktop_lease_invalid", "worker_lease_refused"),
        (
            403,
            "desktop_pool_policy_required",
            "worker_policy_required",
        ),
        (403, "desktop_worker_lan_required", "worker_lan_required"),
        (409, "desktop_pool_policy_changed", "worker_policy_changed"),
        // The same words under another status, or anything unnamed, stay opaque.
        (403, "desktop_worker_credential_invalid", "server_http_403"),
        (401, "", "server_http_401"),
        (409, "desktop_pool_route_changed", "server_http_409"),
        (500, "desktop_pool_policy_changed", "server_http_500"),
    ] {
        assert_eq!(worker_refusal(status, message), expected);
    }
}

#[tokio::test]
async fn a_household_toggle_rejects_the_old_session_and_a_new_one_works() {
    let server = FakeServer::start();
    let device = server.enrol();
    let worker = server.session(&device).await.unwrap();
    let qualification = server.qualification(&worker).await;
    server.queue(&device, 1);
    server.toggle_household(&device);
    assert_eq!(
        worker.claim_many(&[&qualification]).await.err().as_deref(),
        Some("worker_session_rejected")
    );
    // The device itself is still approved: issuing a session under the new epoch succeeds.
    let worker = server.session(&device).await.unwrap();
    let qualification = server.qualification(&worker).await;
    let (_, task) = worker.claim_many(&[&qualification]).await.unwrap().unwrap();
    assert_eq!(task.authorization_epoch, 2);
    assert_eq!(worker.input(&task, &qualification).await.unwrap(), INPUT);
}

#[tokio::test]
async fn a_revoked_device_cannot_obtain_a_new_session() {
    let server = FakeServer::start();
    let device = server.enrol();
    let worker = server.session(&device).await.unwrap();
    let qualification = server.qualification(&worker).await;
    server.revoke(&device);
    assert_eq!(
        worker.claim_many(&[&qualification]).await.err().as_deref(),
        Some("worker_session_rejected")
    );
    assert_eq!(
        server.session(&device).await.err().as_deref(),
        Some("server_http_401")
    );
}

#[tokio::test]
async fn task_refusals_keep_their_reason_and_unnamed_errors_stay_opaque() {
    let server = FakeServer::start();
    let device = server.enrol();
    let other = server.enrol();
    let worker = server.session(&device).await.unwrap();
    let qualification = server.qualification(&worker).await;
    server.queue(&device, 2);
    let claim = || async {
        let claimed = worker.claim_many(&[&qualification]).await;
        claimed.unwrap().unwrap().1
    };

    // Another computer's household change: this session stays, the lease's policy revision does not.
    let task = claim().await;
    server.toggle_household(&other);
    assert_eq!(
        worker.input(&task, &qualification).await.err().as_deref(),
        Some("worker_policy_changed")
    );
    let result = worker.complete(&task, &json!({}), &qualification).await;
    assert_eq!(result.err().as_deref(), Some("worker_policy_changed"));

    // A lease the server no longer knows.
    let mut unknown = claim().await;
    unknown.id = Uuid::new_v4().to_string();
    assert_eq!(
        worker
            .input(&unknown, &qualification)
            .await
            .err()
            .as_deref(),
        Some("worker_lease_refused")
    );

    for (status, body, expected) in [
        (
            403,
            json!({"message":"desktop_pool_policy_required"}),
            "worker_policy_required",
        ),
        (
            403,
            json!({"message":"desktop_worker_lan_required"}),
            "worker_lan_required",
        ),
        (
            409,
            json!({"message":"desktop_pool_policy_changed"}),
            "worker_policy_changed",
        ),
        (
            500,
            json!({"message":"Internal server error"}),
            "server_http_500",
        ),
        (502, json!("<html>Bad Gateway</html>"), "server_http_502"),
    ] {
        server.respond_next(&device, "/claim", status, body);
        assert_eq!(
            worker.claim_many(&[&qualification]).await.err().as_deref(),
            Some(expected)
        );
    }
}

#[tokio::test]
async fn a_result_is_not_sent_once_the_last_granted_lease_has_run_out() {
    let server = FakeServer::start();
    let device = server.enrol();
    let worker = server.session(&device).await.unwrap();
    let qualification = server.qualification(&worker).await;
    server.queue(&device, 1);
    let claimed = worker.claim_many(&[&qualification]).await;
    let mut task = claimed.unwrap().unwrap().1;
    task.expires_at = stamp(-1);
    let result = worker.complete(&task, &json!({}), &qualification).await;
    assert_eq!(result.err().as_deref(), Some("worker_lease_expired"));
    assert!(server.reports(&device).is_empty());
    // A heartbeat extends the same lease, and the result is then accepted under it.
    assert!(worker.heartbeat(&mut task, &qualification).await.unwrap());
    let result = worker.complete(&task, &json!({}), &qualification).await;
    assert_eq!(result, Ok(true));
    assert_eq!(server.reports(&device), ["result"]);
}
