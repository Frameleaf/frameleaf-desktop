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
    stamp_at(OffsetDateTime::now_utc() + time::Duration::seconds(seconds))
}
fn stamp_at(d: OffsetDateTime) -> String {
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
    /// Seconds the server's clock is ahead of this computer's.
    clock_offset: i64,
    /// Every `fail` code reported, in order.
    failures: Vec<String>,
    /// Every authenticated request's path, in the order the server handled it.
    handled: Vec<String>,
}

fn refuse(status: u16, message: &str) -> (u16, Vec<u8>) {
    let body = json!({"message":message,"statusCode":status});
    (status, body.to_string().into_bytes())
}
fn reply(value: Value) -> (u16, Vec<u8>) {
    (200, value.to_string().into_bytes())
}

impl State {
    fn now(&self) -> OffsetDateTime {
        OffsetDateTime::now_utc() + time::Duration::seconds(self.clock_offset)
    }
    /// A time on the server's own clock, as it stamps every deadline.
    fn stamp(&self, seconds: i64) -> String {
        stamp_at(self.now() + time::Duration::seconds(seconds))
    }
    /// As the server: a request timed more than two minutes from its clock is refused.
    fn timely(&self, timestamp: Option<u64>) -> bool {
        let now = (self.now().unix_timestamp_nanos() / 1_000_000) as i64;
        timestamp.is_some_and(|at| (now - at as i64).abs() <= 120_000)
    }
    fn respond(
        &mut self,
        method: &str,
        path: &str,
        authorization: Option<String>,
        proof: Option<String>,
        body: &[u8],
    ) -> (u16, Vec<u8>) {
        let body: Value = serde_json::from_slice(body).unwrap_or(Value::Null);
        if (method, path) == ("GET", "/api/desktop/capabilities") {
            return reply(
                json!({"protocolVersion":1,"serverId":"fixture-server","features":{
                "enrollment":true,"worker":true,"workerSession":true,"workerAutoSetup":true,
                "sources":false,"nativeHost":false}}),
            );
        }
        if (method, path) == ("POST", "/api/desktop/devices/session") {
            let device = body["deviceId"].as_str().unwrap_or_default().to_owned();
            if let Some((_, status, body)) = self.forced.get_mut(&device).and_then(|queue| {
                let index = queue.iter().position(|(part, _, _)| path.contains(part))?;
                queue.remove(index)
            }) {
                return (status, body.into_bytes());
            }
            let Some(epoch) = self
                .epochs
                .get(&device)
                .copied()
                .filter(|_| !self.revoked.contains(&device))
            else {
                return refuse(401, "desktop_worker_credential_invalid");
            };
            // As the server: the device is checked first, then the request's timestamp.
            if !self.timely(body["timestamp"].as_u64()) {
                return refuse(401, "desktop_proof_expired");
            }
            let session = Session {
                id: Uuid::new_v4().to_string(),
                token: format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple()),
                sequence: 0,
                qualification: Uuid::new_v4().to_string(),
                qualification_expires: self.stamp(600),
            };
            let response = json!({"sessionId":session.id,"workerToken":session.token,
                "authorizationEpoch":epoch,"expiresAt":self.stamp(3600),
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
        let timely = self.timely(proof.as_ref().map(|proof| proof.timestamp));
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
        // A good credential with a timestamp too far from the server's clock.
        if !timely {
            return refuse(401, "desktop_proof_expired");
        }
        self.handled.push(path.to_owned());
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
                    "expiresAt":self.stamp(60),"executionDeadline":self.stamp(120)}}))
            }
            ("POST", "/api/desktop/worker/heartbeat", _) => {
                let id = payload["id"].as_str().unwrap_or_default();
                if held(&self.leases, id) == Some(self.revision) {
                    reply(json!({"accepted":true,"expiresAt":self.stamp(60)}))
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
                if kind == "fail" {
                    let code = payload["code"].as_str().unwrap_or_default();
                    self.failures.push(code.to_owned());
                }
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
    let (status, body, date) = {
        let mut state = state.lock().unwrap();
        let (status, body) = state.respond(
            method,
            path,
            header("authorization"),
            header("x-frameleaf-desktop-proof"),
            &bytes[end + 4..],
        );
        let date = state
            .now()
            .format(&time::format_description::well_known::Rfc2822)
            .unwrap();
        (status, body, date)
    };
    // As every real server: the response says what time the server thinks it is.
    let head = format!(
        "HTTP/1.1 {status} Fixture\r\nDate: {date}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
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
        let client = transport::client()?;
        // As `worker_setup::refresh_session`: the capabilities reply shows the server's clock.
        let skew = transport::capabilities(&client, saved)
            .await?
            .ok_or("desktop_protocol_unsupported")?
            .clock_skew_ms;
        let worker =
            transport::issue_worker_session_as(&client, saved, &device.identity, skew).await?;
        Ok(WorkerTransport::over(Connection {
            client,
            base: normalize_server(&saved.server)?,
            worker,
            identity: serde_json::from_value(serde_json::to_value(&device.identity).unwrap())
                .unwrap(),
            checkpoint: |_, _| Ok(()),
            clock: Arc::default(),
        })
        .with_clock_skew(skew))
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
            .map_or((Uuid::new_v4().to_string(), state.stamp(600)), |session| {
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
            qualified_at: millis(&expires).unwrap() - 600_000,
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
    /// Put the server's clock this many seconds ahead of this computer's (negative: behind).
    pub(crate) fn set_clock_offset(&self, seconds: i64) {
        self.state.lock().unwrap().clock_offset = seconds;
    }
    /// Every `fail` code the server was sent, in order.
    pub(crate) fn failures(&self) -> Vec<String> {
        self.state.lock().unwrap().failures.clone()
    }
    /// The last path component of every authenticated request, in the order handled.
    pub(crate) fn handled(&self) -> Vec<String> {
        let state = self.state.lock().unwrap();
        let last = |path: &String| path.rsplit('/').next().unwrap_or_default().to_owned();
        state.handled.iter().map(last).collect()
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
        // Anything unnamed stays opaque.
        (401, "", "server_http_401"),
        (409, "desktop_pool_route_changed", "server_http_409"),
        (500, "Internal server error", "server_http_500"),
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
    // Named, and not the session refusal the worker answers by asking for another session.
    assert_eq!(
        server.session(&device).await.err().as_deref(),
        Some("worker_device_refused")
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

#[tokio::test]
async fn a_wrong_clock_on_this_computer_does_not_stop_the_worker() {
    // The server's clock is an hour ahead of this computer's, then a day behind it.
    for offset in [3600, -86_400] {
        let server = FakeServer::start();
        server.set_clock_offset(offset);
        let device = server.enrol();
        // The server refuses requests timed two minutes from its own clock, and every deadline
        // it sends is on its own clock.
        let worker = server.session(&device).await.unwrap();
        let qualification = server.qualification(&worker).await;
        server.queue(&device, 1);
        let claimed = worker.claim_many(&[&qualification]).await;
        let (_, mut task) = claimed.unwrap().expect("the queued task");
        assert_eq!(worker.input(&task, &qualification).await.unwrap(), INPUT);
        assert!(worker.heartbeat(&mut task, &qualification).await.unwrap());
        let result = worker.complete(&task, &json!({}), &qualification).await;
        assert_eq!(result, Ok(true), "{offset}");
        assert_eq!(server.completed(&device), 1);
    }
}

#[test]
fn the_clock_difference_is_read_from_the_date_header_and_small_ones_are_ignored() {
    let local = 1_795_118_400_000; // 2026-11-19T20:00:00Z
    let skew = |date| transport::clock_skew_from(Some(date), local);
    // As servers write it, and as RFC 2822 does.
    assert_eq!(skew("Thu, 19 Nov 2026 20:00:00 GMT"), Some(0));
    assert_eq!(skew("Thu, 19 Nov 2026 20:00:20 GMT"), Some(0));
    assert_eq!(skew("Thu, 19 Nov 2026 19:59:40 +0000"), Some(0));
    // A real difference, plus the two seconds `Date` can be behind.
    assert_eq!(skew("Thu, 19 Nov 2026 21:00:00 GMT"), Some(3_602_000));
    assert_eq!(skew("Wed, 18 Nov 2026 20:00:00 GMT"), Some(-86_398_000));
    // Nothing usable: the last known difference stays.
    assert_eq!(skew("yesterday"), None);
    assert_eq!(transport::clock_skew_from(None, local), None);
}

#[tokio::test]
async fn signed_requests_reach_the_server_one_at_a_time_in_sequence_order() {
    let server = FakeServer::start();
    let device = server.enrol();
    let worker = server.session(&device).await.unwrap();
    let qualification = server.qualification(&worker).await;
    server.queue(&device, 1);
    let claimed = worker.claim_many(&[&qualification]).await;
    let (_, task) = claimed.unwrap().unwrap();
    // Heartbeats and the result asked for at the same moment, many times over.
    let mut beats = Vec::new();
    for _ in 0..8 {
        let mut lease = task.clone();
        let (worker, qualification) = (&worker, &qualification);
        beats.push(async move { worker.heartbeat(&mut lease, qualification).await });
    }
    let later = beats.split_off(4);
    let (done, all) = (json!({}), [&qualification]);
    let (first, second, result, third) = tokio::join!(
        futures_util::future::join_all(beats),
        futures_util::future::join_all(later),
        worker.complete(&task, &done, &qualification),
        worker.claim_many(&all),
    );
    // None was refused for arriving after a higher sequence number.
    assert!(
        first.iter().chain(&second).all(|beat| beat.is_ok()),
        "{first:?} {second:?}"
    );
    assert_eq!(result, Ok(true));
    assert!(third.is_ok());
    // All eleven passed the server's sequence check: the claim, eight heartbeats, the result
    // and the second claim.
    let handled = server.handled();
    assert_eq!(handled.len(), 11, "{handled:?}");
    assert_eq!(
        handled.iter().filter(|path| *path == "heartbeat").count(),
        8
    );
}

#[tokio::test]
async fn a_new_field_in_a_reply_is_ignored() {
    let server = FakeServer::start();
    let device = server.enrol();
    let worker = server.session(&device).await.unwrap();
    let qualification = server.qualification(&worker).await;
    // A heartbeat acknowledgement and a claim from a newer server.
    server.queue(&device, 1);
    let claimed = worker.claim_many(&[&qualification]).await;
    let (_, mut task) = claimed.unwrap().unwrap();
    server.respond_next(
        &device,
        "/heartbeat",
        200,
        json!({"accepted":true,"expiresAt":stamp(60),"somethingNew":1}),
    );
    assert!(worker.heartbeat(&mut task, &qualification).await.unwrap());
}

#[tokio::test]
async fn a_refused_timestamp_is_a_clock_problem_and_the_next_request_is_timed_right() {
    let server = FakeServer::start();
    let device = server.enrol();
    let worker = server.session(&device).await.unwrap();
    let qualification = server.qualification(&worker).await;
    // The server's clock is now ten minutes from this computer's, which the worker has not
    // seen yet: its next request is timed wrong, and refused for that, not for its credential.
    server.set_clock_offset(600);
    assert_eq!(
        worker.maintain_session().await.err().as_deref(),
        None,
        "nothing is sent while the session is current"
    );
    let source = "0".repeat(40);
    assert_eq!(
        worker
            .model_inventory(&source, "CPUExecutionProvider")
            .await
            .err()
            .as_deref(),
        Some("clock_invalid")
    );
    // That refusal carried the server's time: the same session's next request is accepted.
    let again = worker
        .model_inventory(&source, "CPUExecutionProvider")
        .await;
    assert_ne!(again.err().as_deref(), Some("clock_invalid"));
    let _ = qualification;
    // At session issue a refused timestamp is the clock too, never "this device is refused".
    let stale = transport::issue_worker_session_as(
        &transport::client().unwrap(),
        &device.saved,
        &device.identity,
        0,
    )
    .await;
    assert_eq!(stale.err().as_deref(), Some("clock_invalid"));
}
