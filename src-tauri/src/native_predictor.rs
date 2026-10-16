//! One scoped NAS job at a time; the owned qualified process is stopped on any execution failure.
use crate::{
    ml_transport::{AcceptedQualification, ClaimedTask, InputKind, WorkerFailure, WorkerTransport},
    native_runtime::{NativeSidecar, QualifiedRuntime},
    runtime_store::InstalledRuntime,
    transport,
};
use reqwest::{
    multipart::{Form, Part},
    Client,
};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{future::Future, path::Path, time::Duration};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};
use tokio::sync::watch;
use zeroize::Zeroizing;

struct BoundClient {
    client: Client,
    base: String,
    token: Zeroizing<String>,
    model_key: String,
    entries: Value,
    kind: String,
}
fn execution_duration(task: &ClaimedTask) -> Result<Duration, String> {
    let parse = |value: &str| -> Result<i128, String> {
        OffsetDateTime::parse(value, &Rfc3339)
            .map(|date| date.unix_timestamp_nanos())
            .map_err(|_| "worker_deadline_invalid".into())
    };
    let now = OffsetDateTime::now_utc().unix_timestamp_nanos();
    let deadline = parse(&task.execution_deadline)?.min(parse(&task.qualification_expires_at)?);
    let lease = parse(&task.expires_at)?;
    let remaining = deadline - now;
    if lease <= now || lease > deadline || remaining <= 0 || remaining > 600_000_000_000 {
        return Err("worker_execution_deadline".into());
    }
    Ok(Duration::from_nanos(remaining as u64))
}
impl BoundClient {
    fn new(port: u16, token: String, spec: &Value) -> Result<Self, String> {
        if port < 1024 || !spec["entries"].is_object() {
            return Err("worker_model_binding_invalid".into());
        }
        let model_key = spec["modelKey"]
            .as_str()
            .filter(|s| !s.is_empty() && s.len() <= 256)
            .ok_or("worker_model_binding_invalid")?;
        let kind = spec["fixtureKind"]
            .as_str()
            .filter(|s| matches!(*s, "text" | "image"))
            .ok_or("worker_model_binding_invalid")?;
        Ok(Self {
            client: Client::builder()
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .connect_timeout(Duration::from_secs(2))
                .pool_max_idle_per_host(0)
                .build()
                .map_err(|_| "runtime_client_failed")?,
            base: format!("http://127.0.0.1:{port}"),
            token: Zeroizing::new(token),
            model_key: model_key.into(),
            entries: spec["entries"].clone(),
            kind: kind.into(),
        })
    }
    async fn health(&self) -> Result<bool, String> {
        let mut response = self
            .client
            .get(format!("{}/ping", self.base))
            .bearer_auth(self.token.as_str())
            .timeout(Duration::from_secs(2))
            .send()
            .await
            .map_err(|_| "runtime_not_ready")?;
        let ready = response.status().is_success();
        let mut size = 0;
        while let Some(bytes) = response.chunk().await.map_err(|_| "runtime_not_ready")? {
            size += bytes.len();
            if size > 256 {
                return Err("runtime_health_invalid".into());
            }
        }
        Ok(ready)
    }
    async fn predict(&self, task: &ClaimedTask, input: &[u8]) -> Result<Value, String> {
        let config: Value =
            serde_json::from_str(&task.config_json).map_err(|_| "worker_model_binding_invalid")?;
        if task.model_key != self.model_key
            || config != self.entries
            || task.config_json.len() > 65_536
            || format!("{:x}", Sha256::digest(task.config_json.as_bytes())) != task.config_sha256
            || !matches!(
                (&task.input_kind, self.kind.as_str()),
                (InputKind::Text, "text") | (InputKind::Image, "image")
            )
            || task.max_input_bytes > 16 * 1024 * 1024
        {
            return Err("worker_model_binding_invalid".into());
        }
        task.verify_input(input)?;
        let duration = execution_duration(task)?;
        let form = Form::new().text("entries", task.config_json.clone());
        let form = match task.input_kind {
            InputKind::Text => form.text(
                "text",
                String::from_utf8(input.to_vec()).map_err(|_| "worker_text_invalid")?,
            ),
            InputKind::Image => form.part(
                "image",
                Part::bytes(input.to_vec())
                    .file_name("input")
                    .mime_str("application/octet-stream")
                    .map_err(|_| "worker_input_invalid")?,
            ),
        };
        let response = self
            .client
            .post(format!("{}/predict", self.base))
            .bearer_auth(self.token.as_str())
            .timeout(duration)
            .multipart(form)
            .send()
            .await
            .map_err(|_| "runtime_prediction_interrupted")?;
        let value: Value = transport::json_limit(response, 4 * 1024 * 1024).await?;
        if !value.is_object() {
            return Err("runtime_prediction_invalid".into());
        }
        Ok(value)
    }
}
async fn cancelled(cancel: &mut watch::Receiver<bool>) {
    loop {
        if *cancel.borrow_and_update() {
            return;
        }
        if cancel.changed().await.is_err() {
            return;
        }
    }
}
type WorkerStep<'a> = std::pin::Pin<Box<dyn Future<Output = Result<bool, String>> + Send + 'a>>;
async fn worker_jobs<T>(
    state: &mut T,
    mut execute: impl for<'a> FnMut(&'a mut T, watch::Receiver<bool>) -> WorkerStep<'a>,
    cancel: &mut watch::Receiver<bool>,
) -> Result<(), String> {
    loop {
        let execution_cancel = cancel.clone();
        let completed = tokio::select! {
            biased;
            _ = cancelled(cancel) => return Err("worker_cancelled".into()),
            result = execute(state, execution_cancel) => result?,
        };
        if !completed {
            // A server may answer an empty long-poll immediately; do not spin against it.
            tokio::select! {
                biased;
                _ = cancelled(cancel) => return Err("worker_cancelled".into()),
                _ = tokio::time::sleep(Duration::from_secs(1)) => {},
            }
        }
    }
}
async fn race_prediction<T>(
    prediction: impl Future<Output = Result<T, String>>,
    lease: impl Future<Output = Result<(), String>>,
    cancel: &mut watch::Receiver<bool>,
    duration: Duration,
) -> Result<T, String> {
    tokio::pin!(prediction, lease);
    tokio::select! {
        biased;
        _ = cancelled(cancel) => Err("worker_cancelled".into()),
        _ = tokio::time::sleep(duration) => Err("worker_execution_deadline".into()),
        result = &mut lease => Err(result.err().unwrap_or_else(|| "worker_lease_lost".into())),
        result = &mut prediction => result,
    }
}

pub struct NativePredictor {
    child: NativeSidecar,
    roles: Vec<BoundRole>,
}
struct BoundRole {
    client: BoundClient,
    qualification_id: String,
}
struct ActiveExecution<'a> {
    predictor: &'a mut NativePredictor,
    retain: bool,
}
impl Drop for ActiveExecution<'_> {
    fn drop(&mut self) {
        if !self.retain {
            let _ = self.predictor.stop();
        }
    }
}
impl NativePredictor {
    /// Own the process for a serial, cancellable association; errors require fresh orchestration.
    pub async fn run(
        self,
        transport: WorkerTransport,
        qualification: AcceptedQualification,
        mut cancel: watch::Receiver<bool>,
    ) -> Result<(), String> {
        let mut state = (self, transport, qualification);
        let outcome = worker_jobs(
            &mut state,
            |state, mut execution_cancel| {
                Box::pin(async move {
                    state
                        .0
                        .execute_next(&state.1, &state.2, &mut execution_cancel)
                        .await
                })
            },
            &mut cancel,
        )
        .await;
        state.0.stop()?;
        outcome
    }
    /// The sealed qualification and installed runtime must have the same signed manifest identity.
    pub fn start(
        installed: &InstalledRuntime,
        qualified: &QualifiedRuntime,
        qualification: &AcceptedQualification,
        cache: &Path,
        private_root: &Path,
        port: u16,
    ) -> Result<Self, String> {
        Self::start_many(
            installed,
            &[(qualified, qualification)],
            cache,
            private_root,
            port,
        )
    }
    pub fn start_many(
        installed: &InstalledRuntime,
        bindings: &[(&QualifiedRuntime, &AcceptedQualification)],
        cache: &Path,
        private_root: &Path,
        port: u16,
    ) -> Result<Self, String> {
        if !(1..=64).contains(&bindings.len()) {
            return Err("worker_model_binding_invalid".into());
        }
        let mut keys = std::collections::BTreeSet::new();
        for (qualified, accepted) in bindings {
            accepted.validate_runtime(
                qualified,
                (OffsetDateTime::now_utc().unix_timestamp_nanos() / 1_000_000) as i64,
            )?;
            let spec: Value = serde_json::from_slice(qualified.specification())
                .map_err(|_| "worker_model_binding_invalid")?;
            if !keys.insert(
                spec["modelKey"]
                    .as_str()
                    .ok_or("worker_model_binding_invalid")?
                    .to_owned(),
            ) {
                return Err("worker_model_binding_invalid".into());
            }
        }
        let proofs: Vec<_> = bindings.iter().map(|(qualified, _)| *qualified).collect();
        let child = installed.start_bound_sidecar(&proofs, cache, private_root, port)?;
        let roles = bindings
            .iter()
            .map(|(qualified, accepted)| {
                let spec: Value = serde_json::from_slice(qualified.specification())
                    .map_err(|_| "worker_model_binding_invalid")?;
                Ok(BoundRole {
                    client: BoundClient::new(port, child.authorization().into(), &spec)?,
                    qualification_id: accepted.id().into(),
                })
            })
            .collect::<Result<Vec<_>, String>>()?;
        Ok(Self { child, roles })
    }
    pub fn stop(&mut self) -> Result<(), String> {
        self.child.stop()
    }
    async fn ready(&mut self, cancel: &mut watch::Receiver<bool>) -> Result<(), String> {
        let wait = async {
            loop {
                if !self.child.is_running()? {
                    return Err("runtime_process_stopped".into());
                }
                if self.roles[0].client.health().await.unwrap_or(false) {
                    return Ok(());
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        };
        race_prediction(
            wait,
            std::future::pending(),
            cancel,
            Duration::from_secs(15),
        )
        .await
    }
    /// Execute one admitted job; empty NAS model grants cannot claim work.
    pub async fn execute_next(
        &mut self,
        transport: &WorkerTransport,
        qualification: &AcceptedQualification,
        cancel: &mut watch::Receiver<bool>,
    ) -> Result<bool, String> {
        self.execute_next_many(transport, &[qualification], cancel)
            .await
    }
    pub async fn execute_next_many(
        &mut self,
        transport: &WorkerTransport,
        qualifications: &[&AcceptedQualification],
        cancel: &mut watch::Receiver<bool>,
    ) -> Result<bool, String> {
        let mut active = ActiveExecution {
            predictor: self,
            retain: false,
        };
        let outcome = active
            .predictor
            .execute(transport, qualifications, cancel)
            .await;
        if outcome.is_err() {
            active.predictor.stop()?;
        }
        active.retain = true;
        outcome
    }
    async fn execute(
        &mut self,
        transport: &WorkerTransport,
        qualifications: &[&AcceptedQualification],
        cancel: &mut watch::Receiver<bool>,
    ) -> Result<bool, String> {
        if self.roles.len() != qualifications.len()
            || self
                .roles
                .iter()
                .zip(qualifications)
                .any(|(role, accepted)| role.qualification_id != accepted.id())
        {
            return Err("worker_predictor_qualification_changed".into());
        }
        self.ready(cancel).await?;
        let task = race_prediction(
            transport.claim_many(qualifications),
            std::future::pending(),
            cancel,
            Duration::from_secs(30),
        )
        .await?;
        let Some((index, task)) = task else {
            return Ok(false);
        };
        let qualification = qualifications[index];
        let result = async {
            let input = race_prediction(
                transport.input(&task, qualification),
                std::future::pending(),
                cancel,
                execution_duration(&task)?,
            )
            .await?;
            let mut renewed = task.clone();
            let lease = async {
                loop {
                    tokio::time::sleep(Duration::from_secs(20)).await;
                    if !transport.heartbeat(&mut renewed, qualification).await? {
                        return Err("worker_lease_lost".into());
                    }
                }
            };
            let value = race_prediction(
                self.roles[index].client.predict(&task, &input),
                lease,
                cancel,
                execution_duration(&task)?,
            )
            .await?;
            if !self.child.is_running()? {
                return Err("runtime_process_stopped".into());
            }
            let accepted = race_prediction(
                transport.complete(&task, &value, qualification),
                std::future::pending(),
                cancel,
                Duration::from_secs(30),
            )
            .await?;
            if !accepted {
                return Err("worker_result_refused".into());
            }
            Ok(true)
        }
        .await;
        if result.is_err() {
            // Terminate inference before waiting for a failed/cancelled lease acknowledgement.
            self.stop()?;
            let _ = transport
                .fail(&task, WorkerFailure::InferenceFailed, qualification)
                .await;
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use sha2::{Digest, Sha256};
    use std::{
        io::{Read, Write},
        net::TcpListener,
        thread,
    };

    #[test]
    fn worker_loop_can_run_on_the_background_executor() {
        fn check(
            predictor: NativePredictor,
            transport: WorkerTransport,
            qualification: AcceptedQualification,
            cancel: watch::Receiver<bool>,
        ) {
            let future: std::pin::Pin<Box<dyn Future<Output = Result<(), String>> + Send>> =
                Box::pin(predictor.run(transport, qualification, cancel));
            drop(future);
        }
        let _ = check;
    }

    #[tokio::test]
    async fn worker_loop_runs_serially_and_stops_on_first_failure() {
        let (_sender, mut cancel) = watch::channel(false);
        let mut calls = std::cell::Cell::new(0);
        let result = worker_jobs(
            &mut calls,
            |calls, _| {
                Box::pin(async move {
                    calls.set(calls.get() + 1);
                    if calls.get() == 3 {
                        Err("worker_lease_lost".into())
                    } else {
                        Ok(true)
                    }
                })
            },
            &mut cancel,
        )
        .await;
        assert_eq!(calls.get(), 3);
        assert_eq!(result, Err("worker_lease_lost".into()));
    }

    #[tokio::test]
    async fn worker_loop_cancels_a_pending_claim_and_drops_it() {
        struct Guard<'a>(&'a std::sync::atomic::AtomicBool);
        impl Drop for Guard<'_> {
            fn drop(&mut self) {
                self.0.store(true, std::sync::atomic::Ordering::Relaxed);
            }
        }
        let (sender, mut cancel) = watch::channel(false);
        let mut dropped = std::sync::atomic::AtomicBool::new(false);
        let run = worker_jobs(
            &mut dropped,
            |dropped, _| {
                let sender = sender.clone();
                Box::pin(async move {
                    let _guard = Guard(dropped);
                    sender.send(true).unwrap();
                    std::future::pending::<Result<bool, String>>().await
                })
            },
            &mut cancel,
        );
        assert_eq!(run.await, Err("worker_cancelled".into()));
        assert!(dropped.load(std::sync::atomic::Ordering::Relaxed));
    }

    #[tokio::test]
    async fn worker_loop_throttles_immediate_empty_responses() {
        let (sender, mut cancel) = watch::channel(false);
        let calls = std::sync::atomic::AtomicUsize::new(0);
        let mut state = &calls;
        let run = worker_jobs(
            &mut state,
            |calls, _| {
                Box::pin(async move {
                    calls.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    Ok(false)
                })
            },
            &mut cancel,
        );
        tokio::pin!(run);
        assert!(tokio::time::timeout(Duration::from_millis(30), &mut run)
            .await
            .is_err());
        assert_eq!(calls.load(std::sync::atomic::Ordering::Relaxed), 1);
        sender.send(true).unwrap();
        assert_eq!(run.await, Err("worker_cancelled".into()));
    }

    #[tokio::test]
    async fn worker_loop_never_claims_after_control_is_closed() {
        let (sender, mut cancel) = watch::channel(false);
        drop(sender);
        let result = worker_jobs(
            &mut (),
            |_, _| Box::pin(async { panic!("claim after owner disappeared") }),
            &mut cancel,
        )
        .await;
        assert_eq!(result, Err("worker_cancelled".into()));
    }

    fn stamp(offset: i64) -> String {
        let d = time::OffsetDateTime::now_utc() + time::Duration::seconds(offset);
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
    fn task() -> ClaimedTask {
        let config = json!({"clip":{"textual":{"modelName":"fixture"}}}).to_string();
        serde_json::from_value(json!({"id":"d621bd72-ad35-4199-95ab-76300756a38e","taskId":"c39d4385-84f8-4c37-a643-1b98fc12df93","deviceId":"445bc2b6-f4cd-439e-b8bb-7e84d7ee0550","sessionId":"1117c1ca-0495-46e9-b579-f321520c2b1a","authorizationEpoch":1,"generation":1,"modelKey":"fixture-key","configSha256":format!("{:x}",Sha256::digest(config.as_bytes())),"configJson":config,"inputSha256":format!("{:x}",Sha256::digest("été".as_bytes())),"inputKind":"text","maxInputBytes":1024,"expiresAt":stamp(30),"qualificationId":"ff8f1290-3c1d-4695-8696-af493be01fe0","qualificationExpiresAt":stamp(120),"executionDeadline":stamp(60)})).unwrap()
    }
    #[test]
    fn execution_stops_at_qualification_expiry_even_with_a_later_task_deadline() {
        let mut task = task();
        task.qualification_expires_at = stamp(5);
        task.expires_at = stamp(2);
        assert!(execution_duration(&task).unwrap() <= Duration::from_secs(5));
        task.qualification_expires_at = stamp(-1);
        assert!(execution_duration(&task).is_err());
    }

    fn client(port: u16) -> BoundClient {
        BoundClient::new(port, "a".repeat(64), &json!({"modelKey":"fixture-key","entries":{"clip":{"textual":{"modelName":"fixture"}}},"fixtureKind":"text"})).unwrap()
    }
    fn read_request(socket: &mut std::net::TcpStream) -> Vec<u8> {
        socket
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut bytes = Vec::new();
        loop {
            let mut part = [0; 1024];
            let count = socket.read(&mut part).unwrap();
            assert!(count > 0);
            bytes.extend_from_slice(&part[..count]);
            assert!(bytes.len() <= 65536);
            if let Some(end) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
                let header = String::from_utf8_lossy(&bytes[..end]);
                let length: usize = header
                    .lines()
                    .find_map(|line| {
                        line.to_ascii_lowercase()
                            .strip_prefix("content-length: ")
                            .map(str::to_owned)
                    })
                    .unwrap()
                    .parse()
                    .unwrap();
                if bytes.len() >= end + 4 + length {
                    return bytes;
                }
            }
        }
    }
    #[test]
    fn refuses_changed_configuration_model_kind_hash_and_deadlines_before_network() {
        tauri::async_runtime::block_on(async {
            let client = client(19998);
            let mut task = task();
            task.model_key = "other".into();
            assert_eq!(
                client.predict(&task, "été".as_bytes()).await.unwrap_err(),
                "worker_model_binding_invalid"
            );
            task = self::task();
            task.config_json = "{}".into();
            assert!(client.predict(&task, "été".as_bytes()).await.is_err());
            task = self::task();
            task.input_kind = InputKind::Image;
            assert!(client.predict(&task, "été".as_bytes()).await.is_err());
            task = self::task();
            assert!(client.predict(&task, b"changed").await.is_err());
            task.expires_at = stamp(-1);
            assert!(client.predict(&task, "été".as_bytes()).await.is_err());
            task = self::task();
            task.execution_deadline = stamp(800);
            assert!(client.predict(&task, "été".as_bytes()).await.is_err());
        });
    }
    #[test]
    fn loopback_prediction_preserves_utf8_configuration_and_private_authentication() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let bytes = read_request(&mut socket);
            let request = String::from_utf8(bytes).unwrap();
            assert!(request.starts_with("POST /predict "));
            assert!(request
                .to_ascii_lowercase()
                .contains(&format!("authorization: bearer {}", "a".repeat(64))));
            assert!(request.contains("été"));
            assert!(request.contains("fixture"));
            let body = r#"{"clip":"[1,2]"}"#;
            write!(
                socket,
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            )
            .unwrap();
        });
        let value = tauri::async_runtime::block_on(client(port).predict(&task(), "été".as_bytes()))
            .unwrap();
        assert_eq!(value, json!({"clip":"[1,2]"}));
        server.join().unwrap();
    }
    #[test]
    fn cancellation_and_lease_loss_never_return_a_prediction() {
        tauri::async_runtime::block_on(async {
            let (_tx, mut cancel) = tokio::sync::watch::channel(true);
            let result = race_prediction(
                std::future::ready(Ok(1)),
                std::future::pending(),
                &mut cancel,
                Duration::from_secs(1),
            )
            .await;
            assert_eq!(result.unwrap_err(), "worker_cancelled");
            let (_tx, mut cancel) = tokio::sync::watch::channel(false);
            let result: Result<u8, String> = race_prediction(
                std::future::pending(),
                std::future::ready(Err("worker_lease_lost".into())),
                &mut cancel,
                Duration::from_secs(1),
            )
            .await;
            assert_eq!(result.unwrap_err(), "worker_lease_lost");
            let result: Result<u8, String> = race_prediction(
                std::future::pending(),
                std::future::pending(),
                &mut cancel,
                Duration::ZERO,
            )
            .await;
            assert_eq!(result.unwrap_err(), "worker_execution_deadline");
        });
    }
    #[test]
    fn response_redirects_and_nonobject_results_are_refused() {
        for (status, body, expected) in [
            ("302 Found", "{}".to_owned(), "server_http_302"),
            ("200 OK", "[]".to_owned(), "runtime_prediction_invalid"),
            (
                "200 OK",
                format!("{{\"data\":\"{}\"}}", "a".repeat(4 * 1024 * 1024)),
                "server_response_too_large",
            ),
        ] {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let port = listener.local_addr().unwrap().port();
            let server = thread::spawn(move || {
                let (mut socket, _) = listener.accept().unwrap();
                socket
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                let _ = read_request(&mut socket);
                let _ = write!(socket, "HTTP/1.1 {status}\r\nLocation: http://127.0.0.1:1/private\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
            });
            assert_eq!(
                tauri::async_runtime::block_on(client(port).predict(&task(), "été".as_bytes()))
                    .unwrap_err(),
                expected
            );
            server.join().unwrap();
        }
    }
    #[test]
    fn cancellation_drops_an_inflight_http_prediction() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let (tx, mut cancel) = tokio::sync::watch::channel(false);
        let server = thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let _ = read_request(&mut socket);
            tx.send(true).unwrap();
            assert_eq!(
                socket.read(&mut [0; 1]).unwrap(),
                0,
                "cancelled prediction connection remained open"
            );
        });
        tauri::async_runtime::block_on(async {
            let client = client(port);
            let task = task();
            let result = race_prediction(
                client.predict(&task, "été".as_bytes()),
                std::future::pending(),
                &mut cancel,
                Duration::from_secs(10),
            )
            .await;
            assert_eq!(result.unwrap_err(), "worker_cancelled");
        });
        server.join().unwrap();
    }
    #[test]
    fn image_prediction_preserves_binary_bytes_and_uses_a_file_part() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let input = [0xff, 0, 0x80];
        let server = thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            let bytes = read_request(&mut socket);
            assert!(bytes.windows(input.len()).any(|w| w == input));
            assert!(String::from_utf8_lossy(&bytes).contains("name=\"image\"; filename=\"input\""));
            socket
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}")
                .unwrap();
        });
        let mut task = task();
        task.input_kind = InputKind::Image;
        task.input_sha256 = format!("{:x}", Sha256::digest(input));
        let entries = json!({"clip":{"visual":{"modelName":"fixture"}}});
        task.config_json = entries.to_string();
        task.config_sha256 = format!("{:x}", Sha256::digest(task.config_json.as_bytes()));
        let client = BoundClient::new(
            port,
            "a".repeat(64),
            &json!({"modelKey":"fixture-key", "entries":entries, "fixtureKind":"image"}),
        )
        .unwrap();
        assert_eq!(
            tauri::async_runtime::block_on(client.predict(&task, &input)).unwrap(),
            json!({})
        );
        server.join().unwrap();
    }
    #[test]
    fn dropping_a_pending_execution_stops_its_owned_process() {
        use crate::native_runtime::VerifiedRuntime;
        use ed25519_dalek::{Signer, SigningKey};
        use std::{
            fs,
            process::Command,
            task::{Context, Poll, Waker},
        };
        let root = std::env::temp_dir()
            .canonicalize()
            .unwrap()
            .join(format!("frameleaf-abort-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&root).unwrap();
        for name in ["pack", "cache", "work", "compiler"] {
            fs::create_dir(root.join(name)).unwrap();
        }
        let source = root.join("compiler/main.rs");
        fs::write(&source,r#"use std::{io::{self,Read},thread,time::Duration};fn main(){let mut gate=[0;23];io::stdin().read_exact(&mut gate).unwrap();loop{thread::sleep(Duration::from_millis(10));}}"#).unwrap();
        let name = if cfg!(windows) {
            "python.exe"
        } else {
            "python"
        };
        assert!(Command::new("rustc")
            .arg(&source)
            .arg("-o")
            .arg(root.join("compiler").join(name))
            .status()
            .unwrap()
            .success());
        fs::copy(
            root.join("compiler").join(name),
            root.join("pack").join(name),
        )
        .unwrap();
        let bytes = fs::read(root.join("pack").join(name)).unwrap();
        let raw=serde_json::to_vec(&json!({"schemaVersion":1,"protocolVersion":1,"epoch":1,"platform":std::env::consts::OS,"architecture":std::env::consts::ARCH,"provider":"CPUExecutionProvider","python":name,"sourceRevision":"a".repeat(40),"files":{name:{"sha256":format!("{:x}",Sha256::digest(&bytes)),"bytes":bytes.len()}}})).unwrap();
        let key = SigningKey::from_bytes(&[42; 32]);
        let pack = VerifiedRuntime::verify(
            &root.join("pack"),
            &raw,
            &key.sign(&raw).to_bytes(),
            &[key.verifying_key()],
            1,
        )
        .unwrap();
        let child = pack
            .start_sidecar(&root.join("cache"), &root.join("work"), 19998)
            .unwrap();
        let mut predictor = NativePredictor {
            child,
            roles: vec![BoundRole {
                client: client(19998),
                qualification_id: "fixture".into(),
            }],
        };
        assert!(predictor.child.is_running().unwrap());
        let (_sender, mut cancel) = watch::channel(false);
        let mut future = Box::pin(worker_jobs(
            &mut predictor,
            |predictor, _| {
                Box::pin(async move {
                    let _active = ActiveExecution {
                        predictor,
                        retain: false,
                    };
                    std::future::pending::<Result<bool, String>>().await
                })
            },
            &mut cancel,
        ));
        let mut context = Context::from_waker(Waker::noop());
        assert!(matches!(future.as_mut().poll(&mut context), Poll::Pending));
        drop(future);
        assert!(!predictor.child.is_running().unwrap());
        drop(predictor);
        fs::remove_dir_all(root).unwrap();
    }
}
