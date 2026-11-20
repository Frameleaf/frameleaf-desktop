use crate::connection::{normalize_server, Capabilities, Enrollment, SavedConnection};
use crate::credentials;
use reqwest::{Client, ClientBuilder, Response, StatusCode};
use serde::de::DeserializeOwned;
use std::time::Duration;

// Isolated opt-in fixtures supply their private CA without changing release TLS policy.
#[cfg(test)]
pub(crate) static FIXTURE_CLIENT: std::sync::OnceLock<Client> = std::sync::OnceLock::new();

pub fn client() -> Result<Client, String> {
    #[cfg(test)]
    if let Some(client) = FIXTURE_CLIENT.get() {
        return Ok(client.clone());
    }

    client_builder()
        .build()
        .map_err(|_| "network_client_unavailable".into())
}

pub(crate) fn client_builder() -> ClientBuilder {
    streaming_client_builder().timeout(Duration::from_secs(30))
}

pub(crate) fn streaming_client_builder() -> ClientBuilder {
    // A proxy would look a plain-HTTP home name up itself, and be handed the request, without
    // this app checking where it leads. A home server is reached directly.
    match crate::connection::plain_http_names_in_use() {
        true => public_client_builder().no_proxy(),
        false => public_client_builder(),
    }
}

/// For Frameleaf's own download hosts (the model mirror, the release host), never a person's
/// server: always through the system's proxy settings, whatever server is in use.
pub(crate) fn public_client_builder() -> ClientBuilder {
    Client::builder()
        // Operating-system roots are loaded only for Manager's system-trust option.
        .tls_built_in_native_certs(false)
        .redirect(reqwest::redirect::Policy::none())
        // A name reached over plain HTTP may connect only to the home network.
        .dns_resolver(std::sync::Arc::new(crate::connection::HomeResolver))
        // Retry only through our durable coordinators, so payload attempts cannot evade admission.
        .retry(reqwest::retry::never())
        .user_agent(concat!("FrameleafDesktop/", env!("CARGO_PKG_VERSION")))
}
/// Clocks closer than this are treated as equal: the server accepts requests timed within two
/// minutes of its own clock, and `Date` only counts whole seconds.
const CLOCK_SKEW_IGNORED_MS: i64 = 30_000;
/// How far the server's clock is ahead of this computer's (negative: behind), from the `Date`
/// header of one of its responses and this computer's clock when it arrived. Zero when the
/// clocks agree, so a computer with a correct clock behaves exactly as before; `None` when the
/// header is missing or unreadable. A real difference is returned so requests can be timed, and the
/// server's deadlines read, by the server's clock: a wrong clock here must not stop AI work.
pub(crate) fn clock_skew_from(date: Option<&str>, local_ms: i64) -> Option<i64> {
    let server =
        time::OffsetDateTime::parse(date?, &time::format_description::well_known::Rfc2822).ok()?;
    let skew = (server.unix_timestamp_nanos() / 1_000_000) as i64 - local_ms;
    if skew.abs() < CLOCK_SKEW_IGNORED_MS {
        return Some(0);
    }
    // `Date` is cut to the second and was written before the response travelled: without this,
    // the corrected clock would run up to about two seconds behind the server's.
    Some(skew + 2_000)
}
/// `None` when the response says nothing usable about the server's clock.
pub(crate) fn clock_skew(response: &Response) -> Option<i64> {
    let local = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_millis() as i64;
    let date = response.headers().get(reqwest::header::DATE);
    clock_skew_from(date.and_then(|value| value.to_str().ok()), local)
}
/// The named reason (`message`) of a refused request. Anything but a small JSON error (a
/// proxy's page, a cut connection) has no name.
pub(crate) async fn refused(mut response: Response) -> (u16, String) {
    let status = response.status().as_u16();
    let mut bytes = Vec::new();
    loop {
        match response.chunk().await {
            Ok(Some(chunk)) if bytes.len() + chunk.len() <= 4096 => bytes.extend_from_slice(&chunk),
            Ok(None) => break,
            // Too long, or cut short: what arrived is not known to be the server's whole reply.
            _ => return (status, String::new()),
        }
    }
    let message = serde_json::from_slice::<serde_json::Value>(&bytes)
        .ok()
        .and_then(|value| value["message"].as_str().map(str::to_owned))
        .unwrap_or_default();
    (status, message)
}
pub async fn json<T: DeserializeOwned>(response: Response) -> Result<T, String> {
    json_limit(response, 65_536).await
}
pub(crate) async fn json_limit<T: DeserializeOwned>(
    mut response: Response,
    limit: usize,
) -> Result<T, String> {
    if !response.status().is_success() {
        return Err(format!("server_http_{}", response.status().as_u16()));
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| "server_response_interrupted")?
    {
        if bytes.len() + chunk.len() > limit {
            return Err("server_response_too_large".into());
        }
        bytes.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&bytes).map_err(|_| "server_response_invalid".into())
}
pub async fn capabilities(
    client: &Client,
    saved: &SavedConnection,
) -> Result<Option<Capabilities>, String> {
    let base = normalize_server(&saved.server)?;
    let response = client
        .get(base.join("api/desktop/capabilities").unwrap())
        .bearer_auth(&saved.token)
        .send()
        .await
        .map_err(|_| "server_unreachable_or_certificate_invalid")?;
    if response.status() == StatusCode::NOT_FOUND {
        return Ok(None);
    }
    let clock_skew_ms = clock_skew(&response).unwrap_or(0);
    let mut caps: Capabilities = json(response).await?;
    caps.clock_skew_ms = clock_skew_ms;
    if caps.protocol_version != 1 || caps.server_id.is_empty() || caps.server_id.len() > 128 {
        return Err("desktop_protocol_unsupported".into());
    }
    if !saved.server_id.is_empty() && saved.server_id != caps.server_id {
        return Err("server_identity_changed".into());
    }
    Ok(Some(caps))
}
/// `clock_skew_ms`: from the capabilities just read (`Capabilities::clock_skew_ms`).
pub async fn enroll(
    client: &Client,
    saved: &SavedConnection,
    clock_skew_ms: i64,
) -> Result<Enrollment, String> {
    enroll_with_identity(client, saved, &credentials::identity()?, clock_skew_ms).await
}

pub(crate) async fn enroll_with_identity(
    client: &Client,
    saved: &SavedConnection,
    identity: &crate::connection::DeviceIdentity,
    clock_skew_ms: i64,
) -> Result<Enrollment, String> {
    let dto = identity.enrollment_at(
        &saved.server_id,
        &saved.account_id,
        &saved.device_name,
        &saved.mode,
        clock_skew_ms,
    )?;
    let base = normalize_server(&saved.server)?;
    let response = client
        .post(base.join("api/desktop/devices/enroll").unwrap())
        .bearer_auth(&saved.token)
        .json(&dto)
        .send()
        .await
        .map_err(|_| "desktop_enrollment_interrupted")?;
    if !response.status().is_success() {
        let (status, message) = refused(response).await;
        // The server refuses a request timed more than two minutes from its own clock.
        return Err(if message == "device_proof_expired" {
            "clock_invalid".into()
        } else {
            format!("server_http_{status}")
        });
    }
    json(response).await
}

/// A refusal keeps its name (`ml_transport::worker_refusal`): the worker waits out "AI processing
/// is off" and "not on the home network" instead of failing with a bare status.
pub async fn issue_worker_session(
    client: &Client,
    saved: &SavedConnection,
    clock_skew_ms: i64,
) -> Result<crate::worker::SavedWorker, String> {
    issue_worker_session_as(client, saved, &credentials::identity()?, clock_skew_ms).await
}

pub(crate) async fn issue_worker_session_as(
    client: &Client,
    saved: &SavedConnection,
    identity: &crate::connection::DeviceIdentity,
    clock_skew_ms: i64,
) -> Result<crate::worker::SavedWorker, String> {
    let device = saved
        .device_id
        .as_ref()
        .ok_or("desktop_enrollment_required")?;
    let dto = crate::worker::session_request_at(
        identity,
        &saved.server_id,
        &saved.account_id,
        device,
        clock_skew_ms,
    )?;
    let base = normalize_server(&saved.server)?;
    let response = client
        .post(base.join("api/desktop/devices/session").unwrap())
        .bearer_auth(&saved.token)
        .json(&dto)
        .send()
        .await
        .map_err(|_| "worker_session_setup_interrupted")?;
    if !response.status().is_success() {
        let (status, message) = refused(response).await;
        return Err(crate::ml_transport::session_refusal(status, &message));
    }
    let response: crate::worker::SessionResponse = json(response).await?;
    crate::worker::bind_session(saved, &response)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        io::{Read, Write},
        net::TcpListener,
        thread,
    };

    fn reply(body: String, status: u16) -> (String, thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/", listener.local_addr().unwrap());
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = Vec::new();
            while !request.ends_with(b"\r\n\r\n") {
                let mut byte = [0];
                stream.read_exact(&mut byte).unwrap();
                request.push(byte[0]);
                assert!(request.len() < 8192);
            }
            let response=format!("HTTP/1.1 {status} Test\r\nContent-Length: {}\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{body}",body.len());
            let _ = stream.write_all(response.as_bytes());
        });
        (url, handle)
    }
    #[tokio::test]
    #[ignore = "uses a process-local synthetic Keychain; run alone"]
    async fn cancelled_first_unlock_preserves_only_a_verified_restartable_sign_in() {
        crate::ml_transport::native_nas_tests::install_test_keyring();
        let caps = serde_json::json!({"protocolVersion":1,"serverId":"known-server","features":{
            "enrollment":false,"worker":false,"sources":false,"nativeHost":false
        }});
        for (status, failure, expected_error, expected_token) in [
            (
                200,
                "credential_unlock_required",
                "credential_unlock_required",
                Some("fixture"),
            ),
            (
                200,
                "credential_confirmation_unavailable",
                "credential_confirmation_unavailable",
                Some("fixture"),
            ),
            (
                200,
                "credential_confirmation_changed",
                "credential_confirmation_changed",
                Some("replacement"),
            ),
            (
                404,
                "credential_unlock_required",
                "server_sign_in_retry_required",
                None,
            ),
        ] {
            let (url, server) = reply(caps.to_string(), status);
            let mut saved = SavedConnection {
                server: url,
                server_id: String::new(),
                account_id: "account".into(),
                name: "Test".into(),
                token: "fixture".into(),
                device_name: "Fixture".into(),
                mode: "client-worker".into(),
                device_id: None,
            };
            let result = crate::finish_new_connection(&client().unwrap(), &mut saved, |expected| {
                if failure == "credential_confirmation_changed" {
                    let mut replacement = expected.clone();
                    replacement.token = "replacement".into();
                    crate::credentials::save("connection", &replacement)?;
                }
                Err(failure.into())
            })
            .await;
            assert_eq!(result.err().as_deref(), Some(expected_error));
            let stored: Option<SavedConnection> = crate::credentials::load("connection").unwrap();
            if let Some(expected_token) = expected_token {
                let stored = stored.unwrap();
                assert_eq!(stored.server_id, "known-server");
                assert_eq!(stored.account_id, saved.account_id);
                assert_eq!(stored.token, expected_token);
                crate::credentials::delete("connection").unwrap();
            } else {
                assert!(stored.is_none());
            }
            server.join().unwrap();
        }
    }
    /// Run in a child process (`a_plain_http_home_name_is_never_sent_through_a_configured_proxy`),
    /// where the proxy variables can be set without touching the tests running beside this one.
    #[test]
    #[ignore = "run by its parent test, in a process of its own"]
    fn proxy_child() {
        let Ok(case) = std::env::var("FRAMELEAF_PROXY_CASE") else {
            return;
        };
        let url = if case == "home" {
            // As restoring a saved sign-in and adding a library do: the server is taken into
            // use first, then the client that will carry the credential is built.
            let base = normalize_server("http://nas.proxied.test:2283").unwrap();
            base.join("api/users/me").unwrap()
        } else {
            reqwest::Url::parse("http://control.proxied.test/api/users/me").unwrap()
        };
        let client = client().unwrap();
        tauri::async_runtime::block_on(async {
            let request = client.get(url).bearer_auth("secret").send();
            let _ = tokio::time::timeout(Duration::from_secs(3), request).await;
        });
    }
    #[test]
    fn a_plain_http_home_name_is_never_sent_through_a_configured_proxy() {
        let child = |case: &str| {
            // The "proxy": anything that connects to it was sent through the proxy.
            let proxy = TcpListener::bind("127.0.0.1:0").unwrap();
            let address = format!("http://{}", proxy.local_addr().unwrap());
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "transport::tests::proxy_child", "--ignored"])
                .env("FRAMELEAF_PROXY_CASE", case)
                .env("HTTP_PROXY", &address)
                .env("http_proxy", &address)
                .env("ALL_PROXY", &address)
                .env_remove("NO_PROXY")
                .env_remove("no_proxy")
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()
                .unwrap();
            assert!(status.success(), "{case}");
            proxy.set_nonblocking(true).unwrap();
            proxy.accept().is_ok()
        };
        // The check can see a proxied request: plain HTTP built without taking a home name
        // into use goes to the configured proxy.
        assert!(
            child("control"),
            "the control request did not reach the proxy"
        );
        // A plain-HTTP home name, in a fresh process, with its credential: never the proxy.
        assert!(
            !child("home"),
            "the home server's request went to the proxy"
        );
    }
    #[test]
    fn keeps_photo_json_small_and_accepts_only_explicit_bounded_worker_replies() {
        tauri::async_runtime::block_on(async {
            let body = serde_json::json!({"value":"x".repeat(70_000)}).to_string();
            let (url, server) = reply(body.clone(), 200);
            let response = client().unwrap().get(url).send().await.unwrap();
            assert_eq!(
                json::<serde_json::Value>(response).await.unwrap_err(),
                "server_response_too_large"
            );
            server.join().unwrap();
            let (url, server) = reply(body, 200);
            let response = client().unwrap().get(url).send().await.unwrap();
            assert_eq!(
                json_limit::<serde_json::Value>(response, 256 * 1024)
                    .await
                    .unwrap()["value"]
                    .as_str()
                    .unwrap()
                    .len(),
                70_000
            );
            server.join().unwrap();
            let (url, server) = reply(
                serde_json::json!({"value":"x".repeat(256*1024)}).to_string(),
                200,
            );
            let response = client().unwrap().get(url).send().await.unwrap();
            assert_eq!(
                json_limit::<serde_json::Value>(response, 256 * 1024)
                    .await
                    .unwrap_err(),
                "server_response_too_large"
            );
            server.join().unwrap();
            let (url, server) = reply("private server diagnostic".into(), 401);
            let response = client().unwrap().get(url).send().await.unwrap();
            assert_eq!(
                json::<serde_json::Value>(response).await.unwrap_err(),
                "server_http_401"
            );
            server.join().unwrap();
        });
    }
}
