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
    Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        // Retry only through our durable coordinators, so payload attempts cannot evade admission.
        .retry(reqwest::retry::never())
        .user_agent(concat!("FrameleafDesktop/", env!("CARGO_PKG_VERSION")))
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
    let caps: Capabilities = json(response).await?;
    if caps.protocol_version != 1 || caps.server_id.is_empty() || caps.server_id.len() > 128 {
        return Err("desktop_protocol_unsupported".into());
    }
    if !saved.server_id.is_empty() && saved.server_id != caps.server_id {
        return Err("server_identity_changed".into());
    }
    Ok(Some(caps))
}
pub async fn enroll(client: &Client, saved: &SavedConnection) -> Result<Enrollment, String> {
    let identity = credentials::identity()?;
    let dto = identity.enrollment(
        &saved.server_id,
        &saved.account_id,
        &saved.device_name,
        &saved.mode,
    )?;
    let base = normalize_server(&saved.server)?;
    json(
        client
            .post(base.join("api/desktop/devices/enroll").unwrap())
            .bearer_auth(&saved.token)
            .json(&dto)
            .send()
            .await
            .map_err(|_| "desktop_enrollment_interrupted")?,
    )
    .await
}

pub async fn issue_worker_session(
    client: &Client,
    saved: &SavedConnection,
) -> Result<crate::worker::SavedWorker, String> {
    let identity = credentials::identity()?;
    let device = saved
        .device_id
        .as_ref()
        .ok_or("desktop_enrollment_required")?;
    let dto =
        crate::worker::session_request(&identity, &saved.server_id, &saved.account_id, device)?;
    let base = normalize_server(&saved.server)?;
    let response: crate::worker::SessionResponse = json(
        client
            .post(base.join("api/desktop/devices/session").unwrap())
            .bearer_auth(&saved.token)
            .json(&dto)
            .send()
            .await
            .map_err(|_| "worker_session_setup_interrupted")?,
    )
    .await?;
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
