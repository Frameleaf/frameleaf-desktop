use crate::connection::{normalize_server, Capabilities, Enrollment, SavedConnection};
use crate::credentials;
use reqwest::{Client, Response, StatusCode};
use serde::de::DeserializeOwned;
use std::time::Duration;

pub fn client() -> Result<Client, String> {
    Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(30))
        .user_agent(concat!("FrameleafDesktop/", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|_| "network_client_unavailable".into())
}
pub async fn json<T: DeserializeOwned>(mut response: Response) -> Result<T, String> {
    if !response.status().is_success() {
        return Err(format!("server_http_{}", response.status().as_u16()));
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| "server_response_interrupted")?
    {
        if bytes.len() + chunk.len() > 65_536 {
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
