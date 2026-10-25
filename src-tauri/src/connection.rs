use base64::{engine::general_purpose::STANDARD, Engine};
use ed25519_dalek::{Signer, SigningKey};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};
use url::Url;
use uuid::Uuid;
use zeroize::ZeroizeOnDrop;

pub fn normalize_server(value: &str) -> Result<Url, String> {
    if value.contains('\\') {
        return Err("server_address_invalid".into());
    }
    let url = Url::parse(value.trim()).map_err(|_| "server_address_invalid")?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || !matches!(url.path(), "" | "/")
    {
        return Err("server_requires_https_origin".into());
    }
    Ok(url)
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EnrollmentRequest {
    pub protocol_version: u8,
    pub installation_id: String,
    pub request_id: String,
    pub public_key: String,
    pub name: String,
    pub platform: String,
    pub architecture: String,
    pub mode: String,
    pub timestamp: u64,
    pub signature: String,
}

pub fn enrollment_message(server: &str, account: &str, dto: &EnrollmentRequest) -> String {
    [
        "frameleaf-desktop/enroll/v1",
        server,
        account,
        &dto.installation_id,
        &dto.request_id,
        &dto.timestamp.to_string(),
        &dto.public_key,
        &dto.name,
        &dto.platform,
        &dto.architecture,
        &dto.mode,
    ]
    .join("\n")
}

#[derive(Serialize, Deserialize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
pub struct DeviceIdentity {
    pub installation_id: String,
    secret: [u8; 32],
    #[serde(default, rename = "runtimeEpochs")]
    #[zeroize(skip)]
    pub(crate) runtime_epochs: Option<crate::runtime_epochs::RuntimeEpochs>,
    #[serde(default, rename = "hostEpochs")]
    #[zeroize(skip)]
    pub(crate) host_epochs: Option<crate::host_epochs::HostEpochs>,
}
impl DeviceIdentity {
    pub fn public_key(&self) -> String {
        STANDARD.encode(
            SigningKey::from_bytes(&self.secret)
                .verifying_key()
                .as_bytes(),
        )
    }
    pub fn sign(&self, message: &str) -> String {
        STANDARD.encode(
            SigningKey::from_bytes(&self.secret)
                .sign(message.as_bytes())
                .to_bytes(),
        )
    }
    pub fn generate() -> Self {
        let mut secret = [0; 32];
        rand::rngs::OsRng.fill_bytes(&mut secret);
        Self {
            installation_id: Uuid::new_v4().to_string(),
            secret,
            runtime_epochs: Some(crate::runtime_epochs::RuntimeEpochs::default()),
            host_epochs: Some(crate::host_epochs::HostEpochs::default()),
        }
    }
    pub fn enrollment(
        &self,
        server: &str,
        account: &str,
        name: &str,
        mode: &str,
    ) -> Result<EnrollmentRequest, String> {
        if name.trim().is_empty()
            || name.chars().count() > 128
            || name.chars().any(char::is_control)
            || !matches!(mode, "client-worker" | "local-server")
        {
            return Err("device_details_invalid".into());
        }
        let key = SigningKey::from_bytes(&self.secret);
        let mut dto = EnrollmentRequest {
            protocol_version: 1,
            installation_id: self.installation_id.clone(),
            request_id: Uuid::new_v4().to_string(),
            public_key: STANDARD.encode(key.verifying_key().as_bytes()),
            name: name.trim().into(),
            platform: match std::env::consts::OS {
                "macos" => "macos",
                "windows" => "windows",
                "linux" => "linux",
                _ => return Err("platform_unsupported".into()),
            }
            .into(),
            architecture: match std::env::consts::ARCH {
                "aarch64" => "arm64",
                "x86_64" => "x86_64",
                _ => return Err("architecture_unsupported".into()),
            }
            .into(),
            mode: mode.into(),
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|_| "clock_invalid")?
                .as_millis() as u64,
            signature: String::new(),
        };
        dto.signature = STANDARD.encode(
            key.sign(enrollment_message(server, account, &dto).as_bytes())
                .to_bytes(),
        );
        Ok(dto)
    }
}

#[derive(Clone, Serialize, Deserialize, ZeroizeOnDrop)]
#[serde(rename_all = "camelCase")]
pub struct SavedConnection {
    pub server: String,
    pub server_id: String,
    pub account_id: String,
    pub name: String,
    pub token: String,
    pub device_name: String,
    pub mode: String,
    pub device_id: Option<String>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Features {
    pub enrollment: bool,
    pub worker: bool,
    #[serde(default)]
    pub worker_session: bool,
    #[serde(default)]
    pub qualification_memory: bool,
    pub sources: bool,
    #[serde(default)]
    pub reference_publication: u8,
    pub native_host: bool,
}
impl Features {
    pub(crate) fn require_reference_publication(&self) -> Result<(), String> {
        if self.reference_publication != 1 {
            return Err("source_server_update_required".into());
        }
        Ok(())
    }

    pub(crate) fn require_worker_qualification(&self) -> Result<(), String> {
        if !self.worker_session {
            return Err("desktop_worker_session_unavailable".into());
        }
        if !self.qualification_memory {
            return Err("desktop_worker_memory_unavailable".into());
        }
        Ok(())
    }
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Capabilities {
    pub protocol_version: u8,
    pub server_id: String,
    pub features: Features,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Enrollment {
    pub id: String,
    pub state: String,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnectionView {
    pub server: String,
    pub name: String,
    pub mode: String,
    pub state: String,
    pub features: Features,
}
impl ConnectionView {
    pub fn new(saved: &SavedConnection, state: String, features: Features) -> Self {
        Self {
            server: saved.server.clone(),
            name: saved.name.clone(),
            mode: saved.mode.clone(),
            state,
            features,
        }
    }
}

/// Persist the identity before enrollment can fail; retries must never silently trust a replacement.
pub fn persist_server_identity(
    saved: &mut SavedConnection,
    identity: &str,
    persist: impl FnOnce(&SavedConnection) -> Result<(), String>,
) -> Result<(), String> {
    if identity.is_empty() || (!saved.server_id.is_empty() && saved.server_id != identity) {
        return Err("server_identity_changed".into());
    }
    let mut checkpoint = saved.clone();
    checkpoint.server_id = identity.into();
    persist(&checkpoint)?;
    saved.server_id = identity.into();
    Ok(())
}

pub fn native_origin_allowed(label: &str, url: &Url, development_build: bool) -> bool {
    if !url.username().is_empty() || url.password().is_some() {
        return false;
    }
    let packaged = url.port().is_none()
        && ((url.scheme() == "tauri" && url.host_str() == Some("localhost"))
            || (matches!(url.scheme(), "https" | "http")
                && url.host_str() == Some("tauri.localhost")));
    let development = development_build
        && url.scheme() == "http"
        && url.host_str() == Some("localhost")
        && url.port() == Some(1420);
    label == "main" && (packaged || development)
}

#[cfg(test)]
mod memory_capability_tests {
    use super::*;
    #[test]
    fn reference_publication_capability_preserves_the_explicit_protocol_version() {
        let value = serde_json::json!({"enrollment":true,"worker":false,"workerSession":true,"qualificationMemory":true,"sources":false,"nativeHost":false,"referencePublication":1});
        let features: Features = serde_json::from_value(value).unwrap();
        assert_eq!(
            serde_json::to_value(features).unwrap()["referencePublication"],
            1
        );
    }
    #[test]
    fn reference_capability_defaults_closed_and_rejects_other_versions() {
        let mut value = serde_json::json!({"enrollment":true,"worker":false,"sources":false,"nativeHost":false});
        let legacy: Features = serde_json::from_value(value.clone()).unwrap();
        assert_eq!(
            legacy.require_reference_publication().err().as_deref(),
            Some("source_server_update_required")
        );
        for version in [0, 1, 2] {
            value["referencePublication"] = serde_json::json!(version);
            let features: Features = serde_json::from_value(value.clone()).unwrap();
            assert_eq!(
                features.require_reference_publication().is_ok(),
                version == 1
            );
        }
    }
    #[test]
    fn older_server_keeps_photo_enrollment_but_cannot_start_memory_qualification() {
        let mut value = serde_json::json!({"enrollment":true,"worker":false,"workerSession":true,
            "sources":false,"nativeHost":false});
        let older: Features = serde_json::from_value(value.clone()).unwrap();
        assert!(older.enrollment);
        assert!(!older.qualification_memory);
        assert_eq!(
            older.require_worker_qualification().unwrap_err(),
            "desktop_worker_memory_unavailable"
        );
        value["qualificationMemory"] = serde_json::json!(true);
        let current: Features = serde_json::from_value(value.clone()).unwrap();
        current.require_worker_qualification().unwrap();
        value["workerSession"] = serde_json::json!(false);
        let disabled: Features = serde_json::from_value(value).unwrap();
        assert_eq!(
            disabled.require_worker_qualification().unwrap_err(),
            "desktop_worker_session_unavailable"
        );
    }
}
