use base64::{engine::general_purpose::STANDARD, Engine};
use ed25519_dalek::{Signer, SigningKey};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};
use url::Url;
use uuid::Uuid;
use zeroize::ZeroizeOnDrop;

pub fn normalize_server(value: &str) -> Result<Url, String> {
    if value.contains('\\') {
        return Err("server_address_invalid".into());
    }
    let url = Url::parse(value.trim()).map_err(|_| "server_address_invalid")?;
    let local_http = url.scheme() == "http" && url.host().is_some_and(is_local_network);
    if !(url.scheme() == "https" || local_http)
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

/// A host on this computer or the local network, where servers answer over plain HTTP: loopback,
/// private and link-local addresses, single-label names and the local-only DNS suffixes. Tailscale
/// counts as local: its 100.64.0.0/10 addresses, its fd7a:115c:a1e0::/48 ULAs and `*.ts.net` names.
pub fn is_local_network(host: url::Host<&str>) -> bool {
    match host {
        url::Host::Ipv4(ip) => {
            let [a, b, ..] = ip.octets();
            ip.is_private()
                || ip.is_loopback()
                || ip.is_link_local()
                || (a == 100 && (b & 0xc0) == 64)
        }
        url::Host::Ipv6(ip) => {
            let first = ip.segments()[0];
            ip.is_loopback() || (first & 0xfe00) == 0xfc00 || (first & 0xffc0) == 0xfe80
        }
        url::Host::Domain(name) => {
            let name = name.trim_end_matches('.').to_ascii_lowercase();
            !name.is_empty()
                && (!name.contains('.')
                    || [
                        ".local",
                        ".lan",
                        ".home.arpa",
                        ".internal",
                        ".localdomain",
                        ".ts.net",
                    ]
                    .iter()
                    .any(|suffix| name.ends_with(suffix)))
        }
    }
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
pub struct DeviceIdentity {
    pub installation_id: String,
    secret: [u8; 32],
    #[serde(default, rename = "runtimeEpochs")]
    #[zeroize(skip)]
    pub(crate) runtime_epochs: Option<crate::runtime_epochs::RuntimeEpochs>,
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
    pub sources: bool,
    pub native_host: bool,
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
    pub navigation_scope: Option<String>,
    pub server: String,
    pub name: String,
    pub mode: String,
    pub state: String,
    pub features: Features,
}
impl ConnectionView {
    pub fn new(saved: &SavedConnection, state: String, features: Features) -> Self {
        let navigation_scope = (!saved.server_id.is_empty()
            && !saved.account_id.is_empty()
            && !matches!(
                state.as_str(),
                "identity-changed"
                    | "offline"
                    | "unsupported-server"
                    | "credential-store-unavailable"
            ))
        .then(|| {
            let binding = serde_json::to_vec(&(&saved.server, &saved.server_id, &saved.account_id))
                .expect("serializing strings cannot fail");
            format!("{:x}", Sha256::digest(binding))
        });
        Self {
            navigation_scope,
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
mod local_http_tests {
    use super::*;

    #[test]
    fn plain_http_is_accepted_only_on_the_local_network() {
        for local in [
            "http://192.168.1.20:2283",
            "http://10.0.0.5",
            "http://172.16.4.2:2283/",
            "http://127.0.0.1:2283",
            "http://169.254.1.1",
            "http://[fd00::7]:2283",
            "http://[fe80::1]",
            "http://[::1]",
            "http://tower",
            "http://localhost:2283",
            "http://tower.local:2283",
            "http://nas.home.arpa",
            "http://nas.lan",
            "http://100.64.0.1:2283",
            "http://100.127.255.254",
            "http://[fd7a:115c:a1e0::1]",
            "http://nas.tail1234.ts.net",
        ] {
            assert!(normalize_server(local).is_ok(), "{local}");
        }
        for remote in [
            "http://photos.example.com",
            "http://8.8.8.8",
            "http://100.63.255.255",
            "http://100.128.0.1",
            "http://ts.net.example.com",
            "http://[2001:db8::1]",
            "http://192.168.1.20/photos",
        ] {
            assert!(normalize_server(remote).is_err(), "{remote}");
        }
        assert!(normalize_server("https://photos.example.com").is_ok());
    }
}
