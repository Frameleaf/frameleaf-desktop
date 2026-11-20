use base64::{engine::general_purpose::STANDARD, Engine};
use ed25519_dalek::{Signer, SigningKey};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};
use url::Url;
use uuid::Uuid;
use zeroize::ZeroizeOnDrop;

/// The origin of a server this app talks to: HTTPS anywhere, or plain HTTP on the home network.
///
/// Plain HTTP to an address must be to a local one. Plain HTTP to a *name* is accepted here
/// without looking the name up: a home server saved as `http://nas.fritz.box:2283` stays a
/// valid server when the laptop is away or the router's DNS is down, and failing to reach it is
/// an ordinary network error. That such a name leads only to the home network is enforced where
/// it matters, when connecting (`HomeResolver`), and checked once when a person types it
/// (`typed_servers`).
pub fn normalize_server(value: &str) -> Result<Url, String> {
    let url = server_origin(value)?;
    if url.scheme() == "http" {
        if let Some(name) = looked_up_name(&url) {
            // From now until the app quits, connections to this name are held to the home
            // network. It is never taken off again: something still running may be using the
            // plain-HTTP origin (the AI worker keeps its base address), and an HTTPS address
            // for the same name appearing elsewhere must not lift the rule under it.
            PLAIN_HTTP_NAMES.lock().unwrap().insert(name);
        }
    }
    Ok(url)
}

/// `normalize_server` without taking the origin into use: nothing is held to the home network
/// yet. For an address that may not be used at all (the plain-HTTP fallback of a typed name).
pub(crate) fn server_origin(value: &str) -> Result<Url, String> {
    if value.contains('\\') {
        return Err("server_address_invalid".into());
    }
    let url = Url::parse(value.trim()).map_err(|_| "server_address_invalid")?;
    let named = matches!(url.host(), Some(url::Host::Domain(_)));
    let local_http = url.scheme() == "http" && (named || url.host().is_some_and(is_local_network));
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

/// The host of `url` when it is a name that says nothing by itself about where it leads
/// (`nas.fritz.box`, `photos.example.com`), unlike `tower.local` or an address.
fn looked_up_name(url: &Url) -> Option<String> {
    match url.host()? {
        host @ url::Host::Domain(name) if !is_local_network(host.clone()) => {
            Some(name.trim_end_matches('.').to_ascii_lowercase())
        }
        _ => None,
    }
}

/// Names this app has reached over plain HTTP since it started (`normalize_server`).
static PLAIN_HTTP_NAMES: std::sync::Mutex<std::collections::BTreeSet<String>> =
    std::sync::Mutex::new(std::collections::BTreeSet::new());

/// Where a name leads, as far as looking it up can say.
#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) enum Leads {
    /// To an address on this computer or the home network.
    Home,
    /// Only to addresses elsewhere.
    Elsewhere,
    /// No answer: the name can't be found right now (DNS is down, or this is another network).
    Unknown,
}
fn leads(found: Option<Vec<std::net::IpAddr>>) -> Leads {
    match found {
        Some(found) if found.iter().copied().any(local_address) => Leads::Home,
        Some(found) if !found.is_empty() => Leads::Elsewhere,
        _ => Leads::Unknown,
    }
}
/// How long a name lookup may take before it counts as no answer.
const LOOKUP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3);
/// Look a name up from code that is not async, without waiting on a resolver that hangs: the
/// lookup runs on a thread of its own and is given `LOOKUP_TIMEOUT`.
fn look_up(name: &str) -> Leads {
    use std::net::ToSocketAddrs;
    let (answer, found) = std::sync::mpsc::channel();
    let name = name.to_owned();
    std::thread::spawn(move || {
        let all = (name.as_str(), 0).to_socket_addrs();
        let _ = answer.send(all.ok().map(|all| all.map(|a| a.ip()).collect()));
    });
    leads(found.recv_timeout(LOOKUP_TIMEOUT).ok().flatten())
}

/// The addresses a connection to `name` may use. A name reached over plain HTTP connects only
/// to this computer or the home network: of what it resolves to, the addresses anywhere else
/// are dropped (a home router answers with a public IPv6 address beside the private one), and
/// when none is left (the same name on another network, a hijacked answer) nothing is sent.
pub(crate) fn home_addresses(
    name: &str,
    found: Vec<std::net::SocketAddr>,
) -> Result<Vec<std::net::SocketAddr>, &'static str> {
    let name = name.trim_end_matches('.').to_ascii_lowercase();
    if !PLAIN_HTTP_NAMES.lock().unwrap().contains(&name) {
        return Ok(found);
    }
    let home: Vec<_> = found
        .into_iter()
        .filter(|address| local_address(address.ip()))
        .collect();
    if home.is_empty() {
        return Err("plain HTTP is only for the home network");
    }
    Ok(home)
}

/// A server or Manager on this computer or the home network, where plain HTTP is allowed:
/// local by its shape (`is_local_network`), or a plain-HTTP name that leads home. A name
/// already accepted (typed and checked, or saved) needs no lookup; any other is looked up
/// once, and from then on its connections are held to home addresses (`home_addresses`).
pub fn is_home_server(url: &Url) -> bool {
    home_server(url) == Leads::Home
}
/// As `is_home_server`, telling a name that leads elsewhere from one that can't be found right
/// now: the first needs HTTPS, the second is a network problem and says nothing about HTTPS.
pub(crate) fn home_server(url: &Url) -> Leads {
    if url.host().is_some_and(is_local_network) {
        return Leads::Home;
    }
    if url.scheme() != "http" {
        return Leads::Elsewhere;
    }
    let Some(name) = looked_up_name(url) else {
        return Leads::Elsewhere;
    };
    if PLAIN_HTTP_NAMES.lock().unwrap().contains(&name) {
        return Leads::Home;
    }
    let found = look_up(&name);
    if found == Leads::Home {
        PLAIN_HTTP_NAMES.lock().unwrap().insert(name);
    }
    found
}

/// Take a plain-HTTP origin by name into use, whoever reaches it (a server, a Manager): from
/// now on connections to the name are held to home addresses. `true` when it is such an
/// origin, whose clients must also connect directly, never through a proxy.
pub(crate) fn hold_plain_http_name(url: &Url) -> bool {
    if url.scheme() != "http" {
        return false;
    }
    let Some(name) = looked_up_name(url) else {
        return false;
    };
    PLAIN_HTTP_NAMES.lock().unwrap().insert(name);
    true
}

/// For what this app does not connect itself (the Photos window is a web view with its own
/// name lookup): whether a plain-HTTP name leads home right now. Any other server is `true`.
pub(crate) fn leads_home_now(base: &Url) -> bool {
    if base.scheme() != "http" {
        return true;
    }
    let Some(name) = looked_up_name(base) else {
        return true;
    };
    look_up(&name) == Leads::Home
}

/// The resolver of every client that talks to a server (`transport::streaming_client_builder`).
pub(crate) struct HomeResolver;
impl reqwest::dns::Resolve for HomeResolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        Box::pin(async move {
            let found: Vec<_> = tokio::net::lookup_host((name.as_str(), 0)).await?.collect();
            let allowed = home_addresses(name.as_str(), found)?;
            Ok(Box::new(allowed.into_iter()) as reqwest::dns::Addrs)
        })
    }
}

/// A server address as a person types or pastes it: `192.168.1.20:2283`, `tower.local`, or a page
/// address copied from the browser. It is reduced to its origin: what follows the host and port
/// names a page of the server, not the server. With no scheme, a host on the local network is
/// reached over plain HTTP (a home server is often just an address and a port) and any other
/// host over HTTPS. A scheme the person typed is kept, and plain HTTP to a public address or to
/// a name not known to be local is refused here, without a lookup (`typed_servers` adds one).
pub fn typed_server(value: &str) -> Result<Url, String> {
    let typed = value.trim();
    if typed.is_empty() || typed.contains('\\') || typed.chars().any(char::is_whitespace) {
        return Err("server_address_invalid".into());
    }
    let parse = |address: &str| {
        Url::parse(address)
            .ok()
            .filter(|url| matches!(url.scheme(), "http" | "https") && url.host().is_some())
    };
    let url = if typed.contains("://") {
        parse(typed)
    } else {
        parse(&format!("http://{typed}")).and_then(|url| {
            if url.host().is_some_and(is_local_network) {
                Some(url)
            } else {
                parse(&format!("https://{typed}"))
            }
        })
    }
    .ok_or("server_address_invalid")?;
    // Credentials in an address are never dropped silently.
    if !url.username().is_empty() || url.password().is_some() {
        return Err("server_requires_https_origin".into());
    }
    if url.scheme() == "http" && looked_up_name(&url).is_some() {
        return Err("server_requires_https_origin".into());
    }
    normalize_server(&url.origin().ascii_serialization())
}

/// The origins to try, in order, for an address a person typed. As `typed_server`, plus what a
/// lookup of the name allows: `resolves_home` says the name resolves, and only to this computer
/// or the home network.
///
/// - `http://nas.fritz.box:2283`: plain HTTP, as typed, when the name is a home one.
/// - `nas.fritz.box:2283` with no scheme: HTTPS first (a home server behind a reverse proxy),
///   then plain HTTP when the name is a home one.
fn typed_candidates(value: &str, resolves: Leads) -> Result<Vec<Url>, String> {
    let resolves_home = resolves == Leads::Home;
    let typed = value.trim();
    let plain = || -> Option<Url> {
        let address = match typed.contains("://") {
            true => typed.to_owned(),
            false => format!("http://{typed}"),
        };
        let url = Url::parse(&address).ok()?;
        let named = url.scheme() == "http" && looked_up_name(&url).is_some();
        let bare = url.username().is_empty() && url.password().is_none();
        // Not taken into use yet: the HTTPS try before it goes wherever the name resolves.
        (named && bare && resolves_home)
            .then(|| server_origin(&url.origin().ascii_serialization()).ok())?
    };
    match typed_server(typed) {
        Ok(url) if typed.contains("://") => Ok(vec![url]),
        Ok(url) => Ok(std::iter::once(url).chain(plain()).collect()),
        Err(code) if code == "server_requires_https_origin" => {
            let typed_plain_name = Url::parse(typed)
                .is_ok_and(|url| url.scheme() == "http" && looked_up_name(&url).is_some());
            plain().map(|url| vec![url]).ok_or(
                // A plain-HTTP name that can't be found right now is a network problem, not
                // a reason to ask for HTTPS: it may well be a home server.
                match typed_plain_name && resolves == Leads::Unknown {
                    true => "server_unreachable_or_certificate_invalid".into(),
                    false => code,
                },
            )
        }
        Err(code) => Err(code),
    }
}

/// `typed_candidates`, looking the name up when the answer depends on it. The lookup runs off
/// the async threads and is given three seconds; no answer means "not known to be home".
pub(crate) async fn typed_servers(value: &str) -> Result<Vec<Url>, String> {
    let typed = value.trim();
    let name = [typed.to_owned(), format!("http://{typed}")]
        .iter()
        .find_map(|address| Url::parse(address).ok().filter(|url| url.host().is_some()))
        .and_then(|url| looked_up_name(&url));
    let resolves = match name {
        Some(name) => {
            let lookup = tokio::net::lookup_host((name, 0));
            match tokio::time::timeout(LOOKUP_TIMEOUT, lookup).await {
                Ok(Ok(found)) => leads(Some(found.map(|a| a.ip()).collect())),
                _ => Leads::Unknown,
            }
        }
        None => Leads::Elsewhere,
    };
    typed_candidates(typed, resolves)
}

/// A host that is on this computer or the local network by its own shape, with no lookup: loopback,
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

fn local_address(address: std::net::IpAddr) -> bool {
    match address {
        std::net::IpAddr::V4(ip) => is_local_network(url::Host::Ipv4(ip)),
        std::net::IpAddr::V6(ip) => match ip.to_ipv4_mapped() {
            Some(ip) => is_local_network(url::Host::Ipv4(ip)),
            None => is_local_network(url::Host::Ipv6(ip)),
        },
    }
}

/// A name is a home name when it resolves to an address on this computer or the local
/// network. Connections to it use only those addresses (`home_addresses`). No answer, or only
/// addresses elsewhere, is not a home name.
#[cfg(test)]
fn name_is_local(name: &str, resolve: impl FnOnce(&str) -> Vec<std::net::IpAddr>) -> bool {
    leads(Some(resolve(name))) == Leads::Home
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
        self.enrollment_at(server, account, name, mode, 0)
    }
    /// As `enrollment`, timed by the server's clock: `clock_skew_ms` is how far it is ahead of
    /// this computer's (`transport::clock_skew`).
    pub fn enrollment_at(
        &self,
        server: &str,
        account: &str,
        name: &str,
        mode: &str,
        clock_skew_ms: i64,
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
            timestamp: (SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|_| "clock_invalid")?
                .as_millis() as i64
                + clock_skew_ms) as u64,
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

/// Binds local authority and browsing data to a single approved Photos sign-in.
pub(crate) fn photo_session_scope(saved: &SavedConnection) -> String {
    let mut scope = Sha256::new();
    for field in [
        &saved.server,
        &saved.server_id,
        &saved.account_id,
        &saved.token,
    ] {
        scope.update((field.len() as u64).to_be_bytes());
        scope.update(field.as_bytes());
    }
    format!("{:x}", scope.finalize())
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Features {
    pub enrollment: bool,
    pub worker: bool,
    #[serde(default)]
    pub worker_session: bool,
    /// The server sets workers up from its machine-learning settings alone
    /// (docs/desktop-worker-setup-protocol.md). Older servers omit it.
    #[serde(default)]
    pub worker_auto_setup: bool,
    /// The server answers a claim that names a model it has withdrawn from this computer with
    /// `409 desktop_qualification_hold`, when the claim asks (`reportWithdrawn`).
    #[serde(default)]
    pub worker_withdrawal_notice: bool,
    pub sources: bool,
    pub native_host: bool,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Capabilities {
    pub protocol_version: u8,
    pub server_id: String,
    pub features: Features,
    /// Not from the server's reply: how far its clock is ahead of this computer's, read from the
    /// `Date` header of the response (`transport::clock_skew`).
    #[serde(skip)]
    pub clock_skew_ms: i64,
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
    /// Why, when the state alone does not say (`enrollment-failed`): the backend's code.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
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
            code: None,
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
    fn a_saved_plain_http_name_is_a_valid_server_without_any_lookup() {
        // `.invalid` never resolves: the laptop is away, or the router's DNS is down. The saved
        // server is still a server; reaching it fails as a network error, not as "use HTTPS".
        for saved in [
            "http://nas.fritz.invalid:2283",
            "http://photos.home.invalid/",
            "http://nas.fritz.box:2283",
        ] {
            assert!(normalize_server(saved).is_ok(), "{saved}");
        }
        // Plain HTTP to a public address is still refused outright.
        for refused in ["http://8.8.8.8:2283", "http://[2001:db8::1]:2283"] {
            assert_eq!(
                normalize_server(refused).map(String::from),
                Err("server_requires_https_origin".to_string()),
                "{refused}"
            );
        }
    }

    #[test]
    fn a_plain_http_name_only_ever_connects_to_the_home_network() {
        let addresses = |list: &[&str]| -> Vec<std::net::SocketAddr> {
            list.iter()
                .map(|address| std::net::SocketAddr::new(address.parse().unwrap(), 0))
                .collect()
        };
        normalize_server("http://nas.split.test:2283").unwrap();
        assert!(home_addresses("nas.split.test", addresses(&["192.168.178.20"])).is_ok());
        assert!(home_addresses("NAS.split.test.", addresses(&["10.0.0.2", "fd00::2"])).is_ok());
        // The same name elsewhere, or a hijacked answer: nothing is sent.
        assert!(home_addresses("nas.split.test", addresses(&["203.0.113.7"])).is_err());
        assert!(home_addresses("nas.split.test", addresses(&[])).is_err());
        // A home router answers with a public IPv6 address beside the private one: only the
        // home address is connected to.
        assert_eq!(
            home_addresses(
                "nas.split.test",
                addresses(&["2001:db8::20", "192.168.178.20", "203.0.113.7"])
            ),
            Ok(addresses(&["192.168.178.20"]))
        );
        // A name only ever reached over HTTPS goes wherever it resolves.
        assert!(home_addresses("photos.public.test", addresses(&["203.0.113.7"])).is_ok());
        // An HTTPS address for the same name does not lift the rule: something still running
        // (the AI worker) may be using the plain-HTTP one.
        normalize_server("https://nas.split.test").unwrap();
        assert!(home_addresses("nas.split.test", addresses(&["203.0.113.7"])).is_err());
        // A saved Manager after a restart: building its client is what takes the name into use.
        let public = addresses(&["203.0.113.7"]);
        assert_eq!(
            home_addresses("mgr.saved.test", public.clone()),
            Ok(public.clone())
        );
        assert!(crate::manager::manager_client("http://mgr.saved.test:9443", None, None).is_ok());
        assert!(home_addresses("mgr.saved.test", public).is_err());
        assert!(home_addresses("mgr.saved.test", addresses(&["192.168.178.30"])).is_ok());
        // Sign-in and Manager: a name already reached over plain HTTP is a home server without
        // another lookup; one that resolves nowhere, or an HTTPS name, is not.
        assert!(is_home_server(
            &Url::parse("http://nas.split.test:8443").unwrap()
        ));
        assert!(is_home_server(&Url::parse("http://tower.local").unwrap()));
        assert!(is_home_server(&Url::parse("https://192.168.1.20").unwrap()));
        assert!(!is_home_server(
            &Url::parse("http://manager.fritz.invalid:9443").unwrap()
        ));
        assert!(!is_home_server(
            &Url::parse("https://photos.example.invalid").unwrap()
        ));
        // A plain-HTTP name that does not resolve does not lead home; other servers are not asked.
        assert!(!leads_home_now(
            &Url::parse("http://nas.fritz.invalid:2283").unwrap()
        ));
        assert!(leads_home_now(
            &Url::parse("https://photos.example.invalid").unwrap()
        ));
        assert!(leads_home_now(
            &Url::parse("http://192.168.1.20:2283").unwrap()
        ));
    }

    #[test]
    fn a_typed_home_name_tries_https_first_and_plain_http_only_when_it_resolves_home() {
        let tried = |typed: &str, home: bool| {
            let resolves = match home {
                true => Leads::Home,
                false => Leads::Elsewhere,
            };
            typed_candidates(typed, resolves)
                .map(|urls| urls.iter().map(Url::to_string).collect::<Vec<_>>())
        };
        // No scheme: HTTPS as before (a reverse proxy on 443), then plain HTTP for a home name.
        assert_eq!(
            tried("nas.fritz.box:2283", true).unwrap(),
            ["https://nas.fritz.box:2283/", "http://nas.fritz.box:2283/"]
        );
        assert_eq!(
            tried("photos.example.com", false).unwrap(),
            ["https://photos.example.com/"]
        );
        // Plain HTTP as typed: only for a home name.
        assert_eq!(
            tried("http://nas.fritz.box:2283/photos", true).unwrap(),
            ["http://nas.fritz.box:2283/"]
        );
        assert_eq!(
            tried("http://photos.example.com", false),
            Err("server_requires_https_origin".to_string())
        );
        // A plain-HTTP name that can't be found right now (DNS down, another network) is a
        // network problem; only one that leads elsewhere is told to use HTTPS.
        assert_eq!(
            typed_candidates("http://nas.fritz.box:2283", Leads::Unknown),
            Err("server_unreachable_or_certificate_invalid".to_string())
        );
        assert_eq!(
            typed_candidates("http://nas.fritz.box:2283", Leads::Elsewhere),
            Err("server_requires_https_origin".to_string())
        );
        // With no scheme it is still tried over HTTPS, which answers or fails as a network error.
        assert_eq!(
            typed_candidates("nas.fritz.box:2283", Leads::Unknown)
                .unwrap()
                .len(),
            1
        );
        assert_eq!(leads(None), Leads::Unknown);
        assert_eq!(leads(Some(vec![])), Leads::Unknown);
        assert_eq!(
            home_server(&Url::parse("http://mgr.fritz.invalid:9443").unwrap()),
            Leads::Unknown
        );
        // Listing the plain-HTTP fallback does not yet hold the name to the home network: the
        // HTTPS try before it may use a public address the name also resolves to.
        let public = vec![std::net::SocketAddr::new("203.0.113.7".parse().unwrap(), 0)];
        tried("nas.unused.test:2283", true).unwrap();
        assert_eq!(
            home_addresses("nas.unused.test", public.clone()),
            Ok(public.clone())
        );
        // Taking it into use does.
        normalize_server("http://nas.unused.test:2283").unwrap();
        assert!(home_addresses("nas.unused.test", public).is_err());
        // Unchanged: names and addresses local by shape, HTTPS as typed, public addresses.
        assert_eq!(
            tried("tower.local:2283", false).unwrap(),
            ["http://tower.local:2283/"]
        );
        assert_eq!(
            tried("192.168.1.20:2283", true).unwrap(),
            ["http://192.168.1.20:2283/"]
        );
        assert_eq!(
            tried("https://nas.fritz.box", true).unwrap(),
            ["https://nas.fritz.box/"]
        );
        assert_eq!(
            tried("http://8.8.8.8:2283", true),
            Err("server_requires_https_origin".to_string())
        );
        assert_eq!(
            tried("http://user:secret@nas.fritz.box", true),
            Err("server_requires_https_origin".to_string())
        );
    }

    #[test]
    fn a_name_is_local_when_everything_it_resolves_to_is() {
        use std::net::IpAddr;
        let answers = |addresses: &[&str]| -> Vec<IpAddr> {
            addresses
                .iter()
                .map(|address| address.parse().unwrap())
                .collect()
        };
        for local in [
            &["192.168.178.20"][..],
            &["10.0.0.5", "fd00::5"],
            &["100.101.102.103"],
            &["127.0.0.1", "::1"],
            &["169.254.10.1", "fe80::1"],
            &["::ffff:192.168.1.20"],
        ] {
            assert!(
                name_is_local("nas.fritz.box", |_| answers(local)),
                "{local:?}"
            );
        }
        // A public address beside a home one (a router's IPv6 answer) is still a home name;
        // only the home address is ever connected to (`home_addresses`).
        assert!(name_is_local("nas.fritz.box", |_| answers(&[
            "192.168.1.20",
            "2001:db8::1"
        ])));
        for public in [
            &["8.8.8.8"][..],
            &["203.0.113.7", "2001:db8::7"],
            &["2001:db8::1"],
            &["::ffff:8.8.8.8"],
            // No answer says nothing about where the name leads.
            &[],
        ] {
            assert!(
                !name_is_local("photos.home", |_| answers(public)),
                "{public:?}"
            );
        }
        // Names accepted without a lookup stay that way: this resolves nowhere.
        for name in [
            "tower",
            "tower.local",
            "nas.lan",
            "box.home.arpa",
            "nas.tail1234.ts.net",
        ] {
            assert!(is_local_network(url::Host::Domain(name)), "{name}");
        }
        // Any other name says nothing by its shape, and is never looked up to find out.
        for name in ["nas.fritz.box", "photos.home", "photos.example.com"] {
            assert!(!is_local_network(url::Host::Domain(name)), "{name}");
        }
        // This computer's own name resolves to itself.
        assert!(name_is_local("localhost", |name| {
            use std::net::ToSocketAddrs;
            (name, 0)
                .to_socket_addrs()
                .unwrap()
                .map(|a| a.ip())
                .collect()
        }));
    }

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
            "http://8.8.8.8",
            "http://100.63.255.255",
            "http://100.128.0.1",
            "http://[2001:db8::1]",
            "http://192.168.1.20/photos",
        ] {
            assert!(normalize_server(remote).is_err(), "{remote}");
        }
        // Plain HTTP to a name that is not local by its shape: never accepted as typed without
        // a lookup that shows it is a home name (`typed_candidates`), and a connection to it
        // only ever reaches the home network (`home_addresses`).
        for named in ["http://photos.example.com", "http://ts.net.example.com"] {
            assert!(typed_server(named).is_err(), "{named}");
            assert!(
                typed_candidates(named, Leads::Elsewhere).is_err(),
                "{named}"
            );
        }
        assert!(normalize_server("https://photos.example.com").is_ok());
    }

    #[test]
    fn a_typed_address_becomes_the_origin_with_plain_http_for_local_hosts() {
        for (typed, origin) in [
            // Just an address and a port, as most home servers are reached.
            ("192.168.1.20:2283", "http://192.168.1.20:2283/"),
            ("192.168.1.20", "http://192.168.1.20/"),
            // Copied from the browser's address bar with a page open.
            ("192.168.1.20:2283/photos", "http://192.168.1.20:2283/"),
            (
                "http://192.168.1.20:2283/photos?at=1#top",
                "http://192.168.1.20:2283/",
            ),
            ("  http://192.168.1.20:2283/  ", "http://192.168.1.20:2283/"),
            ("tower.local", "http://tower.local/"),
            ("tower.local:2283/albums", "http://tower.local:2283/"),
            ("tower", "http://tower/"),
            ("localhost:2283", "http://localhost:2283/"),
            ("[fd00::7]:2283", "http://[fd00::7]:2283/"),
            ("100.64.0.1:2283", "http://100.64.0.1:2283/"),
            ("nas.tail1234.ts.net", "http://nas.tail1234.ts.net/"),
            // A local server that does have a certificate keeps the scheme that was typed.
            (
                "https://tower.local:8443/photos",
                "https://tower.local:8443/",
            ),
            // Anything else is public: HTTPS when no scheme was typed.
            ("photos.example.com", "https://photos.example.com/"),
            ("photos.example.com/albums", "https://photos.example.com/"),
            (
                "photos.example.com:8443",
                "https://photos.example.com:8443/",
            ),
            ("8.8.8.8:2283", "https://8.8.8.8:2283/"),
            (
                "https://photos.example.com/photos",
                "https://photos.example.com/",
            ),
        ] {
            assert_eq!(
                typed_server(typed).map(String::from),
                Ok(origin.to_string()),
                "{typed}"
            );
        }
        // Plain HTTP that was typed for a public host is refused, never upgraded or sent.
        for refused in [
            "http://photos.example.com",
            "http://8.8.8.8:2283/photos",
            "user:secret@192.168.1.20:2283",
            "https://user@photos.example.com",
        ] {
            assert_eq!(
                typed_server(refused).map(String::from),
                Err("server_requires_https_origin".to_string()),
                "{refused}"
            );
        }
        for invalid in [
            "",
            "   ",
            "ftp://192.168.1.20",
            "file:///etc/hosts",
            "192.168.1.20 2283",
            "tower\\share",
            "://",
        ] {
            assert_eq!(
                typed_server(invalid).map(String::from),
                Err("server_address_invalid".to_string()),
                "{invalid:?}"
            );
        }
    }
}
