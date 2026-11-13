//! What the installed Manager declares it can do, and this library's own record of where its
//! Manager listens and which certificates it has served. Nothing here is a secret.
use crate::manager_host::{listener, Evidence};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    io::{Read, Write},
    path::Path,
    sync::{Arc, Mutex},
    time::Duration,
};

/// Capabilities a Manager declares in its own `package.json`, which the signed package covers.
/// A Manager that declares none is today's released Manager, and everything gated here is inert.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Features {
    /// The paired `runtime` route says whether the photo server is running.
    pub runtime_status: bool,
    /// Manager accepts changed ports and keeps this computer's grant when its own port moves.
    pub ports: bool,
    /// Manager accepts a renewed TLS certificate handed over by the one it replaces.
    pub tls_rotation: bool,
}
impl Features {
    /// Anything that is not exactly a list of names under `frameleaf.nativeCapabilities`
    /// declares nothing.
    pub(crate) fn declared(package: &[u8]) -> Self {
        let names: Vec<String> = serde_json::from_slice::<serde_json::Value>(package)
            .ok()
            .and_then(|value| {
                serde_json::from_value(value["frameleaf"]["nativeCapabilities"].clone()).ok()
            })
            .unwrap_or_default();
        let has = |name: &str| names.iter().any(|declared| declared == name);
        Self {
            runtime_status: has("runtime-status"),
            ports: has("ports"),
            tls_rotation: has("tls-rotation"),
        }
    }
    /// From a package whose files were already verified against its signed manifest.
    pub(crate) fn of_package(runtime: &Path) -> Self {
        crate::runtime_store::read_bounded(&runtime.join("payload/manager/package.json"), 64 * 1024)
            .map(|package| Self::declared(&package))
            .unwrap_or_default()
    }
}

/// Whether a verified package's Manager declares one capability by name.
#[cfg_attr(not(any(target_os = "macos", target_os = "linux")), allow(dead_code))]
pub(crate) fn package_declares(runtime: &Path, capability: &str) -> bool {
    crate::runtime_store::read_bounded(&runtime.join("payload/manager/package.json"), 64 * 1024)
        .is_ok_and(|package| declares(&package, capability))
}
/// Anything that is not exactly a list of names under `frameleaf.nativeCapabilities` declares
/// nothing.
fn declares(package: &[u8], capability: &str) -> bool {
    serde_json::from_slice::<serde_json::Value>(package)
        .ok()
        .and_then(|value| {
            serde_json::from_value::<Vec<String>>(value["frameleaf"]["nativeCapabilities"].clone())
                .ok()
        })
        .is_some_and(|names| names.iter().any(|declared| declared == capability))
}

/// The loopback ports of one hosted library.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Ports {
    pub manager: u16,
    pub api: u16,
    pub database: u16,
}
impl Default for Ports {
    fn default() -> Self {
        Self {
            manager: 9443,
            api: 2283,
            database: 54329,
        }
    }
}
impl Ports {
    fn valid(&self) -> bool {
        let all = [self.manager, self.api, self.database];
        all.iter().all(|port| *port >= 1024)
            && self.manager != self.api
            && self.manager != self.database
            && self.api != self.database
    }
    pub(crate) fn origin(&self) -> String {
        format!("https://127.0.0.1:{}", self.manager)
    }
}

/// Kept in Manager's data directory: the ports this library was last started with, and the
/// fingerprints of the certificates its Manager may be serving.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Record {
    schema_version: u32,
    pub ports: Ports,
    pub certificates: Vec<String>,
    /// The ports this library last ran on, while `ports` are a move its Manager has not yet
    /// been seen ready with. Manager can refuse a moved port (it admits none while one of its
    /// operations is unfinished), so until then `ports` are only where a start was attempted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unconfirmed_from: Option<Ports>,
}
impl Record {
    pub(crate) fn new(ports: Ports, certificates: Vec<String>) -> Self {
        Self {
            schema_version: 1,
            ports,
            certificates,
            unconfirmed_from: None,
        }
    }
    /// The record for a start on `ports`, after what `before` recorded. Ports that differ from
    /// the ones Manager was last ready on stay unconfirmed, across any number of starts.
    pub(crate) fn for_start(before: &Self, ports: Ports, certificates: Vec<String>) -> Self {
        let confirmed = before.unconfirmed_from.unwrap_or(before.ports);
        Self {
            schema_version: 1,
            ports,
            certificates,
            unconfirmed_from: (confirmed != ports).then_some(confirmed),
        }
    }
    fn valid(&self) -> bool {
        self.schema_version == 1
            && self.ports.valid()
            && self.unconfirmed_from.is_none_or(|ports| ports.valid())
            && self.certificates.len() <= 64
            && self
                .certificates
                .iter()
                .all(|value| crate::native_runtime::digest_valid(value, 64))
    }
}
/// What the record says. A record that cannot be read is its own answer: it is never taken
/// for "no record", because the defaults may not be where this library listens.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Stored {
    Absent,
    Present(Record),
    Unreadable,
}
const RECORD: &str = "desktop-local-manager.json";
pub(crate) fn stored(data: &Path) -> Stored {
    match std::fs::symlink_metadata(data) {
        // No Manager directory yet: this library has never been started.
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Stored::Absent,
        Err(_) => return Stored::Unreadable,
        Ok(_) => {}
    }
    let Ok(directory) = crate::host_storage::directory(data) else {
        return Stored::Unreadable;
    };
    let directory = cap_std::fs::Dir::from_std_file(directory);
    let file = match directory.open_with(RECORD, &crate::host_state::options(false)) {
        Ok(file) => file.into_std(),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Stored::Absent,
        Err(_) => return Stored::Unreadable,
    };
    let mut bytes = Vec::new();
    if crate::host_state::valid_file(&file).is_err()
        || file.take(4097).read_to_end(&mut bytes).is_err()
        || bytes.len() > 4096
    {
        return Stored::Unreadable;
    }
    match serde_json::from_slice::<Record>(&bytes) {
        Ok(record) if record.valid() => Stored::Present(record),
        _ => Stored::Unreadable,
    }
}
/// The recorded ports, or the defaults for a library with no record. An unreadable record
/// refuses: guessing could start this library somewhere its Manager does not expect.
pub(crate) fn recorded(data: &Path) -> Result<Record, String> {
    match stored(data) {
        Stored::Absent => Ok(Record::new(Ports::default(), Vec::new())),
        Stored::Present(record) => Ok(record),
        Stored::Unreadable => Err("local_manager_record_unreadable".into()),
    }
}
/// Replace the record in one step, so a crash leaves either the old one or the new one.
pub(crate) fn save(data: &Path, record: &Record) -> Result<(), String> {
    const TEMPORARY: &str = ".desktop-local-manager.json.tmp";
    let failed = |_: std::io::Error| "local_manager_record_unavailable".to_string();
    if !record.valid() {
        return Err("local_manager_record_unavailable".into());
    }
    let bytes = serde_json::to_vec(record).map_err(|_| "local_manager_record_unavailable")?;
    let directory = cap_std::fs::Dir::from_std_file(
        crate::host_storage::directory(data).map_err(|_| "local_manager_record_unavailable")?,
    );
    match directory.remove_file(TEMPORARY) {
        Err(error) if error.kind() != std::io::ErrorKind::NotFound => return Err(failed(error)),
        _ => {}
    }
    let mut options = crate::host_state::options(true);
    options.create_new(true);
    let mut file = directory
        .open_with(TEMPORARY, &options)
        .map_err(failed)?
        .into_std();
    file.write_all(&bytes)
        .and_then(|_| file.sync_all())
        .map_err(failed)?;
    drop(file);
    directory
        .rename(TEMPORARY, &directory, RECORD)
        .map_err(failed)?;
    // A directory handle cannot be flushed on Windows; the profile's own marker does the same.
    #[cfg(unix)]
    crate::host_storage::directory(data)
        .map_err(|_| "local_manager_record_unavailable".to_string())?
        .sync_all()
        .map_err(failed)?;
    Ok(())
}
/// Manager was verified ready on the recorded ports: they are where this library lives now.
pub(crate) fn confirm(data: &Path) -> Result<(), String> {
    match stored(data) {
        Stored::Present(mut record) if record.unconfirmed_from.is_some() => {
            record.unconfirmed_from = None;
            save(data, &record)
        }
        Stored::Unreadable => Err("local_manager_record_unreadable".into()),
        _ => Ok(()),
    }
}
/// A start did not bring Manager up and nothing it spawned is running. If its ports were a
/// move Manager was never ready on, the record goes back to the ports it was ready on, so the
/// move is not kept, and the start answers as a busy port always did: with that port named.
/// Why Manager did not come up is not known, so nothing about the move is assumed to be fine.
/// Any other failure, and a cancelled start, keep their own code.
pub(crate) fn withdrawn(data: &Path, error: String) -> String {
    let Stored::Present(mut record) = stored(data) else {
        return error;
    };
    let Some(confirmed) = record.unconfirmed_from.take() else {
        return error;
    };
    let moved = record.ports;
    record.ports = confirmed;
    if save(data, &record).is_err() || error == "native_manager_start_cancelled" {
        return error;
    }
    [
        (confirmed.manager, moved.manager),
        (confirmed.api, moved.api),
        (confirmed.database, moved.database),
    ]
    .into_iter()
    .find(|(from, to)| from != to)
    .map_or(error, |(busy, _)| format!("local_port_in_use_{busy}"))
}

/// Whose TLS listener answers on a port. Only positive evidence names it: `Ours` is a
/// completed handshake that presented one of this library's certificates, `Foreign` is a peer
/// that presented some other certificate or answered with something that is not TLS. Silence,
/// a timeout, a refused or dropped connection and every other failure are `Unknown`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Peer {
    Ours,
    Foreign,
    Unknown,
}
#[derive(Debug)]
struct Capture {
    presented: Mutex<Option<String>>,
    algorithms: rustls::crypto::WebPkiSupportedAlgorithms,
}
impl rustls::client::danger::ServerCertVerifier for Capture {
    /// Records what was presented and accepts it: this connection carries nothing, and the
    /// certificate is compared by the caller. The handshake signature is still verified below,
    /// so a peer that only replays this library's certificate cannot finish.
    fn verify_server_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _name: &rustls::pki_types::ServerName<'_>,
        _ocsp: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        *self
            .presented
            .lock()
            .unwrap_or_else(|error| error.into_inner()) =
            Some(format!("{:x}", Sha256::digest(end_entity.as_ref())));
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        certificate: &rustls::pki_types::CertificateDer<'_>,
        signature: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, certificate, signature, &self.algorithms)
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        certificate: &rustls::pki_types::CertificateDer<'_>,
        signature: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, certificate, signature, &self.algorithms)
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.algorithms.supported_schemes()
    }
}
/// Ask the listener on a loopback port for its TLS certificate and compare it with
/// `certificates` (SHA-256 of the DER, lowercase hex). With none to compare against, nothing
/// can be named `Ours`, and nothing is named `Foreign` either.
pub(crate) fn tls_peer(port: u16, certificates: &[String]) -> Peer {
    if certificates.is_empty() {
        return Peer::Unknown;
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let capture = Arc::new(Capture {
        presented: Mutex::new(None),
        algorithms: provider.signature_verification_algorithms,
    });
    let Ok(config) = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map(|builder| {
            builder
                .dangerous()
                .with_custom_certificate_verifier(capture.clone())
                .with_no_client_auth()
        })
    else {
        return Peer::Unknown;
    };
    let address = std::net::SocketAddr::from(([127, 0, 0, 1], port));
    let name = rustls::pki_types::ServerName::IpAddress(std::net::Ipv4Addr::LOCALHOST.into());
    let (Ok(mut connection), Ok(mut stream)) = (
        rustls::ClientConnection::new(Arc::new(config), name),
        std::net::TcpStream::connect_timeout(&address, Duration::from_millis(500)),
    ) else {
        return Peer::Unknown;
    };
    if stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .and_then(|_| stream.set_write_timeout(Some(Duration::from_secs(2))))
        .is_err()
    {
        return Peer::Unknown;
    }
    let mut failure = None;
    while connection.is_handshaking() {
        if let Err(error) = connection.complete_io(&mut stream) {
            failure = Some(error);
            break;
        }
    }
    let presented = capture
        .presented
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .clone();
    match (presented, failure) {
        (Some(presented), None) if certificates.contains(&presented) => Peer::Ours,
        // It showed this library's certificate but did not finish: not proof of either.
        (Some(presented), Some(_)) if certificates.contains(&presented) => Peer::Unknown,
        (Some(_), _) => Peer::Foreign,
        // No certificate at all: only an answer that is plainly not TLS names another program.
        (None, Some(error)) => match error
            .get_ref()
            .and_then(|inner| inner.downcast_ref::<rustls::Error>())
        {
            Some(rustls::Error::InvalidMessage(_)) => Peer::Foreign,
            _ => Peer::Unknown,
        },
        (None, None) => Peer::Unknown,
    }
}
/// For the update gate and for recovering a launch that left no process: whether this
/// library's Manager may be answering on its recorded port. A listener proven to be another
/// program's is not this library's Manager; one that cannot be identified counts as it.
#[cfg_attr(not(unix), allow(dead_code))]
pub(crate) fn recorded_manager_listener(data: &Path) -> Evidence {
    let Ok(record) = recorded(data) else {
        return Evidence::Unknown;
    };
    manager_listener(listener(record.ports.manager), &|| {
        tls_peer(record.ports.manager, &record.certificates)
    })
}
#[cfg_attr(not(unix), allow(dead_code))]
fn manager_listener(listening: Evidence, peer: &dyn Fn() -> Peer) -> Evidence {
    match listening {
        Evidence::Running => match peer() {
            Peer::Foreign => Evidence::Clear,
            Peer::Ours => Evidence::Running,
            Peer::Unknown => Evidence::Unknown,
        },
        other => other,
    }
}

/// How the ports are examined; injected so the decision can be tested without sockets.
pub(crate) struct Probes<'a> {
    /// Whether anything accepts connections on a loopback port.
    pub listening: &'a dyn Fn(u16) -> Evidence,
    /// Whether this process can bind the loopback port right now.
    pub bindable: &'a dyn Fn(u16) -> bool,
    /// Whose TLS listener holds Manager's port.
    pub manager_peer: &'a dyn Fn(u16) -> Peer,
}
/// The ports one start uses, against this computer's real ports. `certificates` are the
/// fingerprints of every certificate this library's Manager may be serving.
pub(crate) fn ports_for_start(
    features: Features,
    current: Ports,
    idle: Evidence,
    certificates: &[String],
) -> Result<Ports, String> {
    ports_with(
        features,
        current,
        idle,
        &Probes {
            listening: &listener,
            bindable: &|port| std::net::TcpListener::bind(("127.0.0.1", port)).is_ok(),
            manager_peer: &|port| tls_peer(port, certificates),
        },
    )
}
/// A Manager that does not declare `ports` refuses a library on any port but the ones it
/// first saw, so nothing is examined or moved for it: a busy port refuses the start, as before.
fn ports_with(
    features: Features,
    current: Ports,
    idle: Evidence,
    probes: &Probes<'_>,
) -> Result<Ports, String> {
    if !features.ports {
        return Ok(current);
    }
    settle(current, idle, probes)
}
/// How far past a default port a replacement is looked for.
const SEARCH: u16 = 200;
/// Choose the ports for this start. A port nothing else holds is kept. A port that another
/// program holds is replaced by the first free one after its default, but only on proof that
/// the holder is not this library:
/// - the photo and database ports, when `idle` is `Clear`: the journal proves no controller,
///   photo server or database of this library is running;
/// - Manager's port, when what answers there is proven `Foreign`. One that answers as this
///   library's Manager is an earlier Manager still running, and refuses the start.
///
/// Without that proof the start is refused with the port named, exactly as before.
pub(crate) fn settle(current: Ports, idle: Evidence, probes: &Probes<'_>) -> Result<Ports, String> {
    let defaults = Ports::default();
    let mut chosen = current;
    type Role = fn(&mut Ports) -> &mut u16;
    let roles: [(Role, u16, bool); 3] = [
        (|ports| &mut ports.manager, defaults.manager, true),
        (|ports| &mut ports.api, defaults.api, false),
        (|ports| &mut ports.database, defaults.database, false),
    ];
    for (role, default, manager) in roles {
        let port = *role(&mut chosen);
        if (probes.listening)(port) != Evidence::Running {
            continue;
        }
        let in_use = || format!("local_port_in_use_{port}");
        if manager {
            match (probes.manager_peer)(port) {
                Peer::Foreign => {}
                Peer::Ours => return Err("native_manager_orphan_running".into()),
                Peer::Unknown => return Err(in_use()),
            }
        } else if idle != Evidence::Clear {
            return Err(in_use());
        }
        let taken = [chosen.manager, chosen.api, chosen.database];
        let free = (1..=SEARCH)
            .filter_map(|step| default.checked_add(step))
            .find(|candidate| {
                !taken.contains(candidate)
                    && (probes.listening)(*candidate) == Evidence::Clear
                    && (probes.bindable)(*candidate)
            })
            .ok_or_else(in_use)?;
        *role(&mut chosen) = free;
    }
    if !chosen.valid() {
        return Err("native_manager_config_invalid".into());
    }
    Ok(chosen)
}

/// What a plain-HTTP server does with a connection, for tests: read what the client sent,
/// refuse it in plain text, and close in order. Closing with the client's bytes unread resets
/// the connection instead, and on Windows a reset discards a reply the client has not read yet.
#[cfg(test)]
pub(crate) fn answer_in_plain_text(stream: &mut std::net::TcpStream) {
    // A TLS hello is one record: a five-byte header, then as many bytes as the header says.
    let mut header = [0u8; 5];
    if stream.read_exact(&mut header).is_ok() && header[0] == 22 {
        let mut hello = vec![0u8; usize::from(u16::from_be_bytes([header[3], header[4]]))];
        let _ = stream.read_exact(&mut hello);
    }
    let _ = stream.write_all(b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n");
    let _ = stream.shutdown(std::net::Shutdown::Write);
    // Whatever else the client sends, until it hangs up or the caller's read timeout passes.
    let _ = std::io::copy(stream, &mut std::io::sink());
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settled(
        current: Ports,
        idle: Evidence,
        busy: &[u16],
        unknown: &[u16],
        peer: Peer,
    ) -> Result<Ports, String> {
        settle(
            current,
            idle,
            &Probes {
                listening: &|port| {
                    if busy.contains(&port) {
                        Evidence::Running
                    } else if unknown.contains(&port) {
                        Evidence::Unknown
                    } else {
                        Evidence::Clear
                    }
                },
                bindable: &|port| !busy.contains(&port),
                manager_peer: &|_| peer,
            },
        )
    }

    #[test]
    fn only_a_list_of_names_in_the_signed_package_declares_a_capability() {
        let all = br#"{"name":"@frameleaf/manager","frameleaf":{"nativeCapabilities":["runtime-status","ports","tls-rotation","later"]}}"#;
        assert_eq!(
            Features::declared(all),
            Features {
                runtime_status: true,
                ports: true,
                tls_rotation: true
            }
        );
        assert_eq!(
            Features::declared(br#"{"frameleaf":{"nativeCapabilities":["ports"]}}"#),
            Features {
                ports: true,
                ..Features::default()
            }
        );
        // Today's released Manager, and every shape that is not exactly a list of names.
        for package in [
            &br#"{"name":"@frameleaf/manager","version":"1.2.20"}"#[..],
            br#"{"frameleaf":{"nativeCapabilities":"ports"}}"#,
            br#"{"frameleaf":{"nativeCapabilities":{"ports":true}}}"#,
            br#"{"frameleaf":{"nativeCapabilities":["ports",1]}}"#,
            br#"{"nativeCapabilities":["ports"]}"#,
            br#"{"frameleaf":["ports"]}"#,
            b"not json",
            b"",
        ] {
            assert_eq!(Features::declared(package), Features::default());
        }
        assert_eq!(
            Features::of_package(Path::new("/nonexistent/frameleaf/package")),
            Features::default()
        );
    }

    #[test]
    fn a_manager_that_does_not_declare_ports_is_never_moved_or_even_probed() {
        let asked = |_: u16| -> Evidence { panic!("no port is examined for a released Manager") };
        let peer = |_: u16| -> Peer { panic!("no listener is identified for a released Manager") };
        let probes = Probes {
            listening: &asked,
            bindable: &|_| panic!("no port is bound for a released Manager"),
            manager_peer: &peer,
        };
        for features in [
            Features::default(),
            Features {
                runtime_status: true,
                tls_rotation: true,
                ports: false,
            },
        ] {
            assert_eq!(
                ports_with(features, Ports::default(), Evidence::Clear, &probes),
                Ok(Ports::default())
            );
        }
        // The same busy port moves once the installed Manager declares it accepts that.
        let busy = |port: u16| {
            if port == 2283 {
                Evidence::Running
            } else {
                Evidence::Clear
            }
        };
        let capable = Features {
            ports: true,
            ..Features::default()
        };
        assert_eq!(
            ports_with(
                capable,
                Ports::default(),
                Evidence::Clear,
                &Probes {
                    listening: &busy,
                    bindable: &|_| true,
                    manager_peer: &|_| Peer::Unknown,
                },
            ),
            Ok(Ports {
                api: 2284,
                ..Ports::default()
            })
        );
    }

    #[test]
    fn ports_nothing_else_holds_are_kept_and_a_port_that_cannot_be_probed_is_not_moved() {
        let defaults = Ports::default();
        for idle in [Evidence::Clear, Evidence::Running, Evidence::Unknown] {
            assert_eq!(
                settled(defaults, idle, &[], &[], Peer::Unknown),
                Ok(defaults)
            );
            // No answer either way is not a reason to move: the start decides as before.
            assert_eq!(
                settled(defaults, idle, &[], &[9443, 2283, 54329], Peer::Unknown),
                Ok(defaults)
            );
        }
        let moved = Ports {
            manager: 9450,
            api: 2290,
            database: 54400,
        };
        assert_eq!(
            settled(
                moved,
                Evidence::Clear,
                &[9443, 2283, 54329],
                &[],
                Peer::Foreign
            ),
            Ok(moved),
            "a library that already moved stays where it is while that is free"
        );
    }

    #[test]
    fn a_photo_or_database_port_moves_only_when_the_journal_proves_the_library_idle() {
        let defaults = Ports::default();
        assert_eq!(
            settled(defaults, Evidence::Clear, &[2283], &[], Peer::Unknown),
            Ok(Ports {
                api: 2284,
                ..defaults
            })
        );
        assert_eq!(
            settled(
                defaults,
                Evidence::Clear,
                &[54329, 54330],
                &[],
                Peer::Unknown
            ),
            Ok(Ports {
                database: 54331,
                ..defaults
            })
        );
        // The first candidate that is definitely free: one that does not answer either way,
        // or cannot be bound, is passed over.
        assert_eq!(
            settled(defaults, Evidence::Clear, &[2283], &[2284], Peer::Unknown),
            Ok(Ports {
                api: 2285,
                ..defaults
            })
        );
        // Without the idle proof whatever answers may be this library's own server or database.
        for idle in [Evidence::Running, Evidence::Unknown] {
            assert_eq!(
                settled(defaults, idle, &[2283], &[], Peer::Foreign).unwrap_err(),
                "local_port_in_use_2283"
            );
            assert_eq!(
                settled(defaults, idle, &[54329], &[], Peer::Foreign).unwrap_err(),
                "local_port_in_use_54329"
            );
        }
    }

    #[test]
    fn managers_port_moves_only_from_a_listener_proven_to_be_another_programs() {
        let defaults = Ports::default();
        // The journal says nothing about Manager, which outlives its controller.
        for idle in [Evidence::Clear, Evidence::Running, Evidence::Unknown] {
            assert_eq!(
                settled(defaults, idle, &[9443], &[], Peer::Foreign),
                Ok(Ports {
                    manager: 9444,
                    ..defaults
                })
            );
            assert_eq!(
                settled(defaults, idle, &[9443], &[], Peer::Ours).unwrap_err(),
                "native_manager_orphan_running"
            );
            assert_eq!(
                settled(defaults, idle, &[9443], &[], Peer::Unknown).unwrap_err(),
                "local_port_in_use_9443"
            );
        }
    }

    #[test]
    fn replacements_never_collide_and_an_exhausted_search_refuses_with_the_port_named() {
        let crowded = Ports {
            manager: 9443,
            api: 9444,
            database: 9445,
        };
        // 9444 and 9445 are this library's other ports: Manager's replacement skips them.
        assert_eq!(
            settled(crowded, Evidence::Clear, &[9443], &[], Peer::Foreign),
            Ok(Ports {
                manager: 9446,
                ..crowded
            })
        );
        let busy: Vec<u16> = (2283..=2283 + SEARCH).collect();
        assert_eq!(
            settled(Ports::default(), Evidence::Clear, &busy, &[], Peer::Unknown).unwrap_err(),
            "local_port_in_use_2283"
        );
        // All three at once.
        assert_eq!(
            settled(
                Ports::default(),
                Evidence::Clear,
                &[9443, 2283, 54329],
                &[],
                Peer::Foreign
            ),
            Ok(Ports {
                manager: 9444,
                api: 2284,
                database: 54330
            })
        );
    }

    #[test]
    fn the_record_is_absent_present_or_unreadable_and_never_guessed() {
        let root = std::env::temp_dir()
            .canonicalize()
            .unwrap()
            .join(format!("frameleaf-local-record-{}", uuid::Uuid::new_v4()));
        assert_eq!(stored(&root), Stored::Absent);
        assert_eq!(recorded(&root).unwrap().ports, Ports::default());
        crate::runtime_store::private_directory(&root).unwrap();
        assert_eq!(stored(&root), Stored::Absent);
        let record = Record::new(
            Ports {
                manager: 9444,
                api: 2284,
                database: 54330,
            },
            vec!["a".repeat(64)],
        );
        save(&root, &record).unwrap();
        assert_eq!(stored(&root), Stored::Present(record.clone()));
        assert_eq!(recorded(&root).unwrap(), record);
        // Saving again replaces it in one step.
        let next = Record::new(Ports::default(), vec!["a".repeat(64), "b".repeat(64)]);
        save(&root, &next).unwrap();
        assert_eq!(recorded(&root).unwrap(), next);
        assert!(!root.join(".desktop-local-manager.json.tmp").exists());
        for invalid in [
            Record::new(
                Ports {
                    api: 9443,
                    ..Ports::default()
                },
                vec![],
            ),
            Record::new(
                Ports {
                    database: 80,
                    ..Ports::default()
                },
                vec![],
            ),
            Record::new(Ports::default(), vec!["not a fingerprint".into()]),
            Record::new(Ports::default(), vec!["a".repeat(64); 65]),
        ] {
            assert_eq!(
                save(&root, &invalid).unwrap_err(),
                "local_manager_record_unavailable"
            );
            assert_eq!(
                recorded(&root).unwrap(),
                next,
                "a refused save changes nothing"
            );
        }
        for bytes in [
            &b"{"[..],
            b"",
            br#"{"schemaVersion":2,"ports":{"manager":9443,"api":2283,"database":54329},"certificates":[]}"#,
            br#"{"schemaVersion":1,"ports":{"manager":9443,"api":2283,"database":2283},"certificates":[]}"#,
            br#"{"schemaVersion":1,"ports":{"manager":9443,"api":2283,"database":54329},"certificates":[],"extra":1}"#,
        ] {
            std::fs::write(root.join(RECORD), bytes).unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(root.join(RECORD), std::fs::Permissions::from_mode(0o600))
                    .unwrap();
            }
            assert_eq!(stored(&root), Stored::Unreadable);
            assert_eq!(recorded(&root).unwrap_err(), "local_manager_record_unreadable");
            assert_eq!(recorded_manager_listener(&root), Evidence::Unknown);
        }
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn a_moved_port_is_kept_only_once_manager_was_ready_on_it() {
        let root = std::env::temp_dir()
            .canonicalize()
            .unwrap()
            .join(format!("frameleaf-local-move-{}", uuid::Uuid::new_v4()));
        crate::runtime_store::private_directory(&root).unwrap();
        let defaults = Ports::default();
        let moved = Ports {
            api: 2284,
            ..defaults
        };
        let certificates = vec!["a".repeat(64)];
        let ran = Record::new(defaults, certificates.clone());
        // A start on the ports Manager was last ready on writes what it always wrote.
        let same = Record::for_start(&ran, defaults, certificates.clone());
        assert_eq!(same, ran);
        assert_eq!(
            serde_json::to_string(&same).unwrap(),
            format!(
                r#"{{"schemaVersion":1,"ports":{{"manager":9443,"api":2283,"database":54329}},"certificates":["{}"]}}"#,
                "a".repeat(64)
            )
        );
        // Moved for this start: where it listens, and where it goes back to.
        let attempt = Record::for_start(&ran, moved, certificates.clone());
        assert_eq!(attempt.ports, moved);
        assert_eq!(attempt.unconfirmed_from, Some(defaults));

        // Manager did not come up: the move is not kept, and the busy port is named.
        save(&root, &attempt).unwrap();
        assert_eq!(recorded(&root).unwrap().ports, moved);
        assert_eq!(
            withdrawn(&root, "native_manager_exited".into()),
            "local_port_in_use_2283"
        );
        assert_eq!(recorded(&root).unwrap(), ran);
        // Nothing left to withdraw: any later failure keeps its own code and changes nothing.
        assert_eq!(
            withdrawn(&root, "native_manager_exited".into()),
            "native_manager_exited"
        );
        assert_eq!(recorded(&root).unwrap(), ran);
        // A cancelled start is withdrawn too, and still reads as cancelled.
        save(&root, &attempt).unwrap();
        assert_eq!(
            withdrawn(&root, "native_manager_start_cancelled".into()),
            "native_manager_start_cancelled"
        );
        assert_eq!(recorded(&root).unwrap(), ran);

        // Manager came up: the move is kept, and no later failure undoes it.
        save(&root, &attempt).unwrap();
        confirm(&root).unwrap();
        let kept = Record::new(moved, certificates.clone());
        assert_eq!(recorded(&root).unwrap(), kept);
        confirm(&root).unwrap();
        assert_eq!(
            withdrawn(&root, "native_manager_exited".into()),
            "native_manager_exited"
        );
        assert_eq!(recorded(&root).unwrap(), kept);

        // A run that ended before either happened leaves the move unconfirmed. The next start
        // on the same ports, or on others, still goes back to where Manager was last ready.
        let again = Record::for_start(&attempt, moved, certificates.clone());
        assert_eq!(again, attempt);
        let further = Ports {
            api: 2285,
            ..defaults
        };
        assert_eq!(
            Record::for_start(&attempt, further, certificates.clone()).unconfirmed_from,
            Some(defaults)
        );
        assert_eq!(
            Record::for_start(&attempt, defaults, certificates.clone()),
            ran,
            "back on the confirmed ports there is nothing unconfirmed"
        );
        // The first port that differs is the one named: Manager's, then photos, then database.
        for (ports, named) in [
            (
                Ports {
                    manager: 9444,
                    api: 2284,
                    database: 54330,
                },
                "local_port_in_use_9443",
            ),
            (
                Ports {
                    database: 54330,
                    ..defaults
                },
                "local_port_in_use_54329",
            ),
        ] {
            save(&root, &Record::for_start(&ran, ports, certificates.clone())).unwrap();
            assert_eq!(withdrawn(&root, "native_manager_exited".into()), named);
            assert_eq!(recorded(&root).unwrap(), ran);
        }
        // Ports to go back to that could not be a library's make the record unreadable.
        let mut invalid = attempt.clone();
        invalid.unconfirmed_from = Some(Ports {
            api: 9443,
            ..defaults
        });
        assert_eq!(
            save(&root, &invalid).unwrap_err(),
            "local_manager_record_unavailable"
        );
        // Without a record, or with one that cannot be read, nothing is withdrawn or confirmed.
        std::fs::write(root.join(RECORD), b"{").unwrap();
        assert_eq!(
            withdrawn(&root, "native_manager_exited".into()),
            "native_manager_exited"
        );
        assert_eq!(
            confirm(&root).unwrap_err(),
            "local_manager_record_unreadable"
        );
        std::fs::remove_file(root.join(RECORD)).unwrap();
        assert_eq!(
            withdrawn(&root, "native_manager_exited".into()),
            "native_manager_exited"
        );
        confirm(&root).unwrap();
        assert_eq!(stored(&root), Stored::Absent);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn a_listener_counts_as_this_librarys_manager_unless_it_is_proven_to_be_another_programs() {
        let peer = |peer: Peer| move || peer;
        assert_eq!(
            manager_listener(Evidence::Clear, &peer(Peer::Ours)),
            Evidence::Clear
        );
        assert_eq!(
            manager_listener(Evidence::Unknown, &peer(Peer::Foreign)),
            Evidence::Unknown
        );
        assert_eq!(
            manager_listener(Evidence::Running, &peer(Peer::Ours)),
            Evidence::Running
        );
        assert_eq!(
            manager_listener(Evidence::Running, &peer(Peer::Unknown)),
            Evidence::Unknown
        );
        assert_eq!(
            manager_listener(Evidence::Running, &peer(Peer::Foreign)),
            Evidence::Clear
        );
    }

    /// A TLS server on loopback presenting `identity`, serving until dropped.
    fn tls_server(
        identity: &crate::manager_tls::TlsIdentity,
    ) -> (u16, std::thread::JoinHandle<()>) {
        use rustls::pki_types::pem::PemObject;
        let certificate =
            rustls::pki_types::CertificateDer::from_pem_slice(identity.certificate().as_bytes())
                .unwrap();
        let key =
            rustls::pki_types::PrivateKeyDer::from_pem_slice(identity.private_key().as_bytes())
                .unwrap();
        let config = Arc::new(
            rustls::ServerConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![certificate], key)
            .unwrap(),
        );
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let handle = std::thread::spawn(move || {
            for stream in listener.incoming().take(2) {
                let mut stream = stream.unwrap();
                let mut connection = rustls::ServerConnection::new(config.clone()).unwrap();
                while connection.is_handshaking() {
                    if connection.complete_io(&mut stream).is_err() {
                        break;
                    }
                }
            }
        });
        (port, handle)
    }
    fn identity() -> crate::manager_tls::TlsIdentity {
        crate::manager_tls::TlsIdentity::load_or_create(
            "aaaaaaaaaaaa",
            "https://127.0.0.1:9443",
            || Ok(None),
            |_| Ok(()),
        )
        .unwrap()
    }

    #[test]
    fn a_tls_listener_is_named_only_by_the_certificate_it_proves_it_holds() {
        let (ours, other) = (identity(), identity());
        let fingerprint = |identity: &crate::manager_tls::TlsIdentity| {
            crate::manager::certificate_fingerprint(identity.certificate()).unwrap()
        };
        let (port, server) = tls_server(&ours);
        assert_eq!(tls_peer(port, &[fingerprint(&ours)]), Peer::Ours);
        assert_eq!(
            tls_peer(port, &[fingerprint(&other), "c".repeat(64)]),
            Peer::Foreign,
            "a completed handshake with another certificate is another program"
        );
        server.join().unwrap();
        // Nothing to compare against: nothing is named.
        let (port, server) = tls_server(&ours);
        assert_eq!(tls_peer(port, &[]), Peer::Unknown);
        drop(std::net::TcpStream::connect(("127.0.0.1", port)));
        drop(std::net::TcpStream::connect(("127.0.0.1", port)));
        server.join().unwrap();

        // A program that answers in plain text is not a TLS Manager.
        let plain = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = plain.local_addr().unwrap().port();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = plain.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            answer_in_plain_text(&mut stream);
        });
        assert_eq!(tls_peer(port, &[fingerprint(&ours)]), Peer::Foreign);
        server.join().unwrap();

        // A listener that accepts and then says nothing, or hangs up, proves nothing.
        let silent = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = silent.local_addr().unwrap().port();
        let server = std::thread::spawn(move || {
            let (stream, _) = silent.accept().unwrap();
            drop(stream);
        });
        assert_eq!(tls_peer(port, &[fingerprint(&ours)]), Peer::Unknown);
        server.join().unwrap();
        // Nothing listening at all.
        let closed = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = closed.local_addr().unwrap().port();
        drop(closed);
        assert_eq!(tls_peer(port, &[fingerprint(&ours)]), Peer::Unknown);
    }

    /// A reset says only that the connection ended. Whatever sent it, a plain-text program
    /// included, is not named by it: the port stays unidentified, which is the safe answer.
    #[test]
    fn a_connection_reset_names_nobody() {
        let ours = crate::manager::certificate_fingerprint(identity().certificate()).unwrap();
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            // The client is now waiting for an answer to its hello.
            stream.read_exact(&mut [0u8; 5]).unwrap();
            stream.set_nonblocking(true).unwrap();
            // Zero linger: closing sends a reset, on every system.
            tauri::async_runtime::block_on(async {
                tokio::net::TcpStream::from_std(stream)
                    .unwrap()
                    .set_zero_linger()
                    .unwrap();
            });
        });
        assert_eq!(tls_peer(port, &[ours]), Peer::Unknown);
        server.join().unwrap();
    }

    // TEMPORARY (FD-69): evidence for the Windows runner, removed in the next commit.
    #[test]
    fn temporary_fd_69_two_hundred_rounds() {
        let ours = crate::manager::certificate_fingerprint(identity().certificate()).unwrap();
        let round = |serve: fn(std::net::TcpStream)| {
            let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
            let port = listener.local_addr().unwrap().port();
            let server = std::thread::spawn(move || serve(listener.accept().unwrap().0));
            let peer = tls_peer(port, std::slice::from_ref(&ours));
            server.join().unwrap();
            peer
        };
        // The listener as it was: at most 16 bytes read, a reply, a close with the rest unread.
        let before = (0..200)
            .filter(|_| {
                round(|mut stream| {
                    let _ = stream.read(&mut [0u8; 16]);
                    let _ =
                        stream.write_all(b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n");
                }) != Peer::Foreign
            })
            .count();
        // Written straight to stderr so a passing run still shows it.
        let _ = writeln!(
            std::io::stderr(),
            "FD-69 old listener: {before}/200 rounds were not Foreign"
        );
        for _ in 0..200 {
            let peer = round(|mut stream| {
                stream
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                answer_in_plain_text(&mut stream);
            });
            assert_eq!(peer, Peer::Foreign);
        }
        let _ = writeln!(std::io::stderr(), "FD-69 fixed listener: 200/200 Foreign");
        for _ in 0..200 {
            a_connection_reset_names_nobody();
        }
        let _ = writeln!(std::io::stderr(), "FD-69 reset: 200/200 Unknown");
    }
}
