//! Finding Frameleaf servers on the local network (DNS-SD `_frameleaf._tcp`), the record the
//! server advertises in `server/src/services/lan-discovery.service.ts`: TXT keys `id`, `name`,
//! `scheme`, `setup`, `linked` and `cloud`; the port lives in the SRV record only.

use mdns_sd::{ServiceDaemon, ServiceEvent, ServiceInfo};
use serde::Serialize;
use std::{
    collections::BTreeMap,
    net::IpAddr,
    time::{Duration, Instant},
};
use tauri::WebviewWindow;

pub(crate) const SERVICE_TYPE: &str = "_frameleaf._tcp.local.";
/// How long one browse listens before answering; a record usually arrives well within a second.
const BROWSE_FOR: Duration = Duration::from_millis(2500);
/// A TXT value longer than this is not one of ours.
const MAX_VALUE: usize = 255;

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct DiscoveredServer {
    pub name: String,
    pub id: String,
    /// `scheme://host:port`, the address to type in or to connect to.
    pub url: String,
    pub host: String,
    pub port: u16,
    pub addresses: Vec<String>,
    /// `needed` while the server has no administrator, else `complete`.
    pub setup: String,
    pub linked: bool,
    /// `available` when the server can link to Frameleaf Cloud, else `unavailable`.
    pub cloud: String,
}

/// The TXT record and SRV details of one resolved instance, as one record.
pub(crate) fn parse_record(
    txt: &BTreeMap<String, String>,
    hostname: &str,
    port: u16,
    addresses: &[IpAddr],
) -> Option<DiscoveredServer> {
    let value = |key: &str| {
        txt.get(key)
            .map(|value| value.trim())
            .filter(|value| !value.is_empty() && value.len() <= MAX_VALUE)
    };
    let id = value("id")?;
    let name = value("name")?;
    if port == 0 {
        return None;
    }
    let scheme = match value("scheme") {
        // FL-435: the server only ever listens on plain HTTP unless something in front of it says otherwise.
        None => "http",
        Some(scheme @ ("http" | "https")) => scheme,
        Some(_) => return None,
    };
    let setup = match value("setup") {
        Some("needed") => "needed",
        _ => "complete",
    };
    let linked = value("linked") == Some("true");
    let cloud = match value("cloud") {
        Some("available") => "available",
        _ => "unavailable",
    };
    let mut sorted: Vec<&IpAddr> = addresses.iter().collect();
    sorted.sort_by_key(|address| (address.is_ipv6(), address.to_string()));
    sorted.dedup();
    let addresses: Vec<String> = sorted.iter().map(|address| address.to_string()).collect();
    let host = hostname.trim().trim_end_matches('.').to_string();
    let host = if host.is_empty() {
        match sorted.first() {
            Some(IpAddr::V4(v4)) => v4.to_string(),
            Some(IpAddr::V6(v6)) => format!("[{v6}]"),
            None => return None,
        }
    } else {
        host
    };
    Some(DiscoveredServer {
        name: name.to_string(),
        id: id.to_string(),
        url: format!("{scheme}://{host}:{port}"),
        host,
        port,
        addresses,
        setup: setup.into(),
        linked,
        cloud: cloud.into(),
    })
}

fn from_info(info: &ServiceInfo) -> Option<DiscoveredServer> {
    let mut txt = BTreeMap::new();
    for key in ["id", "name", "scheme", "setup", "linked", "cloud"] {
        if let Some(value) = info.get_property_val_str(key) {
            txt.insert(key.to_string(), value.to_string());
        }
    }
    let addresses: Vec<IpAddr> = info.get_addresses().iter().copied().collect();
    parse_record(&txt, info.get_hostname(), info.get_port(), &addresses)
}

/// The same server answers once per interface; one entry keeps every address it was seen on.
pub(crate) fn merge(found: &mut Vec<DiscoveredServer>, server: DiscoveredServer) {
    if let Some(existing) = found.iter_mut().find(|item| item.id == server.id) {
        for address in server.addresses {
            if !existing.addresses.contains(&address) {
                existing.addresses.push(address);
            }
        }
        return;
    }
    found.push(server);
}

fn browse() -> Result<Vec<DiscoveredServer>, String> {
    let daemon = ServiceDaemon::new().map_err(|_| "discovery_unavailable")?;
    let receiver = daemon
        .browse(SERVICE_TYPE)
        .map_err(|_| "discovery_unavailable")?;
    let deadline = Instant::now() + BROWSE_FOR;
    let mut found = Vec::new();
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        match receiver.recv_timeout(remaining) {
            Ok(ServiceEvent::ServiceResolved(info)) => {
                if let Some(server) = from_info(&info) {
                    merge(&mut found, server);
                }
            }
            Ok(_) => {}
            Err(_) => break,
        }
    }
    let _ = daemon.stop_browse(SERVICE_TYPE);
    let _ = daemon.shutdown();
    found.sort_by(|a, b| a.name.cmp(&b.name).then(a.id.cmp(&b.id)));
    Ok(found)
}

#[tauri::command]
pub(crate) async fn discover_servers(
    window: WebviewWindow,
) -> Result<Vec<DiscoveredServer>, String> {
    crate::require_local(&window)?;
    tauri::async_runtime::spawn_blocking(browse)
        .await
        .map_err(|_| "discovery_failed")?
}

#[cfg(test)]
mod tests {
    use super::*;

    fn txt(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(key, value)| (key.to_string(), value.to_string()))
            .collect()
    }
    fn addresses() -> Vec<IpAddr> {
        vec![
            "fe80::1".parse().unwrap(),
            "192.168.1.20".parse().unwrap(),
            "10.0.0.5".parse().unwrap(),
        ]
    }

    #[test]
    fn reads_every_txt_key_and_builds_the_address_from_scheme_host_and_port() {
        let server = parse_record(
            &txt(&[
                ("id", "018f5e7a-6b1e-7f6e-9c2e-1a2b3c4d5e6f"),
                ("name", "Family photos"),
                ("scheme", "https"),
                ("setup", "needed"),
                ("linked", "true"),
                ("cloud", "available"),
            ]),
            "nas.local.",
            2283,
            &addresses(),
        )
        .unwrap();
        assert_eq!(server.url, "https://nas.local:2283");
        assert_eq!(server.host, "nas.local");
        assert_eq!(server.port, 2283);
        assert_eq!(server.name, "Family photos");
        assert_eq!(server.id, "018f5e7a-6b1e-7f6e-9c2e-1a2b3c4d5e6f");
        assert_eq!(server.setup, "needed");
        assert!(server.linked);
        assert_eq!(server.cloud, "available");
        assert_eq!(server.addresses, ["10.0.0.5", "192.168.1.20", "fe80::1"]);
    }

    #[test]
    fn missing_scheme_means_plain_http_and_missing_state_keys_take_their_defaults() {
        let server = parse_record(
            &txt(&[("id", "local-1"), ("name", "Frameleaf server")]),
            "nas.local",
            2283,
            &addresses(),
        )
        .unwrap();
        assert_eq!(server.url, "http://nas.local:2283");
        assert_eq!(server.setup, "complete");
        assert!(!server.linked);
        assert_eq!(server.cloud, "unavailable");
    }

    #[test]
    fn refuses_records_without_identity_or_with_an_unknown_scheme_or_port() {
        assert!(parse_record(&txt(&[("name", "x")]), "h", 1, &addresses()).is_none());
        assert!(parse_record(&txt(&[("id", "x")]), "h", 1, &addresses()).is_none());
        assert!(parse_record(&txt(&[("id", " "), ("name", "x")]), "h", 1, &addresses()).is_none());
        assert!(parse_record(
            &txt(&[("id", "x"), ("name", "x"), ("scheme", "ftp")]),
            "h",
            1,
            &addresses()
        )
        .is_none());
        assert!(parse_record(&txt(&[("id", "x"), ("name", "x")]), "h", 0, &addresses()).is_none());
        assert!(parse_record(
            &txt(&[("id", "x"), ("name", &"n".repeat(256))]),
            "h",
            1,
            &addresses()
        )
        .is_none());
    }

    #[test]
    fn falls_back_to_the_first_address_without_a_hostname_and_brackets_ipv6() {
        let v4 = parse_record(&txt(&[("id", "x"), ("name", "x")]), "", 80, &addresses()).unwrap();
        assert_eq!(v4.url, "http://10.0.0.5:80");
        assert_eq!(v4.host, "10.0.0.5");
        let only_v6: Vec<IpAddr> = vec!["fd00::7".parse().unwrap()];
        let v6 = parse_record(&txt(&[("id", "x"), ("name", "x")]), ".", 80, &only_v6).unwrap();
        assert_eq!(v6.url, "http://[fd00::7]:80");
        assert!(parse_record(&txt(&[("id", "x"), ("name", "x")]), "", 80, &[]).is_none());
    }

    #[test]
    fn merging_keeps_one_entry_per_server_id_with_every_address() {
        let a = parse_record(
            &txt(&[("id", "same"), ("name", "A")]),
            "a.local",
            1,
            &["10.0.0.1".parse().unwrap()],
        )
        .unwrap();
        let b = parse_record(
            &txt(&[("id", "same"), ("name", "A")]),
            "a.local",
            1,
            &["10.0.0.1".parse().unwrap(), "10.0.0.2".parse().unwrap()],
        )
        .unwrap();
        let c = parse_record(
            &txt(&[("id", "other"), ("name", "B")]),
            "b.local",
            1,
            &["10.0.0.3".parse().unwrap()],
        )
        .unwrap();
        let mut found = Vec::new();
        merge(&mut found, a);
        merge(&mut found, b);
        merge(&mut found, c);
        assert_eq!(found.len(), 2);
        assert_eq!(found[0].addresses, ["10.0.0.1", "10.0.0.2"]);
        assert_eq!(found[1].id, "other");
    }
}
