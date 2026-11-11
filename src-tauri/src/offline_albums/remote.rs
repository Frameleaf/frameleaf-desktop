use crate::{connection::SavedConnection, transport};
use base64::{engine::general_purpose::STANDARD, Engine};
use reqwest::{
    dns::{Addrs, Name, Resolve, Resolving},
    Client, Response, StatusCode,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    error::Error as _,
    io::{self, ErrorKind},
    sync::Arc,
    time::Duration,
};
use url::Url;
use uuid::Uuid;

pub(super) const MAX_ITEMS: usize = 1_000;
pub(super) const CHUNK: usize = 1024 * 1024;

pub(super) enum Access {
    Offline,
    Denied,
    Invalid,
}
impl From<Access> for String {
    fn from(value: Access) -> Self {
        match value {
            Access::Offline => "offline_library_unreachable",
            Access::Denied => "offline_album_access_changed",
            Access::Invalid => "offline_album_response_invalid",
        }
        .into()
    }
}

#[derive(Clone, Deserialize, Serialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
pub(super) struct Media {
    pub id: Uuid,
    pub name: String,
    pub mime: String,
    pub checksum: String,
}

#[derive(Clone, Deserialize, Serialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
pub(super) struct Plan {
    pub id: Uuid,
    pub name: String,
    pub items: Vec<Media>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Album {
    id: Uuid,
    album_name: String,
    kind: String,
    is_locked: Option<bool>,
    album_users: Vec<Member>,
}
#[derive(Deserialize)]
struct Member {
    user: User,
    role: String,
}
#[derive(Deserialize)]
struct User {
    id: String,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Page {
    items: Vec<Item>,
    next_cursor: Option<Cursor>,
}
#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
enum Item {
    Asset { asset: Asset },
    Bookmark,
}
#[derive(Deserialize)]
struct Cursor {
    kind: String,
    id: Uuid,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Asset {
    id: Uuid,
    owner_id: Option<String>,
    original_file_name: Option<String>,
    original_mime_type: Option<String>,
    checksum: Option<String>,
    visibility: Option<String>,
    is_trashed: Option<bool>,
    #[serde(rename = "type")]
    kind: String,
}

pub(super) struct Library<'a> {
    client: Client,
    base: Url,
    saved: &'a SavedConnection,
}
impl<'a> Library<'a> {
    pub async fn connect(saved: &'a SavedConnection) -> Result<Self, Access> {
        if saved.server_id.is_empty() || saved.account_id.is_empty() {
            return Err(Access::Denied);
        }
        let library = Self {
            client: transport::client_builder()
                .dns_resolver(Arc::new(OfflineDns))
                .connect_timeout(Duration::from_secs(3))
                .build()
                .map_err(|_| Access::Invalid)?,
            base: crate::connection::normalize_server(&saved.server).map_err(|_| Access::Denied)?,
            saved,
        };
        let caps: crate::connection::Capabilities =
            library.json("api/desktop/capabilities", &[]).await?;
        if caps.protocol_version != 1 || caps.server_id != saved.server_id {
            return Err(Access::Denied);
        }
        let owner: User = library.json("api/users/me", &[]).await?;
        if owner.id != saved.account_id {
            return Err(Access::Denied);
        }
        Ok(library)
    }

    async fn request(
        &self,
        path: &str,
        query: &[(&str, &str)],
        timeout: Duration,
    ) -> Result<Response, Access> {
        let response = self
            .client
            .get(self.base.join(path).map_err(|_| Access::Invalid)?)
            .bearer_auth(&self.saved.token)
            .query(query)
            .timeout(timeout)
            .send()
            .await
            .map_err(|error| classify_connection(&error))?;
        match response.status() {
            StatusCode::OK => Ok(response),
            StatusCode::UNAUTHORIZED
            | StatusCode::FORBIDDEN
            | StatusCode::NOT_FOUND
            | StatusCode::GONE => Err(Access::Denied),
            _ => Err(Access::Invalid),
        }
    }

    async fn json<T: serde::de::DeserializeOwned>(
        &self,
        path: &str,
        query: &[(&str, &str)],
    ) -> Result<T, Access> {
        transport::json_limit(
            self.request(path, query, Duration::from_secs(8)).await?,
            1024 * 1024,
        )
        .await
        .map_err(|_| Access::Invalid)
    }

    pub async fn plan(&self, id: Uuid) -> Result<Plan, Access> {
        let album: Album = self.json(&format!("api/albums/{id}"), &[]).await?;
        if album.id != id
            || album.kind != "album"
            || album.is_locked != Some(false)
            || !album
                .album_users
                .iter()
                .any(|member| member.role == "owner" && member.user.id == self.saved.account_id)
        {
            return Err(Access::Denied);
        }
        let mut items = BTreeMap::new();
        let mut previous = None;
        let path = format!("api/albums/{id}/items");
        for _ in 0..=MAX_ITEMS / 100 {
            let after = previous.map(|id: Uuid| id.to_string());
            let query = after.as_ref().map_or_else(
                || vec![("limit", "100")],
                |id| {
                    vec![
                        ("limit", "100"),
                        ("afterKind", "asset"),
                        ("afterId", id.as_str()),
                    ]
                },
            );
            let page: Page = self.json(&path, &query).await?;
            for entry in page.items {
                if let Item::Asset { asset } = entry {
                    let Some(item) = asset.eligible(&self.saved.account_id)? else {
                        continue;
                    };
                    if items.insert(item.id, item).is_some() || items.len() > MAX_ITEMS {
                        return Err(Access::Invalid);
                    }
                }
            }
            match page.next_cursor {
                Some(cursor)
                    if cursor.kind == "asset" && previous.is_none_or(|id| cursor.id > id) =>
                {
                    previous = Some(cursor.id);
                }
                Some(cursor) if cursor.kind != "bookmark" => return Err(Access::Invalid),
                _ => {
                    return Ok(Plan {
                        id,
                        name: album
                            .album_name
                            .chars()
                            .filter(|char| !char.is_control())
                            .take(256)
                            .collect(),
                        items: items.into_values().collect(),
                    });
                }
            }
        }
        Err(Access::Invalid)
    }

    pub async fn original(
        &self,
        item: &Media,
        limit: u64,
        mut write: impl FnMut(u64, Vec<u8>) -> Result<(), String>,
    ) -> Result<u64, String> {
        let mut response = self
            .request(
                &format!("api/assets/{}/original", item.id),
                &[("edited", "false")],
                Duration::from_secs(1800),
            )
            .await?;
        let expected = response.content_length();
        if expected.is_some_and(|bytes| bytes > limit) {
            return Err("offline_album_storage_limit".into());
        }
        let mut bytes = 0u64;
        let mut index = 0u64;
        let mut pending = Vec::with_capacity(CHUNK);
        let mut checksum = Checksum::new(&item.checksum).ok_or("offline_album_original_changed")?;
        while let Some(chunk) = tokio::time::timeout(Duration::from_secs(30), response.chunk())
            .await
            .map_err(|_| "offline_album_interrupted")?
            .map_err(|_| "offline_album_interrupted")?
        {
            bytes = bytes
                .checked_add(chunk.len() as u64)
                .filter(|bytes| *bytes <= limit)
                .ok_or("offline_album_storage_limit")?;
            checksum.update(&chunk);
            let mut input = chunk.as_ref();
            while !input.is_empty() {
                let (head, tail) = input.split_at(input.len().min(CHUNK - pending.len()));
                pending.extend_from_slice(head);
                input = tail;
                if pending.len() == CHUNK {
                    write(
                        index,
                        std::mem::replace(&mut pending, Vec::with_capacity(CHUNK)),
                    )?;
                    index += 1;
                }
            }
        }
        if bytes == 0 || expected.is_some_and(|expected| expected != bytes) || !checksum.valid() {
            return Err("offline_album_original_changed".into());
        }
        if !pending.is_empty() {
            write(index, pending)?;
        }
        Ok(bytes)
    }
}

impl Asset {
    fn eligible(self, owner: &str) -> Result<Option<Media>, Access> {
        if self.owner_id.as_deref() != Some(owner)
            || self.is_trashed != Some(false)
            || !matches!(self.visibility.as_deref(), Some("timeline" | "archive"))
            || !matches!(self.kind.as_str(), "IMAGE" | "VIDEO")
        {
            return Ok(None);
        }
        let checksum = self.checksum.ok_or(Access::Invalid)?;
        if !STANDARD
            .decode(&checksum)
            .is_ok_and(|bytes| matches!(bytes.len(), 20 | 32))
        {
            return Err(Access::Invalid);
        }
        let name: String = self
            .original_file_name
            .ok_or(Access::Invalid)?
            .chars()
            .filter(|char| !char.is_control() && !matches!(char, '/' | '\\'))
            .take(256)
            .collect();
        let mime = self
            .original_mime_type
            .as_deref()
            .filter(|value| {
                matches!(
                    *value,
                    "image/jpeg"
                        | "image/png"
                        | "image/gif"
                        | "image/webp"
                        | "image/avif"
                        | "image/heic"
                        | "image/heif"
                        | "video/mp4"
                        | "video/webm"
                        | "video/quicktime"
                )
            })
            .unwrap_or("application/octet-stream")
            .into();
        Ok(Some(Media {
            id: self.id,
            name,
            mime,
            checksum,
        }))
    }
}

enum Checksum {
    Sha1(sha1::Sha1, Vec<u8>),
    Sha256(Sha256, Vec<u8>),
}
impl Checksum {
    fn new(value: &str) -> Option<Self> {
        let expected = STANDARD.decode(value).ok()?;
        match expected.len() {
            20 => Some(Self::Sha1(sha1::Sha1::new(), expected)),
            32 => Some(Self::Sha256(Sha256::new(), expected)),
            _ => None,
        }
    }
    fn update(&mut self, bytes: &[u8]) {
        match self {
            Self::Sha1(hash, _) => hash.update(bytes),
            Self::Sha256(hash, _) => hash.update(bytes),
        }
    }
    fn valid(self) -> bool {
        match self {
            Self::Sha1(hash, expected) => hash.finalize()[..] == expected,
            Self::Sha256(hash, expected) => hash.finalize()[..] == expected,
        }
    }
}

struct OfflineDns;
impl Resolve for OfflineDns {
    fn resolve(&self, name: Name) -> Resolving {
        Box::pin(async move {
            let addresses: Vec<_> = tokio::net::lookup_host((name.as_str(), 0))
                .await
                .map_err(dns_unreachable)?
                .collect();
            if addresses.is_empty() {
                return Err(io::Error::from(ErrorKind::HostUnreachable).into());
            }
            Ok(Box::new(addresses.into_iter()) as Addrs)
        })
    }
}

fn dns_unreachable(error: io::Error) -> io::Error {
    io::Error::new(ErrorKind::HostUnreachable, error)
}

fn classify_connection(error: &reqwest::Error) -> Access {
    if error.is_timeout() && error.is_connect() {
        return Access::Offline;
    }
    let mut cause = error.source();
    while let Some(value) = cause {
        if let Some(io) = value.downcast_ref::<std::io::Error>() {
            if matches!(
                io.kind(),
                ErrorKind::ConnectionRefused
                    | ErrorKind::NetworkUnreachable
                    | ErrorKind::HostUnreachable
                    | ErrorKind::AddrNotAvailable
                    | ErrorKind::NotConnected
            ) {
                return Access::Offline;
            }
        }
        cause = value.source();
    }
    Access::Invalid
}

#[cfg(test)]
mod tests {
    use super::*;

    fn matches_checksum(bytes: &[u8], value: &str) -> bool {
        let mut checksum = Checksum::new(value).unwrap();
        checksum.update(bytes);
        checksum.valid()
    }

    #[tokio::test]
    async fn a_dns_failure_allows_the_bounded_offline_path() {
        struct FailedDns;
        impl Resolve for FailedDns {
            fn resolve(&self, _: Name) -> Resolving {
                Box::pin(async {
                    Err(dns_unreachable(io::Error::other("synthetic unavailable DNS")).into())
                })
            }
        }
        let client = transport::client_builder()
            .no_proxy()
            .dns_resolver(Arc::new(FailedDns))
            .build()
            .unwrap();
        let error = client
            .get("https://fixture.invalid/")
            .send()
            .await
            .unwrap_err();
        assert!(matches!(classify_connection(&error), Access::Offline));
    }

    #[test]
    fn only_owned_visible_originals_with_real_checksums_are_eligible() {
        let owner = Uuid::new_v4().to_string();
        let checksum = STANDARD.encode(Sha256::digest(b"original"));
        for (visibility, claimed, eligible) in [
            ("timeline", owner.as_str(), true),
            ("locked", owner.as_str(), false),
            ("hidden", owner.as_str(), false),
            ("archive", "other", false),
        ] {
            let asset = Asset {
                id: Uuid::new_v4(),
                owner_id: Some(claimed.into()),
                original_file_name: Some("original.jpg".into()),
                original_mime_type: Some("image/jpeg".into()),
                checksum: Some(checksum.clone()),
                visibility: Some(visibility.into()),
                is_trashed: Some(false),
                kind: "IMAGE".into(),
            };
            assert_eq!(asset.eligible(&owner).ok().flatten().is_some(), eligible);
        }
        assert!(matches_checksum(b"original", &checksum));
        assert!(matches_checksum(
            b"original",
            &STANDARD.encode(sha1::Sha1::digest(b"original"))
        ));
        assert!(!matches_checksum(b"altered!", &checksum));
    }
}
