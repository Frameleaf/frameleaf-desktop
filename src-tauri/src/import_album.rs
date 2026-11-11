//! Album destinations use the signed-in Library's ordinary album endpoints.
use crate::{connection::SavedConnection, copy_upload, transport, DesktopState};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::sync::atomic::AtomicBool;
use tauri::{State, WebviewWindow};
use url::Url;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Destination {
    pub id: String,
    pub name: String,
    pub shared: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Album {
    id: String,
    album_name: String,
    kind: String,
    shared: bool,
    album_users: Vec<Member>,
    #[serde(default)]
    is_smart: bool,
    #[serde(default)]
    is_locked: bool,
    #[serde(default)]
    smart_rule_id: Option<String>,
    #[serde(default)]
    smart_kind: Option<String>,
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

fn uuid_v4(id: &str) -> bool {
    uuid::Uuid::parse_str(id)
        .is_ok_and(|uuid| uuid.get_version_num() == 4 && uuid.to_string() == id)
}

impl Album {
    fn destination(self, account: &str) -> Option<Destination> {
        if !uuid_v4(&self.id)
            || self.album_name.trim().is_empty()
            || self.album_name.len() > 512
            || self.album_name.chars().any(char::is_control)
            || self.kind != "album"
            || self.is_smart
            || self.is_locked
            || self.smart_rule_id.is_some()
            || self.smart_kind.is_some()
            || !self.album_users.iter().any(|member| {
                member.user.id == account && matches!(member.role.as_str(), "owner" | "editor")
            })
        {
            return None;
        }
        Some(Destination {
            id: self.id,
            name: self.album_name,
            shared: self.shared,
        })
    }
}

fn request_error(error: String) -> String {
    match error.as_str() {
        "server_http_401" | "server_http_403" => "source_album_permission_required".into(),
        "server_http_404" => "source_album_missing".into(),
        "server_response_invalid" | "server_response_too_large" => {
            "source_album_response_invalid".into()
        }
        _ => error,
    }
}

fn destination_error(error: String) -> String {
    if error == "server_http_400" {
        // Library's resource-level ACL uses the same response for missing and inaccessible albums.
        "source_album_unavailable_for_write".into()
    } else {
        request_error(error)
    }
}

async fn get(
    client: &Client,
    base: &Url,
    saved: &SavedConnection,
    id: &str,
    cancel: &AtomicBool,
) -> Result<Destination, String> {
    if !uuid_v4(id) {
        return Err("source_album_selection_invalid".into());
    }
    let response = copy_upload::send(
        client
            .get(base.join(&format!("api/albums/{id}")).unwrap())
            .bearer_auth(&saved.token),
        cancel,
    )
    .await?;
    let album: Album = transport::json(response).await.map_err(destination_error)?;
    if album.id != id {
        return Err("source_album_response_invalid".into());
    }
    album
        .destination(&saved.account_id)
        .ok_or_else(|| "source_album_permission_required".into())
}

/// Check the displayed choice against current album metadata before persisting approval.
pub(crate) async fn approve(
    saved: &SavedConnection,
    choice: Option<Destination>,
) -> Result<Option<Destination>, String> {
    let Some(choice) = choice else {
        return Ok(None);
    };
    let client = transport::client()?;
    transport::capabilities(&client, saved)
        .await?
        .ok_or("source_server_update_required")?;
    let base = crate::connection::normalize_server(&saved.server)?;
    let current = get(&client, &base, saved, &choice.id, &AtomicBool::new(false)).await?;
    if current != choice {
        return Err("source_album_selection_changed".into());
    }
    Ok(Some(current))
}

pub(crate) async fn require_writable(
    client: &Client,
    base: &Url,
    saved: &SavedConnection,
    destination: &Destination,
    cancel: &AtomicBool,
) -> Result<(), String> {
    let current = get(client, base, saved, &destination.id, cancel).await?;
    if current.shared != destination.shared {
        return Err("source_album_selection_changed".into());
    }
    Ok(())
}

#[derive(Deserialize)]
struct Attachment {
    id: String,
    success: bool,
    error: Option<String>,
}

fn attachment_result(mut items: Vec<Attachment>, asset: &str) -> Result<(), String> {
    if items.len() != 1 || items[0].id != asset {
        return Err("source_album_response_invalid".into());
    }
    let item = items.pop().unwrap();
    match (item.success, item.error.as_deref()) {
        (true, None) | (false, Some("duplicate")) => Ok(()),
        (false, Some("no_permission")) => Err("source_album_permission_required".into()),
        (false, Some("not_found")) => Err("source_album_asset_missing".into()),
        (false, _) => Err("source_album_attachment_failed".into()),
        _ => Err("source_album_response_invalid".into()),
    }
}

pub(crate) async fn attach(
    client: &Client,
    base: &Url,
    saved: &SavedConnection,
    destination: &Destination,
    asset: &str,
    cancel: &AtomicBool,
) -> Result<(), String> {
    if !uuid_v4(&destination.id) {
        return Err("source_album_selection_invalid".into());
    }
    if !uuid_v4(asset) {
        return Err("source_receipt_invalid".into());
    }
    let response = copy_upload::send(
        client
            .put(
                base.join(&format!("api/albums/{}/assets", destination.id))
                    .unwrap(),
            )
            .bearer_auth(&saved.token)
            .json(&serde_json::json!({ "ids": [asset] })),
        cancel,
    )
    .await?;
    attachment_result(
        transport::json(response).await.map_err(destination_error)?,
        asset,
    )
}

#[tauri::command]
pub(crate) async fn list_photo_import_albums(
    window: WebviewWindow,
    state: State<'_, DesktopState>,
    search: Option<String>,
) -> Result<Vec<Destination>, String> {
    crate::require_local(&window)?;
    let current = state.0.lock().await;
    let saved = current.as_ref().ok_or("sign_in_required")?;
    let search = search.as_deref().unwrap_or("").trim();
    if search.chars().count() > 100 || search.chars().any(char::is_control) {
        return Err("source_album_search_invalid".into());
    }
    let client = transport::client()?;
    transport::capabilities(&client, saved)
        .await?
        .ok_or("source_server_update_required")?;
    let base = crate::connection::normalize_server(&saved.server)?;
    let mut request = client
        .get(base.join("api/albums").unwrap())
        .bearer_auth(&saved.token)
        .query(&[("take", "100")]);
    if !search.is_empty() {
        request = request.query(&[("search", search)]);
    }
    let response = request
        .send()
        .await
        .map_err(|_| "source_album_list_unavailable")?;
    let albums: Vec<Album> = transport::json_limit(response, 4 * 1024 * 1024)
        .await
        .map_err(request_error)?;
    if albums.len() > 100 {
        return Err("source_album_response_invalid".into());
    }
    let mut albums: Vec<_> = albums
        .into_iter()
        .filter_map(|album| album.destination(&saved.account_id))
        .collect();
    albums.sort_by(|a, b| a.name.cmp(&b.name).then(a.id.cmp(&b.id)));
    Ok(albums)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writable_albums_exclude_viewers_and_automatic_or_locked_destinations() {
        let album = |role: &str, kind: &str, smart: bool, locked: bool| {
            serde_json::from_value::<Album>(serde_json::json!({
                "id": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                "albumName": "Vacation", "kind": kind, "shared": true,
                "albumUsers": [{ "user": { "id": "me" }, "role": role }],
                "isSmart": smart, "isLocked": locked
            }))
            .unwrap()
        };
        assert!(
            album("editor", "album", false, false)
                .destination("me")
                .unwrap()
                .shared
        );
        assert!(album("owner", "album", false, false)
            .destination("other")
            .is_none());
        assert!(album("viewer", "album", false, false)
            .destination("me")
            .is_none());
        assert!(album("owner", "collection", false, false)
            .destination("me")
            .is_none());
        assert!(album("owner", "album", true, false)
            .destination("me")
            .is_none());
        assert!(album("owner", "album", false, true)
            .destination("me")
            .is_none());
    }

    #[test]
    fn attachment_requires_an_exact_result_and_accepts_only_the_matching_duplicate() {
        let result = |id: &str, error: &str| {
            vec![Attachment {
                id: id.into(),
                success: false,
                error: Some(error.into()),
            }]
        };
        assert!(attachment_result(result("asset", "duplicate"), "asset").is_ok());
        assert_eq!(
            attachment_result(result("other", "duplicate"), "asset").unwrap_err(),
            "source_album_response_invalid"
        );
        assert_eq!(
            attachment_result(result("asset", "no_permission"), "asset").unwrap_err(),
            "source_album_permission_required"
        );
        assert_eq!(
            attachment_result(result("asset", "not_found"), "asset").unwrap_err(),
            "source_album_asset_missing"
        );
    }
}
