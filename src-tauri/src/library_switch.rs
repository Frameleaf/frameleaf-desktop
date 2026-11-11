//! The active credential remains the commit point for Photos, imports and AI work.
use crate::{
    connection::{Capabilities, ConnectionView, SavedConnection},
    credentials,
    offline_albums::{CleanupScope, OfflineAlbums},
    DesktopState,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tauri::{AppHandle, Manager, State, WebviewWindow};

const INDEX: &str = "approved-libraries";
const MAX_APPROVED: usize = 16;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ApprovedLibrary {
    #[serde(flatten)]
    display: LibraryDisplay,
    active: bool,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct LibraryDisplay {
    id: String,
    server: String,
    name: String,
}

impl LibraryDisplay {
    fn from_saved(saved: &SavedConnection) -> Self {
        Self {
            id: library_id(saved),
            server: saved.server.clone(),
            name: saved.name.clone(),
        }
    }
}

/// Older indexes contained only IDs. Keep those slots selectable without opening them to list.
#[derive(Clone, Deserialize, Serialize)]
#[serde(untagged)]
enum IndexEntry {
    Display {
        display: LibraryDisplay,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        generation: Option<uuid::Uuid>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        cleanup_scope: Option<CleanupScope>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pending: Option<Box<PendingCleanup>>,
    },
    Legacy(String),
}

#[derive(Clone, Deserialize, Serialize)]
struct PendingCleanup {
    generation: Option<uuid::Uuid>,
    scope: CleanupScope,
    revoke_bearer: bool,
}

impl IndexEntry {
    /// Use the stable Library and account identity for both index versions.
    fn id(&self) -> &str {
        match self {
            Self::Display { display, .. } => &display.id,
            Self::Legacy(id) => id,
        }
    }

    /// Give an old approval a label without unlocking its sign-in.
    fn display(&self) -> LibraryDisplay {
        match self {
            Self::Display { display, .. } => display.clone(),
            Self::Legacy(id) => LibraryDisplay {
                id: id.clone(),
                server: String::new(),
                name: format!("Saved library {}", id.chars().take(8).collect::<String>()),
            },
        }
    }

    /// Legacy approvals use the original slot until the user signs in again.
    fn generation(&self) -> Option<uuid::Uuid> {
        match self {
            Self::Display { generation, .. } => *generation,
            Self::Legacy(_) => None,
        }
    }

    fn account(&self) -> Result<String, String> {
        slot_for(self.id(), self.generation())
    }

    fn pending(&self) -> Option<&PendingCleanup> {
        match self {
            Self::Display { pending, .. } => pending.as_deref(),
            Self::Legacy(_) => None,
        }
    }

    /// Older records require a readable credential to recover the exact cleanup scope.
    fn cleanup_scope(&self, saved: Option<&SavedConnection>) -> Result<CleanupScope, String> {
        match self {
            Self::Display {
                cleanup_scope: Some(scope),
                ..
            } => Ok(scope.clone()),
            _ => CleanupScope::from_saved(saved.ok_or("library_cleanup_scope_unavailable")?),
        }
    }
}

fn library_id(saved: &SavedConnection) -> String {
    let mut hash = Sha256::new();
    hash.update((saved.server_id.len() as u64).to_be_bytes());
    hash.update(saved.server_id.as_bytes());
    hash.update(saved.account_id.as_bytes());
    format!("{:x}", hash.finalize())
}

fn slot(id: &str) -> Result<String, String> {
    if id.len() != 64
        || !id
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err("library_not_approved".into());
    }
    Ok(format!("approved-library-{id}"))
}

fn slot_for(id: &str, generation: Option<uuid::Uuid>) -> Result<String, String> {
    let account = slot(id)?;
    Ok(match generation {
        Some(generation) => format!("{account}-{generation}"),
        None => account,
    })
}

fn index() -> Result<Vec<IndexEntry>, String> {
    Ok(credentials::load(INDEX)?.unwrap_or_default())
}

pub(crate) fn already_approved(saved: &SavedConnection) -> Result<bool, String> {
    if saved.server_id.is_empty() {
        return Ok(false);
    }
    let id = library_id(saved);
    Ok(index()?.iter().any(|entry| entry.id() == id))
}

/// Read exactly one approved credential and verify that the slot matches its account and Library.
fn stored_library(
    window: &WebviewWindow,
    approved: &[IndexEntry],
    id: &str,
) -> Result<Option<SavedConnection>, String> {
    let Some(entry) = approved.iter().find(|entry| entry.id() == id) else {
        return Ok(None);
    };
    let saved = read_slot(window, id, &entry.account()?)?;
    if let (Some(saved), Ok(scope)) = (saved.as_ref(), entry.cleanup_scope(None)) {
        if CleanupScope::from_saved(saved)? != scope {
            return Err("credential_record_invalid".into());
        }
    }
    Ok(saved)
}

fn read_slot(
    window: &WebviewWindow,
    id: &str,
    account: &str,
) -> Result<Option<SavedConnection>, String> {
    let saved = credentials::load_interactive::<SavedConnection>(account, window, true)?;
    if saved
        .as_ref()
        .is_some_and(|saved| saved.server_id.is_empty() || library_id(saved) != id)
    {
        return Err("credential_record_invalid".into());
    }
    Ok(saved)
}

/// Persist the display record and confirm the protected slot before treating it as usable.
fn park(
    window: &WebviewWindow,
    approved: &mut Vec<IndexEntry>,
    saved: &SavedConnection,
    pending: Option<PendingCleanup>,
) -> Result<(), String> {
    if saved.server_id.is_empty() {
        return Err("server_identity_not_confirmed".into());
    }
    let id = library_id(saved);
    let existing = approved.iter().position(|entry| entry.id() == id);
    if existing.is_none() && approved.len() >= MAX_APPROVED {
        return Err("approved_library_limit".into());
    }
    let previous = existing.map(|position| &approved[position]);
    if previous.and_then(IndexEntry::pending).is_some() {
        return Err("library_reapproval_cleanup_failed".into());
    }
    // Commit a new slot through the index so a failed confirmation leaves the old slot intact.
    let display = IndexEntry::Display {
        display: LibraryDisplay::from_saved(saved),
        generation: if pending.is_some() {
            Some(uuid::Uuid::new_v4())
        } else {
            previous.and_then(IndexEntry::generation)
        },
        cleanup_scope: Some(CleanupScope::from_saved(saved)?),
        pending: pending.map(Box::new),
    };
    let account = display.account()?;
    let new_slot = existing.is_none() || display.pending().is_some();
    credentials::save(&account, saved)?;
    if let Err(error) = credentials::confirm_new_sign_in(&account, saved, window) {
        if new_slot && error != "credential_confirmation_changed" {
            let _ = credentials::delete(&account);
        }
        return Err(error);
    }
    let mut next = approved.clone();
    if let Some(existing) = existing {
        next[existing] = display;
    } else {
        next.push(display);
    }
    if let Err(error) = credentials::save(INDEX, &next) {
        if new_slot {
            let _ = credentials::delete(&account);
        }
        return Err(error);
    }
    *approved = next;
    Ok(())
}

/// Delete a selected credential before removing its approval from the index.
fn forget(id: &str, approved: &mut Vec<IndexEntry>) -> Result<(), String> {
    if let Some(entry) = approved.iter().find(|entry| entry.id() == id) {
        if entry.pending().is_some() {
            return Err("library_reapproval_cleanup_failed".into());
        }
        credentials::delete(&entry.account()?)?;
        approved.retain(|item| item.id() != id);
        credentials::save(INDEX, approved)?;
    }
    Ok(())
}

pub(crate) fn forget_active(saved: &SavedConnection) -> Result<(), String> {
    if saved.server_id.is_empty() {
        return Ok(());
    }
    forget(&library_id(saved), &mut index()?)
}

async fn verify(client: &reqwest::Client, saved: &SavedConnection) -> Result<Capabilities, String> {
    let capabilities = crate::transport::capabilities(client, saved)
        .await?
        .ok_or("server_identity_not_confirmed")?;
    crate::verify_photo_account(client, saved).await?;
    Ok(capabilities)
}

async fn purge_scope(app: &AppHandle, scope: &CleanupScope) -> Result<(), String> {
    let copies = app.state::<OfflineAlbums>().purge_scope(app, scope).await;
    let approvals = credentials::delete_source_scope(scope.id());
    copies.and(approvals)
}

/// Best-effort revocation uses only a readable old bearer verified for its original scope.
async fn revoke_replaced(window: &WebviewWindow, id: &str, account: &str, scope: &CleanupScope) {
    let Ok(Some(mut old)) = read_slot(window, id, account) else {
        return;
    };
    let Ok(client) = crate::transport::client() else {
        return;
    };
    if CleanupScope::from_saved(&old).ok().as_ref() == Some(scope)
        && verify(&client, &old).await.is_ok()
    {
        // The renewed sign-in can reuse the device. Revoke only the old bearer.
        old.device_id = None;
        let _ = crate::revoke_photo_connection(&old).await;
    }
}

/// Retry the exact previous scope before deleting its protected credential and journal entry.
async fn retry_cleanup(
    app: &AppHandle,
    window: &WebviewWindow,
    approved: &mut [IndexEntry],
    id: &str,
) -> Result<(), String> {
    let Some(position) = approved.iter().position(|entry| entry.id() == id) else {
        return Ok(());
    };
    let Some(pending) = approved[position].pending().cloned() else {
        return Ok(());
    };
    let account = slot_for(id, pending.generation)?;
    if account == approved[position].account()? {
        return Err("credential_record_invalid".into());
    }
    let result = async {
        if pending.scope != approved[position].cleanup_scope(None)? {
            app.state::<OfflineAlbums>().deactivate().await;
            purge_scope(app, &pending.scope).await?;
        }
        if pending.revoke_bearer {
            revoke_replaced(window, id, &account, &pending.scope).await;
        }
        credentials::delete(&account)?;
        let mut next = approved.to_vec();
        if let IndexEntry::Display { pending, .. } = &mut next[position] {
            *pending = None;
        }
        credentials::save(INDEX, &next)?;
        approved.clone_from_slice(&next);
        Ok::<(), String>(())
    }
    .await;
    result.map_err(|_| "library_reapproval_cleanup_failed".into())
}

/// Build the switcher list from display records without unlocking protected sign-ins.
#[tauri::command]
pub(crate) async fn approved_libraries(
    window: WebviewWindow,
    state: State<'_, DesktopState>,
) -> Result<Vec<ApprovedLibrary>, String> {
    crate::require_local(&window)?;
    let active = state.0.lock().await;
    let approved = index()?;
    let mut result = Vec::with_capacity(approved.len() + 1);
    let active = active
        .as_ref()
        .filter(|saved| !saved.server_id.is_empty())
        .map(LibraryDisplay::from_saved);
    let active_id = active.as_ref().map(|display| display.id.clone());
    result.extend(active.map(|display| ApprovedLibrary {
        display,
        active: true,
    }));
    result.extend(
        approved
            .iter()
            .filter(|entry| active_id.as_deref() != Some(entry.id()))
            .map(|entry| ApprovedLibrary {
                display: entry.display(),
                active: false,
            }),
    );
    Ok(result)
}

fn current_connection(
    active: &Option<SavedConnection>,
    window: &WebviewWindow,
) -> Result<Option<SavedConnection>, String> {
    if let Some(saved) = active {
        return Ok(Some(saved.clone()));
    }
    credentials::load_interactive("connection", window, true)
}

/// Verify a new sign-in before saving a new or renewed approval and activating it.
#[tauri::command]
pub(crate) async fn add_approved_library(
    window: WebviewWindow,
    app: AppHandle,
    state: State<'_, DesktopState>,
    server: String,
    email: String,
    password: String,
    device_name: String,
) -> Result<ConnectionView, String> {
    crate::require_local(&window)?;
    let mut active = state.0.lock().await;
    if app
        .state::<crate::host_setup::HostSetup>()
        .background_active()
    {
        return Err("local_host_active".into());
    }
    let previous = current_connection(&active, &window)?;
    let mut approved = index()?;
    let client = crate::transport::client()?;
    let (base, login) =
        crate::request_login(&client, &server, &email, password, &device_name, || {
            credentials::foreground_identity(&window)
        })
        .await?;
    let mut target = crate::saved_login(&base, login, &device_name);
    let mut target_parked = false;
    let result = async {
        let caps = verify(&client, &target).await?;
        target.server_id.clone_from(&caps.server_id);
        let id = library_id(&target);
        if previous
            .as_ref()
            .is_some_and(|saved| library_id(saved) == id)
        {
            return Err("library_already_approved".into());
        }
        retry_cleanup(&app, &window, &mut approved, &id).await?;
        let pending = if let Some(entry) = approved.iter().find(|entry| entry.id() == id) {
            let replaced = stored_library(&window, &approved, &id).ok().flatten();
            Some(PendingCleanup {
                generation: entry.generation(),
                scope: entry.cleanup_scope(replaced.as_ref())?,
                revoke_bearer: replaced.is_some_and(|saved| saved.token != target.token),
            })
        } else {
            None
        };
        if let Some(previous) = previous.as_ref() {
            park(&window, &mut approved, previous, None)?;
        }
        park(&window, &mut approved, &target, pending)?;
        target_parked = true;
        retry_cleanup(&app, &window, &mut approved, &id).await?;
        activate(
            &app,
            &client,
            &mut active,
            previous.as_ref(),
            target.clone(),
            caps,
        )
        .await
    }
    .await;
    if result.is_err() && !target_parked {
        let _ = crate::revoke_photo_connection(&target).await;
    }
    drop(active);
    crate::tray::refresh(&app).await;
    result
}

/// Unlock and reverify the one approved Library chosen by the user.
#[tauri::command]
pub(crate) async fn activate_approved_library(
    window: WebviewWindow,
    app: AppHandle,
    state: State<'_, DesktopState>,
    id: String,
) -> Result<ConnectionView, String> {
    crate::require_local(&window)?;
    let mut active = state.0.lock().await;
    if app
        .state::<crate::host_setup::HostSetup>()
        .background_active()
    {
        return Err("local_host_active".into());
    }
    let previous = current_connection(&active, &window)?;
    if previous
        .as_ref()
        .is_some_and(|saved| library_id(saved) == id)
        && active.is_some()
    {
        return Err("library_already_active".into());
    }
    let mut approved = index()?;
    retry_cleanup(&app, &window, &mut approved, &id).await?;
    let target = stored_library(&window, &approved, &id)?.ok_or("library_not_approved")?;
    let client = crate::transport::client()?;
    let caps = verify(&client, &target)
        .await
        .map_err(|error| match error.as_str() {
            "server_http_401" => "library_sign_in_expired".into(),
            _ => error,
        })?;
    if let Some(previous) = previous.as_ref().filter(|saved| library_id(saved) != id) {
        park(&window, &mut approved, previous, None)?;
    }
    let result = activate(&app, &client, &mut active, previous.as_ref(), target, caps).await;
    drop(active);
    crate::tray::refresh(&app).await;
    result
}

async fn activate(
    app: &AppHandle,
    client: &reqwest::Client,
    active: &mut Option<SavedConnection>,
    previous: Option<&SavedConnection>,
    target: SavedConnection,
    caps: Capabilities,
) -> Result<ConnectionView, String> {
    if let Some(previous) = previous {
        credentials::migrate_source_approvals(previous)?;
    }
    let copies = app.state::<crate::media_copy::MediaCopy>();
    copies.cancel();
    app.state::<crate::offline_albums::OfflineAlbums>()
        .deactivate()
        .await;
    let photos_open = app.get_webview_window("photos").is_some();
    app.state::<crate::source_import::SourceJobs>().park().await;
    app.state::<crate::drop_import::DropImport>().stop().await;
    let setup = app.state::<crate::worker_setup::WorkerSetup>();
    let had_worker_status = !setup.status().state.is_empty();
    setup.stop().await;

    // Read after the worker has joined so rollback cannot restore a stale proof sequence.
    let mut worker = None;
    let result = commit_activation(
        active,
        target,
        || {
            worker = credentials::load::<crate::worker::SavedWorker>("worker-session")?;
            crate::clear_photos_window(app)?;
            app.state::<crate::source_consent::SourceConsent>()
                .clear()?;
            credentials::delete("worker-session")
        },
        |target| credentials::save("connection", target),
    );
    if let Err(error) = result {
        if let Some(old) = active.as_ref() {
            if worker.as_ref().is_some_and(|worker| {
                worker.server_id == old.server_id
                    && worker.account_id == old.account_id
                    && old.device_id.as_deref() == Some(worker.device_id.as_str())
                    && credentials::save("worker-session", worker).is_ok()
            }) && had_worker_status
            {
                let _ = crate::start_worker_setup(app, old, false).await;
            }
            crate::resume_approved_watch(app, old).await;
            if photos_open {
                let _ = crate::open_photos_window(app, old);
            }
        }
        return Err(error);
    }

    copies.fence_session();
    crate::tray::set_import_status(app, None);
    crate::tray::set_drop_status(app, None);
    crate::publish_worker_status(app, setup.status());
    let active = active.as_mut().expect("active credential was committed");
    let mut view = crate::prepare_with_capabilities(client, active, Ok(Some(caps))).await;
    if view.state == "preparing"
        && view.features.worker_session
        && crate::start_worker_setup(app, active, false).await.is_err()
    {
        view.state = "worker-setup-failed".into();
    }
    crate::resume_approved_watch(app, active).await;
    Ok(view)
}

fn commit_activation(
    active: &mut Option<SavedConnection>,
    target: SavedConnection,
    cleanup: impl FnOnce() -> Result<(), String>,
    save: impl FnOnce(&SavedConnection) -> Result<(), String>,
) -> Result<(), String> {
    cleanup()?;
    save(&target)?;
    *active = Some(target);
    Ok(())
}

#[tauri::command]
pub(crate) async fn remove_approved_library(
    window: WebviewWindow,
    app: AppHandle,
    state: State<'_, DesktopState>,
    id: String,
) -> Result<bool, String> {
    crate::require_local(&window)?;
    let active = state.0.lock().await;
    if current_connection(&active, &window)?
        .as_ref()
        .is_some_and(|saved| library_id(saved) == id)
    {
        return Err("library_active_sign_out_required".into());
    }
    let mut approved = index()?;
    retry_cleanup(&app, &window, &mut approved, &id).await?;
    let position = approved
        .iter()
        .position(|entry| entry.id() == id)
        .ok_or("library_not_approved")?;
    let saved = stored_library(&window, &approved, &id).ok().flatten();
    let scope = approved[position].cleanup_scope(saved.as_ref())?;
    if approved[position].cleanup_scope(None).is_err() {
        // Keep legacy cleanup possible if removal is interrupted after deleting the old slot.
        approved[position] = IndexEntry::Display {
            display: LibraryDisplay::from_saved(
                saved.as_ref().ok_or("library_cleanup_scope_unavailable")?,
            ),
            generation: approved[position].generation(),
            cleanup_scope: Some(scope.clone()),
            pending: None,
        };
        credentials::save(INDEX, &approved)?;
    }
    purge_scope(&app, &scope).await?;
    forget(&id, &mut approved)?;
    let (Some(saved), Ok(client)) = (saved, crate::transport::client()) else {
        return Ok(false);
    };
    let revoked =
        verify(&client, &saved).await.is_ok() && crate::revoke_photo_connection(&saved).await;
    // A reapproval for the same account/device must wait for the old session revocation.
    drop(active);
    Ok(revoked)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn saved(server_id: &str, account_id: &str) -> SavedConnection {
        SavedConnection {
            server: "https://example.invalid/".into(),
            server_id: server_id.into(),
            account_id: account_id.into(),
            name: "Fixture".into(),
            token: "fixture".into(),
            device_name: "Desktop".into(),
            mode: "client-worker".into(),
            device_id: None,
        }
    }

    #[test]
    fn approval_keys_distinguish_accounts_and_libraries_even_at_the_same_origin() {
        let original = library_id(&saved("one", "account"));
        assert_ne!(original, library_id(&saved("two", "account")));
        assert_ne!(original, library_id(&saved("one", "another")));
        assert!(slot(&original).is_ok());
        assert!(slot("connection").is_err());
    }

    fn server(
        responses: Vec<(&'static str, serde_json::Value)>,
    ) -> (String, std::thread::JoinHandle<()>) {
        use std::io::{BufRead, BufReader, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/", listener.local_addr().unwrap());
        let thread = std::thread::spawn(move || {
            for (expected, response) in responses {
                let (mut stream, _) = listener.accept().unwrap();
                stream
                    .set_read_timeout(Some(std::time::Duration::from_secs(3)))
                    .unwrap();
                let mut reader = BufReader::new(&mut stream);
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                assert!(line.starts_with(expected));
                loop {
                    line.clear();
                    if reader.read_line(&mut line).unwrap() == 0 || line == "\r\n" {
                        break;
                    }
                }
                let body = response.to_string();
                write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).unwrap();
            }
        });
        (url, thread)
    }

    fn capabilities(server_id: &str) -> serde_json::Value {
        serde_json::json!({
            "protocolVersion": 1, "serverId": server_id,
            "features": { "enrollment": false, "worker": false, "sources": false, "nativeHost": false }
        })
    }

    #[tokio::test]
    async fn verification_rejects_a_replacement_library_before_checking_its_account() {
        let (address, thread) = server(vec![(
            "GET /api/desktop/capabilities ",
            capabilities("replacement"),
        )]);
        let mut target = saved("approved", "account");
        target.server = address;
        let result = verify(&reqwest::Client::new(), &target).await;
        assert_eq!(result.err().unwrap(), "server_identity_changed");
        thread.join().unwrap();
    }

    #[tokio::test]
    async fn verification_requires_the_approved_account_even_on_the_same_library() {
        let (address, thread) = server(vec![
            ("GET /api/desktop/capabilities ", capabilities("approved")),
            (
                "GET /api/users/me ",
                serde_json::json!({ "id": "different-account" }),
            ),
        ]);
        let mut target = saved("approved", "account");
        target.server = address;
        let result = verify(&reqwest::Client::new(), &target).await;
        assert_eq!(result.err().unwrap(), "account_identity_changed");
        thread.join().unwrap();
    }

    #[test]
    fn approved_library_list_exposes_no_session_credential() {
        let display = LibraryDisplay::from_saved(&saved("one", "account"));
        let card = serde_json::to_value(ApprovedLibrary {
            display,
            active: false,
        })
        .unwrap();
        assert_eq!(card.as_object().unwrap().len(), 4);
        assert!(card.get("token").is_none());
        assert!(card.get("accountId").is_none());
    }

    #[test]
    fn old_and_new_approvals_can_be_listed_without_reading_either_protected_slot() {
        let legacy_id = library_id(&saved("old", "account"));
        let display = LibraryDisplay::from_saved(&saved("new", "account"));
        let generation = uuid::Uuid::new_v4();
        let approved: Vec<IndexEntry> = serde_json::from_value(serde_json::json!([
            legacy_id,
            {"display": display, "generation": generation}
        ]))
        .unwrap();
        assert_eq!(approved[0].id(), legacy_id);
        assert_eq!(approved[0].display().server, "");
        assert!(approved[0].display().name.starts_with("Saved library "));
        assert_eq!(approved[1].display().name, "Fixture");
        assert_eq!(approved[1].display().server, "https://example.invalid/");
        assert_eq!(approved[0].account().unwrap(), slot(&legacy_id).unwrap());
        assert_eq!(
            approved[1].account().unwrap(),
            format!("{}-{generation}", slot(approved[1].id()).unwrap())
        );
    }

    #[test]
    fn pending_cleanup_round_trips_both_exact_scopes_without_a_readable_slot() {
        let old = saved("one", "account");
        let mut next = old.clone();
        next.token = "renewed-fixture-token".into();
        let old_scope = CleanupScope::from_saved(&old).unwrap();
        let next_scope = CleanupScope::from_saved(&next).unwrap();
        let entry = IndexEntry::Display {
            display: LibraryDisplay::from_saved(&next),
            generation: Some(uuid::Uuid::new_v4()),
            cleanup_scope: Some(next_scope.clone()),
            pending: Some(Box::new(PendingCleanup {
                generation: None,
                scope: old_scope.clone(),
                revoke_bearer: true,
            })),
        };
        let encoded = serde_json::to_string(&entry).unwrap();
        assert!(!encoded.contains(&next.token));
        let restored: IndexEntry = serde_json::from_str(&encoded).unwrap();
        assert!(restored.cleanup_scope(None).unwrap() == next_scope);
        assert!(restored.pending().unwrap().scope == old_scope);
        assert_ne!(
            restored.account().unwrap(),
            slot_for(restored.id(), restored.pending().unwrap().generation).unwrap()
        );
        assert_eq!(
            IndexEntry::Legacy(library_id(&old))
                .cleanup_scope(None)
                .err()
                .as_deref(),
            Some("library_cleanup_scope_unavailable")
        );
    }

    #[test]
    #[ignore = "uses a process-local synthetic Keychain; run alone"]
    fn signing_out_forgets_only_the_active_library_approval() {
        crate::ml_transport::native_nas_tests::install_test_keyring();
        let active = saved("one", "account");
        let inactive = saved("two", "account");
        let active_id = library_id(&active);
        let inactive_id = library_id(&inactive);
        credentials::save(INDEX, &vec![active_id.clone(), inactive_id.clone()]).unwrap();
        credentials::save(&slot(&active_id).unwrap(), &active).unwrap();
        credentials::save(&slot(&inactive_id).unwrap(), &inactive).unwrap();

        forget_active(&active).unwrap();

        assert_eq!(
            index()
                .unwrap()
                .iter()
                .map(IndexEntry::id)
                .collect::<Vec<_>>(),
            vec![inactive_id.as_str()]
        );
        assert!(
            credentials::load::<SavedConnection>(&slot(&active_id).unwrap())
                .unwrap()
                .is_none()
        );
        assert_eq!(
            credentials::load::<SavedConnection>(&slot(&inactive_id).unwrap())
                .unwrap()
                .unwrap()
                .server_id,
            "two"
        );
        forget(&inactive_id, &mut index().unwrap()).unwrap();
        assert!(index().unwrap().is_empty());
    }

    #[test]
    fn a_failed_cleanup_never_persists_or_changes_the_active_library() {
        let mut active = Some(saved("one", "account"));
        let result = commit_activation(
            &mut active,
            saved("two", "account"),
            || Err("library_photos_clear_failed".into()),
            |_| panic!("a failed cleanup must not persist the target"),
        );
        assert_eq!(result.unwrap_err(), "library_photos_clear_failed");
        assert_eq!(active.as_ref().unwrap().server_id, "one");
    }

    #[test]
    fn failed_credential_commit_after_cleanup_keeps_the_previous_library_active() {
        let mut active = Some(saved("one", "account"));
        let closed = std::cell::Cell::new(false);
        let result = commit_activation(
            &mut active,
            saved("two", "account"),
            || {
                closed.set(true);
                Ok(())
            },
            |target| {
                assert!(closed.get());
                assert_eq!(target.server_id, "two");
                Err("credential_store_locked_or_unavailable".into())
            },
        );
        assert!(result.is_err());
        assert_eq!(active.as_ref().unwrap().server_id, "one");
        commit_activation(&mut active, saved("two", "account"), || Ok(()), |_| Ok(())).unwrap();
        assert_eq!(active.as_ref().unwrap().server_id, "two");
    }
}
