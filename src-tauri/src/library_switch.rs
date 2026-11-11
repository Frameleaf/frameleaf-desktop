//! The active credential remains the commit point for Photos, imports and AI work.
use crate::{
    connection::{photo_session_scope, Capabilities, ConnectionView, SavedConnection},
    credentials, DesktopState,
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
    },
    Legacy(String),
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
        let account = slot(self.id())?;
        Ok(match self.generation() {
            Some(generation) => format!("{account}-{generation}"),
            None => account,
        })
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
    let saved = credentials::load_interactive::<SavedConnection>(&entry.account()?, window, true)?;
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
    replace: bool,
) -> Result<Option<String>, String> {
    if saved.server_id.is_empty() {
        return Err("server_identity_not_confirmed".into());
    }
    let id = library_id(saved);
    let existing = approved.iter().position(|entry| entry.id() == id);
    if existing.is_none() && approved.len() >= MAX_APPROVED {
        return Err("approved_library_limit".into());
    }
    let previous = existing.map(|position| &approved[position]);
    let retired = previous
        .filter(|_| replace)
        .map(IndexEntry::account)
        .transpose()?;
    // Commit a new slot through the index so a failed confirmation leaves the old slot intact.
    let display = IndexEntry::Display {
        display: LibraryDisplay::from_saved(saved),
        generation: if retired.is_some() {
            Some(uuid::Uuid::new_v4())
        } else {
            previous.and_then(IndexEntry::generation)
        },
    };
    let account = display.account()?;
    let new_slot = existing.is_none() || retired.is_some();
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
    Ok(retired)
}

/// Delete a selected credential before removing its approval from the index.
fn forget(id: &str, approved: &mut Vec<IndexEntry>) -> Result<(), String> {
    if let Some(entry) = approved.iter().find(|entry| entry.id() == id) {
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

/// Retire only the superseded login, whose signed local approvals cannot be reused.
async fn retire_replaced(
    app: &AppHandle,
    client: &reqwest::Client,
    mut previous: SavedConnection,
    target: &SavedConnection,
) -> Result<(), String> {
    if previous.token != target.token
        && (previous.server == target.server || verify(client, &previous).await.is_ok())
    {
        // The new login may reuse the device. Revoke only the replaced bearer session.
        previous.device_id = None;
        let _ = crate::revoke_photo_connection(&previous).await;
    }
    if photo_session_scope(&previous) != photo_session_scope(target) {
        let offline = app.state::<crate::offline_albums::OfflineAlbums>();
        offline.deactivate().await;
        let copies = offline.purge(app, &previous).await;
        let approvals = credentials::delete_parked_source_approvals(&previous);
        copies
            .and(approvals)
            .map_err(|_| "library_reapproval_cleanup_failed")?;
    }
    Ok(())
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
        let replaced = stored_library(&window, &approved, &id)?;
        if let Some(previous) = previous.as_ref() {
            park(&window, &mut approved, previous, false)?;
        }
        let retired = park(&window, &mut approved, &target, true)?;
        target_parked = true;
        if let Some(retired) = retired {
            let removed = credentials::delete(&retired)
                .map_err(|_| "library_reapproval_cleanup_failed".to_owned());
            let cleanup = if let Some(replaced) = replaced {
                retire_replaced(&app, &client, replaced, &target).await
            } else {
                Ok(())
            };
            removed.and(cleanup)?;
        }
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
    let target = stored_library(&window, &approved, &id)?.ok_or("library_not_approved")?;
    let client = crate::transport::client()?;
    let caps = verify(&client, &target)
        .await
        .map_err(|error| match error.as_str() {
            "server_http_401" => "library_sign_in_expired".into(),
            _ => error,
        })?;
    if let Some(previous) = previous.as_ref().filter(|saved| library_id(saved) != id) {
        park(&window, &mut approved, previous, false)?;
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
    let saved = stored_library(&window, &approved, &id)?.ok_or("library_not_approved")?;
    app.state::<crate::offline_albums::OfflineAlbums>()
        .purge(&app, &saved)
        .await?;
    credentials::delete_parked_source_approvals(&saved)?;
    forget(&id, &mut approved)?;
    let Ok(client) = crate::transport::client() else {
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
