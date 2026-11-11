//! The active credential remains the commit point for Photos, imports and AI work.
use crate::{
    connection::{Capabilities, ConnectionView, SavedConnection},
    credentials, DesktopState,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use tauri::{AppHandle, Manager, State, WebviewWindow};

const INDEX: &str = "approved-libraries";
const MAX_APPROVED: usize = 16;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ApprovedLibrary {
    id: String,
    server: String,
    name: String,
    active: bool,
}

impl ApprovedLibrary {
    fn from_saved(saved: &SavedConnection, active: bool) -> Self {
        Self {
            id: library_id(saved),
            server: saved.server.clone(),
            name: saved.name.clone(),
            active,
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

fn index() -> Result<Vec<String>, String> {
    Ok(credentials::load(INDEX)?.unwrap_or_default())
}

pub(crate) fn already_approved(saved: &SavedConnection) -> Result<bool, String> {
    Ok(!saved.server_id.is_empty() && index()?.contains(&library_id(saved)))
}

fn stored_library(
    window: &WebviewWindow,
    approved: &[String],
    id: &str,
) -> Result<Option<SavedConnection>, String> {
    if !approved.iter().any(|item| item == id) {
        return Ok(None);
    }
    let saved = credentials::load_interactive::<SavedConnection>(&slot(id)?, window, true)?;
    if saved
        .as_ref()
        .is_some_and(|saved| saved.server_id.is_empty() || library_id(saved) != id)
    {
        return Err("credential_record_invalid".into());
    }
    Ok(saved)
}

fn park(
    window: &WebviewWindow,
    approved: &mut Vec<String>,
    saved: &SavedConnection,
) -> Result<(), String> {
    if saved.server_id.is_empty() {
        return Err("server_identity_not_confirmed".into());
    }
    let id = library_id(saved);
    let existing = approved.contains(&id);
    if !existing && approved.len() >= MAX_APPROVED {
        return Err("approved_library_limit".into());
    }
    let account = slot(&id)?;
    credentials::save(&account, saved)?;
    if let Err(error) = credentials::confirm_new_sign_in(&account, saved, window) {
        if !existing && error != "credential_confirmation_changed" {
            let _ = credentials::delete(&account);
        }
        return Err(error);
    }
    if !existing {
        approved.push(id);
        if let Err(error) = credentials::save(INDEX, approved) {
            let _ = credentials::delete(&account);
            return Err(error);
        }
    }
    Ok(())
}

fn forget(id: &str, approved: &mut Vec<String>) -> Result<(), String> {
    if approved.iter().any(|item| item == id) {
        credentials::delete(&slot(id)?)?;
        approved.retain(|item| item != id);
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

#[tauri::command]
pub(crate) async fn approved_libraries(
    window: WebviewWindow,
    state: State<'_, DesktopState>,
) -> Result<Vec<ApprovedLibrary>, String> {
    crate::require_local(&window)?;
    let active = state.0.lock().await;
    let approved = index()?;
    let mut result = Vec::with_capacity(approved.len() + 1);
    if let Some(saved) = active.as_ref().filter(|saved| !saved.server_id.is_empty()) {
        result.push(ApprovedLibrary::from_saved(saved, true));
    }
    for id in &approved {
        if result.first().is_some_and(|active| active.id == *id) {
            continue;
        }
        if let Some(saved) = stored_library(&window, &approved, id)? {
            result.push(ApprovedLibrary::from_saved(&saved, false));
        }
    }
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
            || stored_library(&window, &approved, &id)?.is_some()
        {
            return Err("library_already_approved".into());
        }
        if let Some(previous) = previous.as_ref() {
            park(&window, &mut approved, previous)?;
        }
        park(&window, &mut approved, &target)?;
        target_parked = true;
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
    let caps = verify(&client, &target).await?;
    if let Some(previous) = previous.as_ref().filter(|saved| library_id(saved) != id) {
        park(&window, &mut approved, previous)?;
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
        let card =
            serde_json::to_value(ApprovedLibrary::from_saved(&saved("one", "account"), false))
                .unwrap();
        assert_eq!(card.as_object().unwrap().len(), 4);
        assert!(card.get("token").is_none());
        assert!(card.get("accountId").is_none());
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

        assert_eq!(index().unwrap(), vec![inactive_id.clone()]);
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
