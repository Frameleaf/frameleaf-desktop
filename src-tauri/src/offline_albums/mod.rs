mod cache;
mod playback;
pub(crate) use playback::serve;
mod remote;

use crate::{connection::SavedConnection, credentials, DesktopState};
use cache::{AlbumView, Cache};
use playback::Playback;
use serde::Serialize;
use std::{
    sync::Mutex,
    time::{Duration, Instant},
};
use tauri::{AppHandle, Manager, State, WebviewWindow};
use tauri_plugin_dialog::{DialogExt, MessageDialogButtons};
use tokio::sync::{watch, Mutex as AsyncMutex};
use url::Url;
use uuid::Uuid;

const PATH: &str = "/offline-photos.html";
const INTENT: &str = "/__frameleaf_desktop__/offline-albums/";
const BUSY: &str = "offline_album_busy";

pub(crate) struct OfflineAlbums {
    operation: AsyncMutex<()>,
    session: Mutex<Option<SavedConnection>>,
    progress: Mutex<Option<Progress>>,
    playback: Mutex<Option<Playback>>,
    cancelled: watch::Sender<()>,
}

impl Default for OfflineAlbums {
    fn default() -> Self {
        Self {
            operation: AsyncMutex::default(),
            session: Mutex::default(),
            progress: Mutex::default(),
            playback: Mutex::default(),
            cancelled: watch::channel(()).0,
        }
    }
}

#[derive(Clone, Serialize)]
struct Progress {
    done: usize,
    total: usize,
    error: Option<String>,
}

#[derive(Serialize)]
pub(crate) struct Status {
    busy: bool,
    albums: Vec<AlbumView>,
    progress: Option<Progress>,
}

impl OfflineAlbums {
    pub async fn clear(&self, app: &AppHandle) -> bool {
        self.cancelled.send_replace(());
        self.clear_playback();
        if let Ok(mut session) = self.session.lock() {
            *session = None;
        }
        let _permit = self.operation.lock().await;
        if let Ok(mut session) = self.session.lock() {
            *session = None;
        }
        self.set_progress(None);
        app.path()
            .app_local_data_dir()
            .is_ok_and(|base| Cache::purge(&base).is_ok())
    }

    fn clear_playback(&self) {
        if let Ok(mut playback) = self.playback.lock() {
            *playback = None;
        }
    }

    fn get_playback(&self, id: Uuid) -> Result<Playback, String> {
        self.playback
            .lock()
            .map_err(|_| BUSY)?
            .as_ref()
            .filter(|playback| {
                playback.id == id && playback.touched.elapsed() < Duration::from_secs(120)
            })
            .cloned()
            .ok_or_else(|| "native_access_denied".into())
    }

    fn renew_playback(&self, next: Playback) -> Result<(), String> {
        let mut active = self.playback.lock().map_err(|_| BUSY)?;
        if active
            .as_ref()
            .is_none_or(|playback| playback.id != next.id)
        {
            return Err("native_access_denied".into());
        }
        *active = Some(next);
        Ok(())
    }

    fn set_progress(&self, progress: Option<Progress>) {
        if let Ok(mut current) = self.progress.lock() {
            *current = progress;
        }
    }

    fn set_session(&self, saved: SavedConnection) -> Result<(), String> {
        *self.session.lock().map_err(|_| BUSY)? = Some(saved);
        Ok(())
    }

    fn saved(&self) -> Result<SavedConnection, String> {
        self.session
            .lock()
            .map_err(|_| BUSY)?
            .clone()
            .ok_or_else(|| "sign_in_required".into())
    }
}

pub(crate) fn local_url(url: &Url) -> bool {
    url.path() == PATH
        && url.query().is_none()
        && url.fragment().is_none()
        && crate::connection::native_origin_allowed("main", url, cfg!(debug_assertions))
}

fn require_local_photos(window: &WebviewWindow) -> Result<(), String> {
    if window.label() != "photos" || !window.url().is_ok_and(|url| local_url(&url)) {
        return Err("native_access_denied".into());
    }
    Ok(())
}

fn intent(url: &Url) -> Option<Uuid> {
    if url.query().is_some() || url.fragment().is_some() {
        return None;
    }
    let id = url.path().strip_prefix(INTENT)?;
    let value = Uuid::parse_str(id).ok()?;
    (id == value.to_string()).then_some(value)
}

pub(crate) fn intercept(app: &AppHandle, url: &Url, expected_scope: &str) -> bool {
    if !url.path().starts_with(INTENT) {
        return false;
    }
    if let Some(id) = intent(url) {
        let app = app.clone();
        let origin = url.origin();
        let expected_scope = expected_scope.to_owned();
        tauri::async_runtime::spawn(async move {
            let Some(window) = app.get_webview_window("photos") else {
                return;
            };
            let result = request(&app, &window, origin, &expected_scope, id).await;
            if let Err(error) = result {
                if window.url().is_ok_and(|url| !local_url(&url)) {
                    app.dialog()
                        .message(message(&error))
                        .title("Offline album")
                        .parent(&window)
                        .show(|_| {});
                }
            }
        });
    }
    true
}

fn show(app: &AppHandle, saved: &SavedConnection) -> Result<(), String> {
    let main = app
        .get_webview_window("main")
        .ok_or("photo_window_unavailable")?;
    let url = main
        .url()
        .map_err(|_| "photo_window_unavailable")?
        .join(PATH)
        .map_err(|_| "photo_window_unavailable")?;
    if !local_url(&url) {
        return Err("photo_window_unavailable".into());
    }
    let base = crate::connection::normalize_server(&saved.server)?;
    let expected = crate::connection::photo_session_scope(saved);
    let state = app.state::<DesktopState>();
    let mut scope = state.1.lock().map_err(|_| "photo_window_unavailable")?;
    let photos = match app.get_webview_window("photos") {
        Some(window) if scope.as_ref() == Some(&expected) => window,
        Some(_) => return Err("library_photos_clear_failed".into()),
        None => crate::photo_window(app, &base, url.clone(), expected.clone())?,
    };
    *scope = Some(expected);
    if !photos.url().is_ok_and(|url| local_url(&url)) {
        photos
            .navigate(url)
            .map_err(|_| "photo_window_unavailable")?;
    }
    photos.show().map_err(|_| "photo_window_unavailable")?;
    photos
        .set_focus()
        .map_err(|_| "photo_window_unavailable".into())
}

async fn request(
    app: &AppHandle,
    window: &WebviewWindow,
    origin: url::Origin,
    expected_scope: &str,
    id: Uuid,
) -> Result<(), String> {
    let native = app.state::<OfflineAlbums>();
    let mut cancelled = native.cancelled.subscribe();
    let saved = app
        .state::<DesktopState>()
        .0
        .lock()
        .await
        .clone()
        .ok_or("sign_in_required")?;
    if crate::connection::photo_session_scope(&saved) != expected_scope
        || crate::connection::normalize_server(&saved.server)?.origin() != origin
        || !window.url().is_ok_and(|url| url.origin() == origin)
    {
        return Err("native_access_denied".into());
    }
    let _permit = native.operation.try_lock().map_err(|_| BUSY)?;
    let task = async {
        let library = remote::Library::connect(&saved).await?;
        let plan = library.plan(id).await?;
        if plan.items.is_empty() {
            return Err("offline_album_no_originals".into());
        }
        let count = plan.items.len();
        let title = if plan.name.is_empty() {
            "this album"
        } else {
            &plan.name
        };
        let copy = format!(
            "Keep {count} original photos or videos from “{title}” on this computer? Offline access lasts up to 24 hours after the last Library check. The cache holds up to 2 GB on this computer."
        );
        let (send, receive) = tokio::sync::oneshot::channel();
        app.dialog()
            .message(copy)
            .title("Keep album offline")
            .parent(window)
            .buttons(MessageDialogButtons::OkCancelCustom(
                "Keep Offline".into(),
                "Cancel".into(),
            ))
            .show(move |approved| {
                let _ = send.send(approved);
            });
        if !receive.await.unwrap_or(false) {
            return Ok(());
        }
        let base = crate::import_base(app)?;
        let cache = Cache::open(&base, &saved, true)?.ok_or("offline_album_storage_unavailable")?;
        native.set_session(saved.clone())?;
        native.set_progress(Some(Progress {
            done: 0,
            total: count,
            error: None,
        }));
        show(app, &saved)?;
        cache
            .download(&library, plan, |done, total| {
                native.set_progress(Some(Progress {
                    done,
                    total,
                    error: None,
                }));
            })
            .await
    };
    let result = tokio::select! {
        biased;
        _ = cancelled.changed() => Err("offline_album_cancelled".into()),
        result = task => result,
    };
    let visible = window.url().is_ok_and(|url| local_url(&url));
    native.set_progress(if visible {
        result.as_ref().err().map(|error| Progress {
            done: 0,
            total: 0,
            error: Some(error.clone()),
        })
    } else {
        None
    });
    result
}

#[tauri::command]
pub(crate) async fn open_offline_photos(
    window: WebviewWindow,
    app: AppHandle,
    state: State<'_, DesktopState>,
) -> Result<(), String> {
    crate::require_local(&window)?;
    let current = state.0.lock().await;
    let saved = match current.as_ref() {
        Some(saved) => saved.clone(),
        None => credentials::load_interactive::<SavedConnection>("connection", &window, false)?
            .ok_or("sign_in_required")?,
    };
    let native = app.state::<OfflineAlbums>();
    let _permit = native.operation.try_lock().map_err(|_| BUSY)?;
    native.set_session(saved.clone())?;
    show(&app, &saved)
}

#[tauri::command]
pub(crate) async fn offline_album_status(
    window: WebviewWindow,
    app: AppHandle,
) -> Result<Status, String> {
    require_local_photos(&window)?;
    let native = app.state::<OfflineAlbums>();
    let mut cancelled = native.cancelled.subscribe();
    let progress = native.progress.lock().map_err(|_| BUSY)?.clone();
    let Ok(_permit) = native.operation.try_lock() else {
        return Ok(Status {
            busy: true,
            albums: Vec::new(),
            progress,
        });
    };
    let saved = native.saved()?;
    let base = crate::import_base(&app)?;
    let albums = match Cache::open(&base, &saved, false)? {
        Some(cache) => tokio::select! {
            biased;
            _ = cancelled.changed() => return Err("offline_album_cancelled".into()),
            albums = cache.list(&saved) => albums?,
        },
        None => Vec::new(),
    };
    require_local_photos(&window)?;
    let progress = native.progress.lock().map_err(|_| BUSY)?.take();
    Ok(Status {
        busy: false,
        albums,
        progress,
    })
}

#[tauri::command]
pub(crate) async fn offline_album_original(
    window: WebviewWindow,
    app: AppHandle,
    album: Uuid,
    item: Uuid,
) -> Result<String, String> {
    require_local_photos(&window)?;
    let native = app.state::<OfflineAlbums>();
    let mut cancelled = native.cancelled.subscribe();
    let _permit = native.operation.try_lock().map_err(|_| BUSY)?;
    native.clear_playback();
    let saved = native.saved()?;
    let base = crate::import_base(&app)?;
    let cache = Cache::open(&base, &saved, false)?.ok_or("offline_album_none")?;
    let access = tokio::select! {
        biased;
        _ = cancelled.changed() => return Err("offline_album_cancelled".into()),
        access = cache.authorize(&saved, album, item) => access?,
    };
    require_local_photos(&window)?;
    if cancelled.has_changed().unwrap_or(true) {
        return Err("offline_album_cancelled".into());
    }
    let id = Uuid::new_v4();
    let checked = Instant::now();
    *native.playback.lock().map_err(|_| BUSY)? = Some(Playback {
        id,
        album,
        item,
        access,
        checked,
        touched: checked,
    });
    #[cfg(windows)]
    let origin = "http://offline-media.localhost";
    #[cfg(not(windows))]
    let origin = "offline-media://localhost";
    Ok(format!("{origin}/{id}"))
}

#[tauri::command]
pub(crate) async fn offline_album_save_original(
    window: WebviewWindow,
    app: AppHandle,
    album: Uuid,
    item: Uuid,
) -> Result<(), String> {
    require_local_photos(&window)?;
    let native = app.state::<OfflineAlbums>();
    let mut cancelled = native.cancelled.subscribe();
    let _permit = native.operation.try_lock().map_err(|_| BUSY)?;
    let saved = native.saved()?;
    let base = crate::import_base(&app)?;
    let cache = Cache::open(&base, &saved, false)?.ok_or("offline_album_none")?;
    let prepared = async {
        let access = cache.authorize(&saved, album, item).await?;
        let name = if access.name.is_empty() {
            "original"
        } else {
            &access.name
        };
        let (send, receive) = tokio::sync::oneshot::channel();
        app.dialog()
            .file()
            .set_title("Save original")
            .set_file_name(name)
            .set_parent(&window)
            .save_file(move |path| {
                let _ = send.send(path);
            });
        let Some(path) = receive.await.ok().flatten() else {
            return Ok(None);
        };
        require_local_photos(&window)?;
        let path = path.into_path().map_err(|_| "offline_album_save_failed")?;
        let access = cache.authorize(&saved, album, item).await?;
        Ok::<_, String>(Some((access, path)))
    };
    let result = tokio::select! {
        biased;
        _ = cancelled.changed() => return Err("offline_album_cancelled".into()),
        result = prepared => result?,
    };
    let Some((access, path)) = result else {
        return Ok(());
    };
    // Keep the native operation lock until the writer has published or cleaned up.
    tauri::async_runtime::spawn_blocking(move || {
        cache.save(album, item, &access, &path, || {
            cancelled.has_changed().unwrap_or(true)
        })
    })
    .await
    .map_err(|_| "offline_album_save_failed")?
}

#[tauri::command]
pub(crate) fn offline_album_close_media(
    window: WebviewWindow,
    app: AppHandle,
    grant: Uuid,
) -> Result<(), String> {
    require_local_photos(&window)?;
    let native = app.state::<OfflineAlbums>();
    let mut playback = native.playback.lock().map_err(|_| BUSY)?;
    if playback.as_ref().is_some_and(|active| active.id == grant) {
        *playback = None;
    }
    Ok(())
}

#[tauri::command]
pub(crate) async fn offline_album_remove(
    window: WebviewWindow,
    app: AppHandle,
    album: Option<Uuid>,
) -> Result<(), String> {
    require_local_photos(&window)?;
    let native = app.state::<OfflineAlbums>();
    let _permit = native.operation.try_lock().map_err(|_| BUSY)?;
    native.clear_playback();
    let saved = native.saved()?;
    let base = crate::import_base(&app)?;
    match album {
        Some(id) => {
            if let Some(cache) = Cache::open(&base, &saved, false)? {
                cache.remove(id)?;
            }
        }
        None => Cache::purge(&base)?,
    }
    native.set_progress(None);
    Ok(())
}

#[tauri::command]
pub(crate) fn offline_album_browse_library(
    window: WebviewWindow,
    app: AppHandle,
) -> Result<(), String> {
    require_local_photos(&window)?;
    let saved = app.state::<OfflineAlbums>().saved()?;
    crate::open_photos_window(&app, &saved)
}

#[tauri::command]
pub(crate) fn offline_album_cancel(window: WebviewWindow, app: AppHandle) -> Result<(), String> {
    require_local_photos(&window)?;
    app.state::<OfflineAlbums>().cancelled.send_replace(());
    Ok(())
}

fn message(code: &str) -> &'static str {
    match code {
        "offline_album_busy" => "Another offline album operation is in progress.",
        "offline_album_access_changed" => {
            "Only albums you own with unlocked originals can be kept offline."
        }
        "offline_album_no_originals" => "This album has no eligible originals to keep offline.",
        "offline_library_unreachable" => "Connect to your Library before keeping an album offline.",
        _ => "Frameleaf could not keep this album offline.",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bridge_accepts_only_the_uuid_action() {
        let id = Uuid::new_v4();
        let url = Url::parse(&format!("https://library.example{INTENT}{id}")).unwrap();
        assert_eq!(intent(&url), Some(id));
        assert_eq!(
            intent(
                &url.join(&format!("{INTENT}{id}?url=file:///private"))
                    .unwrap()
            ),
            None
        );
        assert_eq!(
            intent(&url.join(&format!("{INTENT}{id}/other")).unwrap()),
            None
        );
        assert!(!local_url(
            &Url::parse("https://library.example/offline-photos.html").unwrap()
        ));
    }
}
