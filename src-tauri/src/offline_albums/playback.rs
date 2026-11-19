use super::{
    cache::{Authorized, Cache, MAX_RANGE},
    require_local_photos, OfflineAlbums,
};
use std::time::{Duration, Instant};
use tauri::{
    http::{self, header},
    AppHandle, Manager, UriSchemeContext, UriSchemeResponder,
};
use uuid::Uuid;

const INLINE_LIMIT: u64 = 64 * 1024 * 1024;

#[derive(Clone)]
pub(super) struct Playback {
    pub id: Uuid,
    pub album: Uuid,
    pub item: Uuid,
    pub access: Authorized,
    pub checked: Instant,
    pub touched: Instant,
}

pub(crate) fn serve(
    context: UriSchemeContext<'_, tauri::Wry>,
    request: http::Request<Vec<u8>>,
    responder: UriSchemeResponder,
) {
    if context.webview_label() != "photos" {
        responder.respond(empty(403));
        return;
    }
    let app = context.app_handle().clone();
    tauri::async_runtime::spawn(async move {
        let response = match load(&app, request).await {
            Ok(response) => response,
            Err(_) => empty(403),
        };
        responder.respond(response);
    });
}

async fn load(
    app: &AppHandle,
    request: http::Request<Vec<u8>>,
) -> Result<http::Response<Vec<u8>>, String> {
    let window = app
        .get_webview_window("photos")
        .ok_or("native_access_denied")?;
    require_local_photos(&window)?;
    let id = request
        .uri()
        .path()
        .strip_prefix('/')
        .and_then(|id| Uuid::parse_str(id).ok())
        .filter(|_| request.uri().query().is_none())
        .ok_or("native_access_denied")?;
    if !matches!(*request.method(), http::Method::GET | http::Method::HEAD) {
        return Ok(empty(405));
    }
    let native = app.state::<OfflineAlbums>();
    let mut cancelled = native.cancelled.subscribe();
    let _permit = native.operation.lock().await;
    let saved = native.saved()?;
    let mut playback = native.get_playback(id)?;
    let base = crate::import_base(app)?;
    let cache = Cache::open(&base, &saved, false)?.ok_or("offline_album_none")?;
    if playback.checked.elapsed() >= Duration::from_secs(15) || !playback.access.current() {
        let verified = tokio::select! {
            biased;
            _ = cancelled.changed() => return Err("offline_album_cancelled".into()),
            verified = cache.authorize(&saved, playback.album, playback.item) => verified,
        };
        match verified {
            Ok(access) => playback.access = access,
            Err(error) => {
                native.clear_playback();
                return Err(error);
            }
        }
        playback.checked = Instant::now();
    }
    let access = &playback.access;
    let length = access.size;
    let mut response = http::Response::builder()
        .header(header::CONTENT_TYPE, &access.mime)
        .header(header::CACHE_CONTROL, "no-store")
        .header(header::ACCEPT_RANGES, "bytes")
        .header("X-Content-Type-Options", "nosniff");
    if request.method() == http::Method::HEAD {
        require_local_photos(&window)?;
        if cancelled.has_changed().unwrap_or(true) {
            return Err("offline_album_cancelled".into());
        }
        playback.touched = Instant::now();
        native.renew_playback(playback)?;
        return response
            .header(header::CONTENT_LENGTH, length)
            .body(Vec::new())
            .map_err(|_| "offline_album_response_invalid".into());
    }
    let header_value = request.headers().get(header::RANGE);
    let (start, end, partial) = match header_value {
        Some(value) => match value
            .to_str()
            .ok()
            .and_then(|value| byte_range(value, length))
        {
            Some((start, end)) => (start, end, true),
            None => {
                return response
                    .status(416)
                    .header(header::CONTENT_RANGE, format!("bytes */{length}"))
                    .body(Vec::new())
                    .map_err(|_| "offline_album_response_invalid".into());
            }
        },
        None if access.mime.starts_with("video/") && length > MAX_RANGE => (0, MAX_RANGE, true),
        None if length <= INLINE_LIMIT => (0, length, false),
        None => return Ok(empty(413)),
    };
    let mut bytes = Vec::with_capacity((end - start) as usize);
    let mut offset = start;
    while offset < end {
        let next = (offset + MAX_RANGE).min(end);
        bytes.extend(cache.range(playback.album, playback.item, length, offset, next)?);
        offset = next;
    }
    if partial {
        response = response.status(206).header(
            header::CONTENT_RANGE,
            format!("bytes {start}-{}/{length}", end - 1),
        );
    }
    require_local_photos(&window)?;
    if cancelled.has_changed().unwrap_or(true) {
        return Err("offline_album_cancelled".into());
    }
    playback.touched = Instant::now();
    native.renew_playback(playback)?;
    response
        .header(header::CONTENT_LENGTH, end - start)
        .body(bytes)
        .map_err(|_| "offline_album_response_invalid".into())
}

fn empty(status: u16) -> http::Response<Vec<u8>> {
    http::Response::builder()
        .status(status)
        .header(header::CACHE_CONTROL, "no-store")
        .body(Vec::new())
        .unwrap()
}

fn byte_range(value: &str, size: u64) -> Option<(u64, u64)> {
    let (start, end) = value.strip_prefix("bytes=")?.split_once('-')?;
    let (start, end) = if start.is_empty() {
        let suffix = end.parse::<u64>().ok()?.min(size).min(MAX_RANGE);
        (size - suffix, size)
    } else {
        let start = start.parse::<u64>().ok()?;
        let end = if end.is_empty() {
            size
        } else {
            end.parse::<u64>().ok()?.saturating_add(1).min(size)
        };
        (start, end.min(start.saturating_add(MAX_RANGE)))
    };
    (start < end).then_some((start, end))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn video_byte_ranges_are_bounded_and_support_seeking_near_the_end() {
        let large = 180 * 1024 * 1024;
        assert_eq!(byte_range("bytes=0-", large), Some((0, MAX_RANGE)));
        assert_eq!(byte_range("bytes=100-199", large), Some((100, 200)));
        assert_eq!(byte_range("bytes=-64", large), Some((large - 64, large)));
        assert_eq!(
            byte_range(&format!("bytes={}-", large - 16), large),
            Some((large - 16, large))
        );
        assert_eq!(byte_range("bytes=0-2,4-6", large), None);
        assert_eq!(byte_range(&format!("bytes={large}-"), large), None);
    }
}
