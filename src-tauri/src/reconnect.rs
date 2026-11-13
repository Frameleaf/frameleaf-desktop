//! Reconnecting after the server did not answer. The retries run here, in the backend, so they go
//! on while the window is hidden to the tray; the window only shows what they led to.

use crate::connection::ConnectionView;
use crate::saved_sign_in::UNREACHABLE;
use serde::Serialize;
use std::future::Future;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tauri::{AppHandle, Emitter, Manager};

/// Sent to the main window when a background attempt settled the saved sign-in either way.
pub(crate) const EVENT: &str = "connection-restored";

/// What a background attempt led to: the connection (none when the sign-in is gone), or the
/// error that ended the retries.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Restored {
    pub connection: Option<ConnectionView>,
    pub error: Option<String>,
}

/// The wait before attempt `attempt` (from zero): 5 s doubling to a 5 minute ceiling.
pub(crate) fn delay(attempt: u32) -> Duration {
    Duration::from_secs((5u64 << attempt.min(10)).min(300))
}

/// Only an unanswered server is worth another try; every other answer is shown to the person.
pub(crate) fn retry_after<T>(result: &Result<T, String>) -> bool {
    matches!(result, Err(code) if code == UNREACHABLE)
}

/// Waits, then tries, until an attempt is answered or the retries are no longer wanted (`None`).
pub(crate) async fn run<T, Attempt, Sleep>(
    mut attempt: impl FnMut() -> Attempt,
    sleep: impl Fn(Duration) -> Sleep,
    wanted: impl Fn() -> bool,
) -> Option<Result<T, String>>
where
    Attempt: Future<Output = Result<T, String>>,
    Sleep: Future<Output = ()>,
{
    for tried in 0u32.. {
        sleep(delay(tried)).await;
        if !wanted() {
            return None;
        }
        let result = attempt().await;
        // A sign-out or the window's own attempt since then decides instead.
        if !wanted() {
            return None;
        }
        if !retry_after(&result) {
            return Some(result);
        }
    }
    None
}

/// The one retry loop, if any. A newer start or a cancel ends the loop before it.
#[derive(Default)]
pub(crate) struct Reconnect(AtomicU64);

impl Reconnect {
    /// Ends the retries: the person signed out, or an attempt of the window's own is deciding.
    pub(crate) fn cancel(&self) {
        self.0.fetch_add(1, Ordering::AcqRel);
    }

    /// After the window restored the saved sign-in: keep trying when the server did not answer.
    pub(crate) fn after_restore<T>(&self, app: &AppHandle, result: &Result<T, String>) {
        let generation = self.0.fetch_add(1, Ordering::AcqRel) + 1;
        if !retry_after(result) {
            return;
        }
        let app = app.clone();
        tauri::async_runtime::spawn(async move {
            let wanted = || app.state::<Reconnect>().0.load(Ordering::Acquire) == generation;
            let settled = run(
                || crate::restore_saved(&app, None, false),
                tokio::time::sleep,
                wanted,
            )
            .await;
            let Some(result) = settled else { return };
            let restored = match result {
                Ok(connection) => Restored {
                    connection,
                    error: None,
                },
                Err(error) => Restored {
                    connection: None,
                    error: Some(error),
                },
            };
            if let Ok(restored) = serde_json::to_value(restored) {
                let _ = app.emit_to("main", EVENT, restored);
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::{Cell, RefCell};

    #[test]
    fn the_wait_doubles_from_five_seconds_to_five_minutes() {
        let seconds: Vec<u64> = (0..9).map(|attempt| delay(attempt).as_secs()).collect();
        assert_eq!(seconds, [5, 10, 20, 40, 80, 160, 300, 300, 300]);
        assert_eq!(delay(u32::MAX).as_secs(), 300);
    }

    #[test]
    fn only_an_unanswered_server_is_tried_again() {
        assert!(retry_after::<()>(&Err(UNREACHABLE.into())));
        for settled in [
            Ok(()),
            Err("verification_required".to_string()),
            Err("server_http_401".to_string()),
            Err("credential_unlock_required".to_string()),
        ] {
            assert!(!retry_after(&settled));
        }
    }

    #[tokio::test]
    async fn it_keeps_trying_with_backoff_until_the_server_answers() {
        let waits = RefCell::new(Vec::new());
        let tries = Cell::new(0);
        let settled = run(
            || {
                tries.set(tries.get() + 1);
                let answer = if tries.get() < 4 {
                    Err(UNREACHABLE.to_string())
                } else {
                    Ok("connected")
                };
                async move { answer }
            },
            |wait| {
                waits.borrow_mut().push(wait.as_secs());
                async {}
            },
            || true,
        )
        .await;
        assert_eq!(settled, Some(Ok("connected")));
        assert_eq!(*waits.borrow(), [5, 10, 20, 40]);
    }

    #[tokio::test]
    async fn another_refusal_ends_the_retries_with_its_code() {
        let tries = Cell::new(0);
        let settled = run(
            || {
                tries.set(tries.get() + 1);
                let answer: Result<(), String> = if tries.get() == 1 {
                    Err(UNREACHABLE.into())
                } else {
                    Err("verification_required".into())
                };
                async move { answer }
            },
            |_| async {},
            || true,
        )
        .await;
        assert_eq!(settled, Some(Err("verification_required".into())));
        assert_eq!(tries.get(), 2);
    }

    #[tokio::test]
    async fn a_cancelled_loop_neither_tries_nor_reports() {
        // Cancelled during the wait: no attempt is made.
        let tries = Cell::new(0);
        let attempt = || {
            tries.set(tries.get() + 1);
            async { Ok::<_, String>(()) }
        };
        assert_eq!(run(attempt, |_| async {}, || false).await, None);
        assert_eq!(tries.get(), 0);
        // Cancelled while an attempt was under way: its answer is not reported.
        let wanted = Cell::new(true);
        let attempt = || {
            wanted.set(false);
            async { Ok::<_, String>(()) }
        };
        assert_eq!(run(attempt, |_| async {}, || wanted.get()).await, None);
    }
}
