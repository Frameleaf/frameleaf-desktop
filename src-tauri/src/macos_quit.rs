//! macOS quits that do not come from the app's own menu: Quit in the Dock menu, and a logout,
//! restart or shutdown. Both arrive as the system's `terminate:`, which used to end the process
//! without asking the exit guard. `macos_quit.m` hands the question here.
//!
//! - A Dock quit is refused as a native terminate and requested again as an ordinary exit, so the
//!   same exit guard as Cmd+Q decides it (a media copy or the local server can keep the app open).
//! - A session end is never refused and never waits on a person: running work is cancelled the
//!   way Sign Out and Quit cancel it, within a fixed grace period, and then the app terminates
//!   whether or not everything finished. What was not finished is picked up at the next launch.

#![cfg_attr(not(target_os = "macos"), allow(dead_code))]

use crate::window_close::Activity;
use std::time::Duration;

/// How long a session end may wait for work to stop. The local server's own orderly stop takes
/// up to 10 seconds; macOS gives up on an app that has not answered after about a minute.
pub(crate) const SESSION_END_GRACE: Duration = Duration::from_secs(20);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum QuitSource {
    /// Quit from the Dock menu, or another app asking this one to quit.
    Dock,
    /// The person is logging out, restarting or shutting down.
    SessionEnd,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum QuitDecision {
    /// Nothing is running: let the system terminate the app now.
    Terminate,
    /// Refuse this terminate and request an ordinary exit, which the exit guard judges.
    ThroughExitGuard,
    /// Stop running work, for at most this long, then terminate.
    WindDown(Duration),
}

/// What a system terminate does. Only a Dock quit can be held back by the exit guard; a session
/// end always ends in a terminate, after a bounded wait when something is running.
pub(crate) fn quit_decision(source: QuitSource, activity: Activity) -> QuitDecision {
    match source {
        QuitSource::Dock => QuitDecision::ThroughExitGuard,
        QuitSource::SessionEnd if activity.any() => QuitDecision::WindDown(SESSION_END_GRACE),
        QuitSource::SessionEnd => QuitDecision::Terminate,
    }
}

#[cfg(target_os = "macos")]
mod native {
    use super::*;
    use std::sync::OnceLock;
    use tauri::{AppHandle, Manager};

    extern "C" {
        fn frameleaf_guard_terminate(callback: extern "C" fn(i32) -> i32) -> bool;
        fn frameleaf_reply_terminate(terminate: bool);
    }

    static APP: OnceLock<AppHandle> = OnceLock::new();
    const CANCEL: i32 = 0;
    const NOW: i32 = 1;
    const LATER: i32 = 2;

    /// Routes Dock Quit and session ends through `quit_decision`. Call once, on the main thread.
    pub(crate) fn install(app: &AppHandle) -> Result<(), &'static str> {
        APP.set(app.clone())
            .map_err(|_| "quit guard already installed")?;
        // SAFETY: the callback is a plain function that lives for the whole process.
        if unsafe { frameleaf_guard_terminate(should_terminate) } {
            Ok(())
        } else {
            Err("the app delegate did not take the quit guard")
        }
    }

    extern "C" fn should_terminate(session_ending: i32) -> i32 {
        // Never unwind into AppKit; a failure here lets the app terminate as it always did.
        std::panic::catch_unwind(|| decide(session_ending != 0)).unwrap_or(NOW)
    }

    fn decide(session_ending: bool) -> i32 {
        let Some(app) = APP.get() else { return NOW };
        let source = if session_ending {
            QuitSource::SessionEnd
        } else {
            QuitSource::Dock
        };
        match quit_decision(source, crate::window_close::activity(app)) {
            QuitDecision::Terminate => NOW,
            QuitDecision::ThroughExitGuard => {
                // The same request Cmd+Q makes: `RunEvent::ExitRequested` allows or refuses it.
                app.exit(0);
                CANCEL
            }
            QuitDecision::WindDown(grace) => {
                let app = app.clone();
                tauri::async_runtime::spawn(async move {
                    let _ = tokio::time::timeout(grace, wind_down(&app)).await;
                    // Finished or not, the session end goes ahead.
                    // SAFETY: takes no pointers; the reply is delivered on the main thread.
                    unsafe { frameleaf_reply_terminate(true) };
                });
                LATER
            }
        }
    }

    /// Stops running work the way Sign Out and Quit do. Each stop records where it was, so
    /// nothing is left half-recorded: imports and the worker resume at the next launch, and a
    /// cancelled media copy is reported as cancelled.
    async fn wind_down(app: &AppHandle) {
        app.state::<crate::reconnect::Reconnect>().cancel();
        let copy = app.state::<crate::media_copy::MediaCopy>();
        copy.cancel();
        app.state::<crate::source_import::SourceJobs>().stop().await;
        app.state::<crate::drop_import::DropImport>().stop().await;
        app.state::<crate::worker_setup::WorkerSetup>().stop().await;
        let host = app.state::<crate::host_setup::HostSetup>();
        if host.background_active() && host.quit(None, false).await.is_err() {
            // The local server did not stop in time: record that, so the next launch stops it.
            let _ = host.quit(None, true).await;
        }
        while copy.is_active() {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }
}

#[cfg(target_os = "macos")]
pub(crate) use native::install;

#[cfg(test)]
mod tests {
    use super::*;

    const IDLE: Activity = Activity {
        worker: false,
        import: false,
        watch: false,
        local_host: false,
        media_copy: false,
    };

    fn each_activity() -> [Activity; 5] {
        [
            Activity {
                worker: true,
                ..IDLE
            },
            Activity {
                import: true,
                ..IDLE
            },
            Activity {
                watch: true,
                ..IDLE
            },
            Activity {
                local_host: true,
                ..IDLE
            },
            Activity {
                media_copy: true,
                ..IDLE
            },
        ]
    }

    #[test]
    fn a_dock_quit_always_goes_through_the_exit_guard() {
        // Idle or not: the exit guard decides, exactly as it does for Cmd+Q.
        assert_eq!(
            quit_decision(QuitSource::Dock, IDLE),
            QuitDecision::ThroughExitGuard
        );
        for activity in each_activity() {
            assert_eq!(
                quit_decision(QuitSource::Dock, activity),
                QuitDecision::ThroughExitGuard,
                "{activity:?}"
            );
        }
    }

    #[test]
    fn a_session_end_is_never_refused_and_never_waits_without_a_limit() {
        assert_eq!(
            quit_decision(QuitSource::SessionEnd, IDLE),
            QuitDecision::Terminate
        );
        for activity in each_activity() {
            let decision = quit_decision(QuitSource::SessionEnd, activity);
            // Even a media copy or the local server, which hold back an ordinary quit.
            assert_eq!(
                decision,
                QuitDecision::WindDown(SESSION_END_GRACE),
                "{activity:?}"
            );
        }
        // Inside what macOS allows before it reports the app as not responding to the logout,
        // and long enough for the local server's own 10-second orderly stop.
        assert!(SESSION_END_GRACE > Duration::from_secs(10));
        assert!(SESSION_END_GRACE <= Duration::from_secs(30));
    }
}
