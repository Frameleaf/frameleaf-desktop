// A release build on Windows is a window app: without this, Windows opens a console window
// beside the app every time it starts (and when the Computer backup agent runs).
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

/// A window app has no console of its own. When it was started from one (`Frameleaf --version`
/// in a terminal), write there; output that is piped or redirected needs nothing.
#[cfg(windows)]
fn use_parent_console() {
    unsafe extern "system" {
        fn AttachConsole(process: u32) -> i32;
    }
    // SAFETY: takes no pointers. ATTACH_PARENT_PROCESS; failing (no parent console) is fine.
    unsafe {
        AttachConsole(u32::MAX);
    }
}

fn main() {
    // Answers without opening a window, so a packaging check can prove the installed binary
    // and everything it links against load on a distribution.
    if std::env::args_os()
        .nth(1)
        .is_some_and(|argument| argument == "--version")
    {
        #[cfg(windows)]
        use_parent_console();
        println!("Frameleaf {}", env!("CARGO_PKG_VERSION"));
        return;
    }
    // FD-77: the Computer backup agent, started by launchd or the Task Scheduler, and by Back Up Now.
    if std::env::args_os()
        .nth(1)
        .is_some_and(|argument| argument == frameleaf_desktop::computer_backup::AGENT_FLAG)
    {
        let now = std::env::args_os().any(|argument| argument == "--now");
        std::process::exit(frameleaf_desktop::computer_backup::agent_main(now));
    }
    frameleaf_desktop::run();
}
