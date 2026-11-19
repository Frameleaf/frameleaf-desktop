fn main() {
    // Answers without opening a window, so a packaging check can prove the installed binary
    // and everything it links against load on a distribution.
    if std::env::args_os()
        .nth(1)
        .is_some_and(|argument| argument == "--version")
    {
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
