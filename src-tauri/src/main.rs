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
    frameleaf_desktop::run();
}
