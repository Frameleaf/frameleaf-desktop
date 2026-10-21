fn main() {
    #[cfg(windows)]
    {
        let arguments: Vec<_> = std::env::args_os().skip(1).collect();
        if arguments.len() == 1 && arguments[0] == "--source-read" {
            if frameleaf_desktop::copy_source::run_cloud_reader_child().is_err() {
                std::process::exit(1);
            }
            return;
        }
    }
    frameleaf_desktop::run();
}
