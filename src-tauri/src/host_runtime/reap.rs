use std::io;

pub(super) fn confirm(mut reap: impl FnMut() -> io::Result<()>) {
    // Unconfirmed reaping must retain ownership, even when process-level recovery is required.
    while reap().is_err() {
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::{self, OpenOptions};

    #[test]
    fn wait_errors_cannot_complete_reaping_or_release_the_profile() {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path =
            std::env::temp_dir().join(format!("frameleaf-reap-{}-{unique}", std::process::id()));
        let owner = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        owner.try_lock().unwrap();
        let contender = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        let mut attempts = 0;
        confirm(|| {
            assert!(contender.try_lock().is_err());
            attempts += 1;
            if attempts < 3 {
                Err(io::Error::other("synthetic reap failure"))
            } else {
                Ok(())
            }
        });
        owner.unlock().unwrap();
        contender.try_lock().unwrap();
        contender.unlock().unwrap();
        drop((owner, contender));
        fs::remove_file(path).unwrap();
        assert_eq!(attempts, 3);
    }
}
