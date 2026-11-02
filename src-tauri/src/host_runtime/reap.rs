use std::io;

pub(super) fn confirm(mut reap: impl FnMut() -> io::Result<()>) -> io::Result<()> {
    loop {
        match reap() {
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            result => return result,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::{self, OpenOptions};

    #[test]
    fn terminal_wait_error_is_not_retried() {
        let mut attempts = 0;
        let result = confirm(|| {
            attempts += 1;
            assert_eq!(attempts, 1, "terminal wait error was retried");
            Err(io::Error::other("ownership lost"))
        });
        assert!(result.is_err());
        assert_eq!(attempts, 1);
    }

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
        assert!(confirm(|| Err(io::Error::other("ownership lost"))).is_err());
        assert!(contender.try_lock().is_err());
        confirm(|| {
            assert!(contender.try_lock().is_err());
            attempts += 1;
            if attempts < 3 {
                Err(io::Error::from(io::ErrorKind::Interrupted))
            } else {
                Ok(())
            }
        })
        .unwrap();
        owner.unlock().unwrap();
        contender.try_lock().unwrap();
        contender.unlock().unwrap();
        drop((owner, contender));
        fs::remove_file(path).unwrap();
        assert_eq!(attempts, 3);
    }
}
