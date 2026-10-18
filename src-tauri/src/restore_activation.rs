//! Activation must use identity-bound, handle-relative moves which never replace a destination.

#[cfg(test)]
mod tests {
    use super::*;
    use cap_std::fs::Dir;
    use std::{fs, path::PathBuf, process::Command};

    struct Fixture(PathBuf);
    impl Fixture {
        fn new() -> Self {
            let root =
                std::env::temp_dir().join(format!("frameleaf-activation-{}", uuid::Uuid::new_v4()));
            fs::create_dir(&root).unwrap();
            let value = Self(root);
            for name in ["source", "target", "source/database", "outside"] {
                let path = value.0.join(name);
                fs::create_dir(&path).unwrap();
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
                }
            }
            fs::write(
                value.0.join("source/database/sentinel"),
                b"retain these database bytes",
            )
            .unwrap();
            value
        }
        fn dir(&self, name: &str) -> Dir {
            Dir::open_ambient_dir(self.0.join(name), cap_std::ambient_authority()).unwrap()
        }
        fn identity(&self) -> String {
            // Exercise the actual Node-to-Rust receipt format, particularly on Windows.
            let output = Command::new("node")
                .arg("-e")
                .arg("const m=require('node:fs').statSync(process.argv[1],{bigint:true});process.stdout.write(m.dev+':'+m.ino)")
                .arg(self.0.join("source/database"))
                .output().expect("Node is required by the desktop qualification workflow");
            assert!(output.status.success());
            String::from_utf8(output.stdout).unwrap()
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn moves_only_the_bound_database_with_the_same_identity_node_uses() {
        let f = Fixture::new();
        let expected = f.identity();
        let actual = move_database(&f.dir("source"), &f.dir("target"), &expected).unwrap();
        assert_eq!(actual, expected);
        assert!(!f.0.join("source/database").exists());
        assert_eq!(
            fs::read(f.0.join("target/database/sentinel")).unwrap(),
            b"retain these database bytes"
        );
        assert!(f.0.join("outside").is_dir());
    }

    #[test]
    fn never_replaces_an_existing_database_even_if_the_destination_is_empty() {
        for occupied in [false, true] {
            let f = Fixture::new();
            fs::create_dir(f.0.join("target/database")).unwrap();
            if occupied {
                fs::write(f.0.join("target/database/foreign"), b"must survive").unwrap();
            }
            assert!(move_database(&f.dir("source"), &f.dir("target"), &f.identity()).is_err());
            assert_eq!(
                fs::read(f.0.join("source/database/sentinel")).unwrap(),
                b"retain these database bytes"
            );
            assert!(f.0.join("target/database").is_dir());
            if occupied {
                assert_eq!(
                    fs::read(f.0.join("target/database/foreign")).unwrap(),
                    b"must survive"
                );
            }
        }
    }

    #[test]
    fn refuses_wrong_identity_replaced_directories_and_links_before_moving() {
        for mutation in ["identity", "replaced", "link"] {
            let f = Fixture::new();
            let mut expected = f.identity();
            if mutation == "identity" {
                expected = "0:0".into();
            } else {
                fs::rename(f.0.join("source/database"), f.0.join("source/retained")).unwrap();
                if mutation == "replaced" {
                    fs::create_dir(f.0.join("source/database")).unwrap();
                } else {
                    #[cfg(unix)]
                    std::os::unix::fs::symlink(f.0.join("outside"), f.0.join("source/database"))
                        .unwrap();
                    #[cfg(windows)]
                    std::os::windows::fs::symlink_dir(
                        f.0.join("outside"),
                        f.0.join("source/database"),
                    )
                    .unwrap();
                }
            }
            assert!(move_database(&f.dir("source"), &f.dir("target"), &expected).is_err());
            assert!(!f.0.join("target/database").exists());
            assert!(f.0.join("outside").is_dir());
            let retained = if mutation == "identity" {
                "source/database/sentinel"
            } else {
                "source/retained/sentinel"
            };
            assert_eq!(
                fs::read(f.0.join(retained)).unwrap(),
                b"retain these database bytes"
            );
        }
    }
}
