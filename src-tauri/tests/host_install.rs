use std::process::Command;

#[test]
fn windows_installer_protocol_is_read_only_and_platform_scoped() {
    for extra in [None, Some("unexpected")] {
        let mut command = Command::new(env!("CARGO_BIN_EXE_frameleaf-native-host"));
        command.arg("--installer-protocol");
        if let Some(extra) = extra {
            command.arg(extra);
        }
        let output = command.output().unwrap();
        assert!(output.stderr.is_empty());
        let receipt: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        if cfg!(windows) && extra.is_none() {
            assert!(output.status.success());
            assert_eq!(
                receipt,
                serde_json::json!({
                    "schemaVersion": 1,
                    "installerProtocolVersion": 1,
                    "install": "--install-windows-package",
                    "remove": "--remove-windows-package"
                })
            );
        } else {
            assert!(!output.status.success());
            assert_eq!(receipt["code"], "host_control_arguments_invalid");
        }
    }
}

#[test]
fn windows_profile_provisioning_is_explicit_bounded_and_platform_scoped() {
    for args in [
        vec!["invalid", "invalid"],
        vec!["invalid", "invalid", "S-1-5-18"],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_frameleaf-native-host"))
            .arg("--provision-windows-profile")
            .args(&args)
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert!(output.stderr.is_empty());
        let receipt: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        if args.len() != 3 {
            assert_eq!(receipt["code"], "host_control_arguments_invalid");
        } else if cfg!(windows) {
            assert!([
                "host_install_administrator_required",
                "host_install_identity_invalid"
            ]
            .iter()
            .any(|code| receipt["code"] == *code));
        } else {
            assert_eq!(receipt["code"], "host_install_platform_unsupported");
        }
    }
}

#[test]
fn windows_package_finalization_is_a_bounded_platform_scoped_command() {
    for args in [vec![], vec!["invalid", "invalid"]] {
        let output = Command::new(env!("CARGO_BIN_EXE_frameleaf-native-host"))
            .arg("--finalize-windows-package")
            .args(&args)
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert!(output.stderr.is_empty());
        let receipt: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        if args.is_empty() {
            assert_eq!(receipt["code"], "host_control_arguments_invalid");
        } else if cfg!(windows) {
            assert!([
                "host_install_administrator_required",
                "host_install_identity_invalid"
            ]
            .iter()
            .any(|code| receipt["code"] == *code));
        } else {
            assert_eq!(receipt["code"], "host_install_platform_unsupported");
        }
    }
}

#[test]
fn windows_package_preparation_requires_its_bounded_dedicated_command() {
    for ids in [vec![], vec!["invalid"], vec!["invalid", "invalid"]] {
        let output = Command::new(env!("CARGO_BIN_EXE_frameleaf-native-host"))
            .arg("--prepare-windows-package")
            .args(&ids)
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert!(output.stderr.is_empty());
        let receipt: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        if ids.len() != 2 {
            assert_eq!(receipt["code"], "host_control_arguments_invalid");
        } else if cfg!(windows) {
            assert!([
                "host_install_administrator_required",
                "host_install_identity_invalid"
            ]
            .iter()
            .any(|code| receipt["code"] == *code));
        } else {
            assert_eq!(receipt["code"], "host_install_platform_unsupported");
        }
    }
}

#[test]
fn installer_cli_refuses_nonroot_execution_and_incomplete_arguments() {
    #[cfg(unix)]
    if unsafe { libc::geteuid() } == 0 {
        return;
    }
    for phase in [
        "--prepare-install",
        "--finalize-install",
        "--prepare-maintenance",
        "--prepare-repair",
        "--prepare-linux-package",
    ] {
        for ids in [vec![], vec!["a".repeat(64), "b".repeat(64)]] {
            let output = Command::new(env!("CARGO_BIN_EXE_frameleaf-native-host"))
                .arg(phase)
                .args(&ids)
                .output()
                .unwrap();
            assert!(!output.status.success());
            assert!(output.stderr.is_empty());
            let receipt: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
            let expected = if ids.is_empty() {
                "host_control_arguments_invalid"
            } else if cfg!(target_os = "linux")
                || (cfg!(target_os = "macos") && phase != "--prepare-linux-package")
            {
                "host_install_root_required"
            } else {
                "host_install_platform_unsupported"
            };
            assert_eq!(receipt["code"], expected);
        }
    }
    for phase in ["--provision-install", "--provision-profile"] {
        let output = Command::new(env!("CARGO_BIN_EXE_frameleaf-native-host"))
            .args([phase, &"a".repeat(64), &"b".repeat(64), "1000"])
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert!(output.stderr.is_empty());
        let receipt: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(
            receipt["code"],
            if cfg!(any(target_os = "macos", target_os = "linux")) {
                "host_install_root_required"
            } else {
                "host_install_platform_unsupported"
            }
        );
    }
}
