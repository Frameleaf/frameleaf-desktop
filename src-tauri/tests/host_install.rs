use std::process::Command;

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
            if cfg!(target_os = "linux") {
                "host_install_root_required"
            } else {
                "host_install_platform_unsupported"
            }
        );
    }
}
