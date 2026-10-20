use std::process::{Command, Stdio};

fn command(record: &crate::host_install::Installation, uid: u32) -> Result<Command, String> {
    if uid == 0 || uid == u32::MAX {
        return Err("host_install_profile_user_invalid".into());
    }
    let layout = record.layout()?;
    let manifest = &record.manifest_sha256;
    let controller = &record.controller_sha256;
    #[cfg(not(target_os = "macos"))]
    let mut command = Command::new("/usr/bin/pkexec");
    #[cfg(not(target_os = "macos"))]
    command
        .args(["--disable-internal-agent", "--user", "root"])
        .arg(layout.controller)
        // Older helpers must refuse profile setup instead of finishing package maintenance.
        .arg("--provision-profile")
        .args([manifest, controller, &uid.to_string()]);
    #[cfg(target_os = "macos")]
    let mut command = {
        let mut command = Command::new("/usr/bin/osascript");
        command.args(["-e", r#"on run argv
set helper to quoted form of (item 1 of argv)
set manifestHash to quoted form of (item 2 of argv)
set controllerHash to quoted form of (item 3 of argv)
set profileUid to quoted form of (item 4 of argv)
try
do shell script "/usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C " & helper & " --provision-profile " & manifestHash & " " & controllerHash & " " & profileUid with administrator privileges
return "prepared"
on error number -128
return "cancelled"
end try
end run"#])
            .arg(layout.controller)
            .args([manifest, controller, &uid.to_string()]);
        command
    };
    command
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .env("LC_ALL", "C")
        .current_dir("/")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    #[cfg(target_os = "macos")]
    command.stdout(Stdio::piped());
    Ok(command)
}
#[cfg(any(not(target_os = "macos"), test))]
fn authorization_result(code: Option<i32>) -> Result<(), String> {
    match code {
        Some(0) => Ok(()),
        Some(126) => Err("host_profile_authorization_cancelled".into()),
        Some(127) => Err("host_profile_authorization_unavailable".into()),
        _ => Err("host_profile_prepare_failed".into()),
    }
}
#[cfg(target_os = "macos")]
fn macos_authorization_result(code: Option<i32>, receipt: &[u8]) -> Result<(), String> {
    match (code, receipt) {
        (Some(0), b"prepared\n") => Ok(()),
        (Some(0), b"cancelled\n") => Err("host_profile_authorization_cancelled".into()),
        _ => Err("host_profile_prepare_failed".into()),
    }
}
#[cfg(any(target_os = "macos", target_os = "linux"))]
pub(crate) fn provision(record: &crate::host_install::Installation) -> Result<(), String> {
    let uid = unsafe { libc::getuid() };
    if uid == 0 || uid == u32::MAX || unsafe { libc::geteuid() } != uid {
        return Err("host_install_profile_user_invalid".into());
    }
    crate::host_install::verify_for_profile(record)?;
    let executable = if cfg!(target_os = "macos") {
        "/usr/bin/osascript"
    } else {
        "/usr/bin/pkexec"
    };
    crate::manager_host::protect(
        std::path::Path::new(executable),
        &mut std::collections::BTreeSet::new(),
    )
    .map_err(|_| "host_profile_authorization_unavailable")?;
    let mut command = command(record, uid)?;
    #[cfg(target_os = "linux")]
    authorization_result(
        command
            .status()
            .map_err(|_| "host_profile_authorization_unavailable")?
            .code(),
    )?;
    #[cfg(target_os = "macos")]
    {
        let output = command
            .output()
            .map_err(|_| "host_profile_authorization_unavailable")?;
        macos_authorization_result(output.status.code(), &output.stdout)?;
    }
    if crate::host_install::Installation::read(&record.manifest_sha256)? != *record {
        return Err("host_install_record_invalid".into());
    }
    let profile = record.layout()?.profiles.join(uid.to_string());
    crate::host_setup::require_leaf(&profile.join("state"))?;
    crate::host_setup::require_leaf(&profile.join("manager"))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn record(manifest: &str, controller: &str) -> crate::host_install::Installation {
        let mut value = serde_json::json!({"schemaVersion":1,"manifestSha256":manifest,"controllerSha256":controller});
        if cfg!(target_os = "macos") {
            value["schemaVersion"] = serde_json::json!(2);
            value["controllerBundleVersion"] = serde_json::json!("0.1.0");
        }
        serde_json::from_value(value).unwrap()
    }

    #[test]
    #[cfg(not(target_os = "macos"))]
    fn authorization_invokes_only_fixed_installed_controller_for_current_uid() {
        let manifest = "a".repeat(64);
        let controller = "b".repeat(64);
        let invocation = command(&record(&manifest, &controller), 1000).unwrap();
        assert_eq!(invocation.get_program(), "/usr/bin/pkexec");
        assert_eq!(
            invocation.get_current_dir().unwrap(),
            std::path::Path::new("/")
        );
        let args: Vec<_> = invocation
            .get_args()
            .map(|s| s.to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            args,
            [
                "--disable-internal-agent",
                "--user",
                "root",
                crate::host_install::Layout::new(&manifest, &controller)
                    .unwrap()
                    .controller
                    .to_str()
                    .unwrap(),
                "--provision-profile",
                &manifest,
                &controller,
                "1000"
            ]
        );
        let env: Vec<_> = invocation
            .get_envs()
            .map(|(k, v)| {
                (
                    k.to_string_lossy().into_owned(),
                    v.map(|v| v.to_string_lossy().into_owned()),
                )
            })
            .collect();
        assert_eq!(env.len(), 2);
        assert!(env.contains(&("LC_ALL".into(), Some("C".into()))));
        assert!(env.contains(&("PATH".into(), Some("/usr/sbin:/usr/bin:/sbin:/bin".into()))));
        for uid in [0, u32::MAX] {
            assert!(command(&record(&manifest, &controller), uid).is_err());
        }
        for invalid in ["", "../escape", "a;echo", &"A".repeat(64)] {
            assert!(command(&record(invalid, &controller), 1000).is_err());
            assert!(command(&record(&manifest, invalid), 1000).is_err());
        }
    }
    #[cfg(target_os = "macos")]
    #[test]
    fn macos_authorization_receipts_are_exact_and_cancellation_is_not_success() {
        macos_authorization_result(Some(0), b"prepared\n").unwrap();
        assert_eq!(
            macos_authorization_result(Some(0), b"cancelled\n").unwrap_err(),
            "host_profile_authorization_cancelled"
        );
        for (status, bytes) in [
            (Some(1), b"prepared\n".as_slice()),
            (None, b"prepared\n"),
            (Some(0), b""),
            (Some(0), b"prepared\ncancelled\n"),
        ] {
            assert_eq!(
                macos_authorization_result(status, bytes).unwrap_err(),
                "host_profile_prepare_failed"
            );
        }
    }
    #[cfg(target_os = "macos")]
    #[test]
    fn macos_authorization_is_fixed_and_never_embeds_a_password() {
        let manifest = "a".repeat(64);
        let controller = "b".repeat(64);
        let invocation = command(&record(&manifest, &controller), 501).unwrap();
        assert_eq!(invocation.get_program(), "/usr/bin/osascript");
        let args: Vec<_> = invocation.get_args().map(|s| s.to_str().unwrap()).collect();
        assert_eq!(args[0], "-e");
        assert!(args[1].contains("with administrator privileges"));
        assert!(args[1].contains("quoted form of"));
        assert!(!args[1].contains("password"));
        assert_eq!(args.len(), 6);
        assert_eq!(
            args[2],
            crate::host_install::Layout::new(&manifest, &controller)
                .unwrap()
                .controller
                .to_str()
                .unwrap()
        );
        assert_eq!(&args[3..], [&manifest, &controller, "501"]);
        assert_eq!(
            invocation.get_current_dir().unwrap(),
            std::path::Path::new("/")
        );
        assert_eq!(invocation.get_envs().count(), 2);
        // Evaluate quoting only; never execute the privileged command in a local test.
        let script = args[1]
            .replace("do shell script ", "return ")
            .replace(" with administrator privileges", "");
        let output = Command::new("/usr/bin/osascript")
            .args(["-e", &script])
            .args(&args[2..])
            .output()
            .unwrap();
        assert!(output.status.success(), "{:?}", output.stderr);
        let expected = format!(
            "/usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C '{}' --provision-profile '{}' '{}' '501'\n",
            args[2], manifest, controller
        );
        assert_eq!(output.stdout, expected.as_bytes());
        for (replacement, expected) in [
            ("error number -128", b"cancelled\n".as_slice()),
            ("set unused to 1", b"prepared\n".as_slice()),
            ("error number 1", b"".as_slice()),
        ] {
            let script = args[1]
                .lines()
                .map(|line| {
                    if line.starts_with("do shell script ") {
                        replacement
                    } else {
                        line
                    }
                })
                .collect::<Vec<_>>()
                .join("\n");
            let output = Command::new("/usr/bin/osascript")
                .args(["-e", &script])
                .args(&args[2..])
                .env_clear()
                .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
                .env("LC_ALL", "C")
                .output()
                .unwrap();
            assert_eq!(output.status.success(), replacement != "error number 1");
            assert_eq!(output.stdout, expected);
        }
        for uid in [0, u32::MAX] {
            assert!(command(&record(&manifest, &controller), uid).is_err());
        }
        for invalid in ["", "../escape", "a;echo", &"A".repeat(64)] {
            assert!(command(&record(invalid, &controller), 501).is_err());
            assert!(command(&record(&manifest, invalid), 501).is_err());
        }
    }
    #[cfg(target_os = "macos")]
    #[test]
    fn legacy_profile_authorization_keeps_the_verified_flat_controller() {
        let legacy: crate::host_install::Installation = serde_json::from_value(serde_json::json!({
            "schemaVersion":1, "manifestSha256":"a".repeat(64), "controllerSha256":"b".repeat(64)
        }))
        .unwrap();
        let invocation = command(&legacy, 501).unwrap();
        assert_eq!(
            invocation.get_args().nth(2).unwrap(),
            legacy.layout().unwrap().controller
        );
    }
    #[test]
    fn authorization_failure_and_dismissal_never_report_success() {
        authorization_result(Some(0)).unwrap();
        assert_eq!(
            authorization_result(Some(126)).unwrap_err(),
            "host_profile_authorization_cancelled"
        );
        assert_eq!(
            authorization_result(Some(127)).unwrap_err(),
            "host_profile_authorization_unavailable"
        );
        for code in [None, Some(1), Some(255)] {
            assert_eq!(
                authorization_result(code).unwrap_err(),
                "host_profile_prepare_failed"
            );
        }
    }
}
