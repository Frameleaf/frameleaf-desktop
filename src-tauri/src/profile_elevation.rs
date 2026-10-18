use std::process::{Command, Stdio};

fn command(manifest: &str, controller: &str, uid: u32) -> Result<Command, String> {
    if uid == 0 || uid == u32::MAX {
        return Err("host_install_profile_user_invalid".into());
    }
    let layout = crate::host_install::Layout::new(manifest, controller)?;
    let mut command = Command::new("/usr/bin/pkexec");
    command
        .args(["--disable-internal-agent", "--user", "root"])
        .arg(layout.controller)
        // Older helpers must refuse profile setup instead of finishing package maintenance.
        .arg("--provision-profile")
        .args([manifest, controller, &uid.to_string()])
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .env("LC_ALL", "C")
        .current_dir("/")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    Ok(command)
}
fn authorization_result(code: Option<i32>) -> Result<(), String> {
    match code {
        Some(0) => Ok(()),
        Some(126) => Err("host_profile_authorization_cancelled".into()),
        Some(127) => Err("host_profile_authorization_unavailable".into()),
        _ => Err("host_profile_prepare_failed".into()),
    }
}
#[cfg(target_os = "linux")]
pub(crate) fn provision(record: &crate::host_install::Installation) -> Result<(), String> {
    let uid = unsafe { libc::getuid() };
    if uid == 0 || uid == u32::MAX || unsafe { libc::geteuid() } != uid {
        return Err("host_install_profile_user_invalid".into());
    }
    crate::host_install::verify_for_profile(record)?;
    crate::manager_host::protect(
        std::path::Path::new("/usr/bin/pkexec"),
        &mut std::collections::BTreeSet::new(),
    )
    .map_err(|_| "host_profile_authorization_unavailable")?;
    let status = command(&record.manifest_sha256, &record.controller_sha256, uid)?
        .status()
        .map_err(|_| "host_profile_authorization_unavailable")?;
    authorization_result(status.code())?;
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
    #[test]
    fn authorization_invokes_only_fixed_installed_controller_for_current_uid() {
        let manifest = "a".repeat(64);
        let controller = "b".repeat(64);
        let invocation = command(&manifest, &controller, 1000).unwrap();
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
            assert!(command(&manifest, &controller, uid).is_err());
        }
        for invalid in ["", "../escape", "a;echo", &"A".repeat(64)] {
            assert!(command(invalid, &controller, 1000).is_err());
            assert!(command(&manifest, invalid, 1000).is_err());
        }
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
