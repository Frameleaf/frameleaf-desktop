fn main() {
    let arguments: Vec<_> = std::env::args_os().skip(1).collect();
    #[cfg(target_os = "linux")]
    let session =
        frameleaf_desktop::controller_session::directory_for_mode(&arguments).map(|path| {
            if let Some(path) = path {
                // This dedicated controller initializes its environment before starting any threads.
                std::env::remove_var("DBUS_SESSION_BUS_ADDRESS");
                std::env::set_var("XDG_RUNTIME_DIR", path);
            }
        });
    #[cfg(not(target_os = "linux"))]
    let session = Ok::<(), String>(());
    let result = session.and_then(|()| match arguments.as_slice() {
        #[cfg(windows)]
        [mode] if mode == "--installer-protocol" => {
            const PROTOCOL: &str = r#"{"schemaVersion":1,"installerProtocolVersion":1,"install":"--install-windows-package","remove":"--remove-windows-package"}"#;
            println!("{PROTOCOL}");
            Ok(())
        }
        #[cfg(debug_assertions)]
        [mode, identity] if mode == "--qualify-credential-access" => match identity.to_str() {
            Some(identity) => frameleaf_desktop::host_control::qualify_credential_access(identity)
                .map(|receipt| println!("{receipt}")),
            None => Err("host_control_arguments_invalid".into()),
        },
        [mode] if mode == "--owner-pipe" => frameleaf_desktop::host_control::run(),
        [mode] if mode == "--inspect-owner" => frameleaf_desktop::host_control::inspect_owner(),
        [mode, manifest, controller]
            if mode == "--prepare-install"
                || mode == "--finalize-install"
                || mode == "--prepare-maintenance"
                || mode == "--prepare-repair"
                || mode == "--prepare-windows-package"
                || mode == "--finalize-windows-package"
                || mode == "--remove-windows-package"
                || mode == "--prepare-linux-package" =>
        {
            match (manifest.to_str(), controller.to_str()) {
                (Some(manifest), Some(controller)) => {
                    let result = if mode == "--prepare-install" {
                        frameleaf_desktop::host_install::prepare(manifest, controller)
                    } else if mode == "--prepare-maintenance" {
                        frameleaf_desktop::host_install::prepare_maintenance(manifest, controller)
                    } else if mode == "--prepare-repair" {
                        frameleaf_desktop::host_install::prepare_repair(manifest, controller)
                    } else if mode == "--prepare-windows-package" {
                        frameleaf_desktop::host_install::prepare_windows_package(
                            manifest, controller,
                        )
                    } else if mode == "--remove-windows-package" {
                        frameleaf_desktop::host_install::remove_windows_package(
                            manifest, controller,
                        )
                    } else if mode == "--finalize-windows-package" {
                        frameleaf_desktop::host_install::finalize_windows_package(
                            manifest, controller,
                        )
                    } else if mode == "--prepare-linux-package" {
                        frameleaf_desktop::host_install::prepare_linux_package(manifest, controller)
                    } else {
                        frameleaf_desktop::host_install::finalize(manifest, controller)
                    };
                    result.map(|receipt| println!("{}", receipt))
                }
                _ => Err("host_install_identity_invalid".into()),
            }
        }
        [mode, source, manifest, controller] if mode == "--install-windows-package" => {
            match (manifest.to_str(), controller.to_str()) {
                (Some(manifest), Some(controller)) => {
                    frameleaf_desktop::host_install::install_windows_package(
                        std::path::Path::new(source),
                        manifest,
                        controller,
                    )
                    .map(|receipt| println!("{}", receipt))
                }
                _ => Err("host_install_identity_invalid".into()),
            }
        }
        [mode, manifest, controller, uid]
            if mode == "--provision-install"
                || mode == "--provision-profile"
                || mode == "--provision-windows-profile" =>
        {
            match (manifest.to_str(), controller.to_str(), uid.to_str()) {
                (Some(manifest), Some(controller), Some(uid)) => {
                    let result = if mode == "--provision-windows-profile" {
                        frameleaf_desktop::host_install::provision_windows_profile(
                            manifest, controller, uid,
                        )
                    } else {
                        frameleaf_desktop::host_install::provision(manifest, controller, uid)
                    };
                    result.map(|receipt| println!("{}", receipt))
                }
                _ => Err("host_install_identity_invalid".into()),
            }
        }
        _ => Err("host_control_arguments_invalid".into()),
    });
    if let Err(code) = result {
        let _ = frameleaf_desktop::host_control::report_failure(&code);
        std::process::exit(1);
    }
}
