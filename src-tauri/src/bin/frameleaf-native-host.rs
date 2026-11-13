/// Keep internal agent failures off the controller's owner-protocol stdout pipe.
fn main() {
    let arguments: Vec<_> = std::env::args_os().skip(1).collect();
    let result = match arguments.as_slice() {
        #[cfg(windows)]
        [mode, node] if mode == "--run-windows-host-agent" => {
            match frameleaf_desktop::host_runtime::run_windows_host_agent(node) {
                Ok(code) => std::process::exit(code as i32),
                Err(code) => {
                    eprintln!("{code}");
                    std::process::exit(1);
                }
            }
        }
        // Touches nothing: lets a packaging check prove the installed controller loads.
        [mode] if mode == "--version" => {
            println!("frameleaf-native-host {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        [mode] if mode == "--owner-pipe" => frameleaf_desktop::host_control::run(),
        [mode] if mode == "--inspect-owner" => frameleaf_desktop::host_control::inspect_owner(),
        [mode, manifest, controller]
            if mode == "--prepare-install"
                || mode == "--finalize-install"
                || mode == "--prepare-maintenance"
                || mode == "--prepare-repair"
                || mode == "--prepare-windows-package"
                || mode == "--finalize-windows-package"
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
        [mode, manifest, controller, program] if mode == "--verify-installed-program" => {
            match (manifest.to_str(), controller.to_str(), program.to_str()) {
                (Some(manifest), Some(controller), Some(program)) => {
                    frameleaf_desktop::host_install::verify_installed_program(
                        manifest, controller, program,
                    )
                    .map(|receipt| println!("{}", receipt))
                }
                _ => Err("host_install_identity_invalid".into()),
            }
        }
        [mode, manifest, controller, uid]
            if mode == "--provision-install" || mode == "--provision-profile" =>
        {
            match (manifest.to_str(), controller.to_str(), uid.to_str()) {
                (Some(manifest), Some(controller), Some(uid)) => {
                    frameleaf_desktop::host_install::provision(manifest, controller, uid)
                        .map(|receipt| println!("{}", receipt))
                }
                _ => Err("host_install_identity_invalid".into()),
            }
        }
        _ => Err("host_control_arguments_invalid".into()),
    };
    if let Err(code) = result {
        let _ = frameleaf_desktop::host_control::report_failure(&code);
        std::process::exit(1);
    }
}
