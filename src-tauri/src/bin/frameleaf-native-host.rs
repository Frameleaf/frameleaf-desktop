fn main() {
    let arguments: Vec<_> = std::env::args_os().skip(1).collect();
    let result = match arguments.as_slice() {
        [mode] if mode == "--owner-pipe" => frameleaf_desktop::host_control::run(),
        [mode] if mode == "--inspect-owner" => frameleaf_desktop::host_control::inspect_owner(),
        [mode, manifest, controller]
            if mode == "--prepare-install"
                || mode == "--finalize-install"
                || mode == "--prepare-maintenance" =>
        {
            match (manifest.to_str(), controller.to_str()) {
                (Some(manifest), Some(controller)) => {
                    let result = if mode == "--prepare-install" {
                        frameleaf_desktop::host_install::prepare(manifest, controller)
                    } else if mode == "--prepare-maintenance" {
                        frameleaf_desktop::host_install::prepare_maintenance(manifest, controller)
                    } else {
                        frameleaf_desktop::host_install::finalize(manifest, controller)
                    };
                    result.map(|receipt| println!("{}", receipt))
                }
                _ => Err("host_install_identity_invalid".into()),
            }
        }
        [mode, manifest, controller, uid] if mode == "--provision-install" => {
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
