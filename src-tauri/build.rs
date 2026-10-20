fn main() {
    println!("cargo:rerun-if-changed=native/photos.m");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("macos") {
        let out = std::path::PathBuf::from(std::env::var_os("OUT_DIR").unwrap());
        let arch = match std::env::var("CARGO_CFG_TARGET_ARCH").unwrap().as_str() {
            "aarch64" => "arm64",
            "x86_64" => "x86_64",
            _ => panic!("unsupported macOS architecture"),
        };
        assert!(std::process::Command::new("xcrun")
            .args([
                "clang",
                "-arch",
                arch,
                "-fobjc-arc",
                "-fblocks",
                "-mmacosx-version-min=10.13",
                "-c",
                "native/photos.m",
                "-o"
            ])
            .arg(out.join("photos.o"))
            .status()
            .expect("Apple clang")
            .success());
        assert!(std::process::Command::new("xcrun")
            .args(["ar", "crs"])
            .arg(out.join("libframeleaf_photos.a"))
            .arg(out.join("photos.o"))
            .status()
            .expect("Apple ar")
            .success());
        println!("cargo:rustc-link-search=native={}", out.display());
        println!("cargo:rustc-link-lib=static=frameleaf_photos");
        println!("cargo:rustc-link-lib=framework=Photos");
        println!("cargo:rustc-link-lib=framework=Foundation");
    }
    tauri_build::try_build(tauri_build::Attributes::new().app_manifest(
        tauri_build::AppManifest::new().commands(&[
            "open_local_photos",
            "authorize_local_manager",
            "installed_local_hosts",
            "local_host_status",
            "prepare_local_host",
            "cancel_local_host_start",
            "stop_local_host_manager",
            "connect_server",
            "restore_connection",
            "sign_out",
            "open_photos",
            "worker_setup_status",
            "prepare_models",
            "control_worker",
            "discover_onedrive",
            "choose_photo_folder",
            "choose_apple_photos",
            "approve_photo_folder",
            "photo_source_status",
            "revoke_photo_source",
            "photo_import_status",
            "prepare_photo_import",
            "control_photo_import",
            "manager_view",
            "manager_certificate_fingerprint",
            "pair_manager",
            "manager_request",
            "reauthenticate_manager",
            "disconnect_manager",
        ]),
    ))
    .expect("build desktop ACL");
}
