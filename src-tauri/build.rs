fn main() {
    tauri_build::try_build(tauri_build::Attributes::new().app_manifest(
        tauri_build::AppManifest::new().commands(&[
            "connect_server",
            "restore_connection",
            "sign_out",
            "open_photos",
            "worker_setup_status",
            "prepare_models",
        ]),
    ))
    .expect("build desktop ACL");
}
