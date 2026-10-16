fn main() {
    tauri_build::try_build(tauri_build::Attributes::new().app_manifest(
        tauri_build::AppManifest::new().commands(&[
            "connect_server",
            "restore_connection",
            "sign_out",
            "open_photos",
            "worker_setup_status",
            "prepare_models",
            "control_worker",
            "discover_onedrive",
            "choose_photo_folder",
            "approve_photo_folder",
            "photo_source_status",
            "revoke_photo_source",
            "photo_import_status",
            "prepare_photo_import",
            "control_photo_import",
        ]),
    ))
    .expect("build desktop ACL");
}
