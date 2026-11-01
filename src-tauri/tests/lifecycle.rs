use frameleaf_desktop::connection::{persist_server_identity, SavedConnection};
use frameleaf_desktop::lifecycle::finish_sign_out;
use std::cell::Cell;

fn saved() -> SavedConnection {
    SavedConnection {
        server: "https://nas.example/".into(),
        server_id: String::new(),
        account_id: "account".into(),
        name: "Name".into(),
        token: "photo-token".into(),
        device_name: "Mac".into(),
        mode: "client-worker".into(),
        device_id: None,
    }
}
#[test]
fn server_pin_survives_failed_enrollment_and_refuses_a_replacement_on_restart() {
    let mut connection = saved();
    let mut stored = String::new();
    persist_server_identity(&mut connection, "server-one", |value| {
        stored = serde_json::to_string(value).unwrap();
        Ok(())
    })
    .unwrap();
    // Enrollment/network failure occurs after this checkpoint; restart reads only the checkpoint.
    let mut restarted: SavedConnection = serde_json::from_str(&stored).unwrap();
    assert_eq!(restarted.server_id, "server-one");
    assert!(persist_server_identity(&mut restarted, "server-two", |_| Ok(())).is_err());
}
#[test]
fn failed_pin_persistence_refuses_preparation() {
    assert!(persist_server_identity(&mut saved(), "server-one", |_| Err("locked".into())).is_err());
}
#[test]
fn photo_cleanup_failure_still_runs_server_sign_out_and_is_reported() {
    let remote_called = Cell::new(false);
    let result =
        tauri::async_runtime::block_on(finish_sign_out(async { true }, async { false }, async {
            remote_called.set(true);
            true
        }));
    assert!(remote_called.get());
    assert!(result.local_cleared);
    assert!(!result.photos_cleared);
    assert!(result.remote_revoked);
}
#[test]
fn failed_remote_revoke_cannot_be_reported_as_confirmed() {
    let result =
        tauri::async_runtime::block_on(finish_sign_out(async { true }, async { true }, async {
            false
        }));
    assert!(!result.remote_revoked);
}
