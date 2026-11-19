use frameleaf_desktop::{
    connection::{DeviceIdentity, SavedConnection},
    copy_source::CopyApproval,
};
use std::{fs, path::PathBuf, sync::atomic::AtomicBool};
struct Folder(PathBuf);
impl Folder {
    fn new() -> Self {
        let p = std::env::temp_dir().join(format!("frameleaf-copy-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&p).unwrap();
        Self(fs::canonicalize(p).unwrap())
    }
}
impl Drop for Folder {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn saved() -> SavedConnection {
    SavedConnection {
        server: "https://synthetic.test/".into(),
        server_id: "server".into(),
        account_id: "owner".into(),
        name: "Synthetic".into(),
        token: "not-persisted".into(),
        device_name: "Fixture".into(),
        mode: "client-worker".into(),
        device_id: Some("device".into()),
    }
}
#[test]
fn stages_an_independent_verified_copy_and_preserves_source_bytes() {
    let source = Folder::new();
    let stage = Folder::new();
    let identity = DeviceIdentity::generate();
    let saved = saved();
    fs::create_dir(source.0.join("旅行")).unwrap();
    fs::write(source.0.join("旅行/photo.jpg"), b"approved original").unwrap();
    let approval = CopyApproval::approve(&saved, &identity, &source.0, 1024, true).unwrap();
    let bytes = serde_json::to_vec(&approval).unwrap();
    assert!(!String::from_utf8_lossy(&bytes).contains("not-persisted"));
    let restored: CopyApproval = serde_json::from_slice(&bytes).unwrap();
    let copied = restored
        .stage(
            &saved,
            &identity,
            "旅行/photo.jpg",
            &stage.0,
            &AtomicBool::new(false),
        )
        .unwrap();
    assert_eq!(copied.bytes, 17);
    copied.verify(&saved, &identity, &stage.0).unwrap();
    assert_eq!(
        fs::read(source.0.join("旅行/photo.jpg")).unwrap(),
        b"approved original"
    );
    fs::remove_file(source.0.join("旅行/photo.jpg")).unwrap();
    copied.verify(&saved, &identity, &stage.0).unwrap();
    fs::write(stage.0.join(&copied.id).join("original"), b"changed").unwrap();
    assert!(copied.verify(&saved, &identity, &stage.0).is_err());
}
#[test]
fn approval_is_bound_to_account_device_server_and_immutable_scope() {
    let source = Folder::new();
    let stage = Folder::new();
    let identity = DeviceIdentity::generate();
    let original = saved();
    let approval = CopyApproval::approve(&original, &identity, &source.0, 1024, true).unwrap();
    for field in ["server", "server_id", "account_id", "device_id"] {
        let mut changed = saved();
        match field {
            "server" => changed.server = "https://other.test/".into(),
            "server_id" => changed.server_id = "other-server".into(),
            "account_id" => changed.account_id = "other-owner".into(),
            _ => changed.device_id = Some("other-device".into()),
        }
        assert_eq!(
            approval
                .stage(
                    &changed,
                    &identity,
                    "missing.jpg",
                    &stage.0,
                    &AtomicBool::new(false)
                )
                .err()
                .as_deref(),
            Some("source_approval_invalid")
        );
    }
    let mut value = serde_json::to_value(&approval).unwrap();
    value["scope"]["maxItemBytes"] = serde_json::json!(4096);
    let forged: CopyApproval = serde_json::from_value(value).unwrap();
    assert_eq!(
        forged
            .stage(
                &original,
                &identity,
                "missing.jpg",
                &stage.0,
                &AtomicBool::new(false)
            )
            .err()
            .as_deref(),
        Some("source_approval_invalid")
    );
}

#[test]
fn refuses_unapproved_downloads_budgets_and_cancellation_before_copying() {
    let source = Folder::new();
    let stage = Folder::new();
    let identity = DeviceIdentity::generate();
    let saved = saved();
    fs::write(source.0.join("photo.jpg"), b"original").unwrap();
    for (budget, downloads, cancel, reason) in [
        (1024, false, false, "source_download_permission_required"),
        (3, true, false, "source_copy_budget_exceeded"),
        (1024, true, true, "source_copy_cancelled"),
    ] {
        let approval =
            CopyApproval::approve(&saved, &identity, &source.0, budget, downloads).unwrap();
        assert_eq!(
            approval
                .stage(
                    &saved,
                    &identity,
                    "photo.jpg",
                    &stage.0,
                    &AtomicBool::new(cancel)
                )
                .err()
                .as_deref(),
            Some(reason)
        );
        assert_eq!(fs::read_dir(&stage.0).unwrap().count(), 0);
    }
}
#[cfg(unix)]
#[test]
fn refuses_links_traversal_and_replaced_approved_roots() {
    let source = Folder::new();
    let outside = Folder::new();
    let stage = Folder::new();
    let identity = DeviceIdentity::generate();
    let saved = saved();
    fs::write(outside.0.join("private.jpg"), b"outside").unwrap();
    std::os::unix::fs::symlink(outside.0.join("private.jpg"), source.0.join("link.jpg")).unwrap();
    let approval = CopyApproval::approve(&saved, &identity, &source.0, 1024, true).unwrap();
    for relative in ["../private.jpg", "/private.jpg", "link.jpg"] {
        assert!(approval
            .stage(
                &saved,
                &identity,
                relative,
                &stage.0,
                &AtomicBool::new(false)
            )
            .is_err());
    }
    let previous = source.0.with_extension("replaced");
    fs::rename(&source.0, &previous).unwrap();
    fs::create_dir(&source.0).unwrap();
    assert_eq!(
        approval
            .stage(
                &saved,
                &identity,
                "missing.jpg",
                &stage.0,
                &AtomicBool::new(false)
            )
            .err()
            .as_deref(),
        Some("source_root_changed")
    );
    fs::remove_dir_all(previous).unwrap();
}

#[cfg(unix)]
#[test]
fn a_staged_original_must_not_be_replaced_by_a_link_even_to_matching_bytes() {
    let source = Folder::new();
    let stage = Folder::new();
    let identity = DeviceIdentity::generate();
    let saved = saved();
    fs::write(source.0.join("photo.jpg"), b"original").unwrap();
    let approval = CopyApproval::approve(&saved, &identity, &source.0, 1024, true).unwrap();
    let copy = approval
        .stage(
            &saved,
            &identity,
            "photo.jpg",
            &stage.0,
            &AtomicBool::new(false),
        )
        .unwrap();
    let original = stage.0.join(&copy.id).join("original");
    fs::rename(&original, original.with_file_name("same-bytes")).unwrap();
    std::os::unix::fs::symlink("same-bytes", &original).unwrap();
    assert!(copy.verify(&saved, &identity, &stage.0).is_err());
}

#[test]
fn a_photo_copy_approval_does_not_authorize_other_documents() {
    let source = Folder::new();
    let stage = Folder::new();
    let identity = DeviceIdentity::generate();
    let saved = saved();
    fs::write(source.0.join("private.txt"), b"not a selected media file").unwrap();
    let approval = CopyApproval::approve(&saved, &identity, &source.0, 1024, true).unwrap();
    assert_eq!(
        approval
            .stage(
                &saved,
                &identity,
                "private.txt",
                &stage.0,
                &AtomicBool::new(false)
            )
            .err()
            .as_deref(),
        Some("source_item_invalid")
    );
    assert_eq!(fs::read_dir(&stage.0).unwrap().count(), 0);
}

#[test]
fn restores_a_receipt_after_restart_without_trusting_mutated_journal_fields() {
    let source = Folder::new();
    let stage = Folder::new();
    let identity = DeviceIdentity::generate();
    let saved = saved();
    fs::write(source.0.join("photo.jpg"), b"original").unwrap();
    let approval = CopyApproval::approve(&saved, &identity, &source.0, 1024, true).unwrap();
    let copy = approval
        .stage(
            &saved,
            &identity,
            "photo.jpg",
            &stage.0,
            &AtomicBool::new(false),
        )
        .unwrap();
    let restored =
        frameleaf_desktop::copy_source::StagedCopy::restore(&saved, &identity, &stage.0, &copy.id)
            .unwrap();
    assert_eq!(restored.sha256, copy.sha256);
    let path = stage.0.join(&copy.id).join("receipt.json");
    let mut receipt: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    receipt["bytes"] = serde_json::json!(1);
    fs::write(path, serde_json::to_vec(&receipt).unwrap()).unwrap();
    assert!(frameleaf_desktop::copy_source::StagedCopy::restore(
        &saved, &identity, &stage.0, &copy.id
    )
    .is_err());
}

#[cfg(unix)]
#[test]
fn linked_parent_cannot_bypass_hidden_folder_exclusions() {
    let source = Folder::new();
    let stage = Folder::new();
    let identity = DeviceIdentity::generate();
    let saved = saved();
    fs::create_dir(source.0.join(".hidden")).unwrap();
    fs::write(source.0.join(".hidden/private.jpg"), b"private").unwrap();
    std::os::unix::fs::symlink(".hidden", source.0.join("gallery")).unwrap();
    let approval = CopyApproval::approve(&saved, &identity, &source.0, 1024, true).unwrap();
    assert!(approval
        .stage(
            &saved,
            &identity,
            "gallery/private.jpg",
            &stage.0,
            &AtomicBool::new(false)
        )
        .is_err());
    assert_eq!(fs::read_dir(&stage.0).unwrap().count(), 0);
}

#[test]
fn staging_retains_old_filesystem_dates_when_the_original_is_removed() {
    let source = Folder::new();
    let stage = Folder::new();
    let identity = DeviceIdentity::generate();
    let saved = saved();
    let path = source.0.join("photo.jpg");
    fs::write(&path, b"original").unwrap();
    let modified = std::time::UNIX_EPOCH - std::time::Duration::from_secs(86_400);
    fs::File::options()
        .write(true)
        .open(&path)
        .unwrap()
        .set_times(fs::FileTimes::new().set_modified(modified))
        .unwrap();
    let approval = CopyApproval::approve(&saved, &identity, &source.0, 1024, true).unwrap();
    let copy = approval
        .stage(
            &saved,
            &identity,
            "photo.jpg",
            &stage.0,
            &AtomicBool::new(false),
        )
        .unwrap();
    fs::remove_file(path).unwrap();
    let restored =
        frameleaf_desktop::copy_source::StagedCopy::restore(&saved, &identity, &stage.0, &copy.id)
            .unwrap();
    assert_eq!(restored.file_modified_at_ms, -86_400_000);
}

#[test]
fn approvals_have_no_per_file_ceiling_and_survive_a_signed_round_trip() {
    let source = Folder::new();
    let stage = Folder::new();
    let identity = DeviceIdentity::generate();
    let saved = saved();
    fs::write(source.0.join("movie.mov"), b"large enough").unwrap();
    for max in [3 * 1024 * 1024 * 1024, (1u64 << 53) - 1] {
        let approval = CopyApproval::approve(&saved, &identity, &source.0, max, true).unwrap();
        let restored: CopyApproval =
            serde_json::from_slice(&serde_json::to_vec(&approval).unwrap()).unwrap();
        restored
            .stage(
                &saved,
                &identity,
                "movie.mov",
                &stage.0,
                &AtomicBool::new(false),
            )
            .unwrap();
    }
}

#[test]
fn approvals_refuse_limits_beyond_exact_canonical_signing() {
    let source = Folder::new();
    let stage = Folder::new();
    let identity = DeviceIdentity::generate();
    let saved = saved();
    fs::write(source.0.join("movie.mov"), b"large enough").unwrap();
    assert!(CopyApproval::approve(&saved, &identity, &source.0, 1 << 53, true).is_err());
    // 2 GiB is reserved for approvals signed before FL-1268, which no longer cap files.
    assert!(CopyApproval::approve(&saved, &identity, &source.0, 2 << 30, true).is_err());
    let approval =
        CopyApproval::approve(&saved, &identity, &source.0, (1u64 << 53) - 1, true).unwrap();
    let mut value = serde_json::to_value(&approval).unwrap();
    value["scope"]["maxItemBytes"] = serde_json::json!(u64::MAX);
    let forged: CopyApproval = serde_json::from_value(value).unwrap();
    assert_eq!(
        forged
            .stage(
                &saved,
                &identity,
                "movie.mov",
                &stage.0,
                &AtomicBool::new(false)
            )
            .err()
            .as_deref(),
        Some("source_approval_invalid")
    );
}
