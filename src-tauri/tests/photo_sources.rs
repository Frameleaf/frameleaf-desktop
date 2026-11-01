use frameleaf_desktop::photo_sources::inventory;
use std::{fs, path::PathBuf};
struct Folder(PathBuf);
impl Folder {
    fn new() -> Self {
        let p = std::env::temp_dir().join(format!("frameleaf-folder-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&p).unwrap();
        Self(fs::canonicalize(p).unwrap())
    }
}
impl Drop for Folder {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
#[test]
fn counts_metadata_in_selected_scope_and_bounds_inventory() {
    let root = Folder::new();
    fs::create_dir(root.0.join("旅行")).unwrap();
    fs::write(root.0.join("旅行/photo.HEIC"), b"not opened or decoded").unwrap();
    fs::write(root.0.join("notes.txt"), b"not media").unwrap();
    let result = inventory(&root.0, 10).unwrap();
    assert_eq!(result.photos, 1);
    assert!(!result.truncated);
    assert!(inventory(&root.0, 1).unwrap().truncated);
}
#[cfg(unix)]
#[test]
fn never_follows_links_out_of_selected_folder_or_into_packages() {
    let root = Folder::new();
    let outside = Folder::new();
    fs::write(outside.0.join("private.jpg"), b"outside").unwrap();
    std::os::unix::fs::symlink(&outside.0, root.0.join("escape")).unwrap();
    fs::create_dir(root.0.join("Library.photoslibrary")).unwrap();
    fs::write(
        root.0.join("Library.photoslibrary/original.jpg"),
        b"private package",
    )
    .unwrap();
    let result = inventory(&root.0, 100).unwrap();
    assert_eq!(result.photos, 0);
    assert_eq!(result.skipped, 2);
    assert!(inventory(&root.0.join("escape"), 100).is_err());
}
#[test]
fn refuses_files_and_filesystem_roots() {
    let root = Folder::new();
    fs::write(root.0.join("photo.jpg"), b"fixture").unwrap();
    assert!(inventory(&root.0.join("photo.jpg"), 10).is_err());
    let volume = root.0.ancestors().last().unwrap();
    assert!(inventory(volume, 10).is_err());
}

#[test]
fn discovers_relocated_accounts_without_opening_or_scanning_contents() {
    let root = Folder::new();
    let personal = root.0.join("Personal Photos");
    let work = root.0.join("Work OneDrive");
    fs::create_dir(&personal).unwrap();
    fs::create_dir(&work).unwrap();
    let roots = frameleaf_desktop::photo_sources::known_onedrive_roots(
        &root.0,
        &[personal.clone(), work, personal],
    );
    assert_eq!(roots.len(), 2);
}
#[test]
fn rejects_selected_apple_packages_and_their_internal_originals() {
    let root = Folder::new();
    let package = root.0.join("Photos.photoslibrary");
    fs::create_dir(&package).unwrap();
    let originals = package.join("originals");
    fs::create_dir(&originals).unwrap();
    assert!(inventory(&package, 10).is_err());
    assert!(inventory(&originals, 10).is_err());
}

#[cfg(unix)]
#[test]
fn metadata_preview_does_not_need_read_permission_for_photo_content() {
    use std::os::unix::fs::PermissionsExt;
    let root = Folder::new();
    let file = root.0.join("cloud-placeholder.jpg");
    fs::write(&file, b"private fixture bytes").unwrap();
    fs::set_permissions(&file, fs::Permissions::from_mode(0o000)).unwrap();
    assert!(fs::File::open(&file).is_err());
    assert_eq!(inventory(&root.0, 10).unwrap().photos, 1);
}
