use cap_std::{ambient_authority, fs::Dir};
use serde::Serialize;
use std::{collections::VecDeque, path::Path};

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FolderInventory {
    pub path: String,
    pub photos: u64,
    pub logical_bytes: u64,
    pub skipped: u64,
    pub truncated: bool,
}

/// A bounded metadata preview, never a content read or a persistent source grant.
pub fn inventory(root: &Path, limit: usize) -> Result<FolderInventory, String> {
    if !root.is_absolute() || root.parent().is_none() || limit == 0 || limit > 10_000 {
        return Err("source_folder_invalid".into());
    }
    if root.components().any(|part| {
        let value = part.as_os_str().to_string_lossy().to_lowercase();
        [".photoslibrary", ".photolibrary", ".app", ".bundle"]
            .iter()
            .any(|suffix| value.ends_with(suffix))
    }) {
        return Err("source_package_requires_provider".into());
    }
    crate::native_runtime::absolute_directory(root)?;
    let home = std::env::var_os(if cfg!(windows) { "USERPROFILE" } else { "HOME" });
    if home
        .as_ref()
        .is_some_and(|home| covers_home(root, Path::new(home)))
    {
        return Err("source_choose_photo_subfolder".into());
    }
    let dir = Dir::open_ambient_dir(root, ambient_authority())
        .map_err(|_| "source_folder_unavailable")?;
    let mut result = FolderInventory {
        path: root.to_str().ok_or("source_folder_name_invalid")?.into(),
        photos: 0,
        logical_bytes: 0,
        skipped: 0,
        truncated: false,
    };
    let mut pending = VecDeque::from([(dir, 0usize)]);
    let mut visited = 0;
    while let Some((dir, depth)) = pending.pop_front() {
        let entries = match dir.entries() {
            Ok(entries) => entries,
            Err(_) => {
                result.skipped += 1;
                continue;
            }
        };
        for entry in entries {
            if visited == limit {
                result.truncated = true;
                return Ok(result);
            }
            visited += 1;
            let entry = match entry {
                Ok(entry) => entry,
                Err(_) => {
                    result.skipped += 1;
                    continue;
                }
            };
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                result.skipped += 1;
                continue;
            };
            let lower = name.to_lowercase();
            if name.starts_with('.')
                || [".photoslibrary", ".photolibrary", ".app", ".bundle"]
                    .iter()
                    .any(|suffix| lower.ends_with(suffix))
            {
                result.skipped += 1;
                continue;
            }
            let meta = match dir.symlink_metadata(name) {
                Ok(meta) => meta,
                Err(_) => {
                    result.skipped += 1;
                    continue;
                }
            };
            if meta.is_symlink() {
                result.skipped += 1;
                continue;
            }
            if meta.is_dir() {
                if depth == 16 || pending.len() == 256 {
                    result.truncated = true;
                    result.skipped += 1;
                    continue;
                }
                match dir.open_dir(name) {
                    Ok(child) => pending.push_back((child, depth + 1)),
                    Err(_) => result.skipped += 1,
                }
            } else if meta.is_file() && is_media_filename(name) {
                result.photos += 1;
                result.logical_bytes = result
                    .logical_bytes
                    .checked_add(meta.len())
                    .ok_or("source_inventory_size_invalid")?;
            }
        }
    }
    Ok(result)
}

#[derive(Debug, Serialize)]
pub struct RootHint {
    pub label: String,
    pub path: String,
}

pub fn known_onedrive_roots(home: &Path, supplied: &[std::path::PathBuf]) -> Vec<RootHint> {
    let mut candidates = supplied.to_vec();
    #[cfg(target_os = "macos")]
    if let Ok(entries) = std::fs::read_dir(home.join("Library/CloudStorage")) {
        candidates.extend(
            entries
                .take(100)
                .filter_map(Result::ok)
                .filter(|entry| entry.file_name().to_string_lossy().starts_with("OneDrive-"))
                .map(|entry| entry.path()),
        );
    }
    #[cfg(not(target_os = "macos"))]
    let _ = home;
    candidates.sort();
    candidates.dedup();
    let mut result: Vec<RootHint> = Vec::new();
    for path in candidates {
        if result.len() == 16 {
            break;
        }
        if !path.is_absolute() || crate::native_runtime::absolute_directory(&path).is_err() {
            continue;
        }
        if result
            .iter()
            .any(|entry| path.starts_with(&entry.path) || Path::new(&entry.path).starts_with(&path))
        {
            continue;
        }
        if let (Some(label), Some(path)) =
            (path.file_name().and_then(|v| v.to_str()), path.to_str())
        {
            result.push(RootHint {
                label: label.into(),
                path: path.into(),
            });
        }
    }
    result
}

pub(crate) fn is_media_filename(name: &str) -> bool {
    matches!(
        name.to_lowercase().rsplit('.').next(),
        Some(
            "jpg"
                | "jpeg"
                | "heic"
                | "heif"
                | "png"
                | "gif"
                | "webp"
                | "avif"
                | "tif"
                | "tiff"
                | "dng"
                | "cr2"
                | "cr3"
                | "nef"
                | "arw"
                | "raf"
                | "orf"
                | "rw2"
                | "mp4"
                | "mov"
                | "m4v"
        )
    )
}

fn covers_home(root: &Path, home: &Path) -> bool {
    home.starts_with(root) || std::fs::canonicalize(home).is_ok_and(|home| home.starts_with(root))
}

#[cfg(test)]
mod root_tests {
    #[cfg(unix)]
    #[test]
    fn home_directory_alias_does_not_allow_a_whole_home_scan() {
        let parent =
            std::env::temp_dir().join(format!("frameleaf-home-scope-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&parent).unwrap();
        let actual = parent.join("actual-home");
        std::fs::create_dir(&actual).unwrap();
        let actual = std::fs::canonicalize(actual).unwrap();
        let alias = parent.join("home-alias");
        std::os::unix::fs::symlink(&actual, &alias).unwrap();
        assert!(super::covers_home(&actual, &alias));
        assert!(!super::covers_home(&actual.join("Photos"), &alias));
        std::fs::remove_dir_all(parent).unwrap();
    }
}
