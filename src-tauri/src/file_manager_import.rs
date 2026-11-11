//! Native file manager entry points. Only the existing import queue can approve a copy.
use tauri::{AppHandle, WebviewWindow};

#[cfg(any(windows, test))]
const IMPORT_FLAG: &str = "--import-selection";

pub(crate) fn setup(app: &AppHandle) {
    #[cfg(target_os = "macos")]
    finder::register(app);
    #[cfg(windows)]
    if let Some(selection) = windows_selection(std::env::args_os()) {
        crate::drop_import::launch_event(app, selection);
    }
    #[cfg(not(any(target_os = "macos", windows)))]
    let _ = app;
}

#[cfg(any(windows, test))]
pub(crate) fn windows_selection(
    arguments: impl IntoIterator<Item = std::ffi::OsString>,
) -> Option<crate::drop_import::FileSelection> {
    use crate::drop_import::MAX_FILES;
    use std::path::PathBuf;

    let mut arguments = arguments.into_iter().skip(1);
    if arguments.next().as_deref() != Some(std::ffi::OsStr::new(IMPORT_FLAG)) {
        return None;
    }
    let paths: Vec<PathBuf> = arguments.take(MAX_FILES + 1).map(PathBuf::from).collect();
    if paths.is_empty() || paths.len() > MAX_FILES {
        return Some(Err("source_drop_limit"));
    }
    if paths.iter().any(|path| {
        #[cfg(windows)]
        if !matches!(
            path.components().next(),
            Some(std::path::Component::Prefix(prefix))
                if matches!(prefix.kind(), std::path::Prefix::Disk(_) | std::path::Prefix::VerbatimDisk(_))
        ) {
            return true;
        }
        !path.is_absolute() || path.to_str().is_none_or(|text| text.contains('\u{fffd}'))
    }) {
        return Some(Err("source_item_invalid"));
    }
    Some(Ok(paths))
}

#[cfg(target_os = "macos")]
mod finder {
    use super::*;
    use crate::drop_import::{launch_event, MAX_FILES};
    use std::{
        ffi::{c_char, CStr, OsStr},
        os::unix::ffi::OsStrExt,
        path::PathBuf,
        sync::OnceLock,
    };

    static APP: OnceLock<AppHandle> = OnceLock::new();

    extern "C" {
        fn frameleaf_register_finder_service(callback: extern "C" fn(*const *const c_char, usize));
    }

    pub(super) fn register(app: &AppHandle) {
        if APP.set(app.clone()).is_ok() {
            // AppKit retains the registered provider for the life of this process.
            unsafe { frameleaf_register_finder_service(receive) };
        }
    }

    extern "C" fn receive(paths: *const *const c_char, count: usize) {
        let Some(app) = APP.get() else { return };
        let selection = if count == 0 || count > MAX_FILES {
            Err("source_drop_limit")
        } else if paths.is_null() {
            Err("source_item_invalid")
        } else {
            // AppKit owns these NUL-terminated strings until the synchronous callback returns.
            let paths = unsafe { std::slice::from_raw_parts(paths, count) };
            paths
                .iter()
                .map(|&path| {
                    if path.is_null() {
                        return Err("source_item_invalid");
                    }
                    let bytes = unsafe { CStr::from_ptr(path) }.to_bytes();
                    let path = PathBuf::from(OsStr::from_bytes(bytes));
                    path.is_absolute()
                        .then_some(path)
                        .ok_or("source_item_invalid")
                })
                .collect()
        };
        launch_event(app, selection);
    }
}

#[tauri::command]
pub(crate) async fn explorer_import_shortcut(
    window: WebviewWindow,
    enabled: Option<bool>,
) -> Result<Option<bool>, String> {
    crate::require_local(&window)?;
    #[cfg(windows)]
    {
        tauri::async_runtime::spawn_blocking(move || explorer::shortcut(enabled))
            .await
            .map_err(|_| "explorer_shortcut_unavailable")?
            .map(Some)
    }
    #[cfg(not(windows))]
    {
        let _ = enabled;
        Ok(None)
    }
}

#[cfg(windows)]
mod explorer {
    use super::IMPORT_FLAG;
    use std::{
        ffi::OsString,
        os::windows::ffi::{OsStrExt, OsStringExt},
        path::{Path, PathBuf},
    };
    use windows::{
        core::{Interface, PCWSTR},
        Win32::{
            System::Com::{
                CoCreateInstance, CoInitializeEx, CoTaskMemFree, CoUninitialize, IPersistFile,
                CLSCTX_INPROC_SERVER, COINIT_APARTMENTTHREADED, STGM_READ,
            },
            UI::Shell::{FOLDERID_SendTo, IShellLinkW, SHGetKnownFolderPath, ShellLink},
        },
    };

    const UNAVAILABLE: &str = "explorer_shortcut_unavailable";

    pub(super) fn shortcut(enabled: Option<bool>) -> Result<bool, String> {
        struct Com;
        impl Drop for Com {
            fn drop(&mut self) {
                unsafe { CoUninitialize() };
            }
        }
        unsafe { CoInitializeEx(None, COINIT_APARTMENTTHREADED) }
            .ok()
            .map_err(|_| UNAVAILABLE)?;
        let _com = Com;
        let folder = unsafe { SHGetKnownFolderPath(&FOLDERID_SendTo, Default::default(), None) }
            .map_err(|_| UNAVAILABLE)?;
        let path = unsafe { PathBuf::from(OsString::from_wide(folder.as_wide())) }
            .join("Import to Frameleaf.lnk");
        unsafe { CoTaskMemFree(Some(folder.as_ptr().cast())) };

        let link: IShellLinkW = unsafe { CoCreateInstance(&ShellLink, None, CLSCTX_INPROC_SERVER) }
            .map_err(|_| UNAVAILABLE)?;
        let file: IPersistFile = link.cast().map_err(|_| UNAVAILABLE)?;
        let exists = match std::fs::symlink_metadata(&path) {
            Ok(meta) if !meta.file_type().is_symlink() && meta.is_file() => {
                let name = wide_path(&path);
                unsafe { file.Load(PCWSTR(name.as_ptr()), STGM_READ) }
                    .map_err(|_| "explorer_shortcut_conflict")?;
                let mut args = [0; 64];
                unsafe { link.GetArguments(&mut args) }
                    .map_err(|_| "explorer_shortcut_conflict")?;
                let expected: Vec<_> = IMPORT_FLAG.encode_utf16().chain(Some(0)).collect();
                if !args.starts_with(&expected) {
                    return Err("explorer_shortcut_conflict".into());
                }
                true
            }
            Ok(_) => return Err("explorer_shortcut_conflict".into()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
            Err(_) => return Err(UNAVAILABLE.into()),
        };
        match (enabled, exists) {
            (Some(false), true) => {
                std::fs::remove_file(path).map_err(|_| UNAVAILABLE)?;
                Ok(false)
            }
            (Some(true), false) => {
                let exe = wide_path(&std::env::current_exe().map_err(|_| UNAVAILABLE)?);
                let arguments: Vec<_> = IMPORT_FLAG.encode_utf16().chain(Some(0)).collect();
                let temporary =
                    path.with_file_name(format!(".frameleaf-{}.lnk", uuid::Uuid::new_v4()));
                let from = wide_path(&temporary);
                let to = wide_path(&path);
                let result = unsafe {
                    link.SetPath(PCWSTR(exe.as_ptr()))
                        .and_then(|_| link.SetArguments(PCWSTR(arguments.as_ptr())))
                        .and_then(|_| file.Save(PCWSTR(from.as_ptr()), false))
                };
                let moved = result.is_ok()
                    && unsafe {
                        windows_sys::Win32::Storage::FileSystem::MoveFileW(
                            from.as_ptr(),
                            to.as_ptr(),
                        )
                    } != 0;
                if !moved {
                    let _ = std::fs::remove_file(temporary);
                    return Err(UNAVAILABLE.into());
                }
                Ok(true)
            }
            _ => Ok(exists),
        }
    }

    fn wide_path(path: &Path) -> Vec<u16> {
        path.as_os_str().encode_wide().chain(Some(0)).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;

    fn args<const N: usize>(items: [&str; N]) -> impl Iterator<Item = OsString> + use<'_, N> {
        items.into_iter().map(OsString::from)
    }

    #[test]
    fn only_the_explicit_import_launch_accepts_absolute_selections() {
        let folder = std::env::temp_dir();
        let photo = folder.join("photo with spaces — 東京.jpg");
        let file = photo.to_str().unwrap();
        assert!(windows_selection(args(["Frameleaf", file])).is_none());
        assert!(windows_selection(args(["Frameleaf", "--other", IMPORT_FLAG, file])).is_none());
        assert_eq!(
            windows_selection(args(["Frameleaf", IMPORT_FLAG, file])),
            Some(Ok(vec![photo]))
        );
        assert_eq!(
            windows_selection(args(["Frameleaf", IMPORT_FLAG, "--other"])),
            Some(Err("source_item_invalid"))
        );
        assert_eq!(
            windows_selection(args(["Frameleaf", IMPORT_FLAG])),
            Some(Err("source_drop_limit"))
        );
        let many = args(["Frameleaf", IMPORT_FLAG]).chain(std::iter::repeat_n(
            folder.into_os_string(),
            crate::drop_import::MAX_FILES + 1,
        ));
        assert_eq!(windows_selection(many), Some(Err("source_drop_limit")));
    }
}
