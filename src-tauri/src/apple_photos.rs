//! Bounded read-only PhotoKit selection. Identifiers remain local and inside signed approvals.
use serde::{Deserialize, Serialize};

pub(crate) fn admitted_bytes(used: u64, next: usize, maximum: u64) -> Result<u64, String> {
    used.checked_add(next as u64)
        .filter(|total| *total <= maximum)
        .ok_or_else(|| "photos_export_budget_exceeded".into())
}
pub(crate) const RESOURCE_CEILING: u64 = 2 * 1024 * 1024 * 1024;
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Resource {
    asset: String,
    created: i64,
    modified: i64,
    index: u32,
    kind: u32,
    filename: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Selection {
    pub assets: u32,
    #[serde(default)]
    pub allow_hydration: bool,
    pub resources: Vec<Resource>,
}
impl Selection {
    pub fn validate(&self) -> Result<(), String> {
        if self.assets == 0
            || self.assets > 100
            || self.resources.is_empty()
            || self.resources.len() > 100
        {
            return Err("photos_scope_invalid".into());
        }
        let mut seen = std::collections::HashSet::new();
        let mut assets = std::collections::HashSet::new();
        for r in &self.resources {
            if r.asset.is_empty()
                || r.asset.len() > 1024
                || r.index > 100
                || !matches!(r.kind, 1 | 2 | 4 | 9)
                || r.filename.len() > 255
                || r.filename.starts_with('.')
                || r.filename.contains(['/', '\\'])
                || r.filename.chars().any(char::is_control)
                || !crate::photo_sources::is_media_filename(&r.filename)
                || !seen.insert((&r.asset, r.index))
            {
                return Err("photos_original_resources_unavailable".into());
            }
            assets.insert(&r.asset);
        }
        if assets.len() != self.assets as usize {
            return Err("photos_scope_invalid".into());
        }
        Ok(())
    }
    // Synthetic directory names distinguish resources with the same original filename.
    pub fn files(&self) -> Result<Vec<crate::photo_sources::SourceFile>, String> {
        self.validate()?;
        Ok(self
            .resources
            .iter()
            .enumerate()
            .map(|(i, r)| crate::photo_sources::SourceFile {
                relative: format!("{i}/{}", r.filename),
                bytes: RESOURCE_CEILING,
            })
            .collect())
    }
    pub fn resource(&self, relative: &str) -> Result<&Resource, String> {
        self.files()?
            .iter()
            .position(|f| f.relative == relative)
            .and_then(|i| self.resources.get(i))
            .ok_or_else(|| "photos_scope_changed".into())
    }
}
#[cfg(target_os = "macos")]
unsafe extern "C" {
    fn fl_photos_preview(count: u32) -> *mut std::ffi::c_char;
    fn fl_photos_authorized() -> bool;
    fn fl_photos_current(description: *const std::ffi::c_char) -> i32;
    fn fl_photos_export(
        description: *const std::ffi::c_char,
        allow_hydration: bool,
        sink: extern "C" fn(*mut std::ffi::c_void, *const u8, usize) -> bool,
        context: *mut std::ffi::c_void,
    ) -> i32;
}
pub(crate) fn authorized() -> Result<(), String> {
    #[cfg(target_os = "macos")]
    if unsafe { fl_photos_authorized() } {
        return Ok(());
    }
    Err(if cfg!(target_os = "macos") {
        "photos_permission_required"
    } else {
        "photos_macos_required"
    }
    .into())
}
pub(crate) fn validate_current(resource: &Resource) -> Result<(), String> {
    #[cfg(target_os = "macos")]
    {
        let description = std::ffi::CString::new(
            serde_json::to_string(resource).map_err(|_| "photos_metadata_invalid")?,
        )
        .map_err(|_| "photos_metadata_invalid")?;
        match unsafe { fl_photos_current(description.as_ptr()) } {
            0 => Ok(()),
            1 => Err("photos_permission_required".into()),
            _ => Err("photos_scope_changed".into()),
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = resource;
        Err("photos_macos_required".into())
    }
}
pub(crate) fn preview(count: u32) -> Result<Selection, String> {
    if !(1..=100).contains(&count) {
        return Err("photos_scope_invalid".into());
    }
    #[cfg(target_os = "macos")]
    {
        let raw = unsafe { fl_photos_preview(count) };
        if raw.is_null() {
            return Err("photos_metadata_invalid".into());
        }
        let bytes = unsafe { std::ffi::CStr::from_ptr(raw) }.to_bytes().to_vec();
        unsafe { libc::free(raw.cast()) };
        let value: serde_json::Value =
            serde_json::from_slice(&bytes).map_err(|_| "photos_metadata_invalid")?;
        if let Some(code) = value["error"].as_str() {
            return Err(code.into());
        }
        let selection: Selection =
            serde_json::from_value(value).map_err(|_| "photos_metadata_invalid")?;
        selection.validate()?;
        Ok(selection)
    }
    #[cfg(not(target_os = "macos"))]
    Err("photos_macos_required".into())
}
// The callback is synchronous with bridge lifetime and never unwinds across C/Objective-C.
#[cfg(target_os = "macos")]
pub(crate) fn export(
    resource: &Resource,
    allow_hydration: bool,
    write: &mut dyn FnMut(&[u8]) -> Result<(), String>,
) -> Result<(), String> {
    struct Sink<'a> {
        write: &'a mut dyn FnMut(&[u8]) -> Result<(), String>,
        error: Option<String>,
    }
    extern "C" fn receive(context: *mut std::ffi::c_void, data: *const u8, count: usize) -> bool {
        let sink = unsafe { &mut *context.cast::<Sink<'_>>() };
        if sink.error.is_some() {
            return false;
        }
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let chunk = if count == 0 {
                &[]
            } else {
                unsafe { std::slice::from_raw_parts(data, count) }
            };
            (sink.write)(chunk)
        }))
        .unwrap_or_else(|_| Err("photos_export_interrupted".into()));
        if let Err(error) = result {
            sink.error = Some(error);
            return false;
        }
        true
    }
    let description = std::ffi::CString::new(
        serde_json::to_string(resource).map_err(|_| "photos_metadata_invalid")?,
    )
    .map_err(|_| "photos_metadata_invalid")?;
    let mut sink = Sink { write, error: None };
    let status = unsafe {
        fl_photos_export(
            description.as_ptr(),
            allow_hydration,
            receive,
            (&mut sink as *mut Sink<'_>).cast(),
        )
    };
    if let Some(error) = sink.error {
        return Err(error);
    }
    match status {
        0 => Ok(()),
        1 => Err("photos_permission_required".into()),
        2 => Err("photos_scope_changed".into()),
        _ => Err("photos_original_unavailable".into()),
    }
}
#[cfg(not(target_os = "macos"))]
pub(crate) fn export(
    _: &Resource,
    _: bool,
    _: &mut dyn FnMut(&[u8]) -> Result<(), String>,
) -> Result<(), String> {
    Err("photos_macos_required".into())
}
impl Resource {
    pub fn created(&self) -> i64 {
        self.created
    }
    pub fn modified(&self) -> i64 {
        self.modified
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn selection() -> Selection {
        Selection {
            assets: 1,
            allow_hydration: false,
            resources: vec![
                Resource {
                    asset: "synthetic-id".into(),
                    created: 1000,
                    modified: 1234,
                    index: 0,
                    kind: 1,
                    filename: "IMG_001.HEIC".into(),
                },
                Resource {
                    asset: "synthetic-id".into(),
                    created: 1000,
                    modified: 1234,
                    index: 1,
                    kind: 9,
                    filename: "IMG_001.MOV".into(),
                },
            ],
        }
    }
    #[test]
    fn preserves_paired_resources_and_rejects_unsafe_or_unknown_originals() {
        let mut s = selection();
        assert_eq!(s.resources[0].created(), 1000);
        assert_eq!(s.resources[0].modified(), 1234);
        let files = s.files().unwrap();
        assert_eq!(files.len(), 2);
        assert_eq!(files[1].relative, "1/IMG_001.MOV");
        assert_eq!(files[0].bytes, RESOURCE_CEILING);
        assert!(s.resource("synthetic-id/IMG_001.MOV").is_err());
        s.resources[1].filename = "../escape.mov".into();
        assert!(s.validate().is_err());
        s = selection();
        s.resources[1].kind = 5;
        assert!(s.validate().is_err());
        s = selection();
        s.resources[1].index = 0;
        assert!(s.validate().is_err());
        s = selection();
        s.assets = 2;
        assert!(s.validate().is_err());
    }
    #[test]
    fn mocked_stream_stops_before_oversize_or_policy_denied_bytes_are_written() {
        let mut written = Vec::new();
        let mut used = 0;
        let mut append = |chunk: &[u8], allowed: bool| -> Result<(), String> {
            if !allowed {
                return Err("metered_network".into());
            }
            let next = admitted_bytes(used, chunk.len(), 6)?;
            written.extend_from_slice(chunk);
            used = next;
            Ok(())
        };
        append(b"RAW", true).unwrap();
        assert_eq!(
            append(b"-too-big", true).unwrap_err(),
            "photos_export_budget_exceeded"
        );
        assert_eq!(append(b"MOV", false).unwrap_err(), "metered_network");
        append(b"MOV", true).unwrap();
        assert_eq!(used, 6);
        assert_eq!(written, b"RAWMOV");
        assert!(admitted_bytes(u64::MAX, 1, u64::MAX).is_err());
    }
    #[test]
    fn invalid_scope_never_requests_permission() {
        assert!(preview(0).is_err());
        assert!(preview(101).is_err());
    }
    #[cfg(not(target_os = "macos"))]
    #[test]
    fn nonmacos_provider_fails_closed() {
        assert_eq!(authorized().unwrap_err(), "photos_macos_required");
    }
}
