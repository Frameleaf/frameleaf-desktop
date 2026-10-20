//! Durable identity for Manager recovery; this record never admits host execution.
use super::*;
use crate::copy_source::{opened_stamp, root_identity, staged_file, unchanged};
use cap_std::fs::Dir;
const NAME: &str = ".host-configuration.json";
#[derive(Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Record {
    schema_version: u32,
    installation_id: String,
    secure_installation_id: String,
    state_identity: String,
    manager_identity: String,
    profile_binding_sha256: String,
}
fn private(root: &Dir) -> Result<(), String> {
    #[cfg(unix)]
    {
        use cap_std::fs::MetadataExt;
        if root
            .dir_metadata()
            .map_err(|_| "native_profile_binding_changed")?
            .mode()
            & 0o077
            != 0
        {
            return Err("native_profile_binding_changed".into());
        }
    }
    #[cfg(not(unix))]
    let _ = root;
    Ok(())
}
pub(super) fn bytes(root: &Dir, name: &str, maximum: u64) -> Result<Option<Vec<u8>>, String> {
    match root.symlink_metadata(name) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Ok(_) => {}
        Err(_) => return Err("native_profile_binding_changed".into()),
    }
    let mut file = staged_file(root, Path::new(name))?;
    crate::host_state::valid_file(
        &file
            .try_clone()
            .map_err(|_| "native_profile_unavailable")?
            .into_std(),
    )?;
    let stamp = opened_stamp(&file)?;
    let length = file
        .metadata()
        .map_err(|_| "native_profile_unavailable")?
        .len();
    let mut result = Vec::new();
    Read::by_ref(&mut file)
        .take(maximum + 1)
        .read_to_end(&mut result)
        .map_err(|_| "native_profile_unavailable")?;
    if result.len() as u64 > maximum {
        return Err("native_profile_binding_changed".into());
    }
    unchanged(
        root,
        Path::new(name),
        &file,
        &stamp,
        length,
        result.len() as u64,
    )?;
    Ok(Some(result))
}
fn record(root: &Dir) -> Result<Option<Record>, String> {
    bytes(root, NAME, 4096)?
        .map(|bytes| {
            serde_json::from_slice(&bytes).map_err(|_| "native_profile_binding_changed".into())
        })
        .transpose()
}
pub(crate) fn configuration_id(
    state: &Path,
    data: &Path,
    secure_id: &str,
) -> Result<Option<String>, String> {
    if !crate::host_state::valid_installation_id(secure_id) {
        return Err("native_profile_identity_invalid".into());
    }
    #[cfg(windows)]
    let _pins = [
        crate::windows_protection::pin_private_directory(state)?,
        crate::windows_protection::pin_private_directory(data)?,
    ];
    let state = Dir::from_std_file(crate::host_storage::directory(state)?);
    let data = Dir::from_std_file(crate::host_storage::directory(data)?);
    private(&state)?;
    private(&data)?;
    crate::host_state::no_update(&state)?;
    let Some(record) = record(&data)? else {
        return Ok(None);
    };
    let marker = bytes(&data, ".host-profile", 64)?.ok_or("native_profile_recovery_required")?;
    if record.schema_version != 1
        || record.secure_installation_id != secure_id
        || !crate::native_runtime::digest_valid(&record.installation_id, 12)
        || !crate::native_runtime::digest_valid(&record.profile_binding_sha256, 64)
        || record.profile_binding_sha256.as_bytes() != marker
        || record.state_identity != root_identity(&state)?
        || record.manager_identity != root_identity(&data)?
    {
        return Err("native_profile_binding_changed".into());
    }
    Ok(Some(record.installation_id))
}
impl ProfileGuard {
    pub(crate) fn persist_configuration(
        &self,
        config: &Configuration,
        binding: &str,
    ) -> Result<(), String> {
        self.require_current(config)?;
        if !crate::native_runtime::digest_valid(binding, 64)
            || bytes(&self.data, ".host-profile", 64)?.as_deref() != Some(binding.as_bytes())
        {
            return Err("native_profile_binding_changed".into());
        }
        let expected = Record {
            schema_version: 1,
            installation_id: config.installation_id.clone(),
            secure_installation_id: config.secure_installation_id.clone(),
            state_identity: root_identity(&self.state)?,
            manager_identity: root_identity(&self.data)?,
            profile_binding_sha256: binding.into(),
        };
        if let Some(current) = record(&self.data)? {
            if current != expected {
                return Err("native_profile_binding_changed".into());
            }
        } else {
            let temporary = format!(".host-configuration-{}.tmp", uuid::Uuid::new_v4());
            let result = (|| -> Result<(), String> {
                let mut options = crate::host_state::options(true);
                options.create_new(true);
                let mut file = self
                    .data
                    .open_with(&temporary, &options)
                    .map_err(|_| "native_profile_unavailable")?
                    .into_std();
                crate::host_state::valid_file(&file)?;
                let encoded =
                    serde_json::to_vec(&expected).map_err(|_| "native_profile_unavailable")?;
                if encoded.len() > 4096 {
                    return Err("native_profile_binding_changed".into());
                }
                file.write_all(&encoded)
                    .and_then(|_| file.sync_all())
                    .map_err(|_| "native_profile_unavailable")?;
                drop(file);
                publish_marker(&self.data, &temporary, NAME)?;
                #[cfg(unix)]
                self.data
                    .try_clone()
                    .and_then(|dir| dir.into_std_file().sync_all())
                    .map_err(|_| "native_profile_unavailable")?;
                Ok(())
            })();
            let cleanup = self.data.remove_file(&temporary);
            result?;
            if cleanup.is_err_and(|e| e.kind() != std::io::ErrorKind::NotFound) {
                return Err("native_profile_unavailable".into());
            }
        }
        self.require_current(config)?;
        if configuration_id(&config.state, &config.data, &config.secure_installation_id)?.as_deref()
            != Some(config.installation_id.as_str())
        {
            return Err("native_profile_binding_changed".into());
        }
        Ok(())
    }
}

impl ProfileGuard {
    /// Caller must authenticate the selection and both credential commitments before any publication.
    pub(crate) fn update_metadata(
        &self,
        profiles: [&Configuration; 2],
        bindings: [&str; 2],
        host_records: [&[u8]; 2],
        publish: bool,
    ) -> Result<(), String> {
        use std::io::{Seek, SeekFrom};
        for config in profiles {
            self.require_current(config)?;
        }
        if !bindings
            .iter()
            .all(|binding| crate::native_runtime::digest_valid(binding, 64))
            || bindings[0] == bindings[1]
            || host_records
                .iter()
                .any(|bytes| bytes.is_empty() || bytes.len() > 4096)
        {
            return Err("native_profile_binding_changed".into());
        }
        let encode = |config: &Configuration, binding: &str| -> Result<Vec<u8>, String> {
            serde_json::to_vec(&Record {
                schema_version: 1,
                installation_id: config.installation_id.clone(),
                secure_installation_id: config.secure_installation_id.clone(),
                state_identity: root_identity(&self.state)?,
                manager_identity: root_identity(&self.data)?,
                profile_binding_sha256: binding.into(),
            })
            .map_err(|_| "native_profile_binding_changed".into())
        };
        let old_config = encode(profiles[0], bindings[0])?;
        let next_config = encode(profiles[1], bindings[1])?;
        let mut records = Vec::new();
        for (root, name, old, next, lf) in [
            (
                &self.data,
                NAME,
                old_config.as_slice(),
                next_config.as_slice(),
                false,
            ),
            (
                &self.data,
                ".host-profile",
                bindings[0].as_bytes(),
                bindings[1].as_bytes(),
                false,
            ),
            (
                &self.state,
                "host-state.json",
                host_records[0],
                host_records[1],
                true,
            ),
        ] {
            let current = bytes(root, name, 4096)?.ok_or("native_profile_binding_changed")?;
            let source = current == old || (lf && current.strip_suffix(b"\n") == Some(old));
            if !source && !next.starts_with(&current) {
                return Err("native_profile_binding_changed".into());
            }
            records.push((root, name, current, next));
        }
        if !publish {
            return Ok(());
        }
        // Preflight all records before the first write; the immutable selection authenticates each next value.
        for (root, name, current, next) in records {
            for config in profiles {
                self.require_current(config)?;
            }
            let mut options = crate::host_state::options(true);
            options.create(false);
            let mut file = root
                .open_with(name, &options)
                .map_err(|_| "native_profile_binding_changed")?;
            crate::host_state::valid_file(
                &file
                    .try_clone()
                    .map_err(|_| "native_profile_unavailable")?
                    .into_std(),
            )?;
            let stamp = opened_stamp(&file)?;
            let mut readback = Vec::new();
            Read::by_ref(&mut file)
                .take(4097)
                .read_to_end(&mut readback)
                .map_err(|_| "native_profile_unavailable")?;
            unchanged(
                root,
                Path::new(name),
                &file,
                &stamp,
                current.len() as u64,
                readback.len() as u64,
            )?;
            if readback != current {
                return Err("native_profile_binding_changed".into());
            }
            if current != next {
                file.seek(SeekFrom::Start(0))
                    .and_then(|_| file.set_len(0))
                    .and_then(|_| file.write_all(next))
                    .and_then(|_| file.sync_all())
                    .map_err(|_| "native_profile_unavailable")?;
            }
            let stamp = opened_stamp(&file)?;
            unchanged(
                root,
                Path::new(name),
                &file,
                &stamp,
                next.len() as u64,
                next.len() as u64,
            )?;
            if bytes(root, name, 4096)?.as_deref() != Some(next) {
                return Err("native_profile_binding_changed".into());
            }
        }
        for config in profiles {
            self.require_current(config)?;
        }
        Ok(())
    }
}

impl ProfileGuard {
    pub(crate) fn require_published_update_configuration(
        &self,
        config: &Configuration,
        binding: &str,
    ) -> Result<(), String> {
        self.require_current(config)?;
        let expected = Record {
            schema_version: 1,
            installation_id: config.installation_id.clone(),
            secure_installation_id: config.secure_installation_id.clone(),
            state_identity: root_identity(&self.state)?,
            manager_identity: root_identity(&self.data)?,
            profile_binding_sha256: binding.into(),
        };
        if !crate::native_runtime::digest_valid(binding, 64)
            || bytes(&self.data, ".host-profile", 64)?.as_deref() != Some(binding.as_bytes())
            || record(&self.data)?.as_ref() != Some(&expected)
        {
            return Err("native_profile_binding_changed".into());
        }
        self.require_current(config)
    }
}
