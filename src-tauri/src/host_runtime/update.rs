//! Advisory update facts only; applying or resuming must independently revalidate authority and data.
use super::*;
use crate::{
    copy_source::{opened_stamp, root_identity, staged_file, unchanged},
    host_epochs::HostExecution,
};
use cap_std::fs::Dir;
use std::io::Read;

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HostUpdateReview {
    protocol_version: u32,
    state: &'static str,
    installation_id: String,
    secure_installation_id: String,
    profile_identity: String,
    generation: uuid::Uuid,
    database_identity: String,
    from_manifest_sha256: String,
    to_manifest_sha256: String,
    from_source_revision: String,
    to_source_revision: String,
    from_epoch: u64,
    to_epoch: u64,
    postgres_version: String,
    vector_version: String,
}
#[derive(Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct HostState<'a> {
    schema_version: u32,
    manifest_sha256: &'a str,
    source_revision: &'a str,
    postgres_major: &'a str,
}
pub(super) fn host_state(
    state: &Path,
    runtime: &VerifiedHostRuntime,
    physical: &str,
) -> Result<(), String> {
    let root = Dir::from_std_file(crate::host_storage::directory(state)?);
    if format!("{:x}", Sha256::digest(root_identity(&root)?.as_bytes())) != physical {
        return Err("host_profile_identity_changed".into());
    }
    let name = Path::new("host-state.json");
    let mut file = staged_file(&root, name)?;
    crate::host_state::valid_file(
        &file
            .try_clone()
            .map_err(|_| "host_update_state_invalid")?
            .into_std(),
    )?;
    let stamp = opened_stamp(&file)?;
    let length = file
        .metadata()
        .map_err(|_| "host_update_state_invalid")?
        .len();
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(4097)
        .read_to_end(&mut bytes)
        .map_err(|_| "host_update_state_invalid")?;
    if bytes.len() > 4096 {
        return Err("host_update_state_invalid".into());
    }
    unchanged(&root, name, &file, &stamp, length, bytes.len() as u64)?;
    let expected = HostState {
        schema_version: 1,
        manifest_sha256: runtime.manifest_sha256(),
        source_revision: runtime.source_revision(),
        postgres_major: "19",
    };
    let value: HostState<'_> =
        serde_json::from_slice(&bytes).map_err(|_| "host_update_state_invalid")?;
    // The agent also binds field order; accept its canonical record, with its optional final LF.
    if value != expected
        || bytes.strip_suffix(b"\n").unwrap_or(&bytes)
            != serde_json::to_vec(&expected).map_err(|_| "host_update_state_invalid")?
    {
        return Err("host_update_state_changed".into());
    }
    Ok(())
}
fn database_roles(points: &EntryPoints) -> [&str; 10] {
    [
        &points.postgres,
        &points.initdb,
        &points.pg_dump,
        &points.pg_restore,
        &points.pg_isready,
        &points.pg_checksums,
        &points.pg_ctl,
        &points.createdb,
        &points.psql,
        &points.vector,
    ]
}
fn database_inventory(runtime: &VerifiedHostRuntime) -> impl Iterator<Item = (&str, u64, &str)> {
    runtime
        .manifest
        .files
        .iter()
        .filter(|(name, _)| name.starts_with("pg/"))
        .map(|(name, file)| (name.as_str(), file.bytes, file.sha256.as_str()))
}
impl VerifiedHostRuntime {
    pub(super) fn check_update_target(
        &self,
        target: &Self,
        installation_id: &str,
    ) -> Result<(), String> {
        if !digest_valid(installation_id, 12) {
            return Err("host_update_identity_invalid".into());
        }
        if target.manifest.epoch <= self.manifest.epoch {
            return Err("host_update_not_newer".into());
        }
        if self.manifest.platform != target.manifest.platform
            || self.manifest.architecture != target.manifest.architecture
            || self.manifest.protocol_version != target.manifest.protocol_version
        {
            return Err("host_update_runtime_incompatible".into());
        }
        if self.manifest.postgres_version != target.manifest.postgres_version
            || self.manifest.vector_version != target.manifest.vector_version
        {
            return Err("host_update_database_migration_required".into());
        }
        let roles = database_roles(&self.manifest.entry_points);
        if roles.iter().any(|path| !path.starts_with("pg/"))
            || roles != database_roles(&target.manifest.entry_points)
            || !database_inventory(self).eq(database_inventory(target))
        {
            return Err("host_update_database_component_changed".into());
        }
        Ok(())
    }
    fn update_facts(
        &self,
        target: &Self,
        owner: &mut crate::host_state::Owner,
        state: &Path,
        installation_id: &str,
        secure_id: &str,
        reserved: bool,
    ) -> Result<HostUpdateReview, String> {
        let read = |owner: &mut crate::host_state::Owner| {
            if reserved {
                owner.review_reserved_update(installation_id, self.manifest_sha256())
            } else {
                owner.review_update(installation_id, self.manifest_sha256())
            }
        };
        let (marker, database_identity) = read(owner)?;
        host_state(state, self, &marker.profile_identity)?;
        if read(owner)? != (marker.clone(), database_identity.clone()) {
            return Err("host_update_review_changed".into());
        }
        Ok(HostUpdateReview {
            protocol_version: 1,
            state: "reviewed",
            installation_id: installation_id.into(),
            secure_installation_id: secure_id.into(),
            profile_identity: marker.profile_identity,
            generation: marker.generation,
            database_identity,
            from_manifest_sha256: self.manifest_sha256().into(),
            to_manifest_sha256: target.manifest_sha256().into(),
            from_source_revision: self.source_revision().into(),
            to_source_revision: target.source_revision().into(),
            from_epoch: self.manifest.epoch,
            to_epoch: target.manifest.epoch,
            postgres_version: self.manifest.postgres_version.clone(),
            vector_version: self.manifest.vector_version.clone(),
        })
    }
    /// Initial read-only review, never an update permission or an interrupted-transaction recovery path.
    pub fn review_update(
        &self,
        target: &Self,
        state: &Path,
        installation_id: &str,
        execution: &HostExecution<'_>,
    ) -> Result<HostUpdateReview, String> {
        self.check_update_target(target, installation_id)?;
        let source = self.root.parent().ok_or("native_manager_layout_invalid")?;
        let destination = target
            .root
            .parent()
            .ok_or("native_manager_layout_invalid")?;
        crate::host_control::separate_paths(source, destination)?;
        for candidate in [source, destination] {
            crate::host_control::separate_paths(candidate, state)?;
        }
        let _source_lease = crate::package_lease::CodeLease::acquire(source)?;
        let _target_lease = crate::package_lease::CodeLease::acquire(destination)?;
        self.check_files()?;
        target.check_files()?;
        let mut review = None;
        execution.with_admitted(self, &mut || {
            let mut owner =
                crate::host_state::Owner::acquire(state, false, execution.installation_id())?;
            review = Some(self.update_facts(
                target,
                &mut owner,
                state,
                installation_id,
                execution.installation_id(),
                false,
            )?);
            Ok(())
        })?;
        target.check_files()?;
        review.ok_or_else(|| "host_update_review_failed".into())
    }
}
#[cfg(test)]
#[path = "update_tests.rs"]
mod tests;

#[path = "update_reservation.rs"]
mod reservation;
pub use reservation::HostUpdateReservation;

#[path = "update_abort.rs"]
mod abort;

// The same exact record expected by the agent, without its optional final newline.
pub(super) fn state_record(runtime: &VerifiedHostRuntime) -> Result<Vec<u8>, String> {
    serde_json::to_vec(&HostState {
        schema_version: 1,
        manifest_sha256: runtime.manifest_sha256(),
        source_revision: runtime.source_revision(),
        postgres_major: "19",
    })
    .map_err(|_| "host_update_state_invalid".into())
}

#[cfg(test)]
impl VerifiedHostRuntime {
    pub(in crate::host_runtime) fn prepare_update_qualification(
        &self,
        target: &Self,
        profiles: [&crate::manager_host::Configuration; 2],
        execution: &HostExecution<'_>,
        store: &mut impl crate::manager_profile::UpdateStore,
    ) -> Result<HostUpdateReservation, String> {
        self.update_reservation(target, profiles[0], execution, false, None, store)?;
        self.update_reservation(
            target,
            profiles[0],
            execution,
            false,
            Some(profiles[1]),
            store,
        )
    }
}
