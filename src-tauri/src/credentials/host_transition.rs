//! One authority transaction; database and recovery policy belong to the guarded caller.
use super::*;
use crate::host_runtime::VerifiedHostRuntime;
fn unchanged(expected: &DeviceIdentity, actual: &DeviceIdentity) -> Result<(), String> {
    let before =
        Zeroizing::new(serde_json::to_vec(expected).map_err(|_| "host_epoch_record_invalid")?);
    let after =
        Zeroizing::new(serde_json::to_vec(actual).map_err(|_| "host_epoch_record_invalid")?);
    if *before != *after {
        return Err("host_epoch_persistence_unconfirmed".into());
    }
    Ok(())
}
pub(super) fn transition_host_with(
    installation_id: &str,
    [source, target]: [&VerifiedHostRuntime; 2],
    mut load: impl FnMut() -> Result<Option<DeviceIdentity>, String>,
    mut anchor: impl FnMut() -> Result<Option<String>, String>,
    save: impl FnOnce(&DeviceIdentity) -> Result<(), String>,
    prepare: &mut dyn FnMut() -> Result<(), String>,
    publish: &mut dyn FnMut() -> Result<(), String>,
) -> Result<(), String> {
    let mut identity = host_identity_with(&mut load, &mut anchor)?;
    if identity.installation_id != installation_id {
        return Err("host_epoch_identity_changed".into());
    }
    identity
        .host_epochs
        .as_ref()
        .ok_or("host_epoch_recovery_required")?
        .require_admitted(source)?;
    if target.epoch() <= source.epoch() {
        return Err("host_update_not_newer".into());
    }
    target.check_files()?;
    prepare()?;
    let current = host_identity_with(&mut load, &mut anchor)?;
    unchanged(&identity, &current)?;
    identity
        .host_epochs
        .as_ref()
        .ok_or("host_epoch_recovery_required")?
        .require_admitted(source)?;
    identity
        .host_epochs
        .as_mut()
        .ok_or("host_epoch_recovery_required")?
        .admit(target)?;
    save(&identity)?;
    let confirmed = host_identity_with(load, anchor)?;
    unchanged(&identity, &confirmed)?;
    confirmed
        .host_epochs
        .as_ref()
        .ok_or("host_epoch_recovery_required")?
        .require_admitted(target)?;
    publish()
}
