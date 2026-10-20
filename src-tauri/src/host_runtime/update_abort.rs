//! Release a pre-destructive prepared update without changing data, keys or epochs.
use super::*;
use crate::manager_host::Configuration;
use crate::manager_profile::ProfileGuard;
const INVALID: &str = "host_update_abort_invalid";
impl VerifiedHostRuntime {
    /// Return to the still-admitted source; unused target credentials remain intact.
    pub fn abort_prepared_update(
        &self,
        target: &Self,
        source: &Configuration,
        destination: &Configuration,
        execution: &HostExecution<'_>,
    ) -> Result<(), String> {
        self.abort_prepared_update_with(
            target,
            [source, destination],
            execution,
            &mut crate::manager_profile::Keystore,
        )
    }
    pub(in crate::host_runtime) fn abort_prepared_update_with(
        &self,
        target: &Self,
        profiles: [&Configuration; 2],
        execution: &HostExecution<'_>,
        store: &mut impl crate::manager_profile::UpdateStore,
    ) -> Result<(), String> {
        let [config, destination_config] = profiles;
        for profile in profiles {
            crate::manager_host::validate_configuration(profile)?;
        }
        if execution.installation_id() != config.secure_installation_id {
            return Err(INVALID.into());
        }
        self.check_update_target(target, &config.installation_id)?;
        let source = self.root.parent().ok_or(INVALID)?;
        let destination = target.root.parent().ok_or(INVALID)?;
        crate::host_control::separate_paths(source, destination)?;
        for candidate in [source, destination] {
            crate::manager_host::validate_paths(candidate, &config.state, &config.data)?;
        }
        let _state = crate::host_storage::directory(&config.state)?;
        let _data = crate::host_storage::directory(&config.data)?;
        let _source_lease = crate::package_lease::CodeLease::acquire(source)?;
        let _target_lease = crate::package_lease::CodeLease::acquire(destination)?;
        self.check_files()?;
        target.check_files()?;
        let guard = ProfileGuard::acquire(config)?;
        let mut owner =
            crate::host_state::Owner::acquire_update(&config.state, execution.installation_id())?;
        // Destructive apply must durably advance the target epoch first, making this source path unavailable.
        execution.with_admitted(self, &mut || {
            let current = owner
                .update_record()?
                .ok_or("host_update_reservation_missing")?;
            let value: serde_json::Value =
                serde_json::from_slice(&current.0).map_err(|_| INVALID)?;
            if value["state"].as_str() != Some("credentialsPrepared") {
                return Err(INVALID.into());
            }
            let operation = value["operationId"].as_str().ok_or(INVALID)?;
            let id = uuid::Uuid::parse_str(operation).map_err(|_| INVALID)?;
            if id.is_nil() || id.to_string() != operation {
                return Err(INVALID.into());
            }
            let reservation = self.reservation_facts(target, config, &mut owner, id)?;
            guard.review_prepared_credentials(
                [
                    (config, source, self.manifest_sha256()),
                    (destination_config, destination, target.manifest_sha256()),
                ],
                store,
                |facts, _| {
                    let expected = reservation.prepared_record(
                        destination_config,
                        facts,
                        "credentialsPrepared",
                    )?;
                    if current.0 != expected {
                        return Err(INVALID.into());
                    }
                    guard.require_current(config)?;
                    self.check_files()?;
                    target.check_files()?;
                    let fresh = self
                        .reservation_facts(target, config, &mut owner, id)?
                        .prepared_record(destination_config, facts, "credentialsPrepared")?;
                    if fresh != expected {
                        return Err(INVALID.into());
                    }
                    owner.cancel_update_record(&current.0, &current.1)
                },
            )
        })
    }
}
