//! A reserved update fences normal starts; it grants no permission to change data, secrets or epochs.
use super::*;
use crate::manager_host::{validate_configuration, validate_paths, Configuration};
use crate::manager_profile::ProfileGuard;
use std::io::Read;

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HostUpdateReservation {
    protocol_version: u32,
    state: &'static str,
    operation_id: uuid::Uuid,
    review: HostUpdateReview,
    configuration_sha256: String,
    manager_identity: String,
    profile_binding_sha256: String,
    source_candidate_identity: String,
    target_candidate_identity: String,
}
fn directory_identity(path: &Path) -> Result<String, String> {
    let dir = Dir::from_std_file(crate::host_storage::directory(path)?);
    root_identity(&dir)
}
fn profile_binding(data: &Path) -> Result<String, String> {
    let root = Dir::from_std_file(crate::host_storage::directory(data)?);
    let name = Path::new(".host-profile");
    let mut file = staged_file(&root, name)?;
    crate::host_state::valid_file(
        &file
            .try_clone()
            .map_err(|_| "host_update_profile_invalid")?
            .into_std(),
    )?;
    let stamp = opened_stamp(&file)?;
    let length = file
        .metadata()
        .map_err(|_| "host_update_profile_invalid")?
        .len();
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(65)
        .read_to_end(&mut bytes)
        .map_err(|_| "host_update_profile_invalid")?;
    unchanged(&root, name, &file, &stamp, length, bytes.len() as u64)?;
    let value = String::from_utf8(bytes).map_err(|_| "host_update_profile_invalid")?;
    if !digest_valid(&value, 64) {
        return Err("host_update_profile_invalid".into());
    }
    Ok(value)
}
impl VerifiedHostRuntime {
    pub(in crate::host_runtime) fn reservation_facts(
        &self,
        target: &Self,
        config: &Configuration,
        owner: &mut crate::host_state::Owner,
        operation_id: uuid::Uuid,
    ) -> Result<HostUpdateReservation, String> {
        let review = self.update_facts(
            target,
            owner,
            &config.state,
            &config.installation_id,
            &config.secure_installation_id,
            true,
        )?;
        Ok(HostUpdateReservation {
            protocol_version: 1,
            state: "reserved",
            operation_id,
            review,
            configuration_sha256: format!(
                "{:x}",
                Sha256::digest(
                    serde_json_canonicalizer::to_vec(config)
                        .map_err(|_| "host_update_profile_invalid")?
                )
            ),
            manager_identity: directory_identity(&config.data)?,
            profile_binding_sha256: profile_binding(&config.data)?,
            source_candidate_identity: directory_identity(
                self.root.parent().ok_or("native_manager_layout_invalid")?,
            )?,
            target_candidate_identity: directory_identity(
                target
                    .root
                    .parent()
                    .ok_or("native_manager_layout_invalid")?,
            )?,
        })
    }
    /// Reserve maintenance only. Backup, migration, credential transition and target admission are separate gates.
    pub fn reserve_update(
        &self,
        target: &Self,
        config: &Configuration,
        execution: &HostExecution<'_>,
    ) -> Result<HostUpdateReservation, String> {
        self.update_reservation(
            target,
            config,
            execution,
            false,
            None,
            &mut crate::manager_profile::Keystore,
        )
    }
    /// Cancel only an untouched reservation for this still-admitted source and exact original bindings.
    pub fn cancel_update_reservation(
        &self,
        target: &Self,
        config: &Configuration,
        execution: &HostExecution<'_>,
    ) -> Result<(), String> {
        self.update_reservation(
            target,
            config,
            execution,
            true,
            None,
            &mut crate::manager_profile::Keystore,
        )
        .map(|_| ())
    }
    /// Prepare additional target accounts only; keeps all starts fenced and never changes the admission floor.
    pub fn prepare_update_credentials(
        &self,
        target: &Self,
        source: &Configuration,
        destination: &Configuration,
        execution: &HostExecution<'_>,
    ) -> Result<HostUpdateReservation, String> {
        self.update_reservation(
            target,
            source,
            execution,
            false,
            Some(destination),
            &mut crate::manager_profile::Keystore,
        )
    }
    pub(super) fn update_reservation(
        &self,
        target: &Self,
        config: &Configuration,
        execution: &HostExecution<'_>,
        cancel: bool,
        preparation: Option<&Configuration>,
        store: &mut impl crate::manager_profile::UpdateStore,
    ) -> Result<HostUpdateReservation, String> {
        self.update_reservation_with(
            target,
            config,
            execution,
            (cancel, preparation),
            store,
            None,
        )
    }
    pub(crate) fn reserve_update_held(
        &self,
        target: &Self,
        config: &Configuration,
        execution: &HostExecution<'_>,
        guard: &ProfileGuard,
        owner: &mut crate::host_state::Owner,
    ) -> Result<HostUpdateReservation, String> {
        self.update_reservation_with(
            target,
            config,
            execution,
            (false, None),
            &mut crate::manager_profile::Keystore,
            Some((guard, owner)),
        )
    }
    pub(crate) fn update_candidate_paths<'a>(
        &'a self,
        target: &'a Self,
        config: &Configuration,
    ) -> Result<[&'a Path; 2], String> {
        let source = self.root.parent().ok_or("native_manager_layout_invalid")?;
        let destination = target
            .root
            .parent()
            .ok_or("native_manager_layout_invalid")?;
        crate::host_control::separate_paths(source, destination)?;
        for candidate in [source, destination] {
            validate_paths(candidate, &config.state, &config.data)?;
        }
        Ok([source, destination])
    }
    fn update_reservation_with(
        &self,
        target: &Self,
        config: &Configuration,
        execution: &HostExecution<'_>,
        action: (bool, Option<&Configuration>),
        store: &mut impl crate::manager_profile::UpdateStore,
        held: Option<(&ProfileGuard, &mut crate::host_state::Owner)>,
    ) -> Result<HostUpdateReservation, String> {
        let (cancel, preparation) = action;
        validate_configuration(config)?;
        if execution.installation_id() != config.secure_installation_id {
            return Err("host_installation_identity_changed".into());
        }
        self.check_update_target(target, &config.installation_id)?;
        let [source, destination] = self.update_candidate_paths(target, config)?;
        // Reservation never creates a missing profile or Manager directory.
        directory_identity(&config.state)?;
        directory_identity(&config.data)?;
        let _source_lease = crate::package_lease::CodeLease::acquire(source)?;
        let _target_lease = crate::package_lease::CodeLease::acquire(destination)?;
        self.check_files()?;
        target.check_files()?;
        let acquired_guard;
        let mut acquired_owner;
        let (guard, owner) = match held {
            Some(held) => held,
            None => {
                acquired_guard = ProfileGuard::acquire(config)?;
                acquired_owner = crate::host_state::Owner::acquire_update(
                    &config.state,
                    execution.installation_id(),
                )?;
                (&acquired_guard, &mut acquired_owner)
            }
        };
        if owner.installation_identity() != Some(execution.installation_id()) {
            return Err("host_installation_identity_changed".into());
        }
        let mut result = None;
        execution.with_admitted(self, &mut || {
            guard.require_current(config)?;
            let existing = owner.update_record()?;
            let operation_id = match &existing {
                Some((bytes, _)) => {
                    let value: serde_json::Value = serde_json::from_slice(bytes)
                        .map_err(|_| "host_update_reservation_invalid")?;
                    let id = value["operationId"]
                        .as_str()
                        .ok_or("host_update_reservation_invalid")?;
                    let parsed =
                        uuid::Uuid::parse_str(id).map_err(|_| "host_update_reservation_invalid")?;
                    if parsed.is_nil() || parsed.to_string() != id {
                        return Err("host_update_reservation_invalid".into());
                    }
                    parsed
                }
                None if cancel || preparation.is_some() => {
                    return Err("host_update_reservation_missing".into())
                }
                None => uuid::Uuid::new_v4(),
            };
            let mut reservation = self.reservation_facts(target, config, owner, operation_id)?;
            let expected =
                serde_json::to_vec(&reservation).map_err(|_| "host_update_reservation_invalid")?;
            if let Some((bytes, _)) = &existing {
                if preparation.is_none() && bytes != &expected {
                    return Err("host_update_reservation_changed".into());
                }
            }
            target.check_files()?;
            guard.require_current(config)?;
            if let Some(destination_config) = preparation {
                let mut preparing = None;
                guard.prepare_credentials(
                    [
                        (config, source, self.manifest_sha256()),
                        (destination_config, destination, target.manifest_sha256()),
                    ],
                    store,
                    |facts| {
                        if facts.source_binding != reservation.profile_binding_sha256 {
                            return Err("host_update_profile_invalid".into());
                        }
                        let next = reservation.prepared_record(
                            destination_config,
                            facts,
                            "preparingCredentials",
                        )?;
                        let complete = reservation.prepared_record(
                            destination_config,
                            facts,
                            "credentialsPrepared",
                        )?;
                        let current = owner
                            .update_record()?
                            .ok_or("host_update_reservation_missing")?;
                        if current.0 == expected {
                            owner.advance_update_record(&current.0, &current.1, &next)?;
                        } else if current.0 != next && current.0 != complete {
                            return Err("host_update_reservation_changed".into());
                        }
                        preparing = Some((next, complete));
                        Ok(())
                    },
                )?;
                let (next, complete) = preparing.ok_or("host_update_reservation_invalid")?;
                let current = owner
                    .update_record()?
                    .ok_or("host_update_reservation_missing")?;
                if current.0 == next {
                    owner.advance_update_record(&current.0, &current.1, &complete)?;
                } else if current.0 != complete {
                    return Err("host_update_reservation_changed".into());
                }
                reservation.state = "credentialsPrepared";
            } else if cancel {
                owner.cancel_update_record(
                    &expected,
                    &existing
                        .as_ref()
                        .ok_or("host_update_reservation_missing")?
                        .1,
                )?;
                reservation.state = "cancelled";
            } else {
                owner.reserve_update_record(&expected)?;
            }
            result = Some(reservation);
            Ok(())
        })?;
        if !cancel {
            target.check_files()?;
        }
        result.ok_or_else(|| "host_update_reservation_invalid".into())
    }
}

impl HostUpdateReservation {
    pub(in crate::host_runtime) fn prepared_record(
        &self,
        target: &Configuration,
        facts: &crate::manager_profile::update::CredentialFacts,
        phase: &str,
    ) -> Result<Vec<u8>, String> {
        if facts.source_binding != self.profile_binding_sha256 {
            return Err("host_update_profile_invalid".into());
        }
        let mut value =
            serde_json::to_value(self).map_err(|_| "host_update_reservation_invalid")?;
        value["state"] = phase.into();
        value["targetConfigurationSha256"] = format!(
            "{:x}",
            Sha256::digest(
                serde_json_canonicalizer::to_vec(target)
                    .map_err(|_| "host_update_profile_invalid")?
            )
        )
        .into();
        value["targetProfileBindingSha256"] = facts.target_binding.clone().into();
        value["tlsCertificateSha256"] = facts.tls_certificate_sha256.clone().into();
        value["credentialsSha256"] = facts.credentials_sha256.clone().into();
        serde_json::to_vec(&value).map_err(|_| "host_update_reservation_invalid".into())
    }
}
