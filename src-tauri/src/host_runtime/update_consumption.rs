//! Authenticated maintenance metadata, never database execution or epoch admission authority.
use super::*;
const CONSUMPTION_DOMAIN: &[u8] = b"frameleaf-native-update-consumption-v1\0";
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Consumption {
    schema_version: u32,
    operation_id: String,
    prepared_record_sha256: String,
    approval_sha256: String,
    consumed_at: u64,
    approval: Payload,
    database_identity: String,
}
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AuthenticatedConsumption {
    receipt: Consumption,
    mac: String,
}
fn consumption_mac(receipt: &Consumption, key: &str) -> Result<Hmac<Sha256>, String> {
    if !crate::manager_profile::valid_backup_key(key) {
        return Err(INVALID.into());
    }
    let mut mac = Hmac::<Sha256>::new_from_slice(key.as_bytes()).map_err(|_| INVALID)?;
    mac.update(CONSUMPTION_DOMAIN);
    mac.update(&serde_json_canonicalizer::to_vec(receipt).map_err(|_| INVALID)?);
    Ok(mac)
}
fn authenticate(value: &AuthenticatedConsumption, key: &str) -> Result<(), String> {
    if !digest_valid(&value.mac, 64) {
        return Err(INVALID.into());
    }
    let tag = value
        .mac
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            u8::from_str_radix(std::str::from_utf8(pair).map_err(|_| INVALID)?, 16)
                .map_err(|_| INVALID)
        })
        .collect::<Result<Vec<_>, _>>()?;
    consumption_mac(&value.receipt, key)?
        .verify_slice(&tag)
        .map_err(|_| INVALID.into())
}
pub(super) fn clock() -> Result<u64, String> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| INVALID)?
        .as_millis()
        .try_into()
        .map_err(|_| INVALID.into())
}
#[derive(Clone, Copy)]
enum ContextAdmission<'a> {
    Source,
    TargetRecovery,
    Handover {
        cancel: &'a std::sync::atomic::AtomicBool,
        deadline: std::time::Instant,
    },
}
// Unproven child shutdown must keep every exclusion until this supervisor exits.
struct UpdateGuards {
    held: Option<(
        ProfileGuard,
        crate::host_state::Owner,
        crate::package_lease::CodeLease,
        crate::package_lease::CodeLease,
    )>,
    shutdown_unconfirmed: std::cell::Cell<bool>,
}
impl Drop for UpdateGuards {
    fn drop(&mut self) {
        if self.shutdown_unconfirmed.get() {
            std::mem::forget(self.held.take());
        }
    }
}
impl VerifiedHostRuntime {
    #[cfg(test)]
    pub(in crate::host_runtime) fn fail_update_shutdown_test(
        &self,
        target: &Self,
        profiles: [&Configuration; 2],
        execution: &HostExecution<'_>,
        store: &mut impl crate::manager_profile::UpdateStore,
        successful: bool,
    ) -> Result<HostUpdateApproval, String> {
        self.with_consumption_context(
            target,
            profiles,
            (execution, ContextAdmission::TargetRecovery),
            None,
            clock,
            store,
            |_, _, _, unconfirmed| {
                unconfirmed.set(true);
                if successful {
                    Ok(())
                } else {
                    Err("host_update_preparation_failed".into())
                }
            },
        )
    }
    /// Consume fresh approval into authenticated metadata. Does not authorize apply or start a runtime.
    pub fn consume_update_approval(
        &self,
        target: &Self,
        source: &Configuration,
        destination: &Configuration,
        execution: &HostExecution<'_>,
        sealed: &str,
    ) -> Result<HostUpdateApproval, String> {
        self.consume_update_approval_with(
            target,
            [source, destination],
            execution,
            Some(sealed),
            clock,
            &mut crate::manager_profile::Keystore,
        )
    }
    /// Read an authenticated previous consumption without extending its original approval expiry.
    pub fn review_consumed_update_approval(
        &self,
        target: &Self,
        source: &Configuration,
        destination: &Configuration,
        execution: &HostExecution<'_>,
    ) -> Result<HostUpdateApproval, String> {
        self.consume_update_approval_with(
            target,
            [source, destination],
            execution,
            None,
            clock,
            &mut crate::manager_profile::Keystore,
        )
    }
    pub(in crate::host_runtime) fn consume_update_approval_with(
        &self,
        target: &Self,
        profiles: [&Configuration; 2],
        execution: &HostExecution<'_>,
        sealed: Option<&str>,
        clock: impl Fn() -> Result<u64, String>,
        store: &mut impl crate::manager_profile::UpdateStore,
    ) -> Result<HostUpdateApproval, String> {
        self.with_update_approval(target, profiles, execution, sealed, clock, store, |_, _| {
            Ok(())
        })
    }
    #[allow(clippy::too_many_arguments)] // Fixed authority inputs plus the work performed while all guards are held.
    pub(in crate::host_runtime) fn with_update_approval(
        &self,
        target: &Self,
        profiles: [&Configuration; 2],
        execution: &HostExecution<'_>,
        sealed: Option<&str>,
        clock: impl Fn() -> Result<u64, String>,
        store: &mut impl crate::manager_profile::UpdateStore,
        mut inspect: impl FnMut(&Payload, &str) -> Result<(), String>,
    ) -> Result<HostUpdateApproval, String> {
        self.with_consumption_context(
            target,
            profiles,
            (execution, ContextAdmission::Source),
            sealed,
            clock,
            store,
            |payload, credentials, _, _| inspect(payload, credentials.backup_key),
        )
    }
    #[allow(clippy::too_many_arguments)] // Fixed authority inputs plus the work performed while all guards are held.
    fn with_consumption_context(
        &self,
        target: &Self,
        profiles: [&Configuration; 2],
        authority: (&HostExecution<'_>, ContextAdmission<'_>),
        sealed: Option<&str>,
        clock: impl Fn() -> Result<u64, String>,
        store: &mut impl crate::manager_profile::UpdateStore,
        inspect: impl FnMut(
            &Payload,
            &crate::manager_profile::update::PreparedCredentials<'_>,
            &mut crate::host_state::Owner,
            &std::cell::Cell<bool>,
        ) -> Result<(), String>,
    ) -> Result<HostUpdateApproval, String> {
        self.with_consumption_work(
            target,
            profiles,
            authority,
            sealed,
            clock,
            store,
            inspect,
            |_, _, _, _, _| Ok(()),
        )
    }
    #[allow(clippy::too_many_arguments)] // Fixed authority inputs plus the work performed while all guards are held.
    fn with_consumption_work(
        &self,
        target: &Self,
        profiles: [&Configuration; 2],
        authority: (&HostExecution<'_>, ContextAdmission<'_>),
        sealed: Option<&str>,
        clock: impl Fn() -> Result<u64, String>,
        store: &mut impl crate::manager_profile::UpdateStore,
        mut inspect: impl FnMut(
            &Payload,
            &crate::manager_profile::update::PreparedCredentials<'_>,
            &mut crate::host_state::Owner,
            &std::cell::Cell<bool>,
        ) -> Result<(), String>,
        mut commit: impl FnMut(
            &Payload,
            &crate::manager_profile::update::CredentialFacts,
            &crate::manager_profile::update::PreparedCredentials<'_>,
            &mut crate::host_state::Owner,
            &[u8],
        ) -> Result<(), String>,
    ) -> Result<HostUpdateApproval, String> {
        let (execution, admission) = authority;
        if !matches!(admission, ContextAdmission::Source) && sealed.is_some() {
            return Err(INVALID.into());
        }
        if let ContextAdmission::Handover { cancel, deadline } = admission {
            if cancel.load(std::sync::atomic::Ordering::Acquire)
                || std::time::Instant::now() >= deadline
            {
                return Err(INVALID.into());
            }
        }
        if let Some(token) = sealed {
            split(token)?;
        }
        let now = clock()?;
        let [config, destination_config] = profiles;
        for config in profiles {
            crate::manager_host::validate_configuration(config)?;
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
        let source_lease = crate::package_lease::CodeLease::acquire(source)?;
        let target_lease = crate::package_lease::CodeLease::acquire(destination)?;
        self.check_files()?;
        target.check_files()?;
        let guard = ProfileGuard::acquire(config)?;
        let owner =
            crate::host_state::Owner::acquire_update(&config.state, execution.installation_id())?;
        let mut guards = UpdateGuards {
            held: Some((guard, owner, source_lease, target_lease)),
            shutdown_unconfirmed: std::cell::Cell::new(false),
        };
        let shutdown_unconfirmed = &guards.shutdown_unconfirmed;
        let (guard, owner, _, _) = guards.held.as_mut().ok_or(INVALID)?;
        let mut result = None;
        let mut operation = || {
            let current = owner
                .update_record()?
                .ok_or("host_update_reservation_missing")?;
            let value: serde_json::Value =
                serde_json::from_slice(&current.0).map_err(|_| INVALID)?;
            let initial = match value["state"].as_str() {
                Some("credentialsPrepared") => true,
                Some("approvalConsumed") => false,
                _ => return Err(INVALID.into()),
            };
            let operation = value["operationId"].as_str().ok_or(INVALID)?;
            if !checkpoint_operation_id(operation) {
                return Err(INVALID.into());
            }
            let reservation = self.reservation_facts(
                target,
                config,
                owner,
                uuid::Uuid::parse_str(operation).map_err(|_| INVALID)?,
            )?;
            guard.review_prepared_credentials(
                [
                    (config, source, self.manifest_sha256()),
                    (destination_config, destination, target.manifest_sha256()),
                ],
                store,
                |facts, credentials| {
                    let key = credentials.backup_key;
                    let prepared = reservation.prepared_record(
                        destination_config,
                        facts,
                        "credentialsPrepared",
                    )?;
                    let prepared_sha = format!("{:x}", Sha256::digest(&prepared));
                    let (marker, database_identity) = owner
                        .review_reserved_update(&config.installation_id, self.manifest_sha256())?;
                    let mut authenticated = if initial {
                        if current.0 != prepared {
                            return Err(INVALID.into());
                        }
                        let token = sealed.ok_or(INVALID)?;
                        let payload = decode_verified(token, key, now)?;
                        AuthenticatedConsumption {
                            receipt: Consumption {
                                schema_version: 1,
                                operation_id: operation.into(),
                                prepared_record_sha256: prepared_sha.clone(),
                                approval_sha256: format!("{:x}", Sha256::digest(token.as_bytes())),
                                consumed_at: now,
                                approval: payload,
                                database_identity: database_identity.clone(),
                            },
                            mac: String::new(),
                        }
                    } else {
                        let parsed: AuthenticatedConsumption =
                            serde_json::from_value(value["approvalReceipt"].clone())
                                .map_err(|_| INVALID)?;
                        authenticate(&parsed, key)?;
                        parsed
                    };
                    let receipt = &authenticated.receipt;
                    receipt.approval.validate(receipt.consumed_at)?;
                    if receipt.schema_version != 1
                        || receipt.operation_id != operation
                        || receipt.prepared_record_sha256 != prepared_sha
                        || !digest_valid(&receipt.approval_sha256, 64)
                        || receipt.consumed_at > now
                        || receipt.consumed_at > MAX_SAFE
                        || now > MAX_SAFE
                        || receipt.database_identity != database_identity
                        || sealed.is_some_and(|token| {
                            format!("{:x}", Sha256::digest(token.as_bytes()))
                                != receipt.approval_sha256
                        })
                    {
                        return Err(INVALID.into());
                    }
                    let payload = &receipt.approval;
                    if payload.installation_id != config.installation_id
                        || payload.secure_installation_id != config.secure_installation_id
                        || payload.source_manifest_sha256 != self.manifest_sha256()
                        || payload.source_revision != self.source_revision()
                        || payload.target_manifest_sha256 != target.manifest_sha256()
                        || payload.generation != marker.generation.to_string()
                        || payload.controller_state_sha256 != owner.approval_journal_sha256()?
                    {
                        return Err(INVALID.into());
                    }
                    inspect(
                        &authenticated.receipt.approval,
                        credentials,
                        owner,
                        shutdown_unconfirmed,
                    )?;
                    if shutdown_unconfirmed.get() {
                        return Err("host_update_shutdown_unconfirmed".into());
                    }
                    guard.require_current(config)?;
                    let rechecked = self
                        .reservation_facts(
                            target,
                            config,
                            owner,
                            uuid::Uuid::parse_str(operation).map_err(|_| INVALID)?,
                        )?
                        .prepared_record(destination_config, facts, "credentialsPrepared")?;
                    if rechecked != prepared
                        || owner.approval_journal_sha256()?
                            != authenticated.receipt.approval.controller_state_sha256
                        || owner.update_record()?.as_ref() != Some(&current)
                    {
                        return Err(INVALID.into());
                    }
                    self.check_files()?;
                    target.check_files()?;
                    let fresh = clock()?;
                    if initial {
                        authenticated.receipt.approval.validate(fresh)?;
                        authenticated.receipt.consumed_at = fresh;
                        authenticated.mac = consumption_mac(&authenticated.receipt, key)?
                            .finalize()
                            .into_bytes()
                            .iter()
                            .map(|b| format!("{b:02x}"))
                            .collect();
                    } else if fresh < authenticated.receipt.consumed_at || fresh > MAX_SAFE {
                        return Err(INVALID.into());
                    }
                    let mut next: serde_json::Value =
                        serde_json::from_slice(&prepared).map_err(|_| INVALID)?;
                    next["state"] = "approvalConsumed".into();
                    next["approvalReceipt"] =
                        serde_json::to_value(&authenticated).map_err(|_| INVALID)?;
                    let next = serde_json::to_vec(&next).map_err(|_| INVALID)?;
                    if next.len() > 4096 {
                        return Err(INVALID.into());
                    }
                    if initial {
                        owner.advance_update_record(&current.0, &current.1, &next)?;
                    } else if current.0 != next {
                        return Err(INVALID.into());
                    }
                    commit(
                        &authenticated.receipt.approval,
                        facts,
                        credentials,
                        owner,
                        &next,
                    )?;
                    result = Some(HostUpdateApproval {
                        protocol_version: 1,
                        state: "consumed",
                        approval: authenticated.receipt.approval,
                        database_identity,
                    });
                    Ok(())
                },
            )?;
            if let ContextAdmission::Handover { cancel, deadline } = admission {
                if cancel.load(std::sync::atomic::Ordering::Acquire)
                    || std::time::Instant::now() >= deadline
                {
                    return Err(INVALID.into());
                }
            }
            Ok(())
        };
        match admission {
            ContextAdmission::Source => execution.with_admitted(self, &mut operation),
            ContextAdmission::TargetRecovery => execution.with_admitted(target, &mut operation),
            ContextAdmission::Handover { .. } => {
                execution.transition(self, target, &mut operation, || Ok(()))
            }
        }?;
        result.ok_or_else(|| INVALID.into())
    }
}

#[path = "update_recovery.rs"]
mod recovery;

#[path = "update_handover.rs"]
mod handover;

#[path = "update_staging.rs"]
mod staging;
pub use staging::{HostUpdateCandidate, HostUpdateInput};
