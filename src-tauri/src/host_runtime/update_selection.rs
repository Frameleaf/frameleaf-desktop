//! Authenticated retained selection. This deliberately leaves normal startup fenced.
use super::*;
use crate::{host_state::UpdateSelection, manager_profile::update::CredentialFacts};
use std::cell::RefCell;
const DOMAIN: &[u8] = b"frameleaf-native-update-selection-v1\0";
const FAILED: &str = "host_update_selection_invalid";
#[derive(Clone, Copy, PartialEq, Eq)]
enum SelectionStep {
    Recover,
    Publish,
    Verify,
    Finalize,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Intent {
    schema_version: u32,
    purpose: String,
    operation_id: String,
    consumption_sha256: String,
    from_epoch: u64,
    to_epoch: u64,
    bindings: [String; 4],
    prepared_sha256: String,
    selection: UpdateSelection,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Sealed {
    intent: Intent,
    mac: String,
}
fn bindings(facts: &CredentialFacts) -> [String; 4] {
    [
        facts.source_binding.clone(),
        facts.target_binding.clone(),
        facts.tls_certificate_sha256.clone(),
        facts.credentials_sha256.clone(),
    ]
}
fn mac(intent: &Intent, key: &str) -> Result<Hmac<Sha256>, String> {
    if !crate::manager_profile::valid_backup_key(key) {
        return Err(FAILED.into());
    }
    let mut value = Hmac::<Sha256>::new_from_slice(key.as_bytes()).map_err(|_| FAILED)?;
    value.update(DOMAIN);
    value.update(&serde_json_canonicalizer::to_vec(intent).map_err(|_| FAILED)?);
    Ok(value)
}
fn seal(intent: Intent, key: &str) -> Result<Vec<u8>, String> {
    let tag = mac(&intent, key)?
        .finalize()
        .into_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let bytes = serde_json::to_vec(&Sealed { intent, mac: tag }).map_err(|_| FAILED)?;
    if bytes.len() > 4096 {
        return Err(FAILED.into());
    }
    Ok(bytes)
}
fn authenticate_selection(raw: &[u8], key: &str) -> Result<Intent, String> {
    let value: Sealed = serde_json::from_slice(raw).map_err(|_| FAILED)?;
    if !digest_valid(&value.mac, 64) || serde_json::to_vec(&value).map_err(|_| FAILED)? != raw {
        return Err(FAILED.into());
    }
    let tag = value
        .mac
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            u8::from_str_radix(std::str::from_utf8(pair).map_err(|_| FAILED)?, 16)
                .map_err(|_| FAILED)
        })
        .collect::<Result<Vec<_>, _>>()?;
    mac(&value.intent, key)?
        .verify_slice(&tag)
        .map_err(|_| FAILED)?;
    Ok(value.intent)
}
fn prepared_hash(receipt: &UpdatePrepared) -> Result<String, String> {
    Ok(format!(
        "{:x}",
        Sha256::digest(serde_json_canonicalizer::to_vec(receipt).map_err(|_| FAILED)?)
    ))
}
fn envelope(receipt: &UpdatePrepared) -> Result<Vec<u8>, String> {
    serde_json::to_vec(&serde_json::json!({"state":"update-verified","prepared":receipt,"offlineChecksums":true,"schemaValidated":true})).map_err(|_|FAILED.into())
}
fn retained_stage(config: &Configuration, request: &HostUpdateInput) -> Result<Stage, String> {
    let profile = Directory::open(config.state.clone())?;
    let root = profile.child("restore-input", false)?;
    let operation = root.child(&request.restore.operation_id, false)?;
    let input = operation.child("input", false)?;
    Ok(Stage {
        profile,
        root,
        operation,
        input,
    })
}
impl VerifiedHostRuntime {
    /// Select a freshly verified retained database. Profile publication and writer admission are separate.
    pub fn select_update_candidate(
        &self,
        target: &Self,
        source: &Configuration,
        destination: &Configuration,
        execution: &HostExecution<'_>,
        cancel: &AtomicBool,
    ) -> Result<HostUpdateCandidate, String> {
        let deadline = Instant::now() + Duration::from_secs(7200);
        self.select_candidate_with(
            target,
            [source, destination],
            execution,
            (cancel, deadline),
            &mut crate::manager_profile::Keystore,
            |payload, key, file| {
                target.stage_update_backup_held(source, payload, key, cancel, deadline, file)
            },
        )
    }
    #[cfg(test)]
    pub(in crate::host_runtime) fn select_update_candidate_test(
        &self,
        target: &Self,
        profiles: [&Configuration; 2],
        execution: &HostExecution<'_>,
        cancel: &AtomicBool,
        store: &mut impl crate::manager_profile::UpdateStore,
        write: impl FnMut(&Payload, &str, File) -> Result<Vec<u8>, String>,
    ) -> Result<HostUpdateCandidate, String> {
        self.select_candidate_with(
            target,
            profiles,
            execution,
            (cancel, Instant::now() + Duration::from_secs(30)),
            store,
            write,
        )
    }
    #[allow(clippy::too_many_arguments)] // Fixed held authority and a closed backup reader, never a caller-supplied process.
    fn select_candidate_with(
        &self,
        target: &Self,
        profiles: [&Configuration; 2],
        execution: &HostExecution<'_>,
        activity: (&AtomicBool, Instant),
        store: &mut impl crate::manager_profile::UpdateStore,
        mut write: impl FnMut(&Payload, &str, File) -> Result<Vec<u8>, String>,
    ) -> Result<HostUpdateCandidate, String> {
        let (cancel, deadline) = activity;
        active(cancel, deadline)?;
        if self.epoch() == 0 || target.epoch() <= self.epoch() || target.epoch() > MAX_SAFE {
            return Err(FAILED.into());
        }
        let candidate = RefCell::new(None);
        self.with_consumption_work(
            target,
            profiles,
            (execution, ContextAdmission::TargetRecovery),
            None,
            clock,
            store,
            |payload, credentials, owner, unconfirmed| {
                if owner.update_selection_record()?.is_some() {
                    return Err("host_update_selection_requires_resume".into());
                }
                let prepared = prepare_candidate_held(
                    self,
                    target,
                    profiles[0],
                    (payload, credentials, owner, unconfirmed),
                    activity,
                    &mut write,
                )?;
                *candidate.borrow_mut() = Some(prepared);
                Ok(())
            },
            |payload, facts, credentials, owner, consumption| {
                active(cancel, deadline)?;
                self.update_recovery_record_held(
                    target,
                    payload,
                    credentials.backup_key,
                    owner,
                    true,
                )?;
                let mut held = candidate.borrow_mut();
                let (candidate, stage) = held.as_mut().ok_or(FAILED)?;
                let request = update_input(
                    self,
                    target,
                    payload,
                    candidate.receipt.binding.operation_id.clone(),
                );
                let checked = inspect(
                    target,
                    profiles[0],
                    &request,
                    &envelope(&candidate.receipt)?,
                )?;
                if checked.reference != candidate.reference {
                    return Err(FAILED.into());
                }
                verify_candidate_stage(stage, &request, payload, profiles[0], activity)?;
                if owner.update_record()?.ok_or(FAILED)?.0 != consumption {
                    return Err(FAILED.into());
                }
                let selection = owner.prepare_update_selection(
                    &profiles[0].installation_id,
                    self.manifest_sha256(),
                    target.manifest_sha256(),
                    &candidate.reference,
                )?;
                if format!(
                    "{:x}",
                    Sha256::digest(serde_json::to_vec(&selection.previous).map_err(|_| FAILED)?)
                ) != payload.controller_state_sha256
                {
                    return Err(FAILED.into());
                }
                let record: serde_json::Value =
                    serde_json::from_slice(consumption).map_err(|_| FAILED)?;
                let operation = record["operationId"].as_str().ok_or(FAILED)?;
                if !checkpoint_operation_id(operation) {
                    return Err(FAILED.into());
                }
                let consumed_sha = format!("{:x}", Sha256::digest(consumption));
                let intent = Intent {
                    schema_version: 1,
                    purpose: "native-update-selection".into(),
                    operation_id: operation.into(),
                    consumption_sha256: consumed_sha.clone(),
                    from_epoch: self.epoch(),
                    to_epoch: target.epoch(),
                    bindings: bindings(facts),
                    prepared_sha256: prepared_hash(&candidate.receipt)?,
                    selection: selection.clone(),
                };
                let raw = seal(intent, credentials.backup_key)?;
                owner.reserve_update_selection_record(&raw)?;
                active(cancel, deadline)?;
                owner.publish_update_selection(&selection, &raw, &consumed_sha)?;
                candidate.state = "selected-pending-publication";
                candidate.selection_generation = Some(selection.next.generation);
                Ok(())
            },
        )?;
        active(cancel, deadline)?;
        let (candidate, stage) = candidate.into_inner().ok_or(FAILED)?;
        for directory in [&stage.profile, &stage.root, &stage.operation, &stage.input] {
            directory.check()?;
        }
        candidate.reference.resolve(&profiles[0].state)?;
        active(cancel, deadline)?;
        Ok(candidate)
    }
    /// Resume only the authenticated retained selection; never clears the writer fence or runs source code.
    pub fn resume_update_selection(
        &self,
        target: &Self,
        source: &Configuration,
        destination: &Configuration,
        execution: &HostExecution<'_>,
        cancel: &AtomicBool,
    ) -> Result<HostUpdateCandidate, String> {
        self.resume_selection_with(
            target,
            [source, destination],
            execution,
            (cancel, Instant::now() + Duration::from_secs(7200)),
            &mut crate::manager_profile::Keystore,
            SelectionStep::Recover,
        )
    }
    #[cfg(all(test, unix))]
    pub(in crate::host_runtime) fn resume_update_selection_test(
        &self,
        target: &Self,
        profiles: [&Configuration; 2],
        execution: &HostExecution<'_>,
        cancel: &AtomicBool,
        store: &mut impl crate::manager_profile::UpdateStore,
    ) -> Result<HostUpdateCandidate, String> {
        self.resume_selection_with(
            target,
            profiles,
            execution,
            (cancel, Instant::now() + Duration::from_secs(30)),
            store,
            SelectionStep::Recover,
        )
    }
    /// Publish only authenticated target metadata. Writer admission still requires fresh verification.
    pub fn publish_update_selection(
        &self,
        target: &Self,
        source: &Configuration,
        destination: &Configuration,
        execution: &HostExecution<'_>,
        cancel: &AtomicBool,
    ) -> Result<HostUpdateCandidate, String> {
        self.resume_selection_with(
            target,
            [source, destination],
            execution,
            (cancel, Instant::now() + Duration::from_secs(7200)),
            &mut crate::manager_profile::Keystore,
            SelectionStep::Publish,
        )
    }
    #[cfg(all(test, unix))]
    pub(in crate::host_runtime) fn publish_update_selection_test(
        &self,
        target: &Self,
        profiles: [&Configuration; 2],
        execution: &HostExecution<'_>,
        cancel: &AtomicBool,
        store: &mut impl crate::manager_profile::UpdateStore,
    ) -> Result<HostUpdateCandidate, String> {
        self.resume_selection_with(
            target,
            profiles,
            execution,
            (cancel, Instant::now() + Duration::from_secs(30)),
            store,
            SelectionStep::Publish,
        )
    }
    /// Freshly verify the selected published target. This never clears the startup fence.
    pub fn verify_update_selection(
        &self,
        target: &Self,
        source: &Configuration,
        destination: &Configuration,
        execution: &HostExecution<'_>,
        cancel: &AtomicBool,
    ) -> Result<HostUpdateCandidate, String> {
        self.resume_selection_with(
            target,
            [source, destination],
            execution,
            (cancel, Instant::now() + Duration::from_secs(7200)),
            &mut crate::manager_profile::Keystore,
            SelectionStep::Verify,
        )
    }
    #[cfg(test)]
    pub(in crate::host_runtime) fn verify_update_selection_test(
        &self,
        target: &Self,
        profiles: [&Configuration; 2],
        execution: &HostExecution<'_>,
        cancel: &AtomicBool,
        store: &mut impl crate::manager_profile::UpdateStore,
    ) -> Result<HostUpdateCandidate, String> {
        self.resume_selection_with(
            target,
            profiles,
            execution,
            (cancel, Instant::now() + Duration::from_secs(30)),
            store,
            SelectionStep::Verify,
        )
    }
    /// Commit a freshly reverified update; leaves originals and authenticated operation history intact.
    pub fn finalize_update_selection(
        &self,
        target: &Self,
        source: &Configuration,
        destination: &Configuration,
        execution: &HostExecution<'_>,
        cancel: &AtomicBool,
    ) -> Result<HostUpdateCandidate, String> {
        self.resume_selection_with(
            target,
            [source, destination],
            execution,
            (cancel, Instant::now() + Duration::from_secs(7200)),
            &mut crate::manager_profile::Keystore,
            SelectionStep::Finalize,
        )
    }
    #[cfg(all(test, unix))]
    pub(in crate::host_runtime) fn finalize_update_selection_test(
        &self,
        target: &Self,
        profiles: [&Configuration; 2],
        execution: &HostExecution<'_>,
        cancel: &AtomicBool,
        store: &mut impl crate::manager_profile::UpdateStore,
    ) -> Result<HostUpdateCandidate, String> {
        self.resume_selection_with(
            target,
            profiles,
            execution,
            (cancel, Instant::now() + Duration::from_secs(30)),
            store,
            SelectionStep::Finalize,
        )
    }
    #[allow(clippy::too_many_arguments)] // One recovery path; publication alone accepts authenticated old/next metadata.
    fn resume_selection_with(
        &self,
        target: &Self,
        profiles: [&Configuration; 2],
        execution: &HostExecution<'_>,
        activity: (&AtomicBool, Instant),
        store: &mut impl crate::manager_profile::UpdateStore,
        step: SelectionStep,
    ) -> Result<HostUpdateCandidate, String> {
        let publication = step != SelectionStep::Recover;
        let (cancel, deadline) = activity;
        active(cancel, deadline)?;
        if self.epoch() == 0 || target.epoch() <= self.epoch() || target.epoch() > MAX_SAFE {
            return Err(FAILED.into());
        }
        let [config, destination_config] = profiles;
        for profile in profiles {
            crate::manager_host::validate_configuration(profile)?;
        }
        if execution.installation_id() != config.secure_installation_id {
            return Err(FAILED.into());
        }
        self.check_update_target(target, &config.installation_id)?;
        let source = self.root.parent().ok_or(FAILED)?;
        let destination = target.root.parent().ok_or(FAILED)?;
        crate::host_control::separate_paths(source, destination)?;
        for candidate in [source, destination] {
            crate::manager_host::validate_paths(candidate, &config.state, &config.data)?;
        }
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
        let (guard, owner, _, _) = guards.held.as_mut().ok_or(FAILED)?;
        let mut result = None;
        execution.with_admitted(target, &mut || {
            guard.review_update_credentials(
                [
                    (config, source, self.manifest_sha256()),
                    (destination_config, destination, target.manifest_sha256()),
                ],
                store,
                publication,
                |facts, credentials| {
                    active(cancel, deadline)?;
                    let raw = owner.update_selection_evidence()?.ok_or(FAILED)?.0;
                    let intent = authenticate_selection(&raw, credentials.backup_key)?;
                    let current = owner.update_record()?.ok_or(FAILED)?.0;
                    let record: serde_json::Value =
                        serde_json::from_slice(&current).map_err(|_| FAILED)?;
                    let consumed: AuthenticatedConsumption =
                        serde_json::from_value(record["approvalReceipt"].clone())
                            .map_err(|_| FAILED)?;
                    authenticate(&consumed, credentials.backup_key)?;
                    let payload = &consumed.receipt.approval;
                    payload.validate(consumed.receipt.consumed_at)?;
                    let now = clock()?;
                    if intent.schema_version != 1
                        || intent.purpose != "native-update-selection"
                        || intent.from_epoch != self.epoch()
                        || intent.to_epoch != target.epoch()
                        || intent.bindings != bindings(facts)
                        || !digest_valid(&intent.prepared_sha256, 64)
                        || intent.consumption_sha256 != format!("{:x}", Sha256::digest(&current))
                        || record["state"] != "approvalConsumed"
                        || record["operationId"] != intent.operation_id
                        || consumed.receipt.operation_id != intent.operation_id
                        || !checkpoint_operation_id(&intent.operation_id)
                        || consumed.receipt.schema_version != 1
                        || consumed.receipt.consumed_at > now
                        || now > MAX_SAFE
                        || payload.installation_id != config.installation_id
                        || payload.secure_installation_id != config.secure_installation_id
                        || payload.source_manifest_sha256 != self.manifest_sha256()
                        || payload.source_revision != self.source_revision()
                        || payload.target_manifest_sha256 != target.manifest_sha256()
                        || intent.selection.previous.manifest_sha256 != self.manifest_sha256()
                        || intent.selection.next.manifest_sha256 != target.manifest_sha256()
                        || intent.selection.previous.installation_id != config.installation_id
                        || intent.selection.previous.secure_installation_id.as_deref()
                            != Some(config.secure_installation_id.as_str())
                        || intent.selection.previous.generation.to_string() != payload.generation
                        || format!(
                            "{:x}",
                            Sha256::digest(
                                serde_json::to_vec(&intent.selection.previous)
                                    .map_err(|_| FAILED)?
                            )
                        ) != payload.controller_state_sha256
                    {
                        return Err(FAILED.into());
                    }
                    let source_host = crate::host_runtime::update::state_record(self)?;
                    let target_host = crate::host_runtime::update::state_record(target)?;
                    if publication {
                        guard.update_metadata(
                            profiles,
                            [&facts.source_binding, &facts.target_binding],
                            [&source_host, &target_host],
                            false,
                        )?;
                    } else {
                        crate::host_runtime::update::host_state(
                            &config.state,
                            self,
                            &intent.selection.previous.profile_identity,
                        )?;
                    }
                    let recovery = self.update_recovery_evidence_held(
                        target,
                        payload,
                        credentials.backup_key,
                        owner,
                        true,
                    )?;
                    let reference = intent.selection.reference()?;
                    let target_directory = Directory::open(
                        reference
                            .resolve(&config.state)?
                            .parent()
                            .ok_or(FAILED)?
                            .into(),
                    )?;
                    let prepared: UpdatePrepared = serde_json::from_slice(&json_file(
                        &target_directory,
                        "restore-result.json",
                        4096,
                    )?)
                    .map_err(|_| FAILED)?;
                    if prepared_hash(&prepared)? != intent.prepared_sha256 {
                        return Err(FAILED.into());
                    }
                    let request =
                        update_input(self, target, payload, prepared.binding.operation_id.clone());
                    let mut candidate = inspect(target, config, &request, &envelope(&prepared)?)?;
                    if &candidate.reference != reference {
                        return Err(FAILED.into());
                    }
                    let stage = retained_stage(config, &request)?;
                    verify_candidate_stage(&stage, &request, payload, config, activity)?;
                    guard.require_current(config)?;
                    self.check_files()?;
                    target.check_files()?;
                    active(cancel, deadline)?;
                    owner.publish_update_selection(
                        &intent.selection,
                        &raw,
                        &intent.consumption_sha256,
                    )?;
                    if publication {
                        guard.update_metadata(
                            profiles,
                            [&facts.source_binding, &facts.target_binding],
                            [&source_host, &target_host],
                            true,
                        )?;
                        crate::host_runtime::update::host_state(
                            &config.state,
                            target,
                            &intent.selection.previous.profile_identity,
                        )?;
                    } else {
                        crate::host_runtime::update::host_state(
                            &config.state,
                            self,
                            &intent.selection.previous.profile_identity,
                        )?;
                    }
                    if matches!(step, SelectionStep::Verify | SelectionStep::Finalize) {
                        let checked = target.prepare_child_held(
                            config,
                            (&request, Some(&candidate.receipt)),
                            credentials,
                            shutdown_unconfirmed,
                            cancel,
                            deadline,
                        )?;
                        if shutdown_unconfirmed.get() {
                            return Err("host_update_shutdown_unconfirmed".into());
                        }
                        if checked.reference != candidate.reference
                            || prepared_hash(&checked.receipt)? != intent.prepared_sha256
                        {
                            return Err(FAILED.into());
                        }
                        verify_candidate_stage(&stage, &request, payload, config, activity)?;
                        crate::host_runtime::update::host_state(
                            &config.state,
                            target,
                            &intent.selection.previous.profile_identity,
                        )?;
                        guard.require_published_update_configuration(
                            destination_config,
                            &facts.target_binding,
                        )?;
                        candidate = checked;
                    }
                    guard.require_current(config)?;
                    self.check_files()?;
                    target.check_files()?;
                    owner.publish_update_selection(
                        &intent.selection,
                        &raw,
                        &intent.consumption_sha256,
                    )?;
                    if step == SelectionStep::Finalize {
                        owner.finalize_update_selection(
                            &intent.selection,
                            [&current, &recovery, &raw],
                            || {
                                active(cancel, deadline)?;
                                guard.require_published_update_configuration(
                                    destination_config,
                                    &facts.target_binding,
                                )?;
                                crate::host_runtime::update::host_state(
                                    &config.state,
                                    target,
                                    &intent.selection.previous.profile_identity,
                                )?;
                                verify_candidate_stage(
                                    &stage, &request, payload, config, activity,
                                )?;
                                self.check_files()?;
                                target.check_files()?;
                                active(cancel, deadline)
                            },
                        )?;
                    }
                    candidate.state = match step {
                        SelectionStep::Recover => "selected-pending-publication",
                        SelectionStep::Publish => "published-pending-verification",
                        SelectionStep::Verify => "published-verified",
                        SelectionStep::Finalize => "committed",
                    };
                    if step == SelectionStep::Publish {
                        candidate.offline_checksums = false;
                        candidate.schema_validated = false;
                    }
                    candidate.selection_generation = Some(intent.selection.next.generation);
                    result = Some(candidate);
                    if step == SelectionStep::Finalize {
                        Ok(())
                    } else {
                        active(cancel, deadline)
                    }
                },
            )
        })?;
        result.ok_or_else(|| FAILED.into())
    }
}

#[cfg(test)]
#[path = "update_qualification.rs"]
mod actual_update;
