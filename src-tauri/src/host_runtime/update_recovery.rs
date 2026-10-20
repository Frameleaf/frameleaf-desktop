//! Authenticated recovery metadata, never backup-readback, migration or restore permission.
use super::*;
const DOMAIN: &[u8] = b"frameleaf-native-update-recovery-v1\0";
#[derive(Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Intent {
    schema_version: u32,
    purpose: String,
    operation_id: String,
    installation_id: String,
    secure_installation_id: String,
    consumption_sha256: String,
    source_manifest_sha256: String,
    target_manifest_sha256: String,
    from_epoch: u64,
    to_epoch: u64,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Sealed {
    intent: Intent,
    mac: String,
}
fn mac(intent: &Intent, key: &str) -> Result<Hmac<Sha256>, String> {
    if !crate::manager_profile::valid_backup_key(key) {
        return Err(INVALID.into());
    }
    let mut value = Hmac::<Sha256>::new_from_slice(key.as_bytes()).map_err(|_| INVALID)?;
    value.update(DOMAIN);
    value.update(&serde_json_canonicalizer::to_vec(intent).map_err(|_| INVALID)?);
    Ok(value)
}
fn verify(raw: &[u8], expected: &Intent, key: &str) -> Result<(), String> {
    let sealed: Sealed = serde_json::from_slice(raw).map_err(|_| INVALID)?;
    if !digest_valid(&sealed.mac, 64) {
        return Err(INVALID.into());
    }
    let tag = sealed
        .mac
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            u8::from_str_radix(std::str::from_utf8(pair).map_err(|_| INVALID)?, 16)
                .map_err(|_| INVALID)
        })
        .collect::<Result<Vec<_>, _>>()?;
    mac(&sealed.intent, key)?
        .verify_slice(&tag)
        .map_err(|_| INVALID)?;
    if &sealed.intent != expected || serde_json::to_vec(&sealed).map_err(|_| INVALID)? != raw {
        return Err(INVALID.into());
    }
    Ok(())
}
impl VerifiedHostRuntime {
    pub(super) fn update_recovery_record_held(
        &self,
        target: &Self,
        payload: &Payload,
        key: &str,
        owner: &mut crate::host_state::Owner,
        review: bool,
    ) -> Result<(), String> {
        self.update_recovery_evidence_held(target, payload, key, owner, review)
            .map(|_| ())
    }
    pub(super) fn update_recovery_evidence_held(
        &self,
        target: &Self,
        payload: &Payload,
        key: &str,
        owner: &mut crate::host_state::Owner,
        review: bool,
    ) -> Result<Vec<u8>, String> {
        let current = owner.update_record()?.ok_or(INVALID)?;
        let record: serde_json::Value = serde_json::from_slice(&current.0).map_err(|_| INVALID)?;
        let intent = Intent {
            schema_version: 1,
            purpose: "native-update-handover".into(),
            operation_id: record["operationId"].as_str().ok_or(INVALID)?.into(),
            installation_id: payload.installation_id.clone(),
            secure_installation_id: payload.secure_installation_id.clone(),
            consumption_sha256: format!("{:x}", Sha256::digest(&current.0)),
            source_manifest_sha256: self.manifest_sha256().into(),
            target_manifest_sha256: target.manifest_sha256().into(),
            from_epoch: self.epoch(),
            to_epoch: target.epoch(),
        };
        if review {
            let raw = owner.update_recovery_evidence()?.ok_or(INVALID)?;
            verify(&raw.0, &intent, key)?;
            Ok(raw.0)
        } else {
            let tag = mac(&intent, key)?
                .finalize()
                .into_bytes()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect();
            let raw = serde_json::to_vec(&Sealed { intent, mac: tag }).map_err(|_| INVALID)?;
            owner.reserve_update_recovery_record(&raw)?;
            Ok(raw)
        }
    }
    /// Persist source-authorized intent before epoch handover. Does not verify backup contents or apply updates.
    pub fn prepare_update_recovery(
        &self,
        target: &Self,
        source: &Configuration,
        destination: &Configuration,
        execution: &HostExecution<'_>,
    ) -> Result<HostUpdateApproval, String> {
        self.prepare_update_recovery_with(
            target,
            [source, destination],
            execution,
            &mut crate::manager_profile::Keystore,
        )
    }
    /// Inspect unchanged pre-destructive context under the admitted target; never executes the old runtime.
    pub fn review_update_recovery(
        &self,
        target: &Self,
        source: &Configuration,
        destination: &Configuration,
        execution: &HostExecution<'_>,
    ) -> Result<HostUpdateApproval, String> {
        self.review_update_recovery_with(
            target,
            [source, destination],
            execution,
            &mut crate::manager_profile::Keystore,
        )
    }
    pub(in crate::host_runtime) fn prepare_update_recovery_with(
        &self,
        target: &Self,
        profiles: [&Configuration; 2],
        execution: &HostExecution<'_>,
        store: &mut impl crate::manager_profile::UpdateStore,
    ) -> Result<HostUpdateApproval, String> {
        self.update_recovery_intent_with(target, profiles, execution, store, false)
    }
    pub(in crate::host_runtime) fn review_update_recovery_with(
        &self,
        target: &Self,
        profiles: [&Configuration; 2],
        execution: &HostExecution<'_>,
        store: &mut impl crate::manager_profile::UpdateStore,
    ) -> Result<HostUpdateApproval, String> {
        self.update_recovery_intent_with(target, profiles, execution, store, true)
    }
    fn update_recovery_intent_with(
        &self,
        target: &Self,
        profiles: [&Configuration; 2],
        execution: &HostExecution<'_>,
        store: &mut impl crate::manager_profile::UpdateStore,
        review: bool,
    ) -> Result<HostUpdateApproval, String> {
        let admission = if review {
            ContextAdmission::TargetRecovery
        } else {
            ContextAdmission::Source
        };
        let mut proof = self.with_consumption_context(
            target,
            profiles,
            (execution, admission),
            None,
            clock,
            store,
            |payload, credentials, owner, _| {
                let key = credentials.backup_key;
                self.update_recovery_record_held(target, payload, key, owner, review)
            },
        )?;
        proof.state = if review {
            "target-recovery-reviewed"
        } else {
            "recovery-intent-prepared"
        };
        Ok(proof)
    }
}
