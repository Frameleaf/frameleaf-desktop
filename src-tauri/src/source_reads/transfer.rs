//! Separate explicit original-read and outbound-transfer approvals; neither starts work.
use super::*;
use publication::Receipt;

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AllowanceApproval {
    pub source_id: String,
    pub resource_key: String,
    pub record_id: String,
    pub state_id: String,
    pub additional: u64,
}
impl AllowanceApproval {
    pub(super) fn validate(&self) -> Result<(), String> {
        if !canonical_uuid(&self.source_id)
            || [&self.resource_key, &self.record_id, &self.state_id]
                .iter()
                .any(|value| !crate::native_runtime::digest_valid(value, 64))
            || self.additional == 0
            || self.additional > 2 * 1024 * 1024 * 1024
        {
            return Err("source_transfer_budget_invalid".into());
        }
        Ok(())
    }
}
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TransferStatus {
    pub resource_key: String,
    pub resource_id: String,
    pub version: String,
    pub state_id: String,
    pub bytes: u64,
    pub read_cost: u64,
    pub read_used: u64,
    pub read_remaining: u64,
    pub upload_used: u64,
    pub upload_remaining: u64,
    pub additional_upload: u64,
    pub additional_read: u64,
    pub cache_recorded: bool,
}
fn state_id(state: &State) -> Result<String, String> {
    let mut hash = Sha256::new();
    hash.update(b"frameleaf/reference-transfer-state/v1");
    hash.update(serde_json::to_vec(state).map_err(|_| "source_journal_invalid")?);
    Ok(format!("{:x}", hash.finalize()))
}
impl Job {
    pub(super) fn transfer_status(
        base: &Path,
        saved: &SavedConnection,
        identity: &DeviceIdentity,
        key: &str,
        receipt: &Receipt,
        scope: &str,
    ) -> Result<TransferStatus, String> {
        Self::open_owned(
            base,
            saved,
            identity,
            &receipt.source_id,
            key,
            &receipt.version,
            OpenMode::Inspect,
        )?
        .transfer_view(saved, identity, receipt, scope)
    }
    pub(super) fn transfer_view(
        &self,
        saved: &SavedConnection,
        identity: &DeviceIdentity,
        receipt: &Receipt,
        scope: &str,
    ) -> Result<TransferStatus, String> {
        let state = self.recorded_state(saved, identity)?;
        if self.resource.scope_fingerprint() != scope
            || receipt.source_id != self.resource.source_id()
            || receipt.owner_id != saved.account_id
            || receipt.server_id != saved.server_id
            || receipt.version != self.resource.version()
            || receipt.sha256 != self.resource.sha256
            || receipt.bytes != self.resource.bytes
            || receipt.storage != "reference"
        {
            return Err("source_approval_changed".into());
        }
        let remaining = state.upload.limit - state.upload.used;
        Ok(TransferStatus {
            resource_key: self.resource.resource_key(),
            resource_id: receipt.resource_id.clone(),
            version: self.resource.version(),
            state_id: state_id(&state)?,
            bytes: self.resource.bytes,
            read_cost: self.resource.read_cost(),
            read_used: state.read.used,
            read_remaining: state.read.limit - state.read.used,
            upload_used: state.upload.used,
            upload_remaining: remaining,
            additional_upload: self.resource.bytes.saturating_sub(remaining),
            additional_read: self
                .resource
                .read_cost()
                .saturating_sub(state.read.limit - state.read.used),
            cache_recorded: state.stage.is_some(),
        })
    }
    pub(super) fn approve_transfer_with(
        &self,
        saved: &SavedConnection,
        identity: &DeviceIdentity,
        receipt: &Receipt,
        scope: &str,
        input: &AllowanceApproval,
        gate: &dyn Fn() -> Result<(), String>,
    ) -> Result<TransferStatus, String> {
        input.validate()?;
        gate()?;
        let before = self.transfer_view(saved, identity, receipt, scope)?;
        if input.source_id != self.resource.source_id()
            || input.resource_key != before.resource_key
            || input.state_id != before.state_id
        {
            return Err("source_transfer_state_changed".into());
        }
        if before.additional_upload == 0 || input.additional != before.additional_upload {
            return Err("source_transfer_budget_invalid".into());
        }
        let mut state = self.recorded_state(saved, identity)?;
        state.upload.limit = state
            .upload
            .limit
            .checked_add(input.additional)
            .ok_or("source_transfer_budget_invalid")?;
        state.validate()?;
        self.require_owner()?;
        gate()?;
        self.journal.write("state.json", &state, identity)?;
        gate()?;
        self.transfer_view(saved, identity, receipt, scope)
    }
    pub(super) fn approve_read_with(
        &self,
        saved: &SavedConnection,
        identity: &DeviceIdentity,
        receipt: &Receipt,
        scope: &str,
        input: &AllowanceApproval,
        gate: &dyn Fn() -> Result<(), String>,
    ) -> Result<TransferStatus, String> {
        input.validate()?;
        gate()?;
        let before = self.transfer_view(saved, identity, receipt, scope)?;
        if input.source_id != self.resource.source_id()
            || input.resource_key != before.resource_key
            || input.state_id != before.state_id
        {
            return Err("source_transfer_state_changed".into());
        }
        if before.additional_read == 0 || input.additional != before.additional_read {
            return Err("source_read_budget_invalid".into());
        }
        let mut state = self.recorded_state(saved, identity)?;
        state.read.limit = state
            .read
            .limit
            .checked_add(input.additional)
            .ok_or("source_read_budget_invalid")?;
        state.validate()?;
        self.require_owner()?;
        gate()?;
        self.journal.write("state.json", &state, identity)?;
        gate()?;
        self.transfer_view(saved, identity, receipt, scope)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn transfer_payload_cannot_request_original_reads_or_hide_extra_fields() {
        let input = serde_json::json!({"sourceId":uuid::Uuid::new_v4().to_string(),"resourceKey":"a".repeat(64),"recordId":"b".repeat(64),"stateId":"c".repeat(64),"additional":10});
        serde_json::from_value::<AllowanceApproval>(input.clone())
            .unwrap()
            .validate()
            .unwrap();
        let mut original = input;
        original["read"] = serde_json::json!(10);
        assert!(serde_json::from_value::<AllowanceApproval>(original).is_err());
    }
}
