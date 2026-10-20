//! Host history is independent of ML releases and belongs in the installation credential.
mod execution;
use crate::{host_runtime::VerifiedHostRuntime, native_runtime::digest_valid};
pub use execution::HostExecution;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HostEpochs {
    accepted: Vec<Accepted>,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Accepted {
    scope: String,
    epoch: u64,
    manifest_sha256: String,
}
impl HostEpochs {
    pub fn validate(&self) -> Result<(), String> {
        let mut seen = BTreeSet::new();
        if self.accepted.len() > 6
            || self.accepted.iter().any(|accepted| {
                let parts: Vec<_> = accepted.scope.split('/').collect();
                parts.len() != 3
                    || parts[0] != "factory-host-v1"
                    || !matches!(parts[1], "macos" | "windows" | "linux")
                    || !matches!(parts[2], "aarch64" | "x86_64")
                    || !seen.insert(accepted.scope.as_str())
                    || accepted.epoch == 0
                    || !digest_valid(&accepted.manifest_sha256, 64)
            })
        {
            return Err("host_epoch_record_invalid".into());
        }
        Ok(())
    }
    /// Checks history only; execution also needs verified files, profile binding and code leases.
    pub fn check(&self, runtime: &VerifiedHostRuntime) -> Result<(), String> {
        self.validate()?;
        if let Some(accepted) = self
            .accepted
            .iter()
            .find(|entry| entry.scope == Self::scope())
        {
            if runtime.epoch() < accepted.epoch {
                return Err("host_epoch_rollback".into());
            }
            if runtime.epoch() == accepted.epoch
                && runtime.manifest_sha256() != accepted.manifest_sha256
            {
                return Err("host_epoch_reused".into());
            }
        }
        Ok(())
    }
    /// Changes in-memory history only; callers must persist it before publishing activation.
    pub fn admit(&mut self, runtime: &VerifiedHostRuntime) -> Result<(), String> {
        self.check(runtime)?;
        runtime.check_files()?;
        let entry = Accepted {
            scope: Self::scope(),
            epoch: runtime.epoch(),
            manifest_sha256: runtime.manifest_sha256().into(),
        };
        let mut next = self.clone();
        if let Some(current) = next
            .accepted
            .iter_mut()
            .find(|value| value.scope == entry.scope)
        {
            *current = entry;
        } else {
            next.accepted.push(entry);
        }
        next.accepted.sort_by(|a, b| a.scope.cmp(&b.scope));
        next.validate()?;
        *self = next;
        Ok(())
    }
    /// Requires a prior persisted admission; a merely newer verified release cannot execute.
    pub fn require_admitted(&self, runtime: &VerifiedHostRuntime) -> Result<(), String> {
        self.check(runtime)?;
        if !self.accepted.iter().any(|entry| {
            entry.scope == Self::scope()
                && entry.epoch == runtime.epoch()
                && entry.manifest_sha256 == runtime.manifest_sha256()
        }) {
            return Err("host_epoch_not_admitted".into());
        }
        runtime.check_files()
    }
    fn scope() -> String {
        format!(
            "factory-host-v1/{}/{}",
            std::env::consts::OS,
            std::env::consts::ARCH
        )
    }
}

/// Per-user credential transactions. Callers still need secure profile binding, code leases and journal guards.
pub trait HostEpochAuthority: Send + Sync {
    /// One installation lock: admitted source, recovery preparation, confirmed target floor, then publication.
    /// Callbacks must use held internal guards, never reenter installation credentials or wait for child readiness.
    /// Providers without an atomic implementation must refuse rather than compose two separate transactions.
    fn transition(
        &self,
        _installation_id: &str,
        _runtimes: [&VerifiedHostRuntime; 2],
        _prepare: &mut dyn FnMut() -> Result<(), String>,
        _publish: &mut dyn FnMut() -> Result<(), String>,
    ) -> Result<(), String> {
        Err("host_epoch_transition_unsupported".into())
    }
    fn installation_id(&self) -> Result<String, String>;
    /// Re-read authority and hold its lock across bounded use of a previously admitted candidate.
    /// Callbacks must not reenter installation credentials or wait for a child needing that lock.
    fn with_admitted(
        &self,
        installation_id: &str,
        runtime: &VerifiedHostRuntime,
        operation: &mut dyn FnMut() -> Result<(), String>,
    ) -> Result<(), String>;
    /// Persist and confirm history before publishing. A failed publish never lowers the saved floor.
    /// Publishing must not reenter installation credentials or wait for child readiness.
    fn activate(
        &self,
        installation_id: &str,
        runtime: &VerifiedHostRuntime,
        publish: &mut dyn FnMut() -> Result<(), String>,
    ) -> Result<(), String>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn invalid_or_duplicate_history_never_becomes_an_empty_floor() {
        let good = json!({"scope":HostEpochs::scope(),"epoch":7,"manifestSha256":"a".repeat(64)});
        for (field, value) in [
            (
                "scope",
                json!("factory-v1/macos/aarch64/CPUExecutionProvider"),
            ),
            ("scope", json!("factory-host-v2/macos/aarch64")),
            ("scope", json!("factory-host-v1/unknown/aarch64")),
            ("scope", json!("factory-host-v1/macos/unknown")),
            ("epoch", json!(0)),
            ("manifestSha256", json!("bad")),
        ] {
            let mut entry = good.clone();
            entry[field] = value;
            let history: HostEpochs = serde_json::from_value(json!({"accepted":[entry]})).unwrap();
            assert!(history.validate().is_err());
        }
        for entries in [vec![good.clone(), good.clone()], vec![good; 7]] {
            let history: HostEpochs = serde_json::from_value(json!({"accepted":entries})).unwrap();
            assert!(history.validate().is_err());
        }
        for raw in [
            json!({"accepted":[],"reset":true}),
            json!({"accepted":[{"scope":HostEpochs::scope(),"epoch":1,"manifestSha256":"a".repeat(64),"ignore":true}]}),
        ] {
            assert!(serde_json::from_value::<HostEpochs>(raw).is_err());
        }
    }
    #[test]
    fn legacy_identity_preserves_key_and_ml_history_without_inventing_host_history() {
        let original = crate::connection::DeviceIdentity::generate();
        let key = original.public_key();
        let signature = original.sign("history-preservation");
        let mut raw = serde_json::to_value(&original).unwrap();
        let scope = format!(
            "factory-v1/{}/{}/CPUExecutionProvider",
            std::env::consts::OS,
            std::env::consts::ARCH
        );
        let ml = json!({"accepted":{scope:{"epoch":999,"manifestSha256":"b".repeat(64)}}});
        raw["runtimeEpochs"] = ml.clone();
        raw.as_object_mut().unwrap().remove("hostEpochs");
        let legacy: crate::connection::DeviceIdentity = serde_json::from_value(raw).unwrap();
        assert!(legacy.host_epochs.is_none());
        legacy.runtime_epochs.as_ref().unwrap().validate().unwrap();
        assert_eq!(legacy.public_key(), key);
        assert_eq!(legacy.sign("history-preservation"), signature);
        let saved = serde_json::to_value(&legacy).unwrap();
        assert_eq!(saved["runtimeEpochs"], ml);
        assert!(saved["hostEpochs"].is_null());
    }
}

#[cfg(test)]
#[path = "../tests/common/host_authority.rs"]
pub(crate) mod host_authority;
#[cfg(test)]
#[path = "../tests/common/host_fixture.rs"]
pub(crate) mod host_fixture;
