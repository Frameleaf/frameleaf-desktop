//! Historical runtime identity lives beside the installation key, outside rollbackable runtime files.
use crate::native_runtime::{digest_valid, VerifiedRuntime};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeEpochs {
    accepted: BTreeMap<String, Accepted>,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Accepted {
    epoch: u64,
    manifest_sha256: String,
}
impl RuntimeEpochs {
    pub fn validate(&self) -> Result<(), String> {
        if self.accepted.len() > 10
            || self.accepted.iter().any(|(scope, accepted)| {
                let parts: Vec<_> = scope.split('/').collect();
                parts.len() != 4
                    || parts[0] != "factory-v1"
                    || !matches!(parts[1], "macos" | "windows" | "linux")
                    || !matches!(parts[2], "aarch64" | "x86_64")
                    || !matches!(
                        parts[3],
                        "CPUExecutionProvider"
                            | "CUDAExecutionProvider"
                            | "CoreMLExecutionProvider"
                            | "OpenVINOExecutionProvider"
                            | "MIGraphXExecutionProvider"
                    )
                    || accepted.epoch == 0
                    || !digest_valid(&accepted.manifest_sha256, 64)
            })
        {
            return Err("runtime_epoch_record_invalid".into());
        }
        Ok(())
    }
    pub fn check(&self, runtime: &VerifiedRuntime) -> Result<(), String> {
        self.validate()?;
        let namespace = format!(
            "factory-v1/{}/{}/",
            std::env::consts::OS,
            std::env::consts::ARCH
        );
        if self.accepted.iter().any(|(scope, accepted)| {
            scope.starts_with(&namespace) && runtime.epoch() < accepted.epoch
        }) {
            return Err("runtime_epoch_rollback".into());
        }
        if let Some(accepted) = self.accepted.get(&Self::scope(runtime)) {
            if runtime.epoch() == accepted.epoch
                && runtime.manifest_sha256() != accepted.manifest_sha256
            {
                return Err("runtime_epoch_reused".into());
            }
        }
        Ok(())
    }
    pub fn admit(&mut self, runtime: &VerifiedRuntime) -> Result<(), String> {
        self.check(runtime)?;
        let mut next = self.clone();
        next.accepted.insert(
            Self::scope(runtime),
            Accepted {
                epoch: runtime.epoch(),
                manifest_sha256: runtime.manifest_sha256().into(),
            },
        );
        next.validate()?;
        *self = next;
        Ok(())
    }
    fn scope(runtime: &VerifiedRuntime) -> String {
        format!(
            "factory-v1/{}/{}/{}",
            std::env::consts::OS,
            std::env::consts::ARCH,
            runtime.provider()
        )
    }
}

/// Implementations must serialize check/persist/publish across every runtime root for this installation.
pub trait EpochAuthority: Send + Sync {
    fn installation_id(&self) -> Result<String, String>;
    fn check(&self, installation_id: &str, runtime: &VerifiedRuntime) -> Result<(), String> {
        self.with_current(installation_id, runtime, &mut || Ok(()))
    }
    /// Hold the authority lock through use so an admission cannot race a stale launch.
    fn with_current(
        &self,
        installation_id: &str,
        runtime: &VerifiedRuntime,
        operation: &mut dyn FnMut() -> Result<(), String>,
    ) -> Result<(), String>;
    /// Persist the admitted identity before publishing; a failed publish must retain the higher floor.
    fn activate(
        &self,
        installation_id: &str,
        runtime: &VerifiedRuntime,
        publish: &mut dyn FnMut() -> Result<(), String>,
    ) -> Result<(), String>;
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn malformed_or_unknown_historical_records_are_refused() {
        let scope = format!(
            "factory-v1/{}/{}/CPUExecutionProvider",
            std::env::consts::OS,
            std::env::consts::ARCH
        );
        for (key, epoch, digest) in [
            (scope.clone(), 0, "a".repeat(64)),
            (scope, 1, "bad".into()),
            ("server-selected/evil".into(), 1, "a".repeat(64)),
        ] {
            let raw = serde_json::json!({"accepted":{key:{"epoch":epoch,"manifestSha256":digest}}});
            let epochs: RuntimeEpochs = serde_json::from_value(raw).unwrap();
            assert!(epochs.validate().is_err());
        }
        assert!(
            serde_json::from_str::<RuntimeEpochs>(r#"{"accepted":{},"ignoreHistory":true}"#)
                .is_err()
        );
    }
    #[test]
    fn legacy_identity_retains_its_key_but_never_invents_epoch_history() {
        let identity = crate::connection::DeviceIdentity::generate();
        let key = identity.public_key();
        let mut raw = serde_json::to_value(&identity).unwrap();
        assert!(identity.runtime_epochs.is_some());
        raw.as_object_mut().unwrap().remove("runtimeEpochs");
        let legacy: crate::connection::DeviceIdentity = serde_json::from_value(raw).unwrap();
        assert_eq!(legacy.public_key(), key);
        assert!(legacy.runtime_epochs.is_none());
    }
}
