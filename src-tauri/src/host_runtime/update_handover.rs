//! Verified pre-destructive epoch handover only; no database migration or runtime publication.
use super::*;
use std::{
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};
impl VerifiedHostRuntime {
    /// Verify the exact backup and persist recovery intent before irreversibly admitting the target epoch.
    /// A failure may follow a successful epoch save; reconcile target recovery without lowering history.
    pub fn begin_update_handover(
        &self,
        target: &Self,
        source: &Configuration,
        destination: &Configuration,
        execution: &HostExecution<'_>,
        cancel: &AtomicBool,
    ) -> Result<HostUpdateApproval, String> {
        self.begin_update_handover_with(
            target,
            [source, destination],
            execution,
            cancel,
            &mut crate::manager_profile::Keystore,
        )
    }
    pub(in crate::host_runtime) fn begin_update_handover_with(
        &self,
        target: &Self,
        profiles: [&Configuration; 2],
        execution: &HostExecution<'_>,
        cancel: &AtomicBool,
        store: &mut impl crate::manager_profile::UpdateStore,
    ) -> Result<HostUpdateApproval, String> {
        self.handover_with_backup(
            target,
            profiles,
            execution,
            cancel,
            store,
            |payload, key, deadline| {
                self.read_update_backup_held(profiles[0], payload, key, cancel, deadline)
            },
        )
    }
    #[cfg(test)]
    pub(in crate::host_runtime) fn begin_update_handover_test(
        &self,
        target: &Self,
        profiles: [&Configuration; 2],
        execution: &HostExecution<'_>,
        cancel: &AtomicBool,
        store: &mut impl crate::manager_profile::UpdateStore,
        mut verify: impl FnMut(&Payload, &str) -> Result<(), String>,
    ) -> Result<HostUpdateApproval, String> {
        self.handover_with_backup(
            target,
            profiles,
            execution,
            cancel,
            store,
            |payload, key, _| verify(payload, key),
        )
    }
    fn handover_with_backup(
        &self,
        target: &Self,
        profiles: [&Configuration; 2],
        execution: &HostExecution<'_>,
        cancel: &AtomicBool,
        store: &mut impl crate::manager_profile::UpdateStore,
        mut verify: impl FnMut(&Payload, &str, Instant) -> Result<(), String>,
    ) -> Result<HostUpdateApproval, String> {
        if cancel.load(Ordering::Acquire) {
            return Err(INVALID.into());
        }
        let deadline = Instant::now() + Duration::from_secs(7200);
        let mut proof = self.with_consumption_context(
            target,
            profiles,
            (execution, ContextAdmission::Handover { cancel, deadline }),
            None,
            clock,
            store,
            |payload, credentials, owner, _| {
                let key = credentials.backup_key;
                verify(payload, key, deadline)?;
                self.update_recovery_record_held(target, payload, key, owner, false)
            },
        )?;
        proof.state = "target-admitted";
        Ok(proof)
    }
}
