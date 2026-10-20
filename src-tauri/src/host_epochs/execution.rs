use super::HostEpochAuthority;
use crate::host_runtime::VerifiedHostRuntime;
use std::process::Child;

/// Expected installation identity only; every use rereads authority for the actual runtime.
pub struct HostExecution<'a> {
    authority: &'a dyn HostEpochAuthority,
    installation_id: &'a str,
}
impl<'a> HostExecution<'a> {
    pub fn new(
        authority: &'a dyn HostEpochAuthority,
        installation_id: &'a str,
    ) -> Result<Self, String> {
        if !crate::host_state::valid_installation_id(installation_id) {
            return Err("host_installation_identity_invalid".into());
        }
        Ok(Self {
            authority,
            installation_id,
        })
    }
    /// Callbacks are single-use, ordered and run under one authority lock. Preparation must persist recovery state.
    pub fn transition(
        &self,
        source: &VerifiedHostRuntime,
        target: &VerifiedHostRuntime,
        prepare: impl FnOnce() -> Result<(), String>,
        publish: impl FnOnce() -> Result<(), String>,
    ) -> Result<(), String> {
        let mut prepare = Some(prepare);
        let mut publish = Some(publish);
        let state = std::cell::Cell::new(0);
        let invalid = std::cell::Cell::new(false);
        self.authority.transition(
            self.installation_id,
            [source, target],
            &mut || {
                if state.get() != 0 {
                    invalid.set(true);
                    return Err("host_execution_callback_invalid".into());
                }
                state.set(1);
                prepare.take().ok_or("host_execution_callback_invalid")?()?;
                state.set(2);
                Ok(())
            },
            &mut || {
                if invalid.get() || state.get() != 2 {
                    invalid.set(true);
                    return Err("host_execution_callback_invalid".into());
                }
                state.set(3);
                publish.take().ok_or("host_execution_callback_invalid")?()?;
                state.set(4);
                Ok(())
            },
        )?;
        if invalid.get() || state.get() != 4 {
            return Err("host_execution_callback_invalid".into());
        }
        Ok(())
    }
    pub fn installation_id(&self) -> &str {
        self.installation_id
    }
    pub(crate) fn with_admitted(
        &self,
        runtime: &VerifiedHostRuntime,
        operation: &mut dyn FnMut() -> Result<(), String>,
    ) -> Result<(), String> {
        self.authority
            .with_admitted(self.installation_id, runtime, operation)
    }
    pub(crate) fn spawn(
        &self,
        runtime: &VerifiedHostRuntime,
        launch: impl FnOnce() -> Result<Child, String>,
    ) -> Result<Child, String> {
        let mut launch = Some(launch);
        let mut child = None;
        let mut repeated = false;
        let result = self.with_admitted(runtime, &mut || {
            let Some(launch) = launch.take() else {
                repeated = true;
                return Err("host_execution_callback_invalid".into());
            };
            child = Some(launch()?);
            Ok(())
        });
        // Bootstrap and cleanup must run after the installation credential lock is released.
        if result.is_err() || repeated {
            if let Some(mut child) = child {
                let _ = child.kill();
                let _ = child.wait();
            }
            return Err(result
                .err()
                .unwrap_or_else(|| "host_execution_callback_invalid".into()));
        }
        child.ok_or_else(|| "host_execution_callback_invalid".into())
    }
}

#[cfg(test)]
#[path = "execution_tests.rs"]
mod tests;
