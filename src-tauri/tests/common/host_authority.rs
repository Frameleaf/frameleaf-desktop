use super::{HostEpochAuthority, HostEpochs, HostExecution, VerifiedHostRuntime};
use std::sync::Mutex;

pub const ID: &str = "11111111-1111-4111-8111-111111111111";

pub struct Authority(pub Mutex<(String, HostEpochs)>);
impl Authority {
    pub fn execution(&self) -> HostExecution<'_> {
        HostExecution::new(self, ID).unwrap()
    }
    pub fn admitted(runtime: &VerifiedHostRuntime) -> Self {
        let mut epochs = HostEpochs::default();
        epochs.admit(runtime).unwrap();
        Self(Mutex::new((ID.into(), epochs)))
    }
}
impl HostEpochAuthority for Authority {
    fn installation_id(&self) -> Result<String, String> {
        Ok(self.0.lock().unwrap().0.clone())
    }
    fn with_admitted(
        &self,
        id: &str,
        runtime: &VerifiedHostRuntime,
        operation: &mut dyn FnMut() -> Result<(), String>,
    ) -> Result<(), String> {
        let state = self.0.lock().unwrap();
        if state.0 != id {
            return Err("host_installation_identity_changed".into());
        }
        state.1.require_admitted(runtime)?;
        operation()
    }
    fn activate(
        &self,
        id: &str,
        runtime: &VerifiedHostRuntime,
        publish: &mut dyn FnMut() -> Result<(), String>,
    ) -> Result<(), String> {
        let mut state = self.0.lock().unwrap();
        if state.0 != id {
            return Err("host_installation_identity_changed".into());
        }
        state.1.admit(runtime)?;
        publish()
    }
}
