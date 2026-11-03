use frameleaf_desktop::{
    native_runtime::VerifiedRuntime,
    runtime_epochs::{EpochAuthority, RuntimeEpochs},
};
use std::sync::{Arc, Mutex};
pub struct MemoryEpochAuthority {
    pub id: Mutex<String>,
    pub epochs: Mutex<RuntimeEpochs>,
    pub unavailable: std::sync::atomic::AtomicBool,
    pub fail_persist: std::sync::atomic::AtomicBool,
    pub fail_publish: std::sync::atomic::AtomicBool,
}
impl Default for MemoryEpochAuthority {
    fn default() -> Self {
        Self {
            id: Mutex::new(uuid::Uuid::new_v4().to_string()),
            epochs: Mutex::new(RuntimeEpochs::default()),
            unavailable: false.into(),
            fail_persist: false.into(),
            fail_publish: false.into(),
        }
    }
}
impl EpochAuthority for MemoryEpochAuthority {
    fn installation_id(&self) -> Result<String, String> {
        if self.unavailable.load(std::sync::atomic::Ordering::Acquire) {
            return Err("credential_store_locked_or_unavailable".into());
        }
        Ok(self.id.lock().unwrap().clone())
    }
    fn with_current(
        &self,
        installation_id: &str,
        runtime: &VerifiedRuntime,
        operation: &mut dyn FnMut() -> Result<(), String>,
    ) -> Result<(), String> {
        if self.unavailable.load(std::sync::atomic::Ordering::Acquire) {
            return Err("credential_store_locked_or_unavailable".into());
        }
        if *self.id.lock().unwrap() != installation_id {
            return Err("runtime_epoch_identity_changed".into());
        }
        let epochs = self.epochs.lock().unwrap();
        epochs.check(runtime)?;
        operation()
    }
    fn activate(
        &self,
        installation_id: &str,
        runtime: &VerifiedRuntime,
        publish: &mut dyn FnMut() -> Result<(), String>,
    ) -> Result<(), String> {
        if self.unavailable.load(std::sync::atomic::Ordering::Acquire) {
            return Err("credential_store_locked_or_unavailable".into());
        }
        if *self.id.lock().unwrap() != installation_id {
            return Err("runtime_epoch_identity_changed".into());
        }
        let mut epochs = self.epochs.lock().unwrap();
        let mut next = epochs.clone();
        next.admit(runtime)?;
        if self.fail_persist.load(std::sync::atomic::Ordering::Acquire) {
            return Err("credential_store_locked_or_unavailable".into());
        }
        *epochs = next;
        if self.fail_publish.load(std::sync::atomic::Ordering::Acquire) {
            return Err("runtime_store_activation_failed".into());
        }
        publish()
    }
}
pub fn authority() -> Arc<MemoryEpochAuthority> {
    Arc::new(MemoryEpochAuthority::default())
}
