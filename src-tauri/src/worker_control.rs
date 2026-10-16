use crate::{connection::SavedConnection, credentials};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub(crate) enum WorkerControl {
    #[default]
    Running,
    Paused,
    Stopped,
}
fn key(saved: &SavedConnection) -> Result<String, String> {
    let device = saved
        .device_id
        .as_deref()
        .ok_or("desktop_enrollment_required")?;
    if saved.mode != "client-worker"
        || saved.server_id.is_empty()
        || saved.account_id.is_empty()
        || device.is_empty()
    {
        return Err("desktop_enrollment_required".into());
    }
    let scope = serde_json::to_vec(&[saved.server_id.as_str(), saved.account_id.as_str(), device])
        .map_err(|_| "worker_preference_invalid")?;
    Ok(format!("worker-control-{:x}", Sha256::digest(scope)))
}
pub(crate) fn load(saved: &SavedConnection) -> Result<WorkerControl, String> {
    Ok(credentials::load(&key(saved)?)?.unwrap_or_default())
}
pub(crate) fn save(saved: &SavedConnection, control: WorkerControl) -> Result<(), String> {
    credentials::save(&key(saved)?, &control)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn persisted_controls_are_scoped_to_server_account_and_device() {
        let mut saved = crate::connection::SavedConnection {
            server: "https://synthetic.test/".into(),
            server_id: "server-a".into(),
            account_id: "account-a".into(),
            device_id: Some("device-a".into()),
            name: "Synthetic".into(),
            token: "synthetic".into(),
            device_name: "Synthetic".into(),
            mode: "client-worker".into(),
        };
        let original = key(&saved).unwrap();
        saved.server_id = "server-b".into();
        assert_ne!(key(&saved).unwrap(), original);
        saved.server_id = "server-a".into();
        saved.account_id = "account-b".into();
        assert_ne!(key(&saved).unwrap(), original);
        saved.account_id = "account-a".into();
        saved.device_id = Some("device-b".into());
        assert_ne!(key(&saved).unwrap(), original);
        saved.device_id = None;
        assert!(key(&saved).is_err());
        assert!(serde_json::from_str::<WorkerControl>("\"invalid\"").is_err());
        for value in [
            WorkerControl::Running,
            WorkerControl::Paused,
            WorkerControl::Stopped,
        ] {
            assert_eq!(
                serde_json::from_str::<WorkerControl>(&serde_json::to_string(&value).unwrap())
                    .unwrap(),
                value
            );
        }
    }
}
