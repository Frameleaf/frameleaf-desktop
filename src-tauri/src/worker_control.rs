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
/// Keep existing string preferences readable while storing a deadline for temporary pauses.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(untagged, deny_unknown_fields)]
pub(crate) enum Preference {
    Manual(WorkerControl),
    Timed {
        #[serde(rename = "pausedUntil")]
        until: u64,
    },
}
impl Preference {
    pub fn effective(self, now: u64) -> WorkerControl {
        match self {
            Self::Manual(control) => control,
            Self::Timed { until } if now >= until => WorkerControl::Running,
            Self::Timed { .. } => WorkerControl::Paused,
        }
    }
    pub fn resume_due(self, expected: u64, now: u64) -> bool {
        matches!(self, Self::Timed { until } if until == expected && now >= until)
    }
    pub fn held(self) -> WorkerControl {
        match self {
            Self::Manual(control) => control,
            Self::Timed { .. } => WorkerControl::Paused,
        }
    }
}
pub(crate) fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |value| {
            value.as_millis().min(u128::from(u64::MAX)) as u64
        })
}
pub(crate) fn key(saved: &SavedConnection) -> Result<String, String> {
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
pub(crate) fn load(saved: &SavedConnection) -> Result<Preference, String> {
    Ok(credentials::load(&key(saved)?)?.unwrap_or(Preference::Manual(WorkerControl::Running)))
}
pub(crate) fn save(saved: &SavedConnection, control: WorkerControl) -> Result<(), String> {
    save_preference(saved, Preference::Manual(control))
}
pub(crate) fn save_preference(
    saved: &SavedConnection,
    preference: Preference,
) -> Result<(), String> {
    credentials::save(&key(saved)?, &preference)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn timed_pause_expires_without_changing_manual_preference_format() {
        let timed = Preference::Timed { until: 200 };
        assert_eq!(timed.effective(199), WorkerControl::Paused);
        assert_eq!(timed.effective(200), WorkerControl::Running);
        assert_eq!(timed.held(), WorkerControl::Paused);
        assert!(!timed.resume_due(200, 199));
        assert!(timed.resume_due(200, 200));
        assert!(!timed.resume_due(100, 200));
        assert!(!Preference::Manual(WorkerControl::Paused).resume_due(200, 200));
        assert!(!Preference::Manual(WorkerControl::Stopped).resume_due(200, 200));
        assert_eq!(
            serde_json::from_str::<Preference>(&serde_json::to_string(&timed).unwrap()).unwrap(),
            timed
        );
        assert_eq!(
            serde_json::from_str::<Preference>(r#""paused""#)
                .unwrap()
                .effective(200),
            WorkerControl::Paused
        );
        assert_eq!(
            serde_json::to_string(&Preference::Manual(WorkerControl::Stopped)).unwrap(),
            r#""stopped""#
        );
    }
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
