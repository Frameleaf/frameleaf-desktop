//! Persistent Windows names are identity metadata, never paths for reading or launching.
use crate::manager_host::Configuration;
use serde_json::Value;
pub(super) fn value(
    config: &Configuration,
    manifest: &str,
    [state_identity, manager_identity]: [String; 2],
    names: [String; 4],
) -> Result<Value, String> {
    let [Some(candidate), Some(controller), Some(state), Some(data)] =
        names.map(|name| crate::windows_protection::volume_guid_name(&name))
    else {
        return Err("native_profile_binding_invalid".into());
    };
    let mut configuration =
        serde_json::to_value(config).map_err(|_| "native_profile_binding_invalid")?;
    configuration["controller"] = serde_json::json!(controller);
    configuration["state"] = serde_json::json!(state);
    configuration["data"] = serde_json::json!(data);
    Ok(
        serde_json::json!({"schemaVersion":2, "configuration":configuration,"candidate":candidate,"manifestSha256":manifest,"stateIdentity":state_identity,"managerIdentity":manager_identity}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    fn config(device: u32) -> Configuration {
        let root = format!(r"\\?\GLOBALROOT\Device\HarddiskVolume{device}\Frameleaf");
        Configuration {
            installation_id: "a".repeat(12),
            name: "Synthetic".into(),
            release: "frameleaf-v3.0.0-1".into(),
            controller: format!(r"{root}\controller.exe").into(),
            state: format!(r"{root}\state").into(),
            data: format!(r"{root}\manager").into(),
            origin: "https://127.0.0.1:9443".into(),
            database_port: 54329,
            api_port: 2283,
        }
    }
    fn names() -> [String; 4] {
        ["payload", "controller.exe", "state", "manager"].map(|name| {
            format!(r"\\?\Volume{{11111111-2222-3333-4444-555555555555}}\Frameleaf\{name}")
        })
    }
    fn identities() -> [String; 2] {
        [
            "state-physical-identity".into(),
            "manager-physical-identity".into(),
        ]
    }
    #[test]
    fn kernel_device_renumber_preserves_binding_without_persisting_kernel_paths() {
        let first = value(&config(1), &"b".repeat(64), identities(), names()).unwrap();
        let second = value(&config(99), &"b".repeat(64), identities(), names()).unwrap();
        assert_eq!(first, second);
        assert_eq!(first["schemaVersion"], 2);
        assert!(!first.to_string().contains("HarddiskVolume"));
        assert_eq!(first["configuration"]["state"], names()[2]);
        assert_eq!(first["candidate"], names()[0]);
    }
    #[test]
    fn changed_settings_role_names_and_physical_directories_still_change_binding() {
        let baseline = value(&config(1), &"b".repeat(64), identities(), names()).unwrap();
        let mut changed = config(1);
        changed.api_port = 2284;
        assert_ne!(
            value(&changed, &"b".repeat(64), identities(), names()).unwrap(),
            baseline
        );
        assert_ne!(
            value(&config(1), &"c".repeat(64), identities(), names()).unwrap(),
            baseline
        );
        for index in 0..4 {
            let mut changed = names();
            changed[index].push_str("-other");
            assert_ne!(
                value(&config(1), &"b".repeat(64), identities(), changed).unwrap(),
                baseline
            );
        }
        for index in 0..2 {
            let mut changed = identities();
            changed[index].push_str("-other");
            assert_ne!(
                value(&config(1), &"b".repeat(64), changed, names()).unwrap(),
                baseline
            );
        }
        assert_eq!(
            baseline["configuration"]["installationId"],
            json!("a".repeat(12))
        );
    }
    #[test]
    fn kernel_dos_and_remote_names_cannot_enter_the_persistent_binding() {
        for bad in [
            r"\\?\GLOBALROOT\Device\HarddiskVolume1\profile",
            r"C:\profile",
            r"\\server\share\profile",
            r"\\?\Volume{invalid}\profile",
        ] {
            let mut supplied = names();
            supplied[2] = bad.into();
            assert!(value(&config(1), &"b".repeat(64), identities(), supplied).is_err());
        }
    }
}
