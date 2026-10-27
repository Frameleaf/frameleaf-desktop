use serde_json::Value;

pub fn profiles_for_runtime<'a>(
    catalogue: &'a Value,
    source_revision: &str,
    provider: &str,
) -> Vec<&'a Value> {
    catalogue["profiles"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|profile| {
            profile["runtimeSourceRevision"] == source_revision
                && profile["spec"]["provider"] == provider
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const CURRENT_SOURCE: &str = "1bf2ad55521c49f574cba2f450eb13d49652ea80";

    fn catalogue() -> Value {
        serde_json::from_str(include_str!("../../../runtime/model-catalogue.json")).unwrap()
    }

    #[test]
    fn current_factory_pack_selects_five_roles_for_its_own_provider() {
        let catalogue = catalogue();
        for provider in ["CPUExecutionProvider", "CoreMLExecutionProvider"] {
            let profiles = profiles_for_runtime(&catalogue, CURRENT_SOURCE, provider);
            assert_eq!(profiles.len(), 5);
            assert!(profiles
                .iter()
                .all(|profile| profile["spec"]["provider"] == provider));
            for (workload, count) in [("clip", 3), ("ocr", 1), ("face", 1)] {
                assert_eq!(
                    profiles
                        .iter()
                        .filter(|profile| profile["workload"] == workload)
                        .count(),
                    count
                );
            }
        }
    }

    #[test]
    fn selection_never_falls_back_to_legacy_sources_or_other_providers() {
        let catalogue = catalogue();
        let profiles = profiles_for_runtime(&catalogue, CURRENT_SOURCE, "CPUExecutionProvider");
        assert_ne!(
            profiles[0]["runtimeSourceRevision"],
            catalogue["profiles"][0]["runtimeSourceRevision"]
        );
        assert!(
            profiles_for_runtime(&catalogue, CURRENT_SOURCE, "CUDAExecutionProvider").is_empty()
        );
        assert!(
            profiles_for_runtime(&catalogue, &"0".repeat(40), "CPUExecutionProvider").is_empty()
        );
    }
}
