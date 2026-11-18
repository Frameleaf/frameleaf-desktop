//! The server's catalogue, as the desktop receives it from the server, for tests that need a real profile.
use frameleaf_desktop::model_catalogue::ApprovedProfile;
use serde_json::Value;

/// The profile a server would serve for this model, configuration and runtime, if it has one.
pub fn approved_profile(
    model_name: &str,
    entries: &Value,
    runtime_source_revision: &str,
    provider: &str,
) -> Result<Option<ApprovedProfile>, String> {
    let catalogue: Value =
        serde_json::from_str(include_str!("../../../runtime/model-catalogue.json")).unwrap();
    catalogue["profiles"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| {
            p["modelName"] == model_name
                && p["spec"]["entries"] == *entries
                && p["runtimeSourceRevision"] == runtime_source_revision
                && p["spec"]["provider"] == provider
        })
        .map(ApprovedProfile::from_served)
        .transpose()
}
