use crate::*;
#[derive(Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum ReferenceControl {
    Abandon,
    Discard,
}

pub(crate) fn require_reference_source(
    saved: &SavedConnection,
    source: &str,
) -> Result<(), String> {
    let identity = credentials::identity()?;
    let consent = credentials::load::<source_consent::Consent>(source_consent::CREDENTIAL)?
        .ok_or("source_approval_required")?;
    if consent.source_id() != source {
        return Err("source_approval_changed".into());
    }
    consent.reference_metadata_scope(saved, &identity)?;
    Ok(())
}
#[tauri::command]
pub(crate) async fn photo_reference_status(
    window: WebviewWindow,
    app: tauri::AppHandle,
    state: State<'_, DesktopState>,
    source_id: String,
) -> Result<Option<source_reads::ReferenceStatus>, String> {
    require_local(&window)?;
    let current = state.0.lock().await;
    let saved = current.as_ref().ok_or("sign_in_required")?;
    require_reference_source(saved, &source_id)?;
    app.state::<source_reads::Requests>()
        .reference_status(import_base(&app)?, saved.clone(), source_id)
        .await
}
#[tauri::command]
pub(crate) async fn control_photo_reference(
    window: WebviewWindow,
    app: tauri::AppHandle,
    state: State<'_, DesktopState>,
    source_id: String,
    expected_scan: String,
    action: ReferenceControl,
) -> Result<Option<source_reads::ReferenceStatus>, String> {
    require_local(&window)?;
    let current = state.0.lock().await;
    let saved = current.as_ref().ok_or("sign_in_required")?;
    require_reference_source(saved, &source_id)?;
    let reads = app.state::<source_reads::Requests>();
    let action = match action {
        ReferenceControl::Abandon => source_reads::PreparationAction::Abandon { expected_scan },
        ReferenceControl::Discard => source_reads::PreparationAction::Discard { expected_scan },
    };
    reads
        .prepare_reference(
            import_base(&app)?,
            saved.clone(),
            source_id.clone(),
            action,
            std::sync::Arc::new(|_| {}),
        )
        .await?;
    // The desktop-state lease serializes this command with sign-out and other source commands.
    reads.stop().await?;
    reads
        .reference_status(import_base(&app)?, saved.clone(), source_id)
        .await
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn metadata_controls_cannot_grant_reads_uploads_or_change_scope() {
        for action in ["abandon", "discard"] {
            assert!(serde_json::from_value::<ReferenceControl>(serde_json::json!(action)).is_ok());
        }
        for action in ["read", "rescan", "publish", "approve", "start", "resume"] {
            assert!(serde_json::from_value::<ReferenceControl>(serde_json::json!(action)).is_err());
        }
    }
}
