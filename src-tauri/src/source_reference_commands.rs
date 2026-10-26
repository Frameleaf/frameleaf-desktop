use crate::*;
#[derive(Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum ReferenceControl {
    Abandon,
    Discard,
    Rescan,
    ApproveRead,
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
    additional: Option<u64>,
) -> Result<Option<source_reads::ReferenceStatus>, String> {
    require_local(&window)?;
    let current = state.0.lock().await;
    let saved = current.as_ref().ok_or("sign_in_required")?;
    require_reference_source(saved, &source_id)?;
    let reads = app.state::<source_reads::Requests>();
    if additional.is_some() && !matches!(&action, ReferenceControl::ApproveRead) {
        return Err("source_read_request_invalid".into());
    }
    let action = match action {
        ReferenceControl::Abandon => source_reads::PreparationAction::Abandon { expected_scan },
        ReferenceControl::Discard => source_reads::PreparationAction::Discard { expected_scan },
        ReferenceControl::Rescan => {
            source_reads::PreparationAction::RescanSelected { expected_scan }
        }
        ReferenceControl::ApproveRead => source_reads::PreparationAction::ApproveRead {
            expected_scan,
            additional: additional.ok_or("source_read_budget_required")?,
        },
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
#[tauri::command]
pub(crate) async fn start_photo_reference_read(
    window: WebviewWindow,
    app: tauri::AppHandle,
    state: State<'_, DesktopState>,
    source_id: String,
    expected_scan: String,
    request_id: String,
) -> Result<source_reads::ReferenceWork, String> {
    require_local(&window)?;
    let current = state.0.lock().await;
    let saved = current.as_ref().ok_or("sign_in_required")?;
    require_reference_source(saved, &source_id)?;
    let request = source_reads::PreparationRequest {
        source_id,
        scan_id: expected_scan,
        request_id,
    };
    let events = app.clone();
    // Installation returns promptly; the application owner keeps and drains the blocking export.
    app.state::<source_reads::Requests>()
        .start_reference_preparation(
            import_base(&app)?,
            saved.clone(),
            request,
            std::sync::Arc::new(move |work| {
                let _ = events.emit(
                    "photo-reference-work",
                    source_reads::ReferenceWork::Prepare(work),
                );
            }),
        )
        .await
        .map(source_reads::ReferenceWork::Prepare)
}
#[tauri::command]
pub(crate) async fn pause_photo_reference_read(
    window: WebviewWindow,
    app: tauri::AppHandle,
    state: State<'_, DesktopState>,
    source_id: String,
    expected_scan: String,
    request_id: String,
) -> Result<source_reads::ReferenceWork, String> {
    require_local(&window)?;
    let current = state.0.lock().await;
    let saved = current.as_ref().ok_or("sign_in_required")?;
    // Stopping a matching owned request needs no new keystore access or provider permission.
    app.state::<source_reads::Requests>()
        .pause_reference_preparation(
            saved,
            source_reads::PreparationRequest {
                source_id,
                scan_id: expected_scan,
                request_id,
            },
        )
        .await
        .map(source_reads::ReferenceWork::Prepare)
}
#[tauri::command]
pub(crate) async fn photo_reference_work_status(
    window: WebviewWindow,
    app: tauri::AppHandle,
    state: State<'_, DesktopState>,
    source_id: String,
) -> Result<Option<source_reads::ReferenceWork>, String> {
    require_local(&window)?;
    let current = state.0.lock().await;
    let saved = current.as_ref().ok_or("sign_in_required")?;
    app.state::<source_reads::Requests>()
        .reference_work_status(saved, &source_id)
        .await
}
#[tauri::command]
pub(crate) async fn start_photo_reference_recovery(
    window: WebviewWindow,
    app: tauri::AppHandle,
    state: State<'_, DesktopState>,
    source_id: String,
    resource_key: String,
    expected_record: String,
    request_id: String,
) -> Result<source_reads::ReferenceWork, String> {
    require_local(&window)?;
    let current = state.0.lock().await;
    let saved = current.as_ref().ok_or("sign_in_required")?;
    require_reference_source(saved, &source_id)?;
    let events = app.clone();
    app.state::<source_reads::Requests>()
        .start_reference_recovery(
            import_base(&app)?,
            saved.clone(),
            source_reads::RecoveryRequest {
                source_id,
                resource_key,
                record_id: expected_record,
                request_id,
            },
            std::sync::Arc::new(move |work| {
                let _ = events.emit(
                    "photo-reference-work",
                    source_reads::ReferenceWork::Recover(work),
                );
            }),
        )
        .await
        .map(source_reads::ReferenceWork::Recover)
}
#[tauri::command]
pub(crate) async fn pause_photo_reference_recovery(
    window: WebviewWindow,
    app: tauri::AppHandle,
    state: State<'_, DesktopState>,
    source_id: String,
    resource_key: String,
    expected_record: String,
    request_id: String,
) -> Result<source_reads::ReferenceWork, String> {
    require_local(&window)?;
    let current = state.0.lock().await;
    let saved = current.as_ref().ok_or("sign_in_required")?;
    app.state::<source_reads::Requests>()
        .pause_reference_recovery(
            saved,
            source_reads::RecoveryRequest {
                source_id,
                resource_key,
                record_id: expected_record,
                request_id,
            },
        )
        .await
        .map(source_reads::ReferenceWork::Recover)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn reference_controls_cannot_execute_reads_uploads_or_select_paths() {
        for action in ["abandon", "discard", "rescan", "approve-read"] {
            assert!(serde_json::from_value::<ReferenceControl>(serde_json::json!(action)).is_ok());
        }
        for action in ["read", "publish", "approve", "start", "resume", "selection"] {
            assert!(serde_json::from_value::<ReferenceControl>(serde_json::json!(action)).is_err());
        }
    }
}
