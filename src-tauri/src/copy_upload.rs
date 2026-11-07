//! Resumable transfer of approved staged bytes; ingestion is not a managed-source receipt.
use crate::{
    connection::{normalize_server, Capabilities, DeviceIdentity, SavedConnection},
    copy_source::StagedCopy,
    transport,
};
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine,
};
use reqwest::{Client, Method, Response};
use serde::{Deserialize, Serialize};
use std::{
    io::{Read, Seek, SeekFrom},
    path::Path,
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};
use url::Url;
use uuid::Uuid;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FolderUploadBinding {
    kind: String,
    source_id: String,
    run_id: String,
    item_id: String,
}
impl UploadSession {
    pub(crate) fn resource_id(&self) -> &str {
        &self.resource_id
    }
}
impl FolderUploadBinding {
    pub fn new(copy: &StagedCopy, run: &str, item: &str) -> Result<Self, String> {
        let value = Self {
            kind: "folder".into(),
            source_id: copy.source_id().into(),
            run_id: run.into(),
            item_id: item.into(),
        };
        value.validate(copy)?;
        Ok(value)
    }
    fn validate(&self, copy: &StagedCopy) -> Result<(), String> {
        if self.kind != "folder"
            || self.source_id != copy.source_id()
            || [&self.source_id, &self.run_id, &self.item_id]
                .iter()
                .any(|id| !canonical_uuid(id))
        {
            return Err("source_upload_binding_invalid".into());
        }
        Ok(())
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UploadSession {
    resource_id: String,
    stage_id: String,
    binding: FolderUploadBinding,
    signature: String,
}
/// Even a matching duplicate still needs the NAS source service's healthy-owned-bytes receipt.
#[derive(Debug, PartialEq)]
pub enum UploadOutcome {
    Pending,
    Ingested { asset_id: String, duplicate: bool },
}
fn session_signature(
    saved: &SavedConnection,
    identity: &DeviceIdentity,
    copy: &StagedCopy,
    resource: &str,
    binding: &FolderUploadBinding,
) -> Result<String, String> {
    let value = serde_json_canonicalizer::to_vec(&(
        normalize_server(&saved.server)?.as_str(),
        &saved.server_id,
        &saved.account_id,
        &saved.device_id,
        &identity.installation_id,
        &copy.id,
        &copy.sha256,
        copy.bytes,
        resource,
        binding,
    ))
    .map_err(|_| "source_upload_journal_invalid")?;
    Ok(identity.sign(&format!(
        "frameleaf-desktop/copy-upload/v2\n{}",
        String::from_utf8(value).map_err(|_| "source_upload_journal_invalid")?
    )))
}
fn canonical_uuid(value: &str) -> bool {
    Uuid::parse_str(value).is_ok_and(|id| !id.is_nil() && id.to_string() == value)
}
fn resource_id(base: &Url, location: &str) -> Result<String, String> {
    let url = base
        .join(location)
        .map_err(|_| "source_upload_location_invalid")?;
    let prefix = "/api/assets/uploads/";
    let id = url
        .path()
        .strip_prefix(prefix)
        .ok_or("source_upload_location_invalid")?;
    if url.origin() != base.origin()
        || !canonical_uuid(id)
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || (location != url.path() && location != url.as_str())
    {
        return Err("source_upload_location_invalid".into());
    }
    Ok(id.into())
}
fn header<'a>(response: &'a Response, name: &str) -> Result<&'a str, String> {
    let mut values = response.headers().get_all(name).iter();
    let value = values
        .next()
        .ok_or("source_upload_response_invalid")?
        .to_str()
        .map_err(|_| "source_upload_response_invalid")?;
    if values.next().is_some() {
        return Err("source_upload_response_invalid".into());
    }
    Ok(value)
}
fn number(value: &str) -> Result<u64, String> {
    if value.is_empty()
        || !value.bytes().all(|b| b.is_ascii_digit())
        || (value.len() > 1 && value.starts_with('0'))
    {
        return Err("source_upload_response_invalid".into());
    }
    value
        .parse()
        .map_err(|_| "source_upload_response_invalid".into())
}
fn offset(response: &Response, size: u64) -> Result<(u64, bool), String> {
    let offset = number(header(response, "upload-offset")?)?;
    let complete = match header(response, "upload-complete")? {
        "?0" => false,
        "?1" => true,
        _ => return Err("source_upload_response_invalid".into()),
    };
    if offset > size || (complete && offset != size) {
        return Err("source_upload_response_invalid".into());
    }
    Ok((offset, complete))
}
fn check_cancel(cancelled: &AtomicBool) -> Result<(), String> {
    if cancelled.load(Ordering::Acquire) {
        Err("source_copy_cancelled".into())
    } else {
        Ok(())
    }
}
pub(crate) async fn send(
    request: reqwest::RequestBuilder,
    cancelled: &AtomicBool,
) -> Result<Response, String> {
    check_cancel(cancelled)?;
    let wait = async {
        loop {
            tokio::time::sleep(Duration::from_millis(100)).await;
            if cancelled.load(Ordering::Acquire) {
                break;
            }
        }
    };
    tokio::select! { biased;
        _=wait=>Err("source_copy_cancelled".into()),
        response=request.send()=>{check_cancel(cancelled)?;response.map_err(|_|String::from("source_upload_interrupted"))}
    }
}
fn success(response: &Response, expected: &[u16]) -> Result<(), String> {
    if expected.contains(&response.status().as_u16()) {
        Ok(())
    } else {
        Err(format!("source_upload_http_{}", response.status().as_u16()))
    }
}
fn protocol(response: &Response) -> Result<(), String> {
    if header(response, "upload-draft-interop-version")? == "9" {
        Ok(())
    } else {
        Err("source_upload_protocol_unsupported".into())
    }
}
fn limits(response: &Response, bytes: u64) -> Result<usize, String> {
    let mut max_size = None;
    let mut append = None;
    for part in header(response, "upload-limit")?.split(',') {
        let (name, value) = part
            .trim()
            .split_once('=')
            .ok_or("source_upload_response_invalid")?;
        match name {
            "max-size" => {
                let previous = max_size.replace(number(value)?);
                if previous.is_some() {
                    return Err("source_upload_response_invalid".into());
                }
            }
            "max-append-size" => {
                let previous = append.replace(number(value)?);
                if previous.is_some() {
                    return Err("source_upload_response_invalid".into());
                }
            }
            _ => {}
        }
    }
    if bytes == 0 || bytes > max_size.ok_or("source_upload_response_invalid")? {
        return Err("source_upload_capacity_exceeded".into());
    }
    match append {
        Some(n) if n > 0 => Ok(n.min(1024 * 1024) as usize),
        _ => Err("source_upload_response_invalid".into()),
    }
}
/// The upload's Content-Type from the file's extension; a name without one is plain bytes.
fn upload_mime(filename: &str) -> &'static str {
    let extension = Path::new(filename)
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    match extension.as_str() {
        "mp4" | "m4v" => "video/mp4",
        "mov" => "video/quicktime",
        _ => "application/octet-stream",
    }
}
fn date(ms: i64) -> Result<String, String> {
    let value = time::OffsetDateTime::from_unix_timestamp_nanos(i128::from(ms) * 1_000_000)
        .map_err(|_| "source_date_invalid")?;
    if !(0..=9999).contains(&value.year()) {
        return Err("source_date_invalid".into());
    }
    Ok(format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
        value.year(),
        u8::from(value.month()),
        value.day(),
        value.hour(),
        value.minute(),
        value.second(),
        value.millisecond()
    ))
}
/// `persist` must durably save the signed session before returning success. Cancellation pauses it.
#[allow(clippy::too_many_arguments)]
pub async fn upload(
    saved: &SavedConnection,
    identity: &DeviceIdentity,
    copy: &StagedCopy,
    binding: &FolderUploadBinding,
    staging: &Path,
    session: &mut Option<UploadSession>,
    mut persist: impl FnMut(&UploadSession) -> Result<(), String>,
    cancelled: &AtomicBool,
    gate: &(dyn Fn() -> Result<(), String> + Sync),
) -> Result<UploadOutcome, String> {
    transfer(
        &transport::client()?,
        &normalize_server(&saved.server)?,
        saved,
        identity,
        copy,
        binding,
        staging,
        session,
        |session, _| persist(session),
        cancelled,
        gate,
    )
    .await
}
#[allow(clippy::too_many_arguments)]
pub(crate) async fn transfer(
    client: &Client,
    base: &Url,
    saved: &SavedConnection,
    identity: &DeviceIdentity,
    copy: &StagedCopy,
    binding: &FolderUploadBinding,
    staging: &Path,
    session: &mut Option<UploadSession>,
    mut persist: impl FnMut(&UploadSession, u64) -> Result<(), String>,
    cancelled: &AtomicBool,
    gate: &(dyn Fn() -> Result<(), String> + Sync),
) -> Result<UploadOutcome, String> {
    check_cancel(cancelled)?;
    gate()?;
    binding.validate(copy)?;
    let mut file = copy.verify(saved, identity, staging)?;
    let filename = copy.filename()?;
    let metadata=URL_SAFE_NO_PAD.encode(serde_json::to_vec(&serde_json::json!({"filename":filename,"fileCreatedAt":date(copy.file_created_at_ms)?,"fileModifiedAt":date(copy.file_modified_at_ms)?,"sourceIdentity":binding})).map_err(|_|"source_upload_metadata_invalid")?);
    if metadata.len() > 8192 {
        return Err("source_upload_metadata_invalid".into());
    }
    if let Some(current) = session.as_ref() {
        if current.stage_id != copy.id
            || current.binding != *binding
            || !canonical_uuid(&current.resource_id)
            || current.signature
                != session_signature(saved, identity, copy, &current.resource_id, binding)?
        {
            return Err("source_upload_journal_invalid".into());
        }
        persist(current, 0)?;
    }
    // Recheck the live server and photo owner before revealing filenames or media.
    let request = |method: Method, path: &str| {
        client
            .request(method, base.join(path).expect("fixed API path"))
            .bearer_auth(&saved.token)
    };
    let caps: Capabilities =
        transport::json(send(request(Method::GET, "api/desktop/capabilities"), cancelled).await?)
            .await?;
    if saved.server_id.is_empty() || caps.protocol_version != 1 || caps.server_id != saved.server_id
    {
        return Err("server_identity_changed".into());
    }
    #[derive(Deserialize)]
    struct Owner {
        id: String,
    }
    gate()?;
    let owner: Owner =
        transport::json(send(request(Method::GET, "api/users/me"), cancelled).await?).await?;
    if owner.id != saved.account_id {
        return Err("account_identity_changed".into());
    }
    gate()?;
    let response = send(request(Method::OPTIONS, "api/assets/uploads"), cancelled).await?;
    success(&response, &[204])?;
    protocol(&response)?;
    let chunk_size = limits(&response, copy.bytes)?;
    gate()?;
    let (mut durable, complete) = if let Some(current) = session.as_ref() {
        let response = send(
            request(
                Method::HEAD,
                &format!("api/assets/uploads/{}", current.resource_id),
            )
            .header("Upload-Draft-Interop-Version", "9"),
            cancelled,
        )
        .await?;
        success(&response, &[204])?;
        protocol(&response)?;
        offset(&response, copy.bytes)?
    } else {
        let digest: Vec<u8> = (0..copy.sha256.len())
            .step_by(2)
            .map(|index| {
                u8::from_str_radix(&copy.sha256[index..index + 2], 16)
                    .map_err(|_| "source_stage_invalid")
            })
            .collect::<Result<_, _>>()?;
        let mime = upload_mime(filename);
        let response = send(
            request(Method::POST, "api/assets/uploads")
                .header("Upload-Draft-Interop-Version", "9")
                .header("Upload-Complete", "?0")
                .header("Upload-Length", copy.bytes)
                .header(
                    "Repr-Digest",
                    format!("sha-256=:{}:", STANDARD.encode(digest)),
                )
                .header("Asset-Metadata", metadata)
                .header("Content-Type", mime)
                .body(Vec::new()),
            cancelled,
        )
        .await?;
        success(&response, &[201])?;
        protocol(&response)?;
        let id = resource_id(base, header(&response, "location")?)?;
        let initial = offset(&response, copy.bytes)?;
        if initial != (0, false) {
            return Err("source_upload_response_invalid".into());
        }
        *session = Some(UploadSession {
            signature: session_signature(saved, identity, copy, &id, binding)?,
            resource_id: id,
            stage_id: copy.id.clone(),
            binding: binding.clone(),
        });
        persist(session.as_ref().unwrap(), 0)?;
        initial
    };
    let path = format!(
        "api/assets/uploads/{}",
        session.as_ref().unwrap().resource_id
    );
    if !complete {
        file.seek(SeekFrom::Start(durable))
            .map_err(|_| "source_stage_unavailable")?;
        // An empty completion retries ingestion when all bytes were acknowledged before interruption.
        loop {
            check_cancel(cancelled)?;
            gate()?;
            let count = (copy.bytes - durable).min(chunk_size as u64) as usize;
            let mut bytes = vec![0; count];
            file.read_exact(&mut bytes)
                .map_err(|_| "source_stage_changed")?;
            let expected = durable + count as u64;
            // Persist admission before a send; a lost response or cancellation never refunds it.
            persist(session.as_ref().unwrap(), count as u64)?;
            let response = send(
                request(Method::PATCH, &path)
                    .header("Upload-Draft-Interop-Version", "9")
                    .header("Content-Type", "application/partial-upload")
                    .header("Upload-Offset", durable)
                    .header(
                        "Upload-Complete",
                        if expected == copy.bytes { "?1" } else { "?0" },
                    )
                    .body(bytes),
                cancelled,
            )
            .await?;
            success(&response, &[200, 202, 204])?;
            protocol(&response)?;
            let (ack, _) = offset(&response, copy.bytes)?;
            if ack != expected {
                return Err("source_upload_offset_invalid".into());
            }
            durable = ack;
            if durable == copy.bytes {
                break;
            }
        }
    }
    gate()?;
    let response = send(request(Method::GET, &format!("{path}/result")), cancelled).await?;
    success(&response, &[200, 202])?;
    protocol(&response)?;
    if response.status().as_u16() == 202 {
        return Ok(UploadOutcome::Pending);
    }
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct ResultDto {
        id: String,
        status: String,
        sha256: String,
    }
    let result: ResultDto = transport::json(response).await?;
    if !canonical_uuid(&result.id)
        || result.sha256 != copy.sha256
        || !matches!(result.status.as_str(), "created" | "duplicate")
    {
        return Err("source_upload_receipt_invalid".into());
    }
    check_cancel(cancelled)?;
    Ok(UploadOutcome::Ingested {
        asset_id: result.id,
        duplicate: result.status == "duplicate",
    })
}

#[cfg(test)]
#[path = "copy_upload_tests.rs"]
pub(crate) mod tests;
