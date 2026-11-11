//! Private installed-candidate fixture. Production builds omit the entry point.
use super::*;
use serde_json::{json, Value};
use std::fs::File;
use zeroize::Zeroizing;

const PREFIX: &str = "Frameleaf Media Move Qualification ";
const KEY: &str = "qualification-key.json";
const REVIEW: &str = "qualification-review.json";
const INTERRUPT: &str = "qualification-interrupt-once";
const PHOTO: &str = "qualification-photo.ppm";
const PIXELS: &[u8] = b"P6\n1 1\n255\n\x40\x80\xc0";

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Input {
    protocol_version: u32,
    fixture_id: Uuid,
    action: Action,
    host: Option<Host>,
    library_id: Option<String>,
    reviewed_backup: Option<Value>,
    confirmed_review_sha256: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "kebab-case")]
enum Action {
    Create,
    Seed,
    Review,
    Stage,
    AbortStage,
    InterruptNextCutover,
    CheckInterruptedCutover,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Host {
    installation_id: String,
    candidate: PathBuf,
    manifest_sha256: String,
}

fn root_path(fixture: Uuid) -> Result<PathBuf, String> {
    if fixture.get_version_num() != 4 {
        return Err(INVALID.into());
    }
    Ok(crate::host_install::windows_local_app_data()?.join(format!("{PREFIX}{fixture}")))
}

struct Fixture {
    path: PathBuf,
    directory: Dir,
    _pins: Vec<File>,
}

impl Fixture {
    fn open(path: PathBuf) -> Result<Self, String> {
        let pins = crate::windows_protection::pin_private_directory(&path)?;
        let directory = Dir::from_std_file(crate::host_storage::directory(&path)?);
        Ok(Self {
            path,
            directory,
            _pins: pins,
        })
    }

    fn device(&self) -> Result<DeviceIdentity, String> {
        let raw = Zeroizing::new(activation::read_record(&self.directory, KEY)?.ok_or(INVALID)?);
        serde_json::from_slice(&raw).map_err(|_| INVALID.into())
    }
}

fn fixture_for(state: &Path) -> Result<Option<Fixture>, String> {
    let Some(parent) = state.parent() else {
        return Ok(None);
    };
    let Some(suffix) = parent
        .file_name()
        .and_then(|name| name.to_str())
        .and_then(|name| name.strip_prefix(PREFIX))
    else {
        return Ok(None);
    };
    let id: Uuid = suffix.parse().map_err(|_| INVALID)?;
    let root = root_path(id)?;
    if state != root.join("state") {
        return Err(INVALID.into());
    }
    Fixture::open(root).map(Some)
}

pub(crate) fn device_for(state: &Path) -> Result<Option<DeviceIdentity>, String> {
    fixture_for(state)?
        .map(|fixture| fixture.device())
        .transpose()
}

/// One-shot process-boundary refusal after the real durable intent exists.
pub(crate) fn interrupt_after_intent(state: &Path) -> Result<(), String> {
    let Some(fixture) = fixture_for(state)? else {
        return Ok(());
    };
    if activation::read_record(&fixture.directory, INTERRUPT)?.is_none() {
        return Ok(());
    }
    fixture
        .directory
        .remove_file(INTERRUPT)
        .map_err(|_| INVALID)?;
    activation::sync_directory(&fixture.directory)?;
    Err("host_media_move_qualification_interrupted".into())
}

pub(crate) fn pin_profile(state: &Path, data: &Path) -> Result<Option<Vec<File>>, String> {
    let Some(fixture) = fixture_for(state)? else {
        return Ok(None);
    };
    if data != fixture.path.join("manager") {
        return Err(INVALID.into());
    }
    fixture.device()?;
    let mut pins = fixture._pins;
    for directory in [state, data] {
        pins.extend(crate::windows_protection::pin_private_directory(directory)?);
        crate::host_storage::check(directory)?;
    }
    Ok(Some(pins))
}

fn fixture_inventory(owner: &Owner, seeded: bool) -> Result<Inventory, String> {
    const SERVER_FOLDERS: &[&str] = &[
        "encoded-video",
        "library",
        "upload",
        "profile",
        "thumbs",
        "backups",
        "exports",
    ];
    let source = source(owner)?;
    let mut photo_seen = false;
    let mut expected_entries = 0;
    let mut expected_bytes = 0;
    for entry in source.entries().map_err(|_| INVALID)?.take(9) {
        let name = entry.map_err(|_| INVALID)?.file_name();
        let name = name.to_str().ok_or(INVALID)?;
        expected_entries += 1;
        if name == PHOTO && seeded {
            let mut photo = staged_file(&source, Path::new(PHOTO))?;
            let mut value = Vec::new();
            Read::by_ref(&mut photo)
                .take(64)
                .read_to_end(&mut value)
                .map_err(|_| INVALID)?;
            if value != PIXELS {
                return Err(INVALID.into());
            }
            photo_seen = true;
            expected_bytes += value.len() as u64;
            continue;
        }
        if !SERVER_FOLDERS.contains(&name) {
            return Err(INVALID.into());
        }
        let folder = child(&source, name)?;
        let mut entries = folder.entries().map_err(|_| INVALID)?;
        if let Some(entry) = entries.next() {
            if entry.map_err(|_| INVALID)?.file_name() != ".frameleaf" || entries.next().is_some() {
                return Err(INVALID.into());
            }
            let mut marker = staged_file(&folder, Path::new(".frameleaf"))?;
            let mut value = Vec::new();
            Read::by_ref(&mut marker)
                .take(32)
                .read_to_end(&mut value)
                .map_err(|_| INVALID)?;
            if !(10..=16).contains(&value.len()) || !value.iter().all(u8::is_ascii_digit) {
                return Err(INVALID.into());
            }
            expected_entries += 1;
            expected_bytes += value.len() as u64;
        }
    }
    if photo_seen != seeded {
        return Err(INVALID.into());
    }
    let scanned = inventory(&source, None, &|| false)?;
    if scanned.entries != expected_entries || scanned.bytes != expected_bytes {
        return Err(INVALID.into());
    }
    Ok(scanned)
}

pub(crate) fn run(raw: &[u8]) -> Result<Value, String> {
    let input: Input = serde_json::from_slice(raw).map_err(|_| INVALID)?;
    if input.protocol_version != 1 {
        return Err(INVALID.into());
    }
    let root = root_path(input.fixture_id)?;
    let state = root.join("state");
    let target = root.join("target");
    if matches!(input.action, Action::Create) {
        if input.host.is_some()
            || input.library_id.is_some()
            || input.reviewed_backup.is_some()
            || input.confirmed_review_sha256.is_some()
        {
            return Err(INVALID.into());
        }
        runtime_store::create_private_directory(&root)?;
        let fixture = Fixture::open(root)?;
        for path in [&state, &target, &fixture.path.join("manager")] {
            runtime_store::create_private_directory(path)?;
        }
        let secret = Zeroizing::new(bytes(&DeviceIdentity::generate())?);
        persist(&fixture.directory, KEY, &secret)?;
        return Ok(json!({
            "protocolVersion":1,"state":"fixture-created","statePath":state,
            "managerPath":fixture.path.join("manager"),"targetPath":target,
            "secureInstallationId":crate::host_state::secure_installation_id(&state)?
        }));
    }
    let fixture = Fixture::open(root)?;
    let device = fixture.device()?;
    let host = input.host.ok_or(INVALID)?;
    if !crate::native_runtime::digest_valid(&host.installation_id, 12) {
        return Err(INVALID.into());
    }
    crate::host_control::separate_paths(&host.candidate, &state)?;
    crate::host_control::separate_paths(&host.candidate, &target)?;
    let _lease = crate::package_lease::CodeLease::acquire(&host.candidate)?;
    crate::host_control::verify_candidate(&host.candidate, &host.manifest_sha256)?;
    let mut owner = Owner::acquire(&state, true)?;
    owner.check_movable(&host.installation_id, &host.manifest_sha256)?;
    let marker = owner.inspect(&host.installation_id, &host.manifest_sha256)?;
    let secure_installation_id = owner.secure_installation_id();

    if matches!(input.action, Action::Seed) {
        super::super::no_media_move(&owner.root)?;
        if marker.media_reference.is_some() {
            return Err(INVALID.into());
        }
        let media_path = state.join("media");
        runtime_store::private_directory(&media_path)?;
        fixture_inventory(&owner, false)?;
        let media = source(&owner)?;
        persist(&media, PHOTO, PIXELS)?;
        return Ok(json!({"protocolVersion":1,"state":"fixture-seeded"}));
    }

    let scanned = fixture_inventory(&owner, true)?;
    drop(owner);
    if matches!(input.action, Action::Review) {
        let review = Review::prepare(
            &state,
            &target,
            &host.installation_id,
            &host.manifest_sha256,
            input.library_id.as_deref().ok_or(INVALID)?,
            input.reviewed_backup.ok_or(INVALID)?,
            || false,
        )?;
        if review.inventory != scanned {
            return Err(CHANGED.into());
        }
        let raw = bytes(&review)?;
        persist(&fixture.directory, REVIEW, &raw)?;
        return Ok(json!({
            "protocolVersion":1,"state":"fixture-reviewed","reviewSha256":digest(&raw),
            "targetPath":target,"entries":review.inventory.entries,"bytes":review.inventory.bytes
        }));
    }

    let raw = activation::read_record(&fixture.directory, REVIEW)?.ok_or(INVALID)?;
    let review: Review = serde_json::from_slice(&raw).map_err(|_| INVALID)?;
    if input.confirmed_review_sha256.as_deref() != Some(digest(&raw).as_str())
        || review.target != target
        || review.owner != marker
        || review.inventory != scanned
    {
        return Err(CHANGED.into());
    }
    let approval = review.approve(&device)?;
    if matches!(input.action, Action::AbortStage) {
        approval.rollback(&state, &device, || false)?;
        return Ok(json!({"protocolVersion":1,"state":"fixture-original-restored"}));
    }
    if matches!(input.action, Action::InterruptNextCutover) {
        if approval.status(&state, &device)? != Status::SelectedFenced {
            return Err(INVALID.into());
        }
        persist(&fixture.directory, INTERRUPT, b"interrupt-after-intent")?;
        return Ok(json!({"protocolVersion":1,"state":"fixture-interruption-armed"}));
    }
    if matches!(input.action, Action::CheckInterruptedCutover) {
        let owner = Owner::acquire(&state, true)?;
        approval.require_fence(&owner)?;
        let journal = approval.journal(&owner)?;
        let raw = activation::read_record(&journal, CUTOVER)?.ok_or(INVALID)?;
        let intent: CutoverIntent = serde_json::from_slice(&raw).map_err(|_| INVALID)?;
        if intent.request.binding.move_id != approval.review.operation_id {
            return Err(INVALID.into());
        }
        return Ok(json!({
            "protocolVersion":1,"state":"fixture-cutover-interrupted",
            "operationId":intent.request.operation_id,"decision":intent.decision
        }));
    }
    approval.copy(&state, &device, || false)?;
    approval.select_fenced(&state, &device, || false)?;
    let owner = Owner::acquire(&state, true)?;
    let journal = approval.journal(&owner)?;
    let copy = approval.receipt(&journal, &device)?.ok_or(INVALID)?;
    let binding = CutoverBinding {
        move_id: approval.review.operation_id,
        secure_installation_id,
        manifest_sha256: host.manifest_sha256,
        library_id: approval.review.library_id,
        profile_identity: marker.profile_identity,
        source_generation: marker.generation,
        source_identity: approval.review.source_identity,
        target_identity: copy.target_identity.clone(),
        staged_identity: copy.stage_identity.clone(),
        approval_sha256: copy.approval_sha256.clone(),
        copy_receipt_sha256: digest(&bytes(&copy)?),
    };
    Ok(json!({"protocolVersion":1,"state":"selected-fenced","binding":binding}))
}
