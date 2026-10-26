<script lang="ts">
  import { invoke, isTauri } from '@tauri-apps/api/core';
  import { onMount } from 'svelte';
  import { sourceCopyApprovals } from './source-copy-state';
  import { listen, type UnlistenFn } from '@tauri-apps/api/event';
  type Hint = { label: string; path: string };
  type Availability = { available: number; needsDownload: number; notReady: number; unknown: number; pinned: number; downloadBytes: number };
  type Inventory = { kind: string; selectionId: string; path: string; photos: number; logicalBytes: number; skipped: number; truncated: boolean; availability: Availability };
  let photosCount = $state(10);
  const macos = nativePlatform();
  function nativePlatform() { return typeof navigator !== 'undefined' && /Mac/.test(navigator.platform); }
  let hints = $state<Hint[]>([]);
  let folder = $state<Inventory | null>(null);
  type Consent = { mode?: 'copy' | 'reference'; reconnectRequired?: boolean; allowPhotosHydration: boolean; kind: string; id: string; name: string; path: string; registered: boolean; allowDownload: boolean };
  type CopyJob = { sourceReadRemaining: number | null; additionalSourceReadAllowance: number; provider: string | null; stagedBytes: number | null; exportRemaining: number | null; additionalExportAllowance: number; sourceId: string; state: string; total: number; completed: number; logicalBytes: number; skipped: number; code: string | null; availability: Availability | null; uploadRemaining: number | null; additionalUploadAllowance: number };
  let job = $state<CopyJob | null>(null);
  let approvals = $derived(job ? sourceCopyApprovals(job) : { read: false, export: false, upload: false, canResumeWithoutUpload: false, canResume: false });
  let consent = $state<Consent | null>(null);
  let blockedConsent = $state(false);
  let allowHydration = $state(false);
  let allowReads = $state(false);
  let alive = true;
  let busy = $state(false);
  let message = $state('');
  const native = isTauri();
  const errors: Record<string, string> = {
    photos_macos_update_required: 'Apple Photos integration needs macOS 11 or later. You can still choose an exported photo folder.',
    photos_macos_required: 'Apple Photos is available on macOS. Choose a photo folder on this computer.',
    photos_permission_required: 'Photos access is unavailable or was revoked. Enable it in macOS System Settings, or remove this source permission. Staged data is kept.',
    photos_permission_pending: 'The macOS Photos permission request is still pending. Finish it, then try again.',
    photos_scope_invalid: 'No supported originals were selected. Choose a smaller recent scope or export originals manually from Photos.',
    photos_scope_too_large: 'The selection contains more than 100 original resources. Select fewer recent photos.',
    photos_metadata_invalid: 'Photos metadata could not be verified. No originals were read. Try again.',
    photos_scope_changed: 'Photos no longer exposes this exact approved original. Copying stopped; existing staged bytes are kept. Remove this source and select it again.',
    photos_original_resources_unavailable: 'An original format or paired resource cannot be copied safely. Export those originals from Photos manually.',
    photos_original_unavailable: 'Photos could not export the original, or the export timed out. Check iCloud and Photos access before retrying; staged data is kept.',
    photos_export_interrupted: 'An earlier export was interrupted. Its staged bytes are retained. Retry with an export allowance; it will use a fresh attempt.',
    photos_export_budget_exceeded: 'This original exceeds the approved 2 GiB resource ceiling. Its partial staged bytes are kept. Export this original manually from Photos.',
    photos_export_budget_required: 'This copy needs an explicit export allowance before Photos can read originals.',
    photos_export_budget_exhausted: 'The Photos export allowance was used, including interrupted attempts. Approve another bounded export allowance to retry. Staged bytes are kept.',
    source_metadata_unavailable: 'File metadata could not be checked safely. Check folder access before resuming; staged data is kept.',
    source_folder_excluded: 'This folder is hidden or excluded. Choose an ordinary visible photo folder.',
    source_item_excluded: 'A file or folder became hidden or excluded. Copying stopped before reading it; existing staged data is kept.',
    source_item_invalid: 'This file is unsupported or linked. Some Windows cloud placeholders cannot be copied yet; export selected photos to an ordinary folder and try there.',

    source_preview_policy_unavailable: 'A download-free folder preview could not be enabled. No preview was started. Try again after restarting the app.',
    source_inventory_partial: 'The scan reached its safety limit. Choose a smaller photo subfolder for this copy.',
    source_inventory_unreadable: 'Some entries could not be inspected. Check folder and drive access before preparing the copy again.',
    source_no_media: 'No supported photo or video files were found in this folder.',
    source_copy_budget_exceeded: 'This copy exceeds the server’s current size limits. Choose a smaller subfolder or remove unsupported large files from the selected scope.',
    source_staging_overlap: 'Choose a photo folder outside the app’s own data folder.',
    source_identity_unavailable: 'The filesystem could not provide a reliable file identity. Copying stopped; staged originals are kept. Try an ordinary local photo folder.',
    source_approval_upgrade_required: 'This folder permission uses an older Windows file identity. Remove the source permission and choose the folder again before reading more originals. Verified staged copies are kept.',
    source_item_changed: 'A selected file changed after the scan. This copy is paused; the original and staged data are kept.',
    source_cloud_provider_unavailable: 'The cloud provider could not deliver this original. Check the provider and network before approving another read attempt.',
    source_read_shutdown_unconfirmed: 'Photo-source work could not confirm it stopped. Your files and saved permission have been kept.',
    source_read_shutting_down: 'Photo-source work is stopping before Frameleaf quits.',
    source_copy_shutdown_unconfirmed: 'The source reader could not confirm a clean stop. Private staging was kept, and no new source work will start.',
    source_cloud_copy_pending: 'This Windows cloud folder can be previewed, but copying its placeholders is still being implemented. Export originals to an ordinary local folder for now.',
    source_capacity_unavailable: 'Available storage space could not be checked. Reconnect the photo-source and app-storage volumes, then resume.',
    source_capacity_insufficient: 'There is not enough free space for this original and its staged copy. Free space on the photo-source and app-storage volumes, then resume.',
    source_run_paused: 'Your server paused this copy before another original was staged. Resume explicitly when ready.',
    source_server_processing: 'Your server is still finishing this photo. Its staged original is retained; resume the copy when the server is ready.',
    source_receipt_invalid: 'The server did not confirm the expected healthy original. Copying stopped and the staged original was retained.',
    source_journal_invalid: 'Saved copy progress could not be verified. Staged originals are retained; do not remove them while investigating.',
    source_journal_write_failed: 'Copy progress could not be saved. Check local disk space and access before resuming; staged originals are retained.',
    source_stop_confirmation_pending: 'Copying stopped on this computer. The server could not confirm its stop yet; existing server copies are kept.',
    source_cache_cleanup_pending: 'The verified copy is on your server, but its local staging cache could not be cleared. Check local file access before resuming.',
    source_staging_budget_exceeded: 'The private staging limit is full. Finish existing source transfers and confirmed cleanup before resuming. Retained files are kept.',
    source_input_budget_busy: 'Another source operation is reserving staging space. Wait for it to finish, then resume.',
    source_input_budget_invalid: 'Saved staging capacity could not be verified. Source work is stopped and retained files are kept.',
    source_input_budget_untracked: 'Existing staged files need recovery before another original can be staged. Finish or recover existing source work before resuming; staged originals are kept.',
    source_read_budget_required: 'Reading another original needs an allowance. Approve the displayed amount, then resume. Already staged copies are kept.',
    source_read_budget_exhausted: 'The original-read allowance was used, including interrupted attempts. Approve more original reads to retry; staged copies are kept.',
    source_upload_budget_required: 'This saved copy needs an upload allowance before it can send original data. Approve the displayed amount, then resume.',
    source_upload_budget_exhausted: 'This copy reached its upload allowance. Staged originals are kept. Approve more upload data to retry.',
    source_copy_mode_required: 'This source permission does not allow copying. Remove it before approving a copy.',
    source_reference_mode_required: 'This source permission does not allow serving originals to the server.',
    source_copy_cancelled: 'Copying is paused. Resume when you are ready.',
    metered_network: 'Copying is paused on this metered connection. Resume on an unmetered network.',
    network_unknown: 'Network cost could not be determined. Resume when an unmetered connection is available.',
    server_http_409: 'The server refused this copy. Check its source permission and original-file health before resuming; staged data is kept.',

    source_selection_changed: 'The folder selection expired. Choose the folder again.',
    source_remove_previous_approval: 'Remove the existing folder permission before choosing another folder.',
    source_photo_session_changed: 'This folder permission belongs to an earlier sign-in. Remove it and approve the folder again.',
    source_approval_invalid: 'The saved folder permission no longer matches this connection. Remove it before continuing.',
    credential_store_locked_or_unavailable: 'Unlock your computer’s credential store, then try again.',
    credential_store_unavailable: 'Your computer’s secure credential store is unavailable.',
    credential_record_invalid: 'The saved folder permission could not be read. Remove it before continuing.',
    server_http_404: 'Your server needs the desktop photo-source update before this folder can be registered.',
    source_server_update_required: 'Your server needs the desktop photo-source update.',
    source_registration_unavailable: 'The server could not be reached. The local permission is saved; retry registration when connected.',
    source_registration_response_invalid: 'The server did not confirm this exact source permission. Source work remains stopped.',
    source_reference_reapproval_required: 'This reference permission needs a new local approval before reconnecting.',
    server_identity_changed: 'The server identity changed. Sign out before reconnecting.',

    source_choose_photo_subfolder: 'Choose a photo folder inside your home folder, rather than your entire home folder.',
    source_package_requires_provider: 'Use the Apple Photos button to read selected originals through macOS, or export originals from Photos and choose the exported folder.',
    source_folder_unavailable: 'This folder is unavailable. Check that its drive is connected and you have access.',
    source_account_unavailable: 'This OneDrive folder moved or is unavailable. Choose its new location.',
  };
  function explain(error: unknown) { return errors[String(error)] ?? 'This operation could not finish. Check the server connection and try again.'; }
  function copyAllowed() { return !!consent && (consent.mode ?? 'copy') === 'copy'; }
  async function loadConsent() {
    const previous = consent;
    try {
      const current = await invoke<Consent | null>('photo_source_status');
      if (alive && consent === previous) { consent = current; blockedConsent = false; if (!copyAllowed()) job = null; }
    } catch (error) {
      if (alive && consent === previous) {
        blockedConsent = ['source_photo_session_changed', 'source_approval_invalid', 'credential_record_invalid', 'photos_permission_required', 'photos_macos_required'].includes(String(error));
        message = explain(error);
      }
    }
  }
  onMount(() => {
    let unlisten: UnlistenFn | undefined;
    if (native) void (async () => {
      try {
        unlisten = await listen<CopyJob>('photo-import', event => { if (alive && copyAllowed() && event.payload.sourceId === consent?.id) job = event.payload; });
        if (!alive) { unlisten(); return; }
        await loadConsent();
        if (consent?.registered && copyAllowed()) {
          const source = consent;
          const previous = job;
          // A permission change or live progress event supersedes this snapshot.
          const isCurrent = () => alive && consent === source && job === previous;
          try {
            const current = await invoke<CopyJob | null>('photo_import_status');
            if (isCurrent() && (!current || current.sourceId === source.id)) job = current;
          } catch (error) { if (isCurrent()) message = explain(error); }
        }
      } catch (error) { if (alive) message = explain(error); }
    })();
    return () => { alive = false; unlisten?.(); };
  });
  function size(bytes: number) {
    if (bytes >= 1e9) return `${(bytes / 1e9).toFixed(1)} GB`;
    if (bytes >= 1e6) return `${(bytes / 1e6).toFixed(1)} MB`;
    if (bytes >= 1e3) return `${(bytes / 1e3).toFixed(1)} kB`;
    return `${bytes} bytes`;
  }
  function availabilityText(value: Availability) {
    return `${value.available.toLocaleString()} OS-reported available; ${value.needsDownload.toLocaleString()} need downloading (${size(value.downloadBytes)} in originals); ${value.notReady.toLocaleString()} provider not ready; ${value.unknown.toLocaleString()} unknown. ${value.pinned.toLocaleString()} request pinning. These are metadata snapshots; pinning does not prove a complete local original. Unknown files may also need downloading.`;
  }
  async function prepareCopy() {
    if (!copyAllowed()) { message = errors.source_copy_mode_required; return; }
    const source = consent;
    const previous = job;
    busy = true; message = '';
    try {
      const current = await invoke<CopyJob>('prepare_photo_import');
      if (alive && consent === source && job === previous && current.sourceId === source?.id) job = current;
    }
    catch (error) { if (alive && consent === source) message = explain(error); }
    finally { busy = false; }
  }
  async function controlCopy(action: 'resume' | 'pause' | 'cancel' | 'approve-upload' | 'approve-export' | 'approve-read') {
    if (!copyAllowed()) { message = errors.source_copy_mode_required; return; }
    const source = consent;
    const previous = job;
    busy = true; message = '';
    try {
      const current = await invoke<CopyJob>('control_photo_import', { action });
      if (alive && consent === source && job === previous && current.sourceId === source?.id) job = current;
    }
    catch (error) { if (alive && consent === source) message = explain(error); }
    finally { busy = false; }
  }
  async function approve(retry = false) {
    if (!retry && (!folder || !allowReads)) return;
    busy = true; message = '';
    try {
      consent = await invoke<Consent>('approve_photo_folder', { selectionId: retry ? null : folder!.selectionId, allowDownload: allowReads, allowPhotosHydration: allowHydration });
      folder = null; allowReads = false; allowHydration = false;
    } catch (error) { await loadConsent(); message = explain(error); }
    finally { busy = false; }
  }
  async function reconnect() {
    if (consent?.mode !== 'reference' || !consent.reconnectRequired) return;
    const source = consent;
    busy = true; message = '';
    try {
      const current = await invoke<Consent>('reconnect_photo_source', { sourceId: source.id });
      if (alive && consent === source) {
        if (current.id !== source.id || current.mode !== 'reference' || !current.registered || current.reconnectRequired) {
          message = errors.source_registration_response_invalid;
        } else {
          consent = current; job = null; blockedConsent = false; message = 'Reference source reconnected.';
        }
      }
    } catch (error) { if (alive && consent === source) message = explain(error); }
    finally { busy = false; }
  }
  async function revoke() {
    const reference = consent?.mode === 'reference';
    busy = true; message = '';
    try {
      const confirmed = await invoke<boolean>('revoke_photo_source');
      consent = null; job = null; blockedConsent = false; folder = null; allowReads = false; allowHydration = false;
      message = reference
        ? (confirmed ? 'Reference permission removed. Library entries are kept; this computer no longer serves their originals.' : 'Local reference permission removed. The server could not confirm revocation; check it when connected.')
        : (confirmed ? 'Folder permission removed. Existing server copies are kept.' : 'Local folder permission removed. The server could not confirm revocation; check it when connected.');
    } catch (error) { message = explain(error); }
    finally { busy = false; }
  }
  async function discover() {
    busy = true; message = '';
    try {
      hints = await invoke<Hint[]>('discover_onedrive');
      if (!hints.length) message = 'No OneDrive folder was found in the known sync locations. You can choose a synced folder yourself.';
    } catch { message = 'Could not check OneDrive locations. Choose a synced folder yourself.'; }
    finally { busy = false; }
  }
  async function choosePhotos() {
    busy = true; message = '';
    try { folder = await invoke<Inventory>('choose_apple_photos', { count: photosCount }); allowReads = false; allowHydration = false; }
    catch (error) { message = explain(error); }
    finally { busy = false; }
  }
  async function choose(oneDrive: number | null = null) {
    busy = true; message = '';
    try {
      const selected = await invoke<Inventory | null>('choose_photo_folder', { oneDrive });
      if (selected) { folder = selected; allowReads = false; allowHydration = false; }
    } catch (error) { message = errors[String(error)] ?? 'Could not preview this folder. Choose an accessible photo folder and try again.'; }
    finally { busy = false; }
  }
</script>

<section class="sources" aria-labelledby="photo-sources-heading" aria-busy={busy}>
  <h2 id="photo-sources-heading">Photo sources</h2>
  <p>Choose where to bring photos from. Local folders are separate from this computer’s AI processing permission.</p>
  <div class="actions">
    <button class="secondary" disabled={busy || !native || !!consent || blockedConsent} onclick={() => choose()}>Choose a photo folder</button>
    <button class="text-button" disabled={busy || !native || !!consent || blockedConsent} onclick={discover}>Find OneDrive folders</button>
  </div>
  {#if macos}
    <div class="actions">
      <label>Apple Photos scope <select bind:value={photosCount} disabled={busy || !!consent || blockedConsent}>
        {#each [1, 10, 25, 50, 100] as count}<option value={count}>Most recent {count} {count === 1 ? 'asset' : 'assets'}</option>{/each}
      </select></label>
      <button class="secondary" disabled={busy || !native || !!consent || blockedConsent} onclick={choosePhotos}>Choose Apple Photos originals</button>
    </div>
    <p class="footnote">This button requests macOS Photos access. Preview reads metadata only from the accessible System Photo Library; it does not download originals. iCloud Photos must be enabled in Photos to expose its originals here.</p>
  {/if}
  {#if hints.length}
    <ul aria-label="Known OneDrive folders">
      {#each hints as hint, index (hint.path)}
        <li><strong>{hint.label}</strong><small>{hint.path}</small><button class="text-button" disabled={busy} onclick={() => choose(index)}>Choose folders</button></li>
      {/each}
    </ul>
  {/if}
  {#if busy}<p role="status">Waiting for the folder or server operation to finish…</p>{/if}
  {#if message}<p role="status">{message}</p>{/if}
  {#if consent}
    <div class="folder-preview" aria-label="Approved photo folder">
      <strong>{consent.name}</strong><p>{consent.path}</p>
      {#if consent.kind === 'apple-photos'}<p class="footnote">{consent.allowPhotosHydration ? 'Photos-managed iCloud downloads are allowed. They can exceed the export/staging ceiling.' : 'Photos network downloads are disabled. Cloud-only originals will stop safely until you remove this permission and approve hydration in a new selection.'}</p>{/if}
      {#if consent.reconnectRequired}
        <p>Reconnect this reference source to your current sign-in using its saved scope and permissions.</p>
        <button class="secondary" disabled={busy} onclick={reconnect}>Reconnect source</button>
      {:else}
        <p>{consent.registered ? 'Source permission saved and registered with your server.' : 'Source permission saved locally. Server registration still needs to finish.'}</p>
        {#if !consent.registered}<button class="secondary" disabled={busy} onclick={() => approve(true)}>Retry server registration</button>{/if}
      {/if}
      {#if consent.registered && copyAllowed() && !job}
        <p>Prepare a bounded copy plan before opening any originals. You can review its file count and data size before starting.</p>
        <button class="secondary" disabled={busy} onclick={prepareCopy}>Prepare copy</button>
      {/if}
      {#if job && copyAllowed()}
        <div class="copy-job" aria-label="Photo copy progress">
          <p role="status">{job.state === 'complete' ? 'Copy complete' : job.state === 'cancelled' ? 'Copy cancelled' : job.state === 'copying' ? 'Copying' : job.state === 'ready' ? 'Copy prepared' : job.state === 'paused' ? 'Copy paused' : 'Copy needs attention'}: {job.completed.toLocaleString()} of {job.total.toLocaleString()} copies confirmed.</p>
          <progress max={Math.max(1, job.total)} value={job.completed} aria-label="Copies verified on your server"></progress>
          <p class="footnote">{job.provider ? 'Maximum selected export data' : 'Prepared originals'}: {size(job.logicalBytes)}. {job.skipped ? `${job.skipped.toLocaleString()} linked or excluded entries were skipped. ` : ''}Originals stay in their source. A copy is confirmed only after your server verifies its stored bytes.</p>
          {#if job.provider}
            <p class="footnote">Original sizes are unknown until export. Each resource is capped at 2 GiB; Live Photo and RAW companion resources are copied separately in original formats. {job.exportRemaining === null ? 'No export allowance remains approved.' : `${size(job.exportRemaining)} of maximum exported data remaining.`} Every export attempt reserves its full ceiling before reading, including retries. Interrupted bytes remain in local staging. Photos-managed downloads are separate and can exceed this ceiling when you enable hydration.</p>
            {#if job.stagedBytes !== null}<p class="footnote">Current verified staged original: {size(job.stagedBytes)}. Upload approval is separate from Photos export.</p>{/if}
            {#if approvals.export}<button class="secondary" disabled={busy} onclick={() => controlCopy('approve-export')}>Approve {size(job.additionalExportAllowance)} more export data</button>{/if}
          {/if}
          {#if !job.provider}
            <p class="footnote">{job.sourceReadRemaining === null ? 'New reads of originals need approval. Already staged copies can resume.' : `${size(job.sourceReadRemaining)} of original reads remaining.`} Each attempt counts the full original, including retries and cached files. This allowance covers logical file data; cloud-provider traffic can be larger.</p>
            {#if approvals.read}
              <button class="secondary" disabled={busy} onclick={() => controlCopy('approve-read')}>Approve {size(job.additionalSourceReadAllowance)} more original reads</button>
            {/if}
          {/if}
          <p class="footnote">{job.uploadRemaining === null ? 'No upload allowance approved.' : `${size(job.uploadRemaining)} of original upload data remaining, including retries.`} Protocol overhead and downloads from your cloud provider are separate. Interrupted sends count in full; resuming does not reset this allowance.</p>
          {#if approvals.upload}
            <button class="secondary" disabled={busy} onclick={() => controlCopy('approve-upload')}>Approve {size(job.additionalUploadAllowance)} more upload data</button>
          {/if}
          {#if job.availability}<p class="footnote" aria-label="Prepared file availability">{availabilityText(job.availability)}</p>{/if}
          {#if job.code}<p role="status">{explain(job.code)}</p>{/if}
          {#if ['ready', 'paused', 'needs-attention'].includes(job.state)}
            <button class="secondary" disabled={busy || !approvals.canResume} onclick={() => controlCopy('resume')}>{approvals.canResumeWithoutUpload ? 'Resume without more upload data' : job.provider && job.stagedBytes === null ? 'Export next original within allowance' : job.state === 'ready' ? `Copy ${job.total.toLocaleString()} files` : 'Resume copy'}</button>
          {/if}
          {#if approvals.canResumeWithoutUpload}<p class="footnote">Already received copies can finish without more upload data. Sending additional original data still needs upload approval; existing read and export allowances remain in effect.</p>{/if}
          {#if job.state === 'copying'}<button class="secondary" disabled={busy} onclick={() => controlCopy('pause')}>Pause copy</button>{/if}
          {#if !['complete', 'cancelled'].includes(job.state)}<button class="text-button" disabled={busy} onclick={() => controlCopy('cancel')}>Cancel copy</button>{/if}
          {#if job.state === 'cancelled'}<p class="footnote">Any unconfirmed staged originals and existing server copies are kept. Remove this folder permission before preparing another copy.</p>{/if}
        </div>
      {/if}
      <button class="text-button" disabled={busy} onclick={revoke}>Remove source permission</button>
    </div>
  {:else if blockedConsent}
    <button class="text-button" disabled={busy} onclick={revoke}>Remove previous source permission</button>
  {/if}
  {#if folder && !consent && !blockedConsent}
    <div class="folder-preview" aria-label="Selected folder preview">
      <strong>{folder.path}</strong>
      <p>{folder.photos.toLocaleString()} {folder.kind === 'apple-photos' ? 'original resources selected' : 'photo or video filenames found'}{folder.truncated ? ' in a partial preview' : ''}.</p>
      <p class="footnote">{folder.skipped ? `${folder.skipped} unavailable, linked or excluded entries skipped. ` : ''}Counts use filenames and metadata. Original contents have not been read, downloaded or imported. Availability can change; this folder does not inventory your entire cloud account.</p>
      {#if folder.kind === 'apple-photos'}<p class="footnote">Sizes and cloud residency are unknown. Approval permits up to {size(folder.logicalBytes)} of original export attempts, capped at 2 GiB per resource, including paired originals. Export stops at this ceiling. This metadata snapshot and its exact original resources are bound to your current sign-in and device; library changes require a new selection.</p>{/if}
      {#if folder.kind !== 'apple-photos' && folder.availability}<p class="footnote" aria-label="Preview file availability">{availabilityText(folder.availability)}</p>{/if}
      <label class="source-consent"><input type="checkbox" bind:checked={allowReads} disabled={busy}> {folder.kind === 'apple-photos' ? `Allow Photos to read these selected originals within the ${size(folder.logicalBytes)} export allowance. Upload approval follows verified staging.` : 'Allow this folder to be read for copying. Cloud-only originals may require downloading; approval does not start a copy.'}</label>
      {#if folder.kind === 'apple-photos'}
        <label class="source-consent"><input type="checkbox" bind:checked={allowHydration} disabled={busy}> Allow Apple Photos to download iCloud originals. Photos can download and cache the full original before Frameleaf receives any bytes. The export/staging ceiling does not limit Photos-managed network traffic; downloads may exceed it. An unmetered connection is still required.</label>
      {/if}
      <button class="secondary" disabled={busy || !allowReads} onclick={() => approve()}>Approve this {folder.kind === 'apple-photos' ? 'Photos scope and export allowance' : 'folder'}</button>
      <button class="text-button" disabled={busy} onclick={() => { folder = null; allowReads = false; allowHydration = false; }}>Clear preview</button>
    </div>
  {/if}
  <p class="footnote">Copy jobs require explicit source approval and an unmetered connection. Cloud-only files may download while staging an approved original. External-library connections are still being implemented. Selecting a OneDrive folder does not sign in to or inventory your entire cloud account.</p>
</section>

<style>
  .sources { margin-top: 36px; padding-top: 28px; border-top: 1px solid var(--border); }
  p { color: var(--muted); line-height: 1.6; }
  .actions { flex-wrap: wrap; margin-top: 16px; }
  ul { padding: 0; list-style: none; }
  li, .folder-preview { margin-top: 14px; padding: 16px; border: 1px solid var(--border); border-radius: 8px; background: var(--panel); overflow-wrap: anywhere; }
  .copy-job { margin: 16px 0; border-top: 1px solid var(--border); padding-top: 12px; }
  progress { width: 100%; accent-color: var(--accent); }
  .source-consent { display: flex; align-items: start; gap: 10px; margin: 16px 0; color: var(--muted); line-height: 1.6; }
  .source-consent input { margin-top: 5px; flex-shrink: 0; }
  small { display: block; color: var(--muted); margin: 6px 0; }
</style>
