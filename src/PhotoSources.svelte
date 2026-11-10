<script lang="ts">
  import { invoke, isTauri } from '@tauri-apps/api/core';
  import { onMount } from 'svelte';
  import { listen, type UnlistenFn } from '@tauri-apps/api/event';
  import Icon from './Icon.svelte';
  import Sheet from './Sheet.svelte';
  import { formatBytes, percent } from './ui-state';
  type Hint = { label: string; path: string };
  type Availability = { available: number; needsDownload: number; notReady: number; unknown: number; pinned: number; downloadBytes: number };
  type Inventory = { selectionId: string; path: string; photos: number; logicalBytes: number; skipped: number; truncated: boolean; availability: Availability };
  let hints = $state<Hint[]>([]);
  let folder = $state<Inventory | null>(null);
  type Consent = { id: string; name: string; path: string; registered: boolean; allowDownload: boolean; watch: boolean };
  type CopyJob = { sourceId: string; state: string; total: number; completed: number; logicalBytes: number; skipped: number; code: string | null; availability: Availability | null; uploadRemaining: number | null; additionalUploadAllowance: number };
  let job = $state<CopyJob | null>(null);
  let consent = $state<Consent | null>(null);
  let blockedConsent = $state(false);
  let allowReads = $state(false);
  let watchFolder = $state(false);
  let watchAvailable = $state(false);
  let alive = true;
  let busy = $state(false);
  let message = $state('');
  let revokeSheet = $state(false);
  let detailsOpen = $state(false);
  const native = isTauri();
  const errors: Record<string, string> = {
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
    source_root_changed: 'This is no longer the folder you approved. Remove its permission and choose the folder again.',
    source_watch_local_required: 'Choose a local folder for automatic import.',
    source_watch_history_full: 'This watched folder reached its import history limit. Existing verified copies are kept.',
    source_run_terminal: 'The server stopped this copy. Remove the folder permission before starting again.',
    source_item_changed: 'A selected file changed after the scan. This copy is paused; the original and staged data are kept.',
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
    source_upload_budget_required: 'This saved copy needs an upload allowance before it can send original data. Approve the displayed amount, then resume.',
    source_upload_budget_exhausted: 'This copy reached its upload allowance. Staged originals are kept. Approve more upload data to retry.',
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
    source_registration_response_invalid: 'The server did not confirm this exact folder permission. Copying remains stopped.',
    server_identity_changed: 'The server identity changed. Sign out before reconnecting.',

    source_choose_photo_subfolder: 'Choose a photo folder inside your home folder, rather than your entire home folder.',
    source_package_requires_provider: 'Apple Photos libraries need the Photos connection. Choose an ordinary folder here.',
    source_folder_unavailable: 'This folder is unavailable. Check that its drive is connected and you have access.',
    source_account_unavailable: 'This OneDrive folder moved or is unavailable. Choose its new location.',
  };
  function explain(error: unknown) { return errors[String(error)] ?? 'This operation could not finish. Check the server connection and try again.'; }
  async function loadConsent() {
    try {
      const current = await invoke<Consent | null>('photo_source_status');
      if (alive) { consent = current; blockedConsent = false; }
    } catch (error) {
      if (alive) {
        blockedConsent = ['source_photo_session_changed', 'source_approval_invalid', 'credential_record_invalid'].includes(String(error));
        message = explain(error);
      }
    }
  }
  onMount(() => {
    let unlisten: UnlistenFn | undefined;
    if (native) void (async () => {
      try {
        unlisten = await listen<CopyJob>('photo-import', event => { if (alive && event.payload.sourceId === consent?.id) job = event.payload; });
        if (!alive) { unlisten(); return; }
        await loadConsent();
        if (consent?.registered) {
          const current = await invoke<CopyJob | null>('photo_import_status');
          if (alive) job = current;
        }
      } catch (error) { if (alive) message = explain(error); }
    })();
    return () => { alive = false; unlisten?.(); };
  });
  const size = formatBytes;
  function availabilityText(value: Availability) {
    return `${value.available.toLocaleString()} OS-reported available; ${value.needsDownload.toLocaleString()} need downloading (${size(value.downloadBytes)} in originals); ${value.notReady.toLocaleString()} provider not ready; ${value.unknown.toLocaleString()} unknown. ${value.pinned.toLocaleString()} request pinning. These are metadata snapshots; pinning does not prove a complete local original. Unknown files may also need downloading.`;
  }
  async function prepareCopy() {
    busy = true; message = '';
    try { job = await invoke<CopyJob>('prepare_photo_import'); }
    catch (error) { message = explain(error); }
    finally { busy = false; }
  }
  async function controlCopy(action: 'resume' | 'pause' | 'cancel' | 'approve-upload' | 'watch-pause' | 'watch-resume') {
    busy = true; message = '';
    try { job = await invoke<CopyJob>('control_photo_import', { action }); }
    catch (error) { message = explain(error); }
    finally { busy = false; }
  }
  async function approve(retry = false) {
    if (!retry && (!folder || !allowReads)) return;
    busy = true; message = '';
    try {
      consent = await invoke<Consent>('approve_photo_folder', { selectionId: retry ? null : folder!.selectionId, allowDownload: allowReads, watch: watchFolder });
      if (consent.watch) job = await invoke<CopyJob | null>('photo_import_status');
      folder = null; allowReads = false; watchFolder = false;
    } catch (error) { await loadConsent(); message = explain(error); }
    finally { busy = false; }
  }
  async function revoke() {
    busy = true; message = ''; revokeSheet = false;
    try {
      const confirmed = await invoke<boolean>('revoke_photo_source');
      consent = null; job = null; blockedConsent = false; folder = null; allowReads = false;
      message = confirmed ? 'Folder permission removed. Existing server copies are kept.' : 'Local folder permission removed. The server could not confirm revocation; check it when connected.';
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
  async function choose(oneDrive: number | null = null) {
    busy = true; message = '';
    try {
      const selected = await invoke<Inventory | null>('choose_photo_folder', { oneDrive });
      if (selected) { folder = selected; allowReads = false; watchFolder = false; watchAvailable = oneDrive === null; }
    } catch (error) { message = errors[String(error)] ?? 'Could not preview this folder. Choose an accessible photo folder and try again.'; }
    finally { busy = false; }
  }
  const jobLabel = $derived(!job ? '' : job.state === 'watching' ? (job.code ? 'Watching · waiting' : 'Watching folder') : job.state === 'watch-paused' ? 'Watching paused' : job.state === 'complete' ? 'Copy complete' : job.state === 'cancelled' ? 'Copy cancelled' : job.state === 'copying' ? 'Copying' : job.state === 'ready' ? 'Copy prepared' : job.state === 'paused' ? 'Copy paused' : 'Copy needs attention');
  const jobTone = $derived(!job ? 'off' : ['complete', 'watching'].includes(job.state) ? 'ok' : job.state === 'copying' ? 'wait' : job.state === 'needs-attention' ? 'bad' : 'off');
  const canResume = $derived(!!job && ['ready', 'paused', 'needs-attention'].includes(job.state));
  const watchRunning = $derived(!!job && ['watching', 'copying', 'complete'].includes(job.state));
  const needsAllowance = $derived(!!job && job.total > 0 && !['complete', 'cancelled', 'copying'].includes(job.state) && (job.uploadRemaining === null || job.code === 'source_upload_budget_exhausted'));
</script>

<section class="page" aria-labelledby="photo-sources-heading" aria-busy={busy}>
  <header class="toolbar">
    <h1 id="photo-sources-heading">Photo sources</h1>
    {#if consent}<span class="pill {job ? jobTone : consent.registered ? 'ok' : 'wait'}"><i aria-hidden="true"></i>{job ? jobLabel : consent.registered ? 'Folder registered' : 'Registration pending'}</span>{/if}
    <span class="sp"></span>
    <button class="btn quiet" disabled={busy || !native || !!consent || blockedConsent} onclick={discover}>Find OneDrive Folders</button>
    <button class="btn" disabled={busy || !native || !!consent || blockedConsent} onclick={() => choose()}><Icon name="plus" />Add Folder…</button>
  </header>
  <div class="body">
    {#if busy}<div class="inline-msg" role="status"><span class="spin" aria-hidden="true"></span><p>Waiting for the folder or server operation to finish…</p></div>{/if}
    {#if message}<div class="inline-msg" role="status"><p>{message}</p><button class="btn small quiet" onclick={() => { message = ''; }}>Dismiss</button></div>{/if}
    {#if hints.length}
      <div>
        <div class="group-head"><h2 class="group-title">Known OneDrive folders</h2></div>
        <div class="group">
          {#each hints as hint, index (hint.path)}
            <div class="row"><span class="ic" aria-hidden="true"><Icon name="cloud" /></span><span class="l"><b>{hint.label}</b><small>{hint.path}</small></span><button class="btn" disabled={busy || !!consent || blockedConsent} onclick={() => choose(index)}>Choose Folders…</button></div>
          {/each}
        </div>
      </div>
    {/if}
    <div>
      <div class="group-head">
        <h2 class="group-title">Approved folder</h2>
        {#if consent && job}<button class="btn quiet" onclick={() => { detailsOpen = true; }}>Details</button>{/if}
      </div>
      <div class="group">
        {#if consent}
          <div class="row" class:top={!!job && !['complete', 'cancelled'].includes(job.state)} aria-label="Approved photo folder">
            <span class="ic" aria-hidden="true"><Icon name="folder" /></span>
            <span class="l">
              <b>{consent.name}</b>
              <small style={job && !['complete', 'cancelled'].includes(job.state) ? 'margin-bottom:8px' : ''}>{consent.path} · {consent.watch && (!job || job.total === 0) ? (job ? jobLabel : 'Automatic import to your current library') : job ? `${jobLabel} · ${job.completed.toLocaleString()} of ${job.total.toLocaleString()} copies confirmed${job.uploadRemaining !== null ? ` · ${size(job.uploadRemaining)} upload allowance left` : ' · no upload allowance approved'}` : consent.registered ? 'Folder permission saved and registered with your server.' : 'Folder permission saved locally. Server registration still needs to finish.'}</small>
              {#if job && job.total > 0 && !['complete', 'cancelled'].includes(job.state)}<span class="progress" role="progressbar" aria-valuenow={percent(job.completed, job.total)} aria-valuemin="0" aria-valuemax="100" aria-label="Copies verified on your server"><span style="width:{percent(job.completed, job.total)}%"></span></span>{/if}
            </span>
            {#if job}<span class="pill {jobTone}" role="status"><i aria-hidden="true"></i>{job.state === 'complete' ? 'Up to date' : jobLabel.replace('Copy ', '')}</span>{/if}
            {#if !consent.registered}<button class="btn" disabled={busy} onclick={() => approve(true)}>Retry Registration</button>{/if}
            {#if consent.registered && !consent.watch && !job}<button class="btn primary" disabled={busy} onclick={prepareCopy}>Prepare Copy</button>{/if}
            {#if needsAllowance}<button class="btn" disabled={busy} onclick={() => controlCopy('approve-upload')}>Approve {size(job!.additionalUploadAllowance)} more</button>{/if}
            {#if consent.watch && consent.registered}
              {#if watchRunning}<button class="btn" disabled={busy} onclick={() => controlCopy('watch-pause')}><Icon name="pause" />Pause Watching</button>
              {:else if job?.code !== 'source_run_terminal'}<button class="btn primary" disabled={busy || needsAllowance} onclick={() => controlCopy('watch-resume')}>Resume Watching</button>{/if}
            {:else if canResume}<button class="btn primary" disabled={busy || job!.uploadRemaining === null || job!.code === 'source_upload_budget_exhausted'} onclick={() => controlCopy('resume')}>{job!.state === 'ready' ? `Copy ${job!.total.toLocaleString()} files` : 'Resume'}</button>{/if}
            {#if !consent.watch && job?.state === 'copying'}<button class="btn" disabled={busy} onclick={() => controlCopy('pause')}><Icon name="pause" />Pause</button>{/if}
            {#if !consent.watch && job && !['complete', 'cancelled'].includes(job.state)}<button class="btn quiet" disabled={busy} onclick={() => controlCopy('cancel')}>Cancel</button>{/if}
            <button class="btn quiet" disabled={busy} onclick={() => { revokeSheet = true; }}>Remove…</button>
          </div>
          {#if consent.registered && !consent.watch && !job}
            <div class="row"><span class="l"><small>Prepare a bounded copy plan before opening any originals. You can review its file count and data size before starting.</small></span></div>
          {/if}
          {#if job?.code}<div class="row"><span class="l"><small role="status" class="danger-text">{explain(job.code)}</small></span></div>{/if}
          {#if job?.state === 'cancelled'}<div class="row"><span class="l"><small>Any unconfirmed staged originals and existing server copies are kept. Remove this folder permission before preparing another copy.</small></span></div>{/if}
        {:else if blockedConsent}
          <div class="row"><span class="ic dim" aria-hidden="true"><Icon name="warn" /></span><span class="l"><b>A previous folder permission needs removing</b><small>It belongs to an earlier sign-in or no longer matches this connection.</small></span><button class="btn" disabled={busy} onclick={() => { revokeSheet = true; }}>Remove Previous Permission…</button></div>
        {:else if !folder}
          <div class="row"><span class="ic dim" aria-hidden="true"><Icon name="folder" /></span><span class="l"><b>No folder approved</b><small>Choose where to bring photos from. Local folders are separate from this computer’s AI processing permission.</small></span></div>
        {/if}
        {#if folder && !consent && !blockedConsent}
          <div class="row top" aria-label="Selected folder preview">
            <span class="ic" aria-hidden="true"><Icon name="folder" /></span>
            <span class="l">
              <b>{folder.path}</b>
              <small>{folder.photos.toLocaleString()} photo or video filenames found{folder.truncated ? ' in a partial preview' : ''}. {folder.skipped ? `${folder.skipped} unavailable, linked or excluded entries skipped. ` : ''}Counts use filenames and metadata. Original contents have not been read, downloaded or imported. Availability can change; this folder does not inventory your entire cloud account.</small>
              {#if folder.availability}<small aria-label="Preview file availability">{availabilityText(folder.availability)}</small>{/if}
              {#if watchAvailable && !folder.truncated}
                <label class="check muted" style="margin-top:10px"><input type="checkbox" bind:checked={watchFolder} onchange={() => { allowReads = false; }} disabled={busy} /> Watch this folder and automatically copy photos and videos to my current Frameleaf library.</label>
              {/if}
              <label class="check muted" style="margin-top:10px"><input type="checkbox" bind:checked={allowReads} disabled={busy} /> {watchFolder ? 'Allow Frameleaf to read this folder in the background, including after I close the window. Existing files are included. Originals stay in place.' : 'Allow this folder to be read for copying. Cloud-only originals may require downloading; approval does not start a copy.'}</label>
            </span>
            <button class="btn quiet" disabled={busy} onclick={() => { folder = null; allowReads = false; watchFolder = false; }}>Clear</button>
            <button class="btn primary" disabled={busy || !allowReads} onclick={() => approve()}>{watchFolder ? 'Approve and Watch' : 'Approve Folder'}</button>
          </div>
        {/if}
      </div>
      <p class="foot">Originals stay in their folders. A copy counts only after your server verifies its stored bytes. Copy jobs require explicit folder approval and an unmetered connection. Cloud-only files may download while staging an approved original. Selecting a OneDrive folder does not sign in to or inventory your entire cloud account.</p>
    </div>
  </div>
</section>

{#if revokeSheet}
  <Sheet title={consent ? `Remove the permission for “${consent.name}”?` : 'Remove the previous folder permission?'} kind="warning" {busy} onclose={() => { revokeSheet = false; }} onsubmit={revoke}>
    <p>Existing server copies are kept. Any copy in progress stops, and the folder has to be approved again before another copy.</p>
    {#snippet actions()}
      <button class="btn" type="button" disabled={busy} onclick={() => { revokeSheet = false; }}>Cancel</button>
      <button class="btn danger" type="submit" disabled={busy}>Remove Permission</button>
    {/snippet}
  </Sheet>
{/if}
{#if detailsOpen && job}
  <Sheet title="Copy details" wide onclose={() => { detailsOpen = false; }}>
    <p>Prepared originals: {size(job.logicalBytes)}. {job.skipped ? `${job.skipped.toLocaleString()} linked or excluded entries were skipped. ` : ''}Original files stay in this folder. A copy is confirmed only after your server verifies its stored bytes.</p>
    <p>{job.uploadRemaining === null ? 'No upload allowance approved.' : `${size(job.uploadRemaining)} of original upload data remaining, including retries.`} Protocol overhead and downloads from your cloud provider are separate. Interrupted sends count in full; resuming does not reset this allowance.</p>
    {#if job.availability}<p aria-label="Prepared file availability">{availabilityText(job.availability)}</p>{/if}
    {#snippet actions()}<button class="btn" type="button" onclick={() => { detailsOpen = false; }}>Done</button>{/snippet}
  </Sheet>
{/if}
