<script lang="ts">
  import { onMount } from 'svelte';
  import { invoke } from '@tauri-apps/api/core';
  import { listen, type UnlistenFn } from '@tauri-apps/api/event';
  import Sheet from './Sheet.svelte';
  import PhotoImportDestination from './PhotoImportDestination.svelte';
  import { albumErrors, type AlbumDestination } from './import-destination';
  import { formatBytes, percent } from './ui-state';

  type Preview = { selectionId: string; path: string; count: number; bytes: number; skipped: number; folder: boolean; names: string[] };
  type Job = { sourceId: string; state: string; total: number; completed: number; code: string | null; uploadRemaining: number | null; additionalUploadAllowance: number; albumPending: boolean };
  type Status = { consent: { id: string; name: string; registered: boolean; destination: AlbumDestination | null }; job: Job | null };
  let { visible }: { visible: boolean } = $props();
  let preview = $state<Preview | null>(null);
  let status = $state<Status | null>(null);
  let open = $state(false);
  let busy = $state(false);
  let allowed = $state(false);
  let albumMode = $state(false);
  let destination = $state<AlbumDestination | null>(null);
  let message = $state('');
  const job = $derived(status?.job);
  const terminal = $derived(job?.state === 'complete' || job?.state === 'cancelled');
  const allowance = $derived(!!job && !job.albumPending && !terminal && !['copying', 'queued'].includes(job.state) && (job.uploadRemaining === null || job.code === 'source_upload_budget_exhausted'));
  const messages: Record<string, string> = {
    ...albumErrors,
    source_drop_limit: 'Drop one folder or up to 100 photos and videos from the same folder.',
    source_drop_mixed: 'Drop one folder or select photos and videos from the same folder.',
    source_drop_existing: 'Finish or remove the current dropped import before starting another.',
    source_selection_changed: 'This preview has changed. Drop the folder or files again.',
    source_root_changed: 'This folder was replaced after the preview. Drop the items again.',
    source_item_changed: 'A file changed after the preview. Remove this import and drop the items again to approve the new version.',
    source_item_invalid: 'Choose ordinary local photos or videos. Links and cloud-only files cannot be copied this way.',
    source_item_unavailable: 'A selected file is unavailable. Check the folder before resuming.',
    source_watch_local_required: 'Drop a folder or files stored on this computer.',
    source_no_media: 'No available photos or videos were found.',
    source_inventory_partial: 'The full folder could not be checked. Choose a smaller accessible folder.',
    source_upload_budget_required: 'Approve the displayed upload allowance before resuming.',
    source_upload_budget_exhausted: 'The approved upload allowance was used. Approve more data before resuming.',
    source_server_processing: 'Your server is still finishing a photo. Resume to check again.',
    source_stop_confirmation_pending: 'Copying stopped here. Your server could not confirm the stop yet.',
    metered_network: 'Copying is paused until you resume on an unmetered connection.',
    network_unknown: 'Could not confirm an unmetered connection. Try again when connected.',
  };
  const explain = (code: unknown) => messages[String(code)] ?? 'This import could not finish. Check your library connection and try again.';

  async function refresh() {
    status = await invoke<Status | null>('photo_drop_status');
  }
  async function loadPreview(result: 'ready' | 'limit' | 'busy') {
    if (busy) return;
    open = true;
    allowed = false;
    albumMode = false;
    destination = null;
    message = '';
    preview = null;
    if (result !== 'ready') {
      message = result === 'limit' ? messages.source_drop_limit! : 'Frameleaf is finishing another action. Drop the items again when it’s ready.';
      return;
    }
    busy = true;
    try { preview = await invoke<Preview | null>('preview_photo_drop'); }
    catch (error) { message = explain(error); }
    finally { busy = false; }
  }
  onMount(() => {
    let live = true;
    const listeners: UnlistenFn[] = [];
    void (async () => {
      const add = (stop: UnlistenFn) => { if (live) listeners.push(stop); else stop(); };
      add(await listen<'ready' | 'limit' | 'busy'>('photo-drop-pending', event => { if (live) void loadPreview(event.payload); }));
      add(await listen<Job>('photo-drop-import', event => {
        if (live && status?.consent.id === event.payload.sourceId) status = { ...status, job: event.payload };
      }));
      if (live) await refresh();
    })().catch(error => { if (live) message = explain(error); });
    return () => { live = false; listeners.forEach(stop => stop()); };
  });
  function close() {
    open = false;
    const selectionId = preview?.selectionId;
    preview = null;
    allowed = false;
    albumMode = false;
    destination = null;
    if (selectionId) void invoke('control_photo_drop', { action: 'discard-preview', selectionId }).catch(() => {});
  }
  async function approve() {
    if (preview && (!allowed || (albumMode && !destination))) return;
    busy = true;
    message = '';
    try {
      status = await invoke<Status>('approve_photo_drop', { selectionId: preview?.selectionId ?? null, album: preview ? destination : null });
      preview = null;
      allowed = false;
    } catch (error) {
      message = explain(error);
      await refresh().catch(() => {});
      if (status) preview = null;
    } finally { busy = false; }
  }
  async function control(action: string) {
    if (!status) return;
    busy = true;
    message = '';
    try {
      const job = await invoke<Job | null>('control_photo_drop', { action });
      status = action === 'remove' ? null : { ...status, job };
      if (action === 'remove') close();
    } catch (error) { message = explain(error); }
    finally { busy = false; }
  }
</script>

{#if visible}
  <div class="inline-msg drop-entry">
    <p>Drop one folder or up to 100 photos and videos from the same folder into this window.</p>
    {#if status}<button class="btn small" onclick={() => { open = true; }}>Dropped import</button>{/if}
  </div>
{/if}

{#if open}
  <Sheet title={preview ? (preview.folder ? 'Review dropped folder' : 'Review dropped files') : 'Dropped import'} {busy} onclose={close} onsubmit={preview ? approve : undefined}>
    {#if message}<p role="status">{message}</p>{/if}
    {#if preview}
      <p><strong>{preview.path}</strong></p>
      <p>{preview.count.toLocaleString()} photos or videos · {formatBytes(preview.bytes)}{preview.skipped ? ` · ${preview.skipped} unavailable or excluded entries skipped` : ''}</p>
      {#if preview.names.length}<ul class="drop-list">{#each preview.names as name (name)}<li>{name}</li>{/each}</ul>{/if}
      <PhotoImportDestination bind:albumMode bind:destination disabled={busy} onchange={() => { allowed = false; }} />
      <label class="check"><input type="checkbox" bind:checked={allowed} disabled={busy} /> Allow these items to be copied to the selected destination. Originals stay in place.</label>
    {:else if status}
      <p><strong>{status.consent.name}</strong></p>
      {#if status.consent.destination}<p>Album: {status.consent.destination.name}{status.consent.destination.shared ? ' (shared)' : ''}</p>{/if}
      {#if job?.albumPending}<p>Copy verified. Waiting to add it to the album.</p>{/if}
      {#if !status.consent.registered}
        <p>Finish connecting this import to your library before starting the copy.</p>
      {:else if job}
        <p role="status">{job.completed.toLocaleString()} of {job.total.toLocaleString()} copies verified{job.state === 'cancelled' ? ' · Cancelled' : job.state === 'copying' ? ' · Copying' : job.state === 'queued' ? ' · Waiting for another import' : ''}.</p>
        {#if job.total > 0}<progress max="100" value={percent(job.completed, job.total)} aria-label="Copies verified"></progress>{/if}
        {#if job.code}<p role="status">{explain(job.code)}</p>{/if}
      {/if}
    {:else if !message}
      <p>Drop a folder or photos and videos to start a preview.</p>
    {/if}
    {#snippet actions()}
      <button class="btn" type="button" disabled={busy} onclick={close}>{preview ? 'Cancel' : 'Close'}</button>
      {#if preview}
        <button class="btn primary" type="submit" disabled={busy || !allowed || (albumMode && !destination)}>Approve Copy</button>
      {:else if status}
        {#if !status.consent.registered}
          <button class="btn primary" type="button" disabled={busy} onclick={approve}>Retry Registration</button>
        {:else if allowance}
          <button class="btn primary" type="button" disabled={busy} onclick={() => control('approve-upload')}>Approve {formatBytes(job!.additionalUploadAllowance)} more</button>
        {:else if job && ['copying', 'queued'].includes(job.state)}
          <button class="btn" type="button" disabled={busy} onclick={() => control('pause')}>Pause Copy</button>
        {:else if job && !terminal}
          <button class="btn primary" type="button" disabled={busy} onclick={() => control('resume')}>{job.state === 'ready' ? 'Start Copy' : job.albumPending ? 'Retry Adding to Album' : 'Resume Copy'}</button>
        {/if}
        {#if job && !terminal}
          <button class="btn quiet" type="button" disabled={busy} onclick={() => control('cancel')}>Cancel Copy</button>
        {/if}
        {#if !job || terminal}
          <button class="btn quiet" type="button" disabled={busy} onclick={() => control('remove')}>Remove Import</button>
        {/if}
      {/if}
    {/snippet}
  </Sheet>
{/if}

<style>
  .drop-entry { margin: 12px 24px 0; }
  .drop-list { max-height: 10rem; overflow: auto; margin: 8px 0; padding-left: 24px; overflow-wrap: anywhere; }
</style>
