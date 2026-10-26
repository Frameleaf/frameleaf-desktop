<script lang="ts">
  import { invoke } from '@tauri-apps/api/core';
  import { onMount } from 'svelte';
  type Scan = { scanId: string; current: boolean; abandoned: boolean; spent: number; resources: number; completed: number; reservedBytes: number; discardable: boolean };
  type ReferenceStatus = { sourceId: string; scans: Scan[] };
  let { sourceId, photos = false }: { sourceId: string; photos?: boolean } = $props();
  let status = $state<ReferenceStatus | null>(null);
  let busy = $state(false);
  let message = $state('');
  let confirmation = $state<string | null>(null);
  let visible = $state(20);
  let alive = true;
  let serial = 0;
  const errors: Record<string, string> = {
    source_cache_cleanup_pending: 'The cache could not be discarded safely. It may belong to source work or need ownership recovery. Retained files and reservations are kept.',
    source_read_already_running: 'Photo-source work is active. Let it finish, then refresh.',
    source_scan_changed: 'The current scan changed. Refresh before choosing another action.',
    source_scan_not_abandoned: 'Abandon this scan before discarding its unfinished cache.',
    source_journal_invalid: 'Saved scan records could not be verified. Retained files and reservations are kept.',
    source_input_budget_invalid: 'Saved staging reservations could not be verified. Retained files are kept.',
    source_input_budget_untracked: 'Staged data needs ownership recovery. Retained files are kept.',
    source_input_budget_busy: 'Another source operation is updating staging reservations. Try again when it finishes.',
    source_read_shutdown_unconfirmed: 'Source work could not confirm it stopped. Retained files are kept.',
    source_photo_session_changed: 'Reconnect this source to your current sign-in before managing its scans.',
    source_approval_changed: 'This source permission changed. Refresh its saved permission before continuing.',
    source_approval_required: 'Reconnect or approve this source before managing its scans.',
  };
  function explain(error: unknown) { return errors[String(error)] ?? 'Saved reference work could not be checked. Refresh and try again; retained files are kept.'; }
  function size(bytes: number) {
    if (bytes >= 1e9) return `${(bytes / 1e9).toFixed(1)} GB`;
    if (bytes >= 1e6) return `${(bytes / 1e6).toFixed(1)} MB`;
    if (bytes >= 1e3) return `${(bytes / 1e3).toFixed(1)} kB`;
    return `${bytes} bytes`;
  }
  async function refresh() {
    const request = ++serial; const source = sourceId;
    busy = true; message = ''; confirmation = null;
    const current = () => alive && serial === request && sourceId === source;
    try {
      const reply = await invoke<ReferenceStatus | null>('photo_reference_status', { sourceId: source });
      if (!current()) return;
      if (reply && reply.sourceId !== source) throw 'source_approval_changed';
      status = reply;
    } catch (error) { if (current()) message = explain(error); }
    finally { if (current()) busy = false; }
  }
  function confirmDiscard(scan: Scan) {
    if (!busy && status?.scans.includes(scan) && scan.abandoned && scan.discardable) confirmation = scan.scanId;
  }
  async function control(action: string, scan: Scan) {
    if (busy || !status?.scans.includes(scan)) return;
    if (action === 'abandon' ? !scan.current || scan.abandoned : action !== 'discard' || !scan.abandoned || !scan.discardable || confirmation !== scan.scanId) return;
    const request = ++serial; const source = sourceId;
    busy = true; message = ''; confirmation = null;
    const current = () => alive && serial === request && sourceId === source;
    try {
      const reply = await invoke<ReferenceStatus | null>('control_photo_reference', { sourceId: source, expectedScan: scan.scanId, action });
      if (!current()) return;
      const updated = reply?.sourceId === source ? reply.scans.find(value => value.scanId === scan.scanId) : null;
      if (!updated?.abandoned || (action === 'discard' && (updated.reservedBytes !== 0 || updated.discardable))) throw 'source_cache_cleanup_pending';
      status = reply;
      message = action === 'discard' ? 'Cache discarded. Spent allowances, source originals and server photos are kept.' : 'Scan abandoned. Its remaining allowance cannot be used; retained cache is kept.';
    } catch (error) { if (current()) message = explain(error); }
    finally { if (current()) busy = false; }
  }
  onMount(() => { void refresh(); return () => { alive = false; serial++; }; });
</script>

<section aria-label="Saved reference scans" aria-busy={busy}>
  <h3>Saved reference scans</h3>
  <p class="footnote">Inspect saved preparation and staging reservations without opening or downloading originals.</p>
  <button class="text-button" disabled={busy} onclick={refresh}>Refresh saved scans</button>
  {#if busy}<p role="status">Checking saved reference work…</p>{/if}
  {#if message}<p role="status">{message}</p>{/if}
  {#if status}
    {#each status.scans.slice(0, visible) as scan (scan.scanId)}
      <div class="scan">
        <strong>{scan.current ? 'Current scan' : 'Earlier abandoned scan'}{scan.current && scan.abandoned ? ' · abandoned' : ''}</strong>
        <p>{scan.completed.toLocaleString()} of {scan.resources.toLocaleString()} originals prepared. {photos ? 'Export' : 'Original-read'} allowance used: {size(scan.spent)}.</p>
        <p class="footnote">Unfinished cache reservation: {size(scan.reservedBytes)}. Preparation does not confirm that photos were published on your server.</p>
        {#if scan.current && !scan.abandoned}<button class="secondary" disabled={busy} onclick={() => control('abandon', scan)}>Abandon scan</button>{/if}
        {#if scan.discardable}
          {#if confirmation === scan.scanId}
            <p>Discard this scan’s unfinished cached data and release its staging reservation? Spent allowances and photos on your server are kept.</p>
            <button class="secondary" disabled={busy} onclick={() => control('discard', scan)}>Confirm cache discard</button>
            <button class="text-button" disabled={busy} onclick={() => confirmation = null}>Keep cache</button>
          {:else}<button class="text-button" disabled={busy} onclick={() => confirmDiscard(scan)}>Discard unfinished cache</button>{/if}
        {:else if scan.abandoned && scan.reservedBytes > 0}
          <p class="footnote">This cache belongs to source work or needs ownership recovery. It is retained.</p>
        {/if}
      </div>
    {/each}
    {#if status.scans.length > visible}<button class="text-button" disabled={busy} onclick={() => visible += 20}>Show more scans</button>{/if}
  {:else if !busy && !message}<p>No saved reference scans on this computer.</p>{/if}
</section>

<style>
  section { margin-top: 20px; border-top: 1px solid var(--border); padding-top: 16px; }
  h3 { font-size: 1rem; }
  p { color: var(--muted); line-height: 1.6; }
  .scan { padding: 16px 0; border-bottom: 1px solid var(--border); }
  .footnote { font-size: .85rem; }
</style>
