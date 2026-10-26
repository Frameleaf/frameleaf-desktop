<script lang="ts">
  import { invoke } from '@tauri-apps/api/core';
  import { onMount } from 'svelte';
  import ReferenceRead from './ReferenceRead.svelte';
  type Scan = { scanId: string; current: boolean; abandoned: boolean; spent: number; resources: number; completed: number; reservedBytes: number; discardable: boolean; remaining: number; nextReadBytes: number | null; additionalReadAllowance: number; canRescan: boolean; prepared: boolean };
  type Transfer = { resourceKey: string; resourceId: string; version: string; stateId: string; bytes: number; readUsed: number; readRemaining: number; uploadUsed: number; uploadRemaining: number; additionalUpload: number; cacheRecorded: boolean };
  type Publication = { resourceKey: string; recordId: string; originalFileName: string; state: string; receipt: { publishedAt: string } | null; transfer?: Transfer | null; transferError?: string | null };
  type ReferenceStatus = { sourceId: string; scans: Scan[]; publications?: Publication[] };
  let { sourceId, photos = false }: { sourceId: string; photos?: boolean } = $props();
  let status = $state<ReferenceStatus | null>(null);
  let busy = $state(false);
  let reading = $state(false);
  let message = $state('');
  let confirmation = $state<string | null>(null);
  let visible = $state(20);
  let visiblePublications = $state(20);
  let alive = true;
  let serial = 0;
  const errors: Record<string, string> = {
    source_transfer_state_changed: 'The transfer allowance changed. Refresh before approving it again.',
    source_transfer_budget_invalid: 'The displayed transfer amount is no longer valid. Refresh the saved record.',
    source_publication_changed: 'The publication changed. Refresh before approving a transfer.',
    source_cache_cleanup_pending: 'The cache could not be discarded safely. It may belong to source work or need ownership recovery. Retained files and reservations are kept.',
    source_read_already_running: 'Photo-source work is active. Let it finish, then refresh.',
    source_scan_changed: 'The current scan changed. Refresh before choosing another action.',
    source_scan_not_abandoned: 'Abandon this scan before discarding its unfinished cache.',
    source_preparation_incomplete: 'Finish or abandon the current scan before scanning the same selection again.',
    source_read_budget_invalid: 'The displayed read allowance changed. Refresh before approving it again.',
    source_item_unavailable: 'A selected original is unavailable. Reconnect its source before rescanning; saved progress is kept.',
    photos_permission_required: 'Photos access is unavailable. Restore access before rescanning; saved progress is kept.',
    photos_scope_changed: 'An exact approved Photos resource is no longer available. Saved progress is kept; select it again before granting a new scope.',

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
  function publicationMessage(value: { state: string }) {
    switch (value.state) {
      case 'run': return 'Publication run is not confirmed. A previous receipt, if present, belongs to the earlier version.';
      case 'item': return 'Resource registration is not confirmed. A previous receipt, if present, belongs to the earlier version.';
      case 'publish': return 'Publication may have completed on your server. Its receipt needs recovery before the result can be confirmed.';
      case 'complete': return 'A publication receipt is saved; run completion is pending.';
      case 'recorded': return 'A publication receipt is saved locally.';
      default: return 'This publication record needs attention.';
    }
  }
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
  async function approveTransfer(publication: Publication) {
    const previous = publication.transfer;
    if (busy || reading || !status?.publications?.includes(publication) || publication.state !== 'recorded' || !previous?.cacheRecorded || previous.additionalUpload <= 0) return;
    const request = ++serial; const source = sourceId;
    busy = true; message = ''; confirmation = null;
    const current = () => alive && serial === request && sourceId === source;
    try {
      const reply = await invoke<Transfer>('approve_photo_reference_transfer', { input: { sourceId: source, resourceKey: publication.resourceKey, recordId: publication.recordId, stateId: previous.stateId, additional: previous.additionalUpload } });
      if (!current()) return;
      if (!reply || reply.resourceKey !== publication.resourceKey || reply.resourceId !== previous.resourceId || reply.version !== previous.version || reply.bytes !== previous.bytes
        || !/^[a-f0-9]{64}$/.test(reply.stateId) || reply.stateId === previous.stateId
        || reply.readUsed !== previous.readUsed || reply.readRemaining !== previous.readRemaining || reply.uploadUsed !== previous.uploadUsed
        || reply.uploadRemaining !== previous.uploadRemaining + previous.additionalUpload || reply.additionalUpload !== 0 || !reply.cacheRecorded) throw 'source_transfer_state_changed';
      status = { ...status!, publications: status!.publications!.map(value => value === publication ? { ...value, transfer: reply } : value) };
      message = 'Transfer allowance saved. No original read or transfer was started.';
    } catch (error) { if (current()) message = explain(error); }
    finally { if (current()) busy = false; }
  }
  function confirmDiscard(scan: Scan) {
    if (!busy && !reading && status?.scans.includes(scan) && scan.abandoned && scan.discardable) confirmation = scan.scanId;
  }
  async function control(action: string, scan: Scan) {
    if (busy || reading || !status?.scans.includes(scan)) return;
    if (action === 'abandon') { if (!scan.current || scan.abandoned) return; }
    else if (action === 'discard') { if (!scan.abandoned || !scan.discardable || confirmation !== scan.scanId) return; }
    else if (action === 'rescan') { if (!scan.current || !scan.canRescan) return; }
    else if (action === 'approve-read') { if (!scan.current || scan.abandoned || scan.additionalReadAllowance <= 0) return; }
    else return;
    const request = ++serial; const source = sourceId;
    busy = true; message = ''; confirmation = null;
    const current = () => alive && serial === request && sourceId === source;
    try {
      const reply = await invoke<ReferenceStatus | null>('control_photo_reference', { sourceId: source, expectedScan: scan.scanId, action, ...(action === 'approve-read' ? { additional: scan.additionalReadAllowance } : {}) });
      if (!current()) return;
      if (!reply || reply.sourceId !== source) throw 'source_approval_changed';
      if (action === 'rescan') {
        const fresh = reply.scans.find(value => value.current);
        if (!fresh || fresh.scanId === scan.scanId || fresh.abandoned || fresh.spent !== 0 || fresh.remaining !== 0) throw 'source_scan_changed';
        message = 'Selection rescanned. No new reads were approved or started.';
      } else {
        const updated = reply.scans.find(value => value.scanId === scan.scanId);
        if (action === 'approve-read') {
          if (!updated?.current || updated.abandoned || updated.spent !== scan.spent || updated.additionalReadAllowance !== 0 || updated.remaining < (scan.nextReadBytes ?? 0)) throw 'source_read_budget_invalid';
          message = 'Allowance saved. No original read or upload was started.';
        } else {
          if (!updated?.abandoned || (action === 'discard' && (updated.reservedBytes !== 0 || updated.discardable))) throw 'source_cache_cleanup_pending';
          message = action === 'discard' ? 'Cache discarded. Spent allowances, source originals and server photos are kept.' : 'Scan abandoned. Its remaining allowance cannot be used; retained cache is kept.';
        }
      }
      status = reply;
    } catch (error) { if (current()) message = explain(error); }
    finally { if (current()) busy = false; }
  }
  onMount(() => { void refresh(); return () => { alive = false; serial++; }; });
</script>

<section aria-label="Saved reference scans" aria-busy={busy}>
  <h3>Saved reference scans</h3>
  <p class="footnote">Inspect saved preparation and staging reservations without opening or downloading originals.</p>
  <ReferenceRead {sourceId} scan={status?.scans.find(value => value.current) ?? null} publications={status?.publications ?? []} disabled={busy} onActiveChange={value => reading = value} onSettled={() => void refresh()} />
  <button class="text-button" disabled={busy || reading} onclick={refresh}>Refresh saved scans</button>
  {#if busy}<p role="status">Checking saved reference work…</p>{/if}
  {#if message}<p role="status">{message}</p>{/if}
  {#if status}
    {#each status.scans.slice(0, visible) as scan (scan.scanId)}
      <div class="scan">
        <strong>{scan.current ? 'Current scan' : 'Earlier abandoned scan'}{scan.current && scan.abandoned ? ' · abandoned' : ''}</strong>
        <p>{scan.completed.toLocaleString()} of {scan.resources.toLocaleString()} originals prepared. {photos ? 'Export' : 'Original-read'} allowance used: {size(scan.spent)}.</p>
        <p class="footnote">Unfinished cache reservation: {size(scan.reservedBytes)}. Preparation does not confirm that photos were published on your server.</p>
        {#if scan.current}
          <p class="footnote">Remaining {photos ? 'maximum export' : 'original-read'} allowance: {size(scan.remaining)}.</p>
          {#if !scan.abandoned && !scan.prepared && scan.nextReadBytes === null}
            <p class="footnote">An unfinished attempt is retained. Recover the staged original, or abandon this scan to review cache cleanup.</p>
          {/if}
          {#if scan.additionalReadAllowance > 0 && !scan.abandoned}
            <p class="footnote">The next selected original needs {photos ? 'up to ' : ''}{size(scan.nextReadBytes ?? 0)} of {photos ? 'maximum export' : 'read'} allowance, including retries. Approval does not open or upload originals. {photos ? 'Photos-managed downloads are separate and can exceed the export ceiling when hydration is enabled for this source.' : 'Cloud-provider network traffic can exceed logical file data.'}</p>
            <button class="secondary" disabled={busy || reading} onclick={() => control('approve-read', scan)}>Approve {size(scan.additionalReadAllowance)} more {photos ? 'maximum export' : 'original-read'} allowance</button>
          {/if}
          {#if scan.canRescan}
            <p class="footnote">Scan the same selected originals again to refresh their metadata. Earlier receipts and caches are kept. A new scan starts with no read allowance.</p>
            <button class="secondary" disabled={busy || reading} onclick={() => control('rescan', scan)}>Scan the same selection again</button>
          {/if}
        {/if}
        {#if scan.current && !scan.abandoned}<button class="secondary" disabled={busy || reading} onclick={() => control('abandon', scan)}>Abandon scan</button>{/if}
        {#if scan.discardable}
          {#if confirmation === scan.scanId}
            <p>Discard this scan’s unfinished cached data and release its staging reservation? Spent allowances and photos on your server are kept.</p>
            <button class="secondary" disabled={busy || reading} onclick={() => control('discard', scan)}>Confirm cache discard</button>
            <button class="text-button" disabled={busy || reading} onclick={() => confirmation = null}>Keep cache</button>
          {:else}<button class="text-button" disabled={busy || reading} onclick={() => confirmDiscard(scan)}>Discard unfinished cache</button>{/if}
        {:else if scan.abandoned && scan.reservedBytes > 0}
          <p class="footnote">This cache belongs to source work or needs ownership recovery. It is retained.</p>
        {/if}
      </div>
    {/each}
    {#if status.publications?.length}
      <h4>Saved publication records</h4>
      <p class="footnote">These signed local records do not check current server availability or whether originals are still reachable. Refreshing reads only saved metadata.</p>
      {#each status.publications.slice(0, visiblePublications) as publication (publication.resourceKey)}
        <div class="scan">
          <strong>{publication.originalFileName}</strong>
          <p>{publicationMessage(publication)}</p>
          {#if publication.receipt}<p class="footnote">Saved server receipt dated {publication.receipt.publishedAt}.</p>{/if}
          {#if publication.transfer}
            <p class="footnote">Original-read allowance used: {size(publication.transfer.readUsed)}. Remaining: {size(publication.transfer.readRemaining)}. Transfer allowance used: {size(publication.transfer.uploadUsed)}. Remaining: {size(publication.transfer.uploadRemaining)}.</p>
            {#if publication.transfer.cacheRecorded}
              <p class="footnote">A private cache is recorded; its availability is checked when serving.</p>
              {#if publication.transfer.additionalUpload > 0}
                <p class="footnote">Allow one cached-original transfer by adding the displayed deficit. This starts no transfer and adds no original-read allowance.</p>
                <button class="secondary" disabled={busy || reading} onclick={() => approveTransfer(publication)}>Approve {size(publication.transfer.additionalUpload)} more transfer allowance</button>
              {/if}
            {:else}<p class="footnote">No private cache is recorded. Prepare the original again before approving another cached transfer.</p>{/if}
          {:else if publication.transferError}<p class="footnote">Transfer allowances could not be verified. Saved publication records are kept.</p>{/if}
        </div>
      {/each}
      {#if status.publications.length > visiblePublications}<button class="text-button" disabled={busy || reading} onclick={() => visiblePublications += 20}>Show more publication records</button>{/if}
    {/if}
    {#if status.scans.length > visible}<button class="text-button" disabled={busy || reading} onclick={() => visible += 20}>Show more scans</button>{/if}
  {:else if !busy && !message}<p>No saved reference scans on this computer.</p>{/if}
</section>

<style>
  section { margin-top: 20px; border-top: 1px solid var(--border); padding-top: 16px; }
  h3 { font-size: 1rem; }
  p { color: var(--muted); line-height: 1.6; }
  .scan { padding: 16px 0; border-bottom: 1px solid var(--border); }
  .footnote { font-size: .85rem; }
</style>
