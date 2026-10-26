<script lang="ts">
  import { invoke } from '@tauri-apps/api/core';
  import { listen, type UnlistenFn } from '@tauri-apps/api/event';
  import { onMount } from 'svelte';
  type Scan = { scanId: string; current: boolean; abandoned: boolean; prepared: boolean; additionalReadAllowance: number; nextReadBytes: number | null };
  type Publication = { resourceKey: string; recordId: string; originalFileName: string; state: string };
  type Work = { sourceId: string; requestId: string; state: string; code: string | null } & ({ operation: 'prepare'; scanId: string } | { operation: 'recover'; resourceKey: string; recordId: string });
  let { sourceId, scan = null, publications = [], disabled = false, onActiveChange, onSettled }: {
    sourceId: string; scan?: Scan | null; publications?: Publication[]; disabled?: boolean; onActiveChange: (active: boolean) => void; onSettled: () => void;
  } = $props();
  let work = $state<Work | null>(null);
  let visibleRecoveries = $state(20);
  let message = $state('');
  let ready = $state(false);
  let checking = $state(false);
  let startPending = $state(false);
  let pausePending = $state(false);
  let alive = true;
  let version = 0;
  let settledRequest: string | null = null;
  let unlisten: UnlistenFn | undefined;
  const observed = new Map<string, Work>();
  const errors: Record<string, string> = {
    source_publication_changed: 'The saved publication record changed. Refresh its metadata before recovering its receipt.',
    source_publication_not_committed: 'This attempt has not reached publication. Its earlier receipt and pending metadata are kept.',
    source_reference_receipt_invalid: 'The server reply does not match this saved publication. The existing record is kept.',
    source_publication_interrupted: 'Receipt recovery was interrupted. Its saved state is kept; refresh before retrying.',
    server_http_409: 'The server no longer accepts this reference binding. Reconnect the source or review its saved record.',
    server_http_404: 'The saved reference was not found on this server. Its local record is kept.',
    source_read_shutdown_unconfirmed: 'Source work could not confirm it stopped. Retained data is kept and new work remains blocked.',
    source_copy_shutdown_unconfirmed: 'The original reader could not confirm it stopped. Retained data is kept and new reads remain blocked.',
    source_read_already_running: 'Another source operation is active. Check preparation status before trying again.',
    source_read_operation_changed: 'This preparation request changed. Check status before pausing it again.',
    source_scan_changed: 'The saved scan changed. Refresh its metadata before preparing an original.',
    source_scan_abandoned: 'This scan was abandoned. Scan the same selection again before preparing originals.',
    source_read_budget_exhausted: 'This scan needs more original-read allowance. Refresh its metadata to review the exact amount.',
    source_staging_budget_exceeded: 'Private staging is full. Finish existing source work or review retained cache before trying again.',
    source_cache_cleanup_pending: 'A retained attempt needs recovery or cache cleanup. Saved originals and spent allowances are kept.',
    on_battery: 'Preparation is paused on battery power. Connect external power, then prepare explicitly.',
    power_unknown: 'External power could not be checked. Preparation remains stopped.',
    metered_network: 'Preparation is paused on a metered connection.',
    network_unknown: 'Network cost could not be checked. Preparation remains stopped.',
    memory_low: 'There is not enough available memory to prepare this original safely.',
    memory_unknown: 'Available memory could not be checked. Preparation remains stopped.',
    source_delivery_interrupted: 'Preparation was interrupted. Retained staging and spent allowances are kept.',
    source_item_changed: 'The selected original changed. Retained staging is kept; review a new scan before reading again.',
    photos_original_unavailable: 'Photos could not export this original. Retained staging and spent allowances are kept.',
    photos_permission_required: 'Photos access is unavailable or was revoked. Retained staging is kept.',
    source_photo_session_changed: 'Reconnect this source to the current sign-in before preparing originals.',
  };
  function explain(error: unknown) { return errors[String(error)] ?? 'Source work needs attention. Check its status; retained data is kept.'; }
  function uncertain(value: Work | null) { return !!value && ['source_read_shutdown_unconfirmed', 'source_copy_shutdown_unconfirmed'].includes(value.code ?? ''); }
  function finished(value: Work | null) { return !!value && ['stopped', 'paused', 'needs-attention'].includes(value.state) && !uncertain(value); }
  function activeWork() { return !!work && !finished(work); }
  function announce() { if (alive) onActiveChange(!ready || checking || startPending || pausePending || activeWork()); }
  function valid(value: unknown): value is Work {
    if (!value || typeof value !== 'object') return false;
    const v = value as Work;
    const digest = (input: unknown) => typeof input === 'string' && /^[a-f0-9]{64}$/.test(input);
    return v.sourceId === sourceId && typeof v.requestId === 'string' && v.requestId.length === 36 && /^[a-f0-9-]{36}$/.test(v.requestId)
      && (v.code === null || typeof v.code === 'string') && (
        v.operation === 'prepare' && digest(v.scanId) && ['starting', 'preparing', 'stopped', 'paused', 'needs-attention'].includes(v.state)
        || v.operation === 'recover' && digest(v.resourceKey) && digest(v.recordId) && ['starting', 'recovering', 'stopped', 'paused', 'needs-attention'].includes(v.state)
      );
  }
  function same(a: Work | null, b: Work) {
    return !!a && a.sourceId === b.sourceId && a.requestId === b.requestId && (a.operation === 'prepare' && b.operation === 'prepare'
      ? a.scanId === b.scanId : a.operation === 'recover' && b.operation === 'recover' && a.resourceKey === b.resourceKey && a.recordId === b.recordId);
  }
  function settle() {
    announce();
    if (alive && finished(work) && !pausePending && work && settledRequest !== work.requestId) {
      settledRequest = work.requestId;
      onSettled();
    }
  }
  function accept(value: Work, trustedSnapshot = false) {
    if (same(work, value) && uncertain(work) && !trustedSnapshot && !uncertain(value)) return;
    if (same(work, value) && finished(work) && !finished(value)) return;
    work = value;
    if (value.code) message = explain(value.code);
    else if (value.state === 'paused') message = value.operation === 'recover' ? 'Receipt recovery paused. Saved publication records are kept.' : 'Preparation paused. Retained staging and spent allowances are kept.';
    else if (value.state === 'stopped') message = value.operation === 'recover' ? 'Receipt recovery stopped. Refreshing saved publication records…' : 'Preparation stopped. Refreshing saved scan progress…';
    else message = '';
    settle();
  }
  function receive(value: unknown) {
    if (!alive || !valid(value)) return;
    if (checking) {
      if (observed.size >= 16) observed.delete(observed.keys().next().value!);
      observed.set(value.requestId, value);
    }
    if (!same(work, value) || (pausePending && finished(value))) return;
    accept(value);
  }
  async function subscribe() {
    if (unlisten) return;
    const stop = await listen<Work>('photo-reference-work', event => receive(event.payload));
    if (!alive) { stop(); return; }
    unlisten = stop;
  }
  async function checkStatus() {
    const request = ++version; const source = sourceId;
    checking = true; observed.clear(); announce();
    const current = () => alive && sourceId === source && version === request;
    try {
      await subscribe(); if (!current()) return;
      const reply = await invoke<Work | null>('photo_reference_work_status', { sourceId: source });
      if (!current()) return;
      if (reply !== null && !valid(reply)) throw 'source_read_shutdown_unconfirmed';
      ready = true;
      if (reply) {
        const event = observed.get(reply.requestId);
        const newer = event && same(reply, event) && (uncertain(event) || (!uncertain(reply) && (finished(event) || !finished(reply))));
        accept(newer ? event : reply, true);
      } else {
        const previous = work; work = null;
        if (previous && settledRequest !== previous.requestId) { settledRequest = previous.requestId; onSettled(); }
      }
    } catch (error) { if (current()) { ready = false; message = explain(error); } }
    finally { if (current()) { checking = false; observed.clear(); announce(); } }
  }
  function idle() { return ready && !checking && !startPending && !pausePending && !activeWork() && !disabled; }
  function canRecover(value: Publication) { return idle() && publications.includes(value) && ['publish', 'complete', 'recorded'].includes(value.state) && /^[a-f0-9]{64}$/.test(value.resourceKey) && /^[a-f0-9]{64}$/.test(value.recordId); }
  function canStart() { return idle() && !!scan?.current && !scan.abandoned && !scan.prepared && scan.additionalReadAllowance === 0; }
  function newRequestId() {
    if (typeof crypto.randomUUID === 'function') return crypto.randomUUID();
    const bytes = crypto.getRandomValues(new Uint8Array(16));
    bytes[6] = (bytes[6] & 15) | 64; bytes[8] = (bytes[8] & 63) | 128;
    const hex = Array.from(bytes, value => value.toString(16).padStart(2, '0')).join('');
    return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
  }
  async function start() {
    if (!canStart() || !scan) return;
    await launch({ operation: 'prepare', sourceId, scanId: scan.scanId });
  }
  async function startRecovery(value: Publication) {
    if (!canRecover(value)) return;
    await launch({ operation: 'recover', sourceId, resourceKey: value.resourceKey, recordId: value.recordId });
  }
  async function launch(target: { sourceId: string } & ({ operation: 'prepare'; scanId: string } | { operation: 'recover'; resourceKey: string; recordId: string })) {
    let requestId: string;
    try { requestId = newRequestId(); }
    catch { message = 'Secure request IDs are unavailable. Restart Frameleaf before preparing an original.'; return; }
    version++; checking = false; settledRequest = null; message = '';
    const requested: Work = { ...target, requestId, state: 'starting', code: null };
    work = requested; startPending = true; announce();
    const current = () => alive && same(work, requested);
    try {
      const reply = requested.operation === 'prepare'
        ? await invoke<Work>('start_photo_reference_read', { sourceId: requested.sourceId, expectedScan: requested.scanId, requestId: requested.requestId })
        : await invoke<Work>('start_photo_reference_recovery', { sourceId: requested.sourceId, resourceKey: requested.resourceKey, expectedRecord: requested.recordId, requestId: requested.requestId });
      if (!current()) return;
      if (!valid(reply) || !same(requested, reply)) throw 'source_read_shutdown_unconfirmed';
      if (!pausePending) accept(reply);
    } catch (error) {
      if (current() && !finished(work)) {
        message = explain(error);
        work = { ...requested, state: 'needs-attention', code: 'source_read_shutdown_unconfirmed' };
        await checkStatus();
      }
    } finally { if (alive && sourceId === requested.sourceId) { startPending = false; announce(); } }
  }
  async function pause() {
    if (!work || !activeWork() || pausePending) return;
    const requested = work; version++; checking = false; pausePending = true; announce();
    const current = () => alive && same(work, requested);
    try {
      const reply = requested.operation === 'prepare'
        ? await invoke<Work>('pause_photo_reference_read', { sourceId: requested.sourceId, expectedScan: requested.scanId, requestId: requested.requestId })
        : await invoke<Work>('pause_photo_reference_recovery', { sourceId: requested.sourceId, resourceKey: requested.resourceKey, expectedRecord: requested.recordId, requestId: requested.requestId });
      if (!current()) return;
      if (!valid(reply) || !same(requested, reply) || reply.state !== 'paused') throw 'source_read_shutdown_unconfirmed';
      work = reply;
      message = requested.operation === 'recover' ? 'Receipt recovery paused. Saved publication records are kept.' : 'Preparation paused. Retained staging and spent allowances are kept.';
    } catch (error) {
      if (current()) { message = explain(error); work = { ...requested, state: 'needs-attention', code: 'source_read_shutdown_unconfirmed' }; }
    } finally { if (current()) { pausePending = false; settle(); } }
  }
  onMount(() => { void checkStatus(); return () => { alive = false; version++; unlisten?.(); }; });
</script>

<div class="read-work" aria-label="Local reference work" aria-busy={checking || startPending || pausePending || activeWork()}>
  <h4>Prepare an original</h4>
  <p class="footnote">Prepare one selected original at a time using the saved read or export allowance. Originals stay in their source; this action starts no server upload.</p>
  {#if checking}<p role="status">Checking source work status…</p>{/if}
  {#if activeWork()}
    <p role="status">{pausePending ? 'Pausing and waiting for source work to stop…' : uncertain(work) ? 'Source work stop remains unconfirmed.' : work?.operation === 'recover' ? 'Recovering the saved server receipt…' : 'Preparing one original within its saved allowance…'}</p>
    <progress aria-label={work?.operation === 'recover' ? 'Recovering saved server receipt' : 'Preparing one approved original'}></progress>
    <button class="secondary" disabled={pausePending} onclick={pause}>{work?.operation === 'recover' ? 'Pause receipt recovery' : 'Pause preparation'}</button>
  {/if}
  {#if message}<p role="status">{message}</p>{/if}
  <button class="text-button" disabled={checking || pausePending || startPending} onclick={checkStatus}>Check source work status</button>
  {#if canStart()}<button class="secondary" onclick={() => start()}>{scan?.nextReadBytes === null ? 'Recover staged original' : 'Prepare next original within allowance'}</button>{/if}
  {#if publications.some(value => ['publish', 'complete', 'recorded'].includes(value.state))}
    <h4>Recover a server receipt</h4>
    <p class="footnote">Check the exact saved publication on your server and finish its run if needed. This reads no original and starts no upload or new publication.</p>
    {#each publications.filter(value => ['publish', 'complete', 'recorded'].includes(value.state)).slice(0, visibleRecoveries) as publication (publication.resourceKey)}
      <button class="secondary" disabled={!canRecover(publication)} onclick={() => startRecovery(publication)}>Recover receipt · {publication.originalFileName}</button>
    {/each}
    {#if publications.filter(value => ['publish', 'complete', 'recorded'].includes(value.state)).length > visibleRecoveries}<button class="text-button" disabled={!idle()} onclick={() => visibleRecoveries += 20}>Show more recoverable receipts</button>{/if}
  {/if}
</div>

<style>
  .read-work { margin: 16px 0; padding-bottom: 16px; border-bottom: 1px solid var(--border); }
  h4 { font-size: 1rem; }
  p { color: var(--muted); line-height: 1.6; }
  .footnote { font-size: .85rem; }
  progress { display: block; width: 100%; margin: 12px 0; accent-color: var(--accent); }
</style>
