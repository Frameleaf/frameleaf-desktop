<script lang="ts">
  import { invoke, isTauri } from '@tauri-apps/api/core';
  import { listen, type UnlistenFn } from '@tauri-apps/api/event';
  import { onMount } from 'svelte';
  import { formatWhen, verifiedImportMilestone } from './ui-state';

  type Kind = 'folder' | 'camera' | 'watch' | 'drop';
  type Status = 'ready' | 'running' | 'interrupted' | 'complete' | 'cancelled';
  type Entry = { runId: string; kind: Kind; status: Status; createdAt: number | null; album: string | null; verified: number; total: number; skipped: number; albumPending: boolean; canRetry: boolean };
  const kinds: Record<Kind, string> = { folder: 'Folder import', camera: 'Camera import', watch: 'Watched folder', drop: 'One-time drop' };
  const statuses: Record<Status, string> = { ready: 'Ready', running: 'In progress', interrupted: 'Interrupted', complete: 'Completed', cancelled: 'Cancelled' };
  const native = isTauri();
  let entries = $state<Entry[]>([]);
  const completion = $derived(verifiedImportMilestone(entries));
  let loaded = $state(false);
  let error = $state('');
  let retrying = $state(false);
  let visible = $state(20);
  let alive = true;
  let request = 0;
  let refresh: ReturnType<typeof setTimeout>;

  async function load() {
    const id = ++request;
    try {
      const value = await invoke<Entry[]>('photo_import_history');
      if (alive && id === request) {
        entries = value;
        loaded = true;
        error = '';
      }
    } catch {
      if (alive && id === request) error = 'Import history could not be read. Refresh to try again.';
    }
  }

  function schedule() {
    clearTimeout(refresh);
    refresh = setTimeout(() => void load(), 120);
  }

  onMount(() => {
    if (!native) return;
    const subscriptions: UnlistenFn[] = [];
    void load();
    const subscribe = (subscription: Promise<UnlistenFn>) => {
      void subscription.then(stop => { if (alive) subscriptions.push(stop); else stop(); }).catch(() => {});
    };
    const onImport = ({ payload }: { payload: { state: string } }) => {
      if (['complete', 'paused', 'watch-paused', 'cancelled', 'needs-attention'].includes(payload.state)) schedule();
    };
    subscribe(listen('photo-import-history', schedule));
    subscribe(listen('photo-import', onImport));
    subscribe(listen('photo-drop-import', onImport));
    return () => {
      alive = false;
      clearTimeout(refresh);
      subscriptions.forEach(stop => stop());
    };
  });

  async function retry(entry: Entry) {
    retrying = true;
    error = '';
    try {
      await invoke('retry_photo_import', { kind: entry.kind, runId: entry.runId });
      await load();
    } catch (reason) {
      await load();
      if (alive) error = reason === 'source_history_retry_unavailable'
        ? 'This import has changed. Check the current import and its approval before retrying.'
        : 'The import could not restart. Check the current source or album before trying again.';
    } finally {
      retrying = false;
    }
  }
</script>

{#if native}
  <section aria-labelledby="import-history-heading" aria-busy={retrying}>
    <div class="group-head">
      <h2 class="group-title" id="import-history-heading">Import history</h2>
      <button class="btn quiet" disabled={retrying} onclick={load}>Refresh</button>
    </div>
    <div class="group">
      {#if error}<div class="row"><span class="l"><small class="danger-text" role="status">{error}</small></span></div>{/if}
      {#if entries.length}
        {#if !error && completion !== 'unobserved'}
          <div class="row"><span class="l"><small>{completion === 'repeat' ? 'First and repeat verified imports observed in retained history.' : 'One verified import observed in retained history.'}</small></span></div>
        {/if}
        {#each entries.slice(0, visible) as entry (entry.runId)}
          <div class="row top">
            <span class="l">
              <b>{kinds[entry.kind]}</b>
              <small>{entry.createdAt === null ? 'Earlier import' : formatWhen(entry.createdAt, Date.now())} · {entry.album ?? 'Library'}</small>
              <small>{entry.verified.toLocaleString()} of {entry.total.toLocaleString()} verified{#if entry.skipped} · {entry.skipped.toLocaleString()} skipped{/if}{#if entry.albumPending} · Album attachment pending{/if}</small>
            </span>
            <span class="pill {entry.status === 'complete' ? 'ok' : entry.status === 'interrupted' || entry.status === 'running' ? 'wait' : 'off'}"><i aria-hidden="true"></i>{statuses[entry.status]}</span>
            {#if entry.canRetry}<button class="btn" disabled={retrying} onclick={() => retry(entry)}>Retry import</button>{/if}
          </div>
        {/each}
        {#if visible < entries.length}<div class="row"><button class="btn quiet" onclick={() => { visible += 20; }}>Show earlier imports</button></div>{/if}
      {:else if loaded}
        <div class="empty">No import runs for this sign-in.</div>
      {:else if !error}
        <div class="empty" role="status">Loading import history…</div>
      {/if}
    </div>
  </section>
{/if}
