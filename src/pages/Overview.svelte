<script lang="ts">
  import { onMount } from 'svelte';
  import { invoke } from '@tauri-apps/api/core';
  import { listen, type UnlistenFn } from '@tauri-apps/api/event';
  import Icon from '../Icon.svelte';
  import AiLibrary from './AiLibrary.svelte';
  import { workerView, workloadReason } from '../mode-state';
  import { describeError } from '../errors';
  import { workloadName, workloadPill, hostOf, connectionTransport, formatBytes, relativeTime, percent, computerWord, platformFromUserAgent } from '../ui-state';
  import type { Connection, SetupStatus, ServerSummary, AttentionItem } from '../server-types';
  import { backupHealth, backupWarning, libraryHeadroom, storageWarning } from '../server-health';

  let { connection, setup, summary, native, section = 'all', onsetup, onconnection, onrefresh, onsignout, onopen }: {
    connection: Connection; setup: SetupStatus | null; summary: ServerSummary | null; native: boolean; section?: 'all' | 'ai';
    onsetup: (value: SetupStatus | null) => void; onconnection: (value: Connection) => void; onrefresh: () => Promise<void> | void; onsignout: () => void; onopen: (page: string) => void;
  } = $props();
  const computer = computerWord(platformFromUserAgent(navigator.userAgent));
  let busy = $state(false);
  let failure = $state('');
  let failureReference = $state<string | null>(null);
  function fail(error: unknown) { ({ message: failure, reference: failureReference } = describeError(error)); }
  // The backend publishes every worker status change as the worker-setup event, which App passes down as `setup`.
  const worker = $derived(workerView({ connectionState: connection.state, workerSupported: connection.features.worker || connection.features.workerSession, computer, setup }));
  const connectionPill = $derived(connection.state === 'offline' ? { label: 'Server unavailable', tone: 'off' } : connection.state === 'identity-changed' ? { label: 'Identity changed', tone: 'bad' } : connection.state === 'awaiting-approval' ? { label: 'Awaiting approval', tone: 'wait' } : { label: 'Connected', tone: 'ok' });
  const control = $derived(setup?.control ?? 'running');
  const canControl = $derived(connection.mode === 'client-worker' && connection.features.workerSession);
  const attention = $derived(summary?.me?.isAdmin === true
    ? (summary.attention?.items ?? []).filter(item => !(summary?.attention?.dismissed ?? []).includes(item.id))
    : []);
  const storage = $derived(libraryHeadroom(summary?.storage));
  const backup = $derived(backupHealth(summary));
  const healthChecked = $derived(relativeTime(summary?.attention?.checkedAt));

  // Photo sources summary (read-only here; the Photo sources page owns the actions).
  type Consent = { id: string; name: string; path: string; registered: boolean; allowDownload: boolean };
  type CopyJob = { sourceId: string; state: string; total: number; completed: number; logicalBytes: number; skipped: number; code: string | null; uploadRemaining: number | null };
  let consent = $state<Consent | null>(null);
  let job = $state<CopyJob | null>(null);
  let alive = true;
  onMount(() => {
    let unlisten: UnlistenFn | undefined;
    if (native) void (async () => {
      try {
        unlisten = await listen<CopyJob>('photo-import', event => { if (alive && event.payload.sourceId === consent?.id) job = event.payload; });
        if (!alive) { unlisten(); return; }
        consent = await invoke<Consent | null>('photo_source_status').catch(() => null);
        if (consent?.registered) job = await invoke<CopyJob | null>('photo_import_status').catch(() => null);
      } catch { /* the summary is best-effort */ }
    })();
    return () => { alive = false; unlisten?.(); };
  });

  async function photos() {
    failure = '';
    try { await invoke('open_photos'); } catch (error) { fail(error); }
  }
  async function controlWorker(target: 'running' | 'paused' | 'stopped') {
    if (!native || busy) return;
    busy = true; failure = '';
    try { onsetup(await invoke<SetupStatus>('control_worker', { control: target })); }
    catch (error) {
      fail(error);
      onsetup(await invoke<SetupStatus>('worker_setup_status').catch(() => setup));
    }
    finally { busy = false; }
  }
  async function prepareModels(allowDownload: boolean) {
    if (!native || busy) return;
    busy = true; failure = '';
    try { await invoke('prepare_models', { allowDownload }); }
    catch (error) { fail(error); }
    finally { busy = false; }
  }
  async function checkApproval() {
    if (!native || busy) return;
    busy = true; failure = '';
    try {
      const restored = await invoke<Connection | null>('restore_connection', { retry: true });
      if (restored) onconnection(restored);
      onsetup(await invoke<SetupStatus>('worker_setup_status'));
      await onrefresh();
    } catch (error) { fail(error); }
    finally { busy = false; }
  }
  function attentionText(item: AttentionItem): { title: string; detail: string; page: string } {
    switch (item.reason) {
      case 'not-backed-up':
      case 'backup-failed':
      case 'backup-behind': return backupWarning(item);
      case 'nearly-full':
      case 'out-of-space': return { ...storageWarning(item), page: 'manager' };
      case 'work-failed': return { title: 'Some server work failed', detail: item.work ? `${item.work.count.toLocaleString()} items across ${item.work.queues.map(queue => queue.name).join(', ')}.` : '', page: 'ai' };
      case 'work-paused': return { title: 'Server work is paused', detail: item.work ? `${item.work.count.toLocaleString()} items are waiting.` : '', page: 'ai' };
      case 'new-version': return { title: `Frameleaf ${item.version?.available ?? ''} is available`, detail: item.version ? `This server runs ${item.version.current}.` : '', page: 'manager' };
      default: return { title: 'Your server needs attention', detail: '', page: 'overview' };
    }
  }
</script>

<section class="page" aria-labelledby="page-title">
  <header class="toolbar">
    <h1 id="page-title">{section === 'ai' ? 'AI processing' : 'My computer'}</h1>
    <span class="pill {section === 'ai' ? worker.pill.tone : connectionPill.tone}"><i aria-hidden="true"></i>{section === 'ai' ? worker.headline : connectionPill.label}</span>
    <span class="sp"></span>
    {#if section === 'ai' && canControl}
      <div class="seg" role="group" aria-label="Worker control">
        <button class:on={control === 'running'} aria-pressed={control === 'running'} disabled={busy || !native} onclick={() => controlWorker('running')}>Running</button>
        <button class:on={control === 'paused'} aria-pressed={control === 'paused'} disabled={busy || !native} onclick={() => controlWorker('paused')}>Pause</button>
        <button class:on={control === 'stopped'} aria-pressed={control === 'stopped'} disabled={busy || !native} onclick={() => controlWorker('stopped')}>Stop</button>
      </div>
    {/if}
    <button class="btn primary" disabled={busy || !native || connection.state === 'identity-changed'} onclick={photos}><Icon name="open" />Open Photos</button>
  </header>
  <div class="body">
    {#if failure}<div class="inline-msg error" role="alert"><p>{failure}{#if failureReference} <small class="muted">Reference: {failureReference}</small>{/if}</p><button class="btn small quiet" onclick={() => { failure = ''; }}>Dismiss</button></div>{/if}
    {#if section === 'all'}
      {#if attention.length}
        <div>
          <div class="group-head"><h2 class="group-title">Needs attention</h2></div>
          <div class="group">
            {#each attention as item (item.id)}
              {@const text = attentionText(item)}
              <div class="row">
                <span class="ic" aria-hidden="true"><Icon name="warn" /></span>
                <span class="l"><b>{text.title}</b><small>{text.detail}</small></span>
                <span class="pill {item.level === 'now' ? 'wait' : 'off'}"><i aria-hidden="true"></i>{item.level === 'now' ? 'Now' : 'Soon'}</span>
                <button class="btn quiet" disabled={text.page === 'photos' && (!native || busy || connection.state === 'identity-changed')} onclick={() => text.page === 'photos' ? void photos() : onopen(text.page)}>{text.page === 'photos' ? 'Open Photos' : 'Open'}</button>
              </div>
            {/each}
          </div>
        </div>
      {/if}
      <div>
        <div class="group-head"><h2 class="group-title">Server</h2></div>
        <div class="group">
          <div class="row">
            <span class="ic" aria-hidden="true"><Icon name="server" /></span>
            <span class="l"><b>{hostOf(connection.server)}</b><small>Signed in as {connection.name} · {connectionTransport(connection.server)}{summary?.me?.isAdmin ? ' · Administrator' : ''}</small></span>
            <button class="btn" disabled={busy} onclick={onsignout}>Sign Out…</button>
          </div>
          {#if summary?.storage || summary?.version}
            <div class="kv">
              <div><span>Version check</span><b>{summary?.version?.releaseVersion ? `Newest ${summary.version.releaseVersion}` : 'No newer version seen'}</b><small class="muted" style="display:block;font-size:12px;margin-top:3px">checked {relativeTime(summary?.version?.checkedAt ?? null)}</small></div>
              <div><span>Connection</span><b>{connection.features.worker ? 'Desktop workers supported' : 'Desktop workers need a server update'}</b><small class="muted" style="display:block;font-size:12px;margin-top:3px">{connection.features.sources ? 'Photo sources available' : 'Photo sources need a server update'}</small></div>
            </div>
          {/if}
        </div>
      </div>
      <div>
        <div class="group-head"><h2 class="group-title">Server health</h2></div>
        <div class="group">
          <div class="row" class:top={storage.usedPercent !== null}>
            <span class="ic" aria-hidden="true"><Icon name="server" /></span>
            <span class="l">
              <b>Library drive</b>
              <small style={storage.usedPercent !== null ? 'margin-bottom:8px' : ''}>{storage.capacity ?? 'Available space is unknown.'}{storage.usedPercent !== null ? ` · ${storage.usedPercent}% used` : ''}</small>
              {#if storage.usedPercent !== null}<span class="progress" role="progressbar" aria-valuenow={storage.usedPercent} aria-valuemin="0" aria-valuemax="100" aria-label="Library drive used"><span style="width:{storage.usedPercent}%"></span></span>{/if}
            </span>
          </div>
          {#if backup}
            <div class="row">
              <span class="ic" aria-hidden="true"><Icon name="backup" /></span>
              <span class="l"><b>Backup check</b>{#if healthChecked !== 'never'}<small>Checked {healthChecked}</small>{/if}</span>
              <span class="pill {backup.tone}"><i aria-hidden="true"></i>{backup.label}</span>
            </div>
          {/if}
        </div>
      </div>
    {/if}

    <div>
      <div class="group-head">
        <h2 class="group-title">{section === 'ai' ? 'This computer' : 'AI processing'}</h2>
        {#if section === 'all' && canControl}
          <div class="seg" role="group" aria-label="Worker control">
            <button class:on={control === 'running'} aria-pressed={control === 'running'} disabled={busy || !native} onclick={() => controlWorker('running')}>Running</button>
            <button class:on={control === 'paused'} aria-pressed={control === 'paused'} disabled={busy || !native} onclick={() => controlWorker('paused')}>Pause</button>
            <button class:on={control === 'stopped'} aria-pressed={control === 'stopped'} disabled={busy || !native} onclick={() => controlWorker('stopped')}>Stop</button>
          </div>
        {/if}
      </div>
      <div class="group" aria-label="Computer processing status">
        <div class="row">
          <span class="ic" aria-hidden="true"><Icon name="ai" /></span>
          <span class="l"><b>{worker.headline}</b><small>{worker.detail}{#if worker.reference} <span class="muted">Reference: {worker.reference}</span>{/if}</small></span>
          <span class="pill {worker.pill.tone}"><i aria-hidden="true"></i>{worker.pill.label}</span>
          {#if worker.action === 'download-models'}<button class="btn" disabled={busy || !native} onclick={() => prepareModels(true)}>Download Models</button>{/if}
          {#if worker.action === 'check-approval'}<button class="btn" disabled={busy || !native} onclick={checkApproval}>Check Approval</button>{/if}
          {#if worker.action === 'check-server'}<button class="btn" disabled={busy || !native} onclick={checkApproval}>Check Again</button>{/if}
          {#if worker.action === 'retry-setup'}<button class="btn" disabled={busy || !native} onclick={() => prepareModels(false)}>Retry Setup</button>{/if}
        </div>
        {#if worker.finished}
          <div class="row"><span class="l"><b>Tasks finished</b><small>{worker.finished}</small></span></div>
        {/if}
        {#if section === 'ai'}
          {#if setup?.activeWorkload}
            <div class="row"><span class="l"><b>{workloadName(setup.activeWorkload)}</b><small>Processing on this computer</small></span></div>
          {/if}
          <div class="row" class:top={!!setup?.models?.download}>
            <span class="l">
              <b>Selected model files</b>
              <small>{setup?.models ? `${formatBytes(setup.models.verifiedBytes)} verified on this computer · ${formatBytes(setup.models.totalBytes)} needed` : 'Storage unknown'}</small>
              {#if setup?.models?.download}
                {@const transfer = setup.models.download}
                {@const downloaded = Math.min(100, Math.round(transfer.receivedBytes / transfer.totalBytes * 100))}
                <small>Downloading a model file · {formatBytes(transfer.receivedBytes)} of {formatBytes(transfer.totalBytes)}</small>
                <span class="progress" role="progressbar" aria-valuenow={downloaded} aria-valuemin="0" aria-valuemax="100" aria-label="Model file download"><span style="width:{downloaded}%"></span></span>
              {/if}
            </span>
          </div>
        {/if}
        {#each setup?.workloads ?? [] as workload (workload.workload)}
          {@const pill = workloadPill(workload.state)}
          <div class="row">
            <span class="l"><b>{workloadName(workload.workload)}</b><small>{workload.modelNames?.length ? workload.modelNames.join(' · ') : pill.detail}{workload.modelNames?.length && workload.state !== 'ready' ? ` · ${pill.detail}` : ''}{workload.state === 'unavailable' && workloadReason(workload.code) ? ` · ${workloadReason(workload.code)}` : ''}</small></span>
            <span class="pill {pill.tone}"><i aria-hidden="true"></i>{pill.label}</span>
          </div>
        {/each}
      </div>
      <p class="foot">Processing starts only after the selected models pass qualification on this {computer}. Pausing finishes the current task first. Server administration uses your existing Frameleaf permissions inside Photos.</p>
    </div>

    {#if section === 'ai'}
      {#key JSON.stringify([connection.server, summary?.me?.id])}
        <AiLibrary {native} server={connection.server} accountId={summary?.me?.id} admin={summary?.me?.isAdmin === true} connected={connection.state !== 'offline' && connection.state !== 'identity-changed'} />
      {/key}
    {/if}

    {#if section === 'all'}
      <div>
        <div class="group-head">
          <h2 class="group-title">Photo sources</h2>
          <button class="btn quiet" onclick={() => onopen('sources')}>Manage…</button>
        </div>
        <div class="group">
          {#if consent}
            <div class="row" class:top={!!job && !['complete', 'cancelled'].includes(job.state)}>
              <span class="ic" aria-hidden="true"><Icon name="folder" /></span>
              <span class="l">
                <b>{consent.name}</b>
                <small style={job && !['complete', 'cancelled'].includes(job.state) ? 'margin-bottom:8px' : ''}>{consent.path}{job ? ` · ${job.state === 'complete' ? 'Copy complete' : job.state === 'cancelled' ? 'Copy cancelled' : job.state === 'copying' ? 'Copying' : job.state === 'ready' ? 'Copy prepared' : job.state === 'paused' ? 'Copy paused' : 'Copy needs attention'} · ${job.completed.toLocaleString()} of ${job.total.toLocaleString()} copies confirmed${job.uploadRemaining !== null ? ` · ${formatBytes(job.uploadRemaining)} upload allowance left` : ''}` : consent.registered ? ' · Registered with your server' : ' · Registration pending'}</small>
                {#if job && !['complete', 'cancelled'].includes(job.state)}<span class="progress" role="progressbar" aria-valuenow={percent(job.completed, job.total)} aria-valuemin="0" aria-valuemax="100" aria-label="Copy progress"><span style="width:{percent(job.completed, job.total)}%"></span></span>{/if}
              </span>
              {#if job?.state === 'complete'}<span class="pill ok"><i aria-hidden="true"></i>Up to date</span>{:else if job?.state === 'copying'}<span class="pill wait"><i aria-hidden="true"></i>Copying</span>{:else if job}<span class="pill off"><i aria-hidden="true"></i>{job.state === 'ready' ? 'Prepared' : job.state === 'paused' ? 'Paused' : 'Attention'}</span>{/if}
              <button class="btn quiet" onclick={() => onopen('sources')}>Details</button>
            </div>
          {:else}
            <div class="row">
              <span class="ic dim" aria-hidden="true"><Icon name="folder" /></span>
              <span class="l"><b>No photo folder connected</b><small>Choose a folder to copy photos to your server. Originals stay where they are.</small></span>
              <button class="btn" onclick={() => onopen('sources')}>Add Folder…</button>
            </div>
          {/if}
        </div>
        <p class="foot">Originals stay in their folders. A copy counts only after your server verifies its stored bytes.</p>
      </div>
    {/if}
  </div>
</section>
