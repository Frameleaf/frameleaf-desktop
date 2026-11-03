<script lang="ts">
  import { onMount } from 'svelte';
  import { invoke } from '@tauri-apps/api/core';
  import { listen, type UnlistenFn } from '@tauri-apps/api/event';
  import Icon from '../Icon.svelte';
  import { workerStatus, runtimeRecoveryMessage } from '../mode-state';
  import { connectionError } from '../errors';
  import { workloadName, workloadPill, workerTone, hostOf, formatBytes, relativeTime, percent, computerWord, platformFromUserAgent } from '../ui-state';
  import type { Connection, SetupStatus, ServerSummary, AttentionItem } from '../server-types';

  let { connection, setup, summary, native, section = 'all', onsetup, onconnection, onrefresh, onsignout, onopen }: {
    connection: Connection; setup: SetupStatus | null; summary: ServerSummary | null; native: boolean; section?: 'all' | 'ai';
    onsetup: (value: SetupStatus | null) => void; onconnection: (value: Connection) => void; onrefresh: () => Promise<void> | void; onsignout: () => void; onopen: (page: string) => void;
  } = $props();
  const computer = computerWord(platformFromUserAgent(navigator.userAgent));
  let busy = $state(false);
  let failure = $state('');
  const explain = connectionError;
  const setupState = $derived(setup?.state || connection?.state || '');
  const headline = $derived(connection.state === 'offline' ? 'Server unavailable' : connection.state === 'identity-changed' ? 'Server identity changed' : connection.state === 'enrollment-failed' ? 'Computer setup needs attention' : workerStatus({ state: setupState, workerSupported: connection.features.worker }));
  const setupDetail = $derived(runtimeRecoveryMessage(setup?.code ?? null) ?? (setup?.code === 'runtime_pack_unavailable'
    ? 'This build does not include a signed AI runtime yet. Photos remain available.'
    : setup?.state === 'model-download-required'
    ? 'The selected models need downloading. Downloading waits for your permission on metered or unclassified networks.'
    : setup?.state === 'reconnecting'
    ? 'Waiting for a secure connection to your server. This computer will recheck its session, models and resources before processing again.'
    : setup?.state === 'pausing'
    ? 'The current bounded task will finish, then this computer will stop requesting work.'
    : setup?.state === 'stopped'
    ? 'AI processing is stopped on this computer. Resume whenever you are ready. Photos remain available.'
    : setup?.state === 'paused'
    ? ({ system_resumed: 'This computer resumed or its clock changed. Rechecking the selected models before more work.', user_paused: 'Paused by you. This computer will stay paused after reopening the app.', on_battery: 'Plug in this computer to continue AI processing.', power_unknown: 'Power status could not be read. AI processing is paused.', metered_network: 'AI processing pauses on metered networks. Photos remain available.', network_unknown: 'Network cost could not be determined. AI processing is paused.', memory_low: 'Waiting for enough memory for the selected model.', memory_unknown: 'Memory status could not be read. AI processing is paused.' } as Record<string, string>)[setup.code ?? ''] ?? 'AI processing is paused.'
    : setup?.state === 'qualified'
    ? 'The selected models passed this computer’s checks.'
    : setup?.state === 'starting-worker'
    ? 'Starting the checked models locally before requesting work from your server.'
    : setup?.state === 'working'
    ? 'This computer can process one selected AI task at a time while power, network and memory allow.'
    : setup?.state === 'waiting-for-work'
    ? 'Connected and waiting for your server to send AI work.'
    : setup?.state === 'qualifying'
    ? 'Running the selected models locally and checking the results with your server.'
    : setup?.state === 'preparing-models'
    ? 'Verifying the selected model files. You can keep using Photos while this runs.'
    : setup?.state === 'preparing-runtime'
    ? 'Checking the signed runtime included with this app.'
    : setup?.state === 'setup-needs-attention'
    ? 'AI setup could not finish. Photos remain available. Retry setup when your server and network are ready.' : ''));
  const connectionDetail = $derived(connection.state === 'identity-changed' ? 'Processing is stopped. Verify the server before signing in again.' : connection.state === 'worker-setup-failed' ? 'Photos are available, but this computer could not complete worker setup. Reopen the app to retry.' : connection.state === 'credential-store-unavailable' ? 'Unlock your computer’s credential store and reopen the app to finish setup.' : connection.state === 'enrollment-failed' ? 'Photo sign-in succeeded, but this computer could not be enrolled. Reopen the app to retry setup.' : `Processing starts only after the selected models pass qualification on this ${computer}. Pausing finishes the current task first.`);
  const connectionPill = $derived(connection.state === 'offline' ? { label: 'Server unavailable', tone: 'off' } : connection.state === 'identity-changed' ? { label: 'Identity changed', tone: 'bad' } : connection.state === 'awaiting-approval' ? { label: 'Awaiting approval', tone: 'wait' } : { label: 'Connected', tone: 'ok' });
  const control = $derived(setup?.control ?? 'running');
  const canControl = $derived(connection.mode === 'client-worker' && connection.features.workerSession);
  const attention = $derived((summary?.attention?.items ?? []).filter(item => !(summary?.attention?.dismissed ?? []).includes(item.id)));

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
    try { await invoke('open_photos'); } catch (error) { failure = explain(error); }
  }
  async function controlWorker(target: 'running' | 'paused' | 'stopped') {
    if (!native || busy) return;
    busy = true; failure = '';
    try { onsetup(await invoke<SetupStatus>('control_worker', { control: target })); }
    catch (error) {
      failure = explain(error);
      onsetup(await invoke<SetupStatus>('worker_setup_status').catch(() => setup));
    }
    finally { busy = false; }
  }
  async function prepareModels(allowDownload: boolean) {
    if (!native || busy) return;
    busy = true; failure = '';
    try { await invoke('prepare_models', { allowDownload }); }
    catch (error) { failure = explain(error); }
    finally { busy = false; }
  }
  async function checkApproval() {
    if (!native || busy) return;
    busy = true; failure = '';
    try {
      const restored = await invoke<Connection | null>('restore_connection');
      if (restored) onconnection(restored);
      onsetup(await invoke<SetupStatus>('worker_setup_status'));
      await onrefresh();
    } catch (error) { failure = explain(error); }
    finally { busy = false; }
  }
  function attentionText(item: AttentionItem): { title: string; detail: string; page: string } {
    switch (item.reason) {
      case 'not-backed-up': return { title: 'Your library is not backed up', detail: 'Set up a backup so your photos survive a failed drive.', page: 'cloud' };
      case 'backup-failed': return { title: 'The last backup failed', detail: item.backup?.lastSuccessAt ? `Last successful backup ${relativeTime(item.backup.lastSuccessAt)}.` : 'No backup has completed yet.', page: 'cloud' };
      case 'backup-behind': return { title: 'Backup is behind', detail: item.backup?.days != null ? `${item.backup.days} days since the last successful backup.` : 'The last backup is older than expected.', page: 'cloud' };
      case 'nearly-full': return { title: 'Storage is nearly full', detail: item.storage ? `${formatBytes(item.storage.availableBytes)} left of ${formatBytes(item.storage.totalBytes)}.` : '', page: 'manager' };
      case 'out-of-space': return { title: 'The server is out of space', detail: item.storage ? `${formatBytes(item.storage.availableBytes)} left of ${formatBytes(item.storage.totalBytes)}.` : '', page: 'manager' };
      case 'work-failed': return { title: 'Some server work failed', detail: item.work ? `${item.work.count.toLocaleString()} items across ${item.work.queues.map(queue => queue.name).join(', ')}.` : '', page: 'ai' };
      case 'work-paused': return { title: 'Server work is paused', detail: item.work ? `${item.work.count.toLocaleString()} items are waiting.` : '', page: 'ai' };
      case 'new-version': return { title: `Frameleaf ${item.version?.available ?? ''} is available`, detail: item.version ? `This server runs ${item.version.current}.` : '', page: 'manager' };
      default: return { title: item.reason, detail: '', page: 'overview' };
    }
  }
</script>

<section class="page" aria-labelledby="page-title">
  <header class="toolbar">
    <h1 id="page-title">{section === 'ai' ? 'AI processing' : 'My computer'}</h1>
    <span class="pill {section === 'ai' ? workerTone(setupState) : connectionPill.tone}"><i aria-hidden="true"></i>{section === 'ai' ? headline : connectionPill.label}</span>
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
    {#if failure}<div class="inline-msg error" role="alert"><p>{failure}</p><button class="btn small quiet" onclick={() => { failure = ''; }}>Dismiss</button></div>{/if}
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
                <button class="btn quiet" onclick={() => onopen(text.page)}>Open</button>
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
            <span class="l"><b>{hostOf(connection.server)}</b><small>Signed in as {connection.name} · Encrypted connection · This {computer} is enrolled{summary?.me?.isAdmin ? ' · Administrator' : ''}</small></span>
            <button class="btn" disabled={busy} onclick={onsignout}>Sign Out…</button>
          </div>
          {#if summary?.storage || summary?.version}
            <div class="kv">
              <div><span>Storage</span><b>{summary?.storage?.diskAvailable ?? formatBytes(summary?.storage?.diskAvailableRaw)} free</b><small class="muted" style="display:block;font-size:12px;margin-top:3px">of {summary?.storage?.diskSize ?? formatBytes(summary?.storage?.diskSizeRaw)}</small></div>
              <div><span>Version check</span><b>{summary?.version?.releaseVersion ? `Newest ${summary.version.releaseVersion}` : 'No newer version seen'}</b><small class="muted" style="display:block;font-size:12px;margin-top:3px">checked {relativeTime(summary?.version?.checkedAt ?? null)}</small></div>
              <div><span>Connection</span><b>{connection.features.worker ? 'Desktop workers supported' : 'Desktop workers need a server update'}</b><small class="muted" style="display:block;font-size:12px;margin-top:3px">{connection.features.sources ? 'Photo sources available' : 'Photo sources need a server update'}</small></div>
            </div>
          {/if}
          {#if summary?.storage && typeof summary.storage.diskUsagePercentage === 'number'}
            <div class="row top"><span class="l"><small style="margin:0 0 8px">{summary.storage.diskUse ?? formatBytes(summary.storage.diskUseRaw)} used · {Math.round(summary.storage.diskUsagePercentage)}% of the library drive</small><span class="progress" class:warn={summary.storage.diskUsagePercentage > 90} role="progressbar" aria-valuenow={Math.round(summary.storage.diskUsagePercentage)} aria-valuemin="0" aria-valuemax="100" aria-label="Server storage used"><span style="width:{percent(summary.storage.diskUseRaw, summary.storage.diskSizeRaw) || Math.round(summary.storage.diskUsagePercentage)}%"></span></span></span></div>
          {/if}
        </div>
      </div>
    {/if}

    <div>
      <div class="group-head">
        <h2 class="group-title">AI processing</h2>
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
          <span class="l"><b>{headline}</b><small>{setupDetail || connectionDetail}</small></span>
          <span class="pill {workerTone(setupState)}"><i aria-hidden="true"></i>{setupState === 'working' ? 'Available' : setupState === 'pausing' ? 'Finishing' : setupState === 'waiting-for-work' ? 'Idle' : control === 'paused' ? 'Paused' : control === 'stopped' ? 'Stopped' : 'Not running'}</span>
          {#if setup?.state === 'model-download-required'}<button class="btn" disabled={busy || !native} onclick={() => prepareModels(true)}>Download Models</button>{/if}
          {#if connection.state === 'awaiting-approval'}<button class="btn" disabled={busy || !native} onclick={checkApproval}>Check Approval</button>{/if}
          {#if setup?.state === 'setup-needs-attention'}<button class="btn" disabled={busy || !native} onclick={() => prepareModels(false)}>Retry Setup</button>{/if}
        </div>
        {#each setup?.workloads ?? [] as workload (workload.workload)}
          {@const pill = workloadPill(workload.state)}
          <div class="row">
            <span class="l"><b>{workloadName(workload.workload)}</b><small>{workload.modelNames?.length ? workload.modelNames.join(' · ') : pill.detail}{workload.modelNames?.length && workload.state !== 'ready' ? ` · ${pill.detail}` : ''}</small></span>
            <span class="pill {pill.tone}"><i aria-hidden="true"></i>{pill.label}</span>
          </div>
        {/each}
      </div>
      <p class="foot">{connectionDetail} Server administration uses your existing Frameleaf permissions inside Photos.</p>
    </div>

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
