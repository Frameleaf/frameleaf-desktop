<script lang="ts">
  import { onMount } from 'svelte';
  import { invoke } from '@tauri-apps/api/core';
  import Icon from '../Icon.svelte';
  import Sheet from '../Sheet.svelte';
  import { connectionError } from '../errors';
  import StepUp from '../StepUp.svelte';
  import { verificationRequired, type StepOffer } from '../sign-in-steps';
  import { connectionPath, pathIndicator, formatBytes, formatDate, percent, relativeTime, hostOf, type PathEntry } from '../ui-state';
  import type { RemoteStatus, RemoteUpdate, RemoteTest, CloudStatus, ServerSummary, Connection } from '../server-types';

  let { native, summary, connection, onrefresh }: { native: boolean; summary: ServerSummary | null; connection: Connection; onrefresh: () => Promise<void> | void } = $props();
  let data = $state<RemoteStatus | null>(null);
  let cloud = $state<CloudStatus | null>(null);
  let busy = $state(false);
  let saving = $state(false);
  let testing = $state(false);
  let failure = $state('');
  let notice = $state('');
  let copied = $state('');
  let dnsOpen = $state(false);
  let test = $state<RemoteTest | null>(null);
  const explain = connectionError;
  // A request the server refuses until Two-Step Verification is answered in place, then run again.
  let stepUp = $state<{ offer: StepOffer; retry: () => void } | null>(null);
  function failed(error: unknown, retry: () => void) {
    const offer = verificationRequired(error);
    if (offer) stepUp = { offer, retry }; else failure = explain(error);
  }
  const remote = $derived(data?.remote ?? null);
  const usage = $derived(data?.usage ?? null);
  const path = $derived(connectionPath(summary?.connections ?? remote?.candidates ?? null, connection.server));
  const steps = $derived(pathIndicator(path.current));
  const entries = $derived<PathEntry[]>(path.entries.length ? path.entries : connectionPath(remote?.candidates ?? null, connection.server).entries);
  const pill = $derived(!remote ? { label: busy ? 'Checking' : 'Unavailable', tone: 'off' } : !remote.enabled ? { label: 'Off', tone: 'off' } : remote.status === 'ready' ? { label: 'On', tone: 'ok' } : remote.status === 'error' ? { label: 'Error', tone: 'bad' } : remote.status === 'starting' ? { label: 'Starting', tone: 'wait' } : { label: remote.status === 'unknown' ? 'No recent report' : 'Idle', tone: 'wait' });
  const serverName = $derived(hostOf(connection.server));
  async function load() {
    if (!native) return;
    busy = true; failure = '';
    const [status, link] = await Promise.allSettled([invoke<RemoteStatus>('remote_status'), invoke<CloudStatus>('cloud_status')]);
    if (status.status === 'fulfilled') data = status.value; else failed(status.reason, () => { void load(); });
    cloud = link.status === 'fulfilled' ? link.value : null;
    busy = false;
  }
  onMount(() => { void load(); });
  async function update(settings: RemoteUpdate, done: string) {
    if (!native || saving) return;
    saving = true; failure = ''; notice = '';
    try {
      await invoke('update_remote', { settings });
      notice = done;
      await load();
      await onrefresh();
    } catch (error) { failed(error, () => { void update(settings, done); }); }
    finally { saving = false; }
  }
  async function runTest() {
    if (!native || testing) return;
    testing = true; failure = ''; notice = ''; test = null;
    try {
      const result = await invoke<RemoteTest>('test_remote_access');
      test = result;
      const checks = result?.checks ?? result?.lastTestChecks ?? [];
      const ok = result?.ok ?? result?.lastTestOk ?? checks.every(check => check.ok);
      notice = ok ? 'Remote access test passed.' : 'Remote access test found a problem. See the checks below.';
      await load();
    } catch (error) { failed(error, () => { void runTest(); }); }
    finally { testing = false; }
  }
  async function copy(uri: string) {
    try { await navigator.clipboard.writeText(uri); copied = uri; setTimeout(() => { if (copied === uri) copied = ''; }, 1500); }
    catch { failure = 'The address could not be copied. Select it and copy it yourself.'; }
  }
  function statusFor(entry: PathEntry): { label: string; tone: string } {
    if (entry.kind === 'custom') return remote?.customHostnameStatus === 'verified' ? { label: 'Verified', tone: 'ok' } : { label: 'Waiting for CNAME', tone: 'wait' };
    if (entry.kind === 'relay') return remote?.relayConnected ? { label: 'Connected', tone: 'ok' } : remote?.relayRevoked ? { label: 'Revoked', tone: 'bad' } : { label: 'Not connected', tone: 'off' };
    if (entry.kind === 'direct') return remote?.wanVerified ? { label: 'Verified by cloud probe', tone: 'ok' } : remote?.wanProblem ? { label: `Not reachable · ${remote.wanProblem}`, tone: 'wait' } : entry.verified ? { label: 'Verified', tone: 'ok' } : { label: 'Reported by server', tone: 'off' };
    return entry.verified ? { label: 'Verified', tone: 'ok' } : { label: 'Reported by server', tone: 'off' };
  }
  function detailFor(entry: PathEntry): string {
    if (entry.current) return 'in use now';
    if (entry.kind === 'direct') return `public, port ${remote?.directPort ?? hostOf(entry.uri).split(':')[1] ?? '443'}${remote?.mappingMethod ? ` via ${remote.mappingMethod === 'upnp' ? 'UPnP' : remote.mappingMethod === 'nat-pmp' ? 'NAT-PMP' : 'manual forwarding'}` : ''}`;
    if (entry.kind === 'relay') return `${remote?.relayRegion ?? 'relay'}${remote?.relayLatencyMs != null ? ` · ${remote.relayLatencyMs} ms` : ''}`;
    if (entry.kind === 'custom') return remote?.mode === 'relay' ? 'relay only' : 'relay and direct';
    return entry.detail;
  }
</script>

<section class="page" aria-labelledby="remote-title">
  <header class="toolbar">
    <h1 id="remote-title">Remote access</h1>
    <span class="pill {pill.tone}"><i aria-hidden="true"></i>{pill.label}</span>
    <span class="sp"></span>
    <span class="path" aria-label="How this computer is connected: {path.currentLabel}">{#each steps as step (step.key)}<span class:on={step.on}>{step.label}</span>{/each}</span>
    {#if remote && !remote.unavailableReason}
      <button class="toggle" style="margin-left:6px" class:on={!!remote.enabled} role="switch" aria-checked={!!remote.enabled} aria-label="Remote access" disabled={saving || !native} onclick={() => update({ enabled: !remote?.enabled }, remote?.enabled ? 'Remote access turned off.' : 'Remote access turned on.')}></button>
    {/if}
    <button class="btn" style="margin-left:6px" disabled={testing || !native || !remote?.enabled} onclick={runTest}>{testing ? 'Testing…' : 'Test Connection'}</button>
  </header>
  <div class="body">
    {#if !native}<p class="foot" style="margin:0">Open the installed desktop app to see this server’s remote access addresses.</p>{/if}
    {#if failure}<div class="inline-msg error" role="alert"><p>{failure}</p><button class="btn small quiet" onclick={() => { failure = ''; }}>Dismiss</button></div>{/if}
    {#if stepUp}{#key stepUp}<StepUp offer={stepUp.offer} retry={stepUp.retry} onclose={() => { stepUp = null; }} />{/key}{/if}
    {#if notice}<div class="inline-msg" role="status"><p>{notice}</p><button class="btn small quiet" onclick={() => { notice = ''; }}>Dismiss</button></div>{/if}
    {#if remote?.unavailableReason}<div class="inline-msg" role="status"><p>{remote.unavailableReason}</p></div>{:else if remote?.reason && remote.status !== 'ready'}<div class="inline-msg" role="status"><p>{remote.reason}</p></div>{/if}
    {#if test}
      <div>
        <div class="group-head"><h2 class="group-title">Last test{remote?.lastTestAt ? ` · ${relativeTime(remote.lastTestAt)}` : ''}</h2></div>
        <div class="group">
          {#each test.checks ?? test.lastTestChecks ?? [] as check (check.id)}
            <div class="row"><span class="l"><b>{({ certificate: 'Certificate', listener: 'Listener', api: 'API', relay: 'Relay', direct: 'Direct' } as Record<string, string>)[check.id] ?? check.id}</b><small>{check.detail}</small></span><span class="pill {check.ok ? 'ok' : 'bad'}"><i aria-hidden="true"></i>{check.ok ? 'OK' : 'Failed'}</span></div>
          {/each}
        </div>
      </div>
    {/if}
    <div>
      <div class="group-head"><h2 class="group-title">Addresses for {serverName}</h2><button class="btn quiet" disabled={busy || !native} onclick={load}>Refresh</button></div>
      <div class="group">
        {#if entries.length === 0}
          <div class="empty">{busy ? 'Reading this server’s addresses…' : 'This server has not reported any addresses yet.'}</div>
        {:else}
          <table class="table">
            <thead><tr><th scope="col">Path</th><th scope="col">Address</th><th scope="col">Status</th><th scope="col" class="right"><span class="sr">Actions</span></th></tr></thead>
            <tbody>
              {#each entries as entry (entry.kind + entry.uri)}
                {@const status = statusFor(entry)}
                <tr>
                  <td><b>{entry.label}</b><small>{detailFor(entry)}</small></td>
                  <td><span class="url">{entry.uri}</span></td>
                  <td><span class="pill {status.tone}"><i aria-hidden="true"></i>{status.label}</span></td>
                  <td class="right">
                    {#if entry.kind === 'custom' && remote?.customHostnameStatus !== 'verified' && remote?.customHostnameRecords?.length}
                      <button class="btn quiet" onclick={() => { dnsOpen = true; }}>Show DNS records</button>
                    {:else}
                      <button class="btn quiet" aria-label="Copy address" onclick={() => copy(entry.uri)}><Icon name={copied === entry.uri ? 'check' : 'copy'} />{copied === entry.uri ? 'Copied' : 'Copy'}</button>
                    {/if}
                  </td>
                </tr>
              {/each}
            </tbody>
          </table>
        {/if}
      </div>
      <p class="foot">Apps try these in order and use the first that answers, so the direct address is used whenever it works and the relay only as a fallback. Share the public server URL below with people you invite.</p>
    </div>
    <div>
      <div class="group-head"><h2 class="group-title">Public server URL</h2></div>
      <div class="group">
        <div class="row">
          <span class="l"><b>Which address do invitations and links use?</b><small>{remote?.publicUrl ? `Currently ${remote.publicUrl}.` : 'No public address yet.'}{remote?.customHostname ? remote.customHostnameStatus === 'verified' ? ` Your domain ${remote.customHostname} is verified.` : ` Your domain ${remote.customHostname} is used once its DNS records verify.` : ' Add a domain from Settings › Frameleaf Cloud inside Photos.'}</small></span>
          <span class="seg" role="group" aria-label="Public URL">
            <button class:on={remote?.publicUrlChoice === 'frameleaf'} aria-pressed={remote?.publicUrlChoice === 'frameleaf'} disabled={saving || !native || !remote} onclick={() => update({ publicUrl: 'frameleaf' }, 'Invitations and links now use the Frameleaf address.')}>Frameleaf address</button>
            <button class:on={remote?.publicUrlChoice === 'custom'} aria-pressed={remote?.publicUrlChoice === 'custom'} disabled={saving || !native || !remote?.customHostname} onclick={() => update({ publicUrl: 'custom' }, 'Invitations and links now use your domain.')}>My domain</button>
          </span>
        </div>
        <div class="row">
          <span class="l"><b>Allow originals over the relay</b><small>Off keeps full-size downloads, archives and database backups on direct paths only.</small></span>
          <button class="toggle" class:on={!!cloud?.cloud?.allowOriginalsOverRelay} role="switch" aria-checked={!!cloud?.cloud?.allowOriginalsOverRelay} aria-label="Allow originals over relay" disabled={saving || !native || !cloud} onclick={() => update({ allowOriginalsOverRelay: !cloud?.cloud?.allowOriginalsOverRelay }, cloud?.cloud?.allowOriginalsOverRelay ? 'Originals now stay on direct paths.' : 'Originals may now go through the relay.')}></button>
        </div>
        <div class="row">
          <span class="l"><b>Require Frameleaf sign-in away from home</b><small>On refuses password sign-in through the relay and direct paths; shared links stay public.</small></span>
          <button class="toggle" class:on={cloud?.cloud?.allowPasswordOverRelay === false} role="switch" aria-checked={cloud?.cloud?.allowPasswordOverRelay === false} aria-label="Require Frameleaf sign-in away from home" disabled={saving || !native || !cloud} onclick={() => update({ allowPasswordOverRelay: cloud?.cloud?.allowPasswordOverRelay === false }, cloud?.cloud?.allowPasswordOverRelay === false ? 'Password sign-in is allowed away from home again.' : 'Frameleaf sign-in is now required away from home.')}></button>
        </div>
        <div class="row">
          <span class="l"><b>Direct connections</b><small>{remote?.mode === 'relay-and-direct' ? `Port ${remote.directPort ?? ''}${remote.portMapping ? ' opened by the router automatically' : ' forwarded by hand'}${remote.mappingError ? ` · ${remote.mappingError}` : ''}${remote.cgnatSuspected ? ' · your connection may be behind carrier-grade NAT' : ''}` : 'Every remote connection goes through the relay.'}</small></span>
          <span class="seg" role="group" aria-label="Remote access mode">
            <button class:on={remote?.mode === 'relay-and-direct'} aria-pressed={remote?.mode === 'relay-and-direct'} disabled={saving || !native || !remote} onclick={() => update({ mode: 'relay-and-direct' }, 'Direct connections turned on.')}>Relay and direct</button>
            <button class:on={remote?.mode === 'relay'} aria-pressed={remote?.mode === 'relay'} disabled={saving || !native || !remote} onclick={() => update({ mode: 'relay' }, 'Remote connections now use the relay only.')}>Relay only</button>
          </span>
        </div>
      </div>
    </div>
    <div>
      <div class="group-head"><h2 class="group-title">Relay usage{usage?.period ? ` · ${new Date(`${usage.period}-01T00:00:00Z`).toLocaleDateString('en-US', { month: 'long', timeZone: 'UTC' })}` : ''}</h2></div>
      <div class="group">
        <div class="row top">
          <span class="l">
            <b>{usage ? `${formatBytes(usage.bytes)} of ${formatBytes(usage.limitBytes)}` : remote?.relayNeedsPlan ? 'No relay without a Frameleaf Cloud plan' : 'No usage report'}</b>
            <small style="margin-bottom:8px">{usage ? `Resets ${formatDate(usage.periodEnd)} · ${usage.throttled ? `slowed to ${Math.round((usage.throttleBps ?? 0) / 1_000_000)} Mbps${usage.throttleUntil ? ` until ${formatDate(usage.throttleUntil)}` : ''}` : 'slowed down after the allowance, never cut off'}` : 'Relay traffic in and out counts towards the plan’s monthly allowance.'}{remote?.relayLastError ? ` · last relay problem: ${remote.relayLastError}` : ''}</small>
            {#if usage}<span class="progress" class:warn={percent(usage.bytes, usage.limitBytes) > 80} role="progressbar" aria-valuenow={percent(usage.bytes, usage.limitBytes)} aria-valuemin="0" aria-valuemax="100" aria-label="Relay usage"><span style="width:{percent(usage.bytes, usage.limitBytes)}%"></span></span>{/if}
          </span>
        </div>
        <div class="row">
          <span class="l"><b>Certificate</b><small>{remote?.certificateName ? `${remote.certificateName} · Let’s Encrypt${remote.certificateExpiresAt ? ` · renews ${formatDate(remote.certificateExpiresAt)}` : ''} · keys never leave the server` : remote?.certificateError ?? 'No certificate issued yet'}</small></span>
          <span class="pill {remote?.certificateError ? 'bad' : remote?.certificateName ? 'ok' : 'off'}"><i aria-hidden="true"></i>{remote?.certificateError ? 'Problem' : remote?.certificateName ? 'Valid' : 'None'}</span>
        </div>
      </div>
    </div>
  </div>
</section>

{#if dnsOpen && remote?.customHostnameRecords?.length}
  <Sheet title="DNS records for {remote.customHostname}" wide onclose={() => { dnsOpen = false; }}>
    <p>Add these records at your DNS provider. Frameleaf Cloud checks them every few minutes.{remote.customHostnameProblem ? ` ${remote.customHostnameProblem}` : ''}</p>
    <div class="list">
      {#each remote.customHostnameRecords as record (record.name)}
        <div class="row"><span class="l"><b>{record.type} <span class="url">{record.name}</span></b><small><span class="url">{record.value}</span> · {record.purpose}</small></span><button class="btn quiet" type="button" onclick={() => copy(record.value)}><Icon name="copy" />Copy</button></div>
      {/each}
    </div>
    {#snippet actions()}<button class="btn" type="button" onclick={() => { dnsOpen = false; }}>Done</button>{/snippet}
  </Sheet>
{/if}
