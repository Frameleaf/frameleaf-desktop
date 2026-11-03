<script lang="ts">
  import { onMount } from 'svelte';
  import { invoke } from '@tauri-apps/api/core';
  import Icon from '../Icon.svelte';
  import { connectionError } from '../errors';
  import { formatBytes, formatDate, relativeTime, percent, formatWhen } from '../ui-state';
  import type { CloudStatus, ServerSummary } from '../server-types';

  let { native, summary }: { native: boolean; summary: ServerSummary | null } = $props();
  let data = $state<CloudStatus | null>(null);
  let busy = $state(false);
  let failure = $state('');
  const cloud = $derived(data?.cloud ?? null);
  const license = $derived(data?.license ?? null);
  const backup = $derived(data?.backup ?? null);
  const explain = connectionError;
  const linkPill = $derived(!cloud ? { label: busy ? 'Checking' : 'Unavailable', tone: 'off' } : cloud.state === 'linked' ? { label: 'Linked', tone: 'ok' } : cloud.state === 'pending' ? { label: 'Waiting for approval', tone: 'wait' } : cloud.state === 'revoked' ? { label: 'Link revoked', tone: 'bad' } : cloud.state === 'not-configured' ? { label: 'Not set up', tone: 'off' } : { label: 'Not linked', tone: 'off' });
  const planState = $derived(license?.state ?? 'none');
  const planSlot = $derived(license?.plan ?? null);
  const keySlot = $derived(license?.key ?? null);
  const regionName = $derived(cloud?.dataRegion === 'na' ? 'North America' : cloud?.dataRegion === 'eu' ? 'Europe' : cloud?.dataRegion ?? null);
  const quota = $derived(backup?.managed?.quotaBytes ?? null);
  const used = $derived(backup?.managed?.usedBytes ?? backup?.usage?.bytes ?? null);
  const includes = $derived([
    { label: 'Remote access', on: license?.entitlements?.remoteAccess },
    { label: 'Cloud backup', on: license?.entitlements?.cloudBackup },
    { label: 'Cloud AI', on: license?.entitlements?.cloudMl },
    { label: 'Supporter', on: license?.entitlements?.supporter },
  ]);
  async function load() {
    if (!native) return;
    busy = true; failure = '';
    try { data = await invoke<CloudStatus>('cloud_status'); }
    catch (error) { failure = explain(error); }
    finally { busy = false; }
  }
  onMount(() => { void load(); });
  async function open(url: string | null | undefined) {
    if (!url || !native) return;
    failure = '';
    try { await invoke('open_external', { url }); } catch (error) { failure = explain(error); }
  }
  function stateWord(state: string | undefined): { label: string; tone: string } {
    switch (state) {
      case 'active': return { label: 'Active', tone: 'ok' };
      case 'grace': return { label: 'Renewal needed', tone: 'wait' };
      case 'expired': return { label: 'Expired', tone: 'bad' };
      case 'invalid': return { label: 'Invalid', tone: 'bad' };
      default: return { label: 'None', tone: 'off' };
    }
  }
</script>

<section class="page" aria-labelledby="cloud-title">
  <header class="toolbar">
    <h1 id="cloud-title">Frameleaf Cloud</h1>
    <span class="pill {linkPill.tone}"><i aria-hidden="true"></i>{linkPill.label}</span>
    <span class="sp"></span>
    <button class="btn quiet" disabled={busy || !native} onclick={load}>Refresh</button>
    <button class="btn" disabled={!cloud?.manageUrl || !native} onclick={() => open(cloud?.manageUrl)}><Icon name="open" />Manage on frameleaf.cloud</button>
  </header>
  <div class="body">
    {#if !native}<p class="foot" style="margin:0">Open the installed desktop app to see this server’s Frameleaf Cloud account and plan.</p>{/if}
    {#if failure}<div class="inline-msg error" role="alert"><p>{failure}</p><button class="btn small quiet" onclick={() => { failure = ''; }}>Dismiss</button></div>{/if}
    {#if cloud?.lastError}<div class="inline-msg" role="status"><p>{cloud.lastError}</p></div>{/if}
    <div>
      <div class="group-head"><h2 class="group-title">Account</h2></div>
      <div class="group">
        <div class="row">
          <span class="ic" aria-hidden="true"><Icon name="cloud" /></span>
          <span class="l"><b>{cloud?.account?.label || (cloud?.state === 'linked' ? 'Linked Frameleaf account' : 'No Frameleaf account linked')}</b><small>{[cloud?.state === 'linked' ? 'Owner' : null, regionName ? `Data region ${regionName}` : null, cloud?.cloudHost ? cloud.cloudHost : null].filter(Boolean).join(' · ') || 'Link this server from Settings › Frameleaf Cloud inside Photos.'}</small></span>
          <button class="btn" disabled={!cloud?.manageUrl || !native} onclick={() => open(cloud?.manageUrl)}>Account Settings…</button>
        </div>
        <div class="row">
          <span class="l"><b>{cloud?.state === 'linked' ? 'This server is linked to this account' : cloud?.state === 'pending' ? 'Waiting for the link to be approved' : cloud?.state === 'revoked' ? 'Frameleaf Cloud ended this link' : 'This server is not linked'}</b><small>{cloud?.instanceId ? `Instance ` : ''}{#if cloud?.instanceId}<span class="mono">{cloud.instanceId}</span>{/if}{cloud?.linkedAt ? ` · linked ${formatDate(cloud.linkedAt)}` : ''}{cloud?.lastContactAt ? ` · last contact ${relativeTime(cloud.lastContactAt)}` : ''}{cloud?.revoked ? ` · ${cloud.revoked.reason}` : ''}{cloud?.heartbeatFailures ? ` · ${cloud.heartbeatFailures} check-ins failed in a row` : ''}</small></span>
          {#if cloud?.state === 'linked'}<span class="pill {cloud.heartbeatFailures ? 'wait' : 'ok'}"><i aria-hidden="true"></i>{cloud.heartbeatFailures ? 'Check-in failing' : 'Healthy'}</span>{/if}
        </div>
        {#if cloud?.permissions}
          <div class="row"><span class="l"><b>What Frameleaf Cloud may do</b><small>Changed from Settings › Frameleaf Cloud inside Photos.</small></span>
            <span class="chip" class:faint={!cloud.permissions.allowRemoteEnable}>Remote access</span>
            <span class="chip" class:faint={!cloud.permissions.allowBackupTrigger}>Start backups</span>
            <span class="chip" class:faint={!cloud.permissions.allowEntitlementRefresh}>Refresh plan</span>
          </div>
        {/if}
      </div>
    </div>
    <div>
      <div class="group-head"><h2 class="group-title">Plan</h2></div>
      <div class="group">
        <div class="tile">
          <div><span>Frameleaf Cloud</span><b>{planSlot ? (planSlot.kind === 'plan' ? 'Cloud plan' : planSlot.kind === 'server' ? 'Server licence' : 'Individual licence') : keySlot ? (keySlot.kind === 'server' ? 'Server licence' : 'Individual licence') : 'No plan'}</b><small>{planSlot?.source === 'account' ? 'From your account' : planSlot?.source === 'file' ? 'Installed from a file' : license?.linked ? 'Linked server' : 'Not linked'}{license?.offline ? ' · offline' : ''}</small></div>
          <div><span>Status</span><b class={stateWord(planState).tone === 'ok' ? 'good' : stateWord(planState).tone === 'bad' ? 'bad' : ''}>{stateWord(planState).label}</b><small>{license?.expiresAt ? `${planState === 'expired' ? 'Ended' : 'Renews'} ${formatDate(license.expiresAt)}` : planState === 'active' ? 'Lifetime' : 'No renewal date'}{license?.graceUntil ? ` · grace until ${formatDate(license.graceUntil)}` : ''}</small></div>
          <div><span>Cloud backup</span><b>{used !== null ? formatBytes(used) : backup?.configured ? 'On' : 'Off'}</b><small>{quota ? `of ${formatBytes(quota)} included` : backup?.configured ? backup.target === 'own' || backup.endpoint ? 'your own storage' : 'Frameleaf-managed storage' : 'not set up'}{backup?.managed?.readOnly ? ' · uploads paused' : ''}</small></div>
        </div>
        <div class="row"><span class="l"><b>Includes</b></span>
          {#each includes as item (item.label)}<span class="chip" class:faint={!item.on}>{item.label}</span>{/each}
        </div>
        <div class="row"><span class="l"><b>Server licence</b><small>{keySlot ? `FL-····-····-${keySlot.keyHint ?? '····'} · activated ${formatDate(keySlot.activatedAt)}${keySlot.expiresAt ? ` · until ${formatDate(keySlot.expiresAt)}` : ' · lifetime'}` : license?.licensed ? 'Covered by your plan' : 'No supporter key on this server'} · required for AI credit and backup</small></span><span class="pill {stateWord(keySlot?.state ?? (license?.licensed ? 'active' : 'none')).tone}"><i aria-hidden="true"></i>{stateWord(keySlot?.state ?? (license?.licensed ? 'active' : 'none')).label}</span></div>
        <div class="row"><span class="l"><b>Billing</b><small>Change plan, invoices and payment method open on frameleaf.cloud in your browser.</small></span><button class="btn quiet" disabled={!cloud?.manageUrl || !native} onclick={() => open(cloud?.manageUrl)}>Invoices</button><button class="btn" disabled={!cloud?.manageUrl || !native} onclick={() => open(cloud?.manageUrl)}>Change Plan…</button></div>
      </div>
      <p class="foot">Plan changes and payments use Frameleaf Cloud’s own sign-in. The app never stores your card.</p>
    </div>
    <div>
      <div class="group-head"><h2 class="group-title">Cloud backup</h2></div>
      <div class="group">
        {#if backup?.configured}
          <div class="row">
            <span class="l"><b>{backup.activeRun ? `Backing up · ${Math.round(backup.activeRun.progress)}%` : backup.lastRun ? `Last backup ${formatWhen(backup.lastRun.finishedAt ?? backup.lastRun.startedAt)}` : 'No backup has run yet'}</b><small>{backup.activeRun ? `${backup.activeRun.uploaded.toLocaleString()} files uploaded · ${formatBytes(backup.activeRun.bytesUploaded)}` : backup.lastRun ? `${backup.lastRun.status === 'completed' ? 'Done' : backup.lastRun.status === 'failed' ? `Failed${backup.lastRun.error ? ` · ${backup.lastRun.error}` : ''}` : backup.lastRun.status} · ${backup.lastRun.uploaded.toLocaleString()} new files${backup.lastSuccessAt ? ` · last success ${relativeTime(backup.lastSuccessAt)}` : ''}` : ''}{backup.keyMode ? ` · key ${backup.keyMode === 'server' ? 'kept on server' : 'in your memory'}${backup.escrow?.stored ? ' with recovery kit' : ''}` : ''}</small></span>
            <span class="pill {backup.activeRun ? 'wait' : backup.lastRun?.status === 'completed' ? 'ok' : backup.lastRun?.status === 'failed' ? 'bad' : 'off'}"><i aria-hidden="true"></i>{backup.activeRun ? 'Running' : backup.lastRun?.status === 'completed' ? 'Healthy' : backup.lastRun?.status === 'failed' ? 'Failed' : backup.lastRun?.status === 'waiting-for-key' ? 'Waiting for key' : 'Idle'}</span>
          </div>
          <div class="row top"><span class="l"><b>Storage</b><small style="margin-bottom:8px">{used !== null ? formatBytes(used) : 'Usage unknown'}{quota ? ` of ${formatBytes(quota)} included · extra 1 TB blocks are added automatically` : backup.bucket ? ` in ${backup.bucket}` : ''}{backup.managed?.location ? ` · ${backup.managed.location.city}, ${backup.managed.location.country}` : ''}</small>{#if quota}<span class="progress" class:warn={percent(used, quota) > 90} role="progressbar" aria-valuenow={percent(used, quota)} aria-valuemin="0" aria-valuemax="100" aria-label="Backup storage used"><span style="width:{percent(used, quota)}%"></span></span>{/if}</span></div>
        {:else}
          <div class="row"><span class="ic dim" aria-hidden="true"><Icon name="backup" /></span><span class="l"><b>Cloud backup is not set up</b><small>{backup?.managedAvailable ? 'Frameleaf-managed storage is available for this linked server.' : 'Set it up from Settings › Frameleaf Cloud inside Photos.'}</small></span></div>
        {/if}
      </div>
    </div>
  </div>
</section>
