<script lang="ts">
  import ErrorText from '../ErrorText.svelte';
  import { onMount } from 'svelte';
  import { invoke } from '@tauri-apps/api/core';
  import Icon from '../Icon.svelte';
  import { connectionError } from '../errors';
  import StepUp from '../StepUp.svelte';
  import { verificationRequired, type StepOffer } from '../sign-in-steps';
  import { formatUsd, formatUsdShort, formatWhen, relativeTime, workloadName } from '../ui-state';
  import type { WalletStatus, Wallet, Settlement } from '../server-types';

  let { native }: { native: boolean } = $props();
  let data = $state<WalletStatus | null>(null);
  let busy = $state(false);
  let saving = $state(false);
  let failure = $state('');
  let notice = $state('');
  const explain = connectionError;
  // A request the server refuses until Two-Step Verification is answered in place, then run again.
  let stepUp = $state<{ offer: StepOffer; retry: () => void } | null>(null);
  function failed(error: unknown, retry: () => void) {
    const offer = verificationRequired(error);
    if (offer) stepUp = { offer, retry }; else failure = explain(error);
  }
  const wallet = $derived<Wallet | null>(data?.wallet ?? data?.ml?.wallet ?? null);
  const settlements = $derived<Settlement[]>(data?.settlements?.items ?? []);
  const caps = [10, 20, 50, 100];
  const connection = $derived(data?.ml?.connection ?? null);
  const monthTotal = $derived.by(() => {
    const now = new Date();
    return settlements.filter(item => { const at = new Date(item.finishedAt); return at.getFullYear() === now.getFullYear() && at.getMonth() === now.getMonth(); }).reduce((sum, item) => sum + (Number.isFinite(item.costUsd) ? item.costUsd : 0), 0);
  });
  const pill = $derived(!data ? { label: busy ? 'Checking' : 'Unavailable', tone: 'off' } : connection === 'ready' ? (wallet?.autoTopUp ? { label: 'Auto-reload on', tone: 'ok' } : { label: 'Ready', tone: 'ok' }) : connection === 'not-linked' ? { label: 'Not linked', tone: 'off' } : connection === 'not-configured' ? { label: 'Not set up', tone: 'off' } : { label: 'Cloud unavailable', tone: 'wait' });
  async function load() {
    if (!native) return;
    busy = true; failure = '';
    try { data = await invoke<WalletStatus>('wallet_status'); }
    catch (error) { failed(error, () => { void load(); }); }
    finally { busy = false; }
  }
  onMount(() => { void load(); });
  async function update(change: { dailyCapUsd?: number; autoTopUp?: boolean }) {
    if (!native || saving) return;
    saving = true; failure = ''; notice = '';
    try {
      const updated = await invoke<Wallet>('update_wallet', { dailyCapUsd: change.dailyCapUsd ?? null, autoTopUp: change.autoTopUp ?? null });
      if (data) data = { ...data, wallet: updated && typeof updated === 'object' ? { ...(wallet ?? {}), ...updated } : wallet };
      notice = change.dailyCapUsd !== undefined ? `Daily cap set to ${formatUsdShort(change.dailyCapUsd)}.` : change.autoTopUp ? 'Auto-reload turned on.' : 'Auto-reload turned off.';
    } catch (error) {
      failed(error, () => { void update(change); });
      if (String(error) === 'wallet_step_up_required' && wallet?.settingsUrl) notice = 'Open your account settings on frameleaf.cloud to raise the cap or turn on auto-reload.';
    } finally { saving = false; }
  }
  async function open(url: string | null | undefined, amount?: number) {
    if (!url || !native) return;
    failure = '';
    let target = url;
    if (amount) { try { const parsed = new URL(url); parsed.searchParams.set('amount', String(amount)); target = parsed.toString(); } catch { target = url; } }
    try { await invoke('open_external', { url: target }); } catch (error) { failure = explain(error); }
  }
  function jobName(item: Settlement): string {
    const base = workloadName(item.workload);
    return item.modelSku ? `${base} · ${item.modelSku}` : item.jobName ? `${base} · ${item.jobName}` : base;
  }
</script>

<section class="page" aria-labelledby="wallet-title">
  <header class="toolbar">
    <h1 id="wallet-title">AI credit</h1>
    <span class="pill {pill.tone}"><i aria-hidden="true"></i>{pill.label}</span>
    <span class="sp"></span>
    <button class="btn quiet" disabled={busy || !native} onclick={load}>Refresh</button>
    <button class="btn" disabled={!wallet?.topUpUrl || !native} onclick={() => open(wallet?.topUpUrl, 25)}>Add $25</button>
    <button class="btn" disabled={!wallet?.topUpUrl || !native} onclick={() => open(wallet?.topUpUrl, 50)}>Add $50</button>
    <button class="btn primary" disabled={!wallet?.topUpUrl || !native} onclick={() => open(wallet?.topUpUrl, 100)}>Add $100</button>
  </header>
  <div class="body">
    {#if !native}<p class="foot" style="margin:0">Open the installed desktop app to see this server’s AI credit.</p>{/if}
    {#if failure}<div class="inline-msg error" role="alert"><p><ErrorText text={failure} /></p>{#if String(failure).includes('frameleaf.cloud') && wallet?.settingsUrl}<button class="btn small" onclick={() => open(wallet?.settingsUrl)}>Open Settings</button>{/if}<button class="btn small quiet" onclick={() => { failure = ''; }}>Dismiss</button></div>{/if}
    {#if stepUp}{#key stepUp}<StepUp offer={stepUp.offer} retry={stepUp.retry} onclose={() => { stepUp = null; }} />{/key}{/if}
    {#if notice}<div class="inline-msg" role="status"><p>{notice}</p>{#if notice.includes('frameleaf.cloud') && wallet?.settingsUrl}<button class="btn small" onclick={() => open(wallet?.settingsUrl)}>Open Settings</button>{/if}<button class="btn small quiet" onclick={() => { notice = ''; }}>Dismiss</button></div>{/if}
    {#if data?.ml?.detail && connection !== 'ready'}<div class="inline-msg" role="status"><p>{data.ml.detail}</p></div>{/if}
    <div>
      <div class="group">
        <div class="tile">
          <div><span>Available</span><b>{formatUsd(wallet?.availableUsd)}</b><small>{wallet ? `${formatUsd(wallet.balanceUsd)} balance · ${formatUsd(wallet.heldUsd)} held for running jobs` : 'No wallet read yet'}</small></div>
          <div><span>Spent today</span><b>{formatUsd(wallet?.spentTodayUsd)}</b><small>{wallet?.dailyCapUsd != null ? `of ${formatUsd(wallet.dailyCapUsd)} daily cap` : 'no daily cap'}</small></div>
          <div><span>This month</span><b>{formatUsd(monthTotal)}</b><small>{settlements.length ? `${settlements.length} settled jobs listed` : 'no settled jobs yet'}{wallet?.updatedAt ? ` · read ${relativeTime(wallet.updatedAt)}` : ''}</small></div>
        </div>
        <div class="row">
          <span class="l"><b>Daily cap</b><small>Cloud jobs pause for the day when reached. Nothing is sent elsewhere.{wallet?.settingsUrl ? ' Raising the cap above the account’s limit happens on frameleaf.cloud.' : ''}</small></span>
          <span class="seg" role="group" aria-label="Daily cap">
            {#each caps as cap (cap)}
              <button class:on={wallet?.dailyCapUsd === cap} aria-pressed={wallet?.dailyCapUsd === cap} disabled={saving || !native || !wallet} onclick={() => update({ dailyCapUsd: cap })}>{formatUsdShort(cap)}</button>
            {/each}
            {#if wallet?.dailyCapUsd != null && !caps.includes(wallet.dailyCapUsd)}<button class="on" aria-pressed="true" disabled>{formatUsdShort(wallet.dailyCapUsd)}</button>{/if}
          </span>
        </div>
        <div class="row">
          <span class="l"><b>Auto-reload</b><small>{wallet?.autoTopUp ? 'Adds credit with the payment method saved on the account when available credit runs low.' : 'Off. Turn it on to keep cloud jobs running when credit runs low.'}</small></span>
          {#if wallet?.settingsUrl}<button class="btn quiet" disabled={!native} onclick={() => open(wallet?.settingsUrl)}>Edit…</button>{/if}
          <button class="toggle" class:on={!!wallet?.autoTopUp} role="switch" aria-checked={!!wallet?.autoTopUp} aria-label="Auto-reload" disabled={saving || !native || !wallet} onclick={() => update({ autoTopUp: !wallet?.autoTopUp })}></button>
        </div>
      </div>
      <p class="foot">Credit is prepaid and shared by every server linked to your account. Statements and refunds are on frameleaf.cloud.</p>
    </div>
    <div>
      <div class="group-head"><h2 class="group-title">Cloud AI jobs · this month {formatUsd(monthTotal)}</h2>{#if wallet?.settingsUrl}<button class="btn quiet" disabled={!native} onclick={() => open(wallet?.settingsUrl)}>Statements</button>{/if}</div>
      <div class="group">
        {#if settlements.length === 0}
          <div class="empty">{busy ? 'Loading settled jobs…' : 'No settled cloud jobs yet.'}</div>
        {:else}
          <table class="table">
            <thead><tr><th scope="col">Finished</th><th scope="col">Job</th><th scope="col">Compute</th><th scope="col">Cost</th><th scope="col">Status</th></tr></thead>
            <tbody>
              {#each settlements as item (item.cloudJobId)}
                <tr>
                  <td class="nowrap">{formatWhen(item.finishedAt)}</td>
                  <td>{jobName(item)}</td>
                  <td>{item.gpuSeconds != null ? `${Math.round(item.gpuSeconds)} s GPU` : item.computeSku ?? '—'}{item.workers ? ` · ${item.workers} workers` : ''}</td>
                  <td><span class="mono">{formatUsd(item.costUsd)}</span>{item.estimateUsd != null ? ` · est. ${formatUsd(item.estimateUsd)}` : ''}</td>
                  <td><span class="pill {item.succeeded ? 'ok' : 'off'}"><i aria-hidden="true"></i>{item.succeeded ? 'Settled' : 'Failed · refunded'}</span></td>
                </tr>
              {/each}
            </tbody>
          </table>
        {/if}
      </div>
      <p class="foot">Cost shows the settled amount when a job finishes. Failures on Frameleaf’s side are refunded in full.</p>
    </div>
  </div>
</section>
