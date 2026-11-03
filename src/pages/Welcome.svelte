<script lang="ts">
  import { onMount } from 'svelte';
  import { invoke } from '@tauri-apps/api/core';
  import mark from '../mark.svg';
  import Icon from '../Icon.svelte';
  import Sheet from '../Sheet.svelte';
  import LocalHost from '../LocalHost.svelte';
  import ManagerPanel from '../ManagerPanel.svelte';
  import { connectionError } from '../errors';
  import { mergeServers, initials, computerWord, platformFromUserAgent, type ServerEntry } from '../ui-state';
  import type { Connection, CloudAccount, CloudServer, DiscoveredServer } from '../server-types';

  let { native, hostActive, cloudAccount, managerRevision, onconnected, oncloudaccount, onhostactive, onmanagerchange, onmanagerstate }: {
    native: boolean; hostActive: boolean; cloudAccount: CloudAccount | null; managerRevision: number;
    onconnected: (connection: Connection) => void; oncloudaccount: (account: CloudAccount | null) => void;
    onhostactive: (active: boolean) => void; onmanagerchange: () => void; onmanagerstate: (paired: boolean) => void;
  } = $props();
  const CLOUD_URL = 'https://frameleaf.cloud';
  const platform = platformFromUserAgent(navigator.userAgent);
  const computer = computerWord(platform);
  const version = (import.meta.env?.VITE_APP_VERSION as string | undefined) || '0.1.0';
  let mode = $state<'client-worker' | 'local-server'>('client-worker');
  let addressMode = $state(false);
  let managerOnly = $state(false);
  let server = $state('');
  let email = $state('');
  let password = $state('');
  let deviceName = $state('My computer');
  let busy = $state(false);
  let discovering = $state(false);
  let cloudBusy = $state(false);
  let loadingServers = $state(false);
  let failure = $state('');
  let notice = $state('');
  let found = $state<DiscoveredServer[]>([]);
  let picker = $state(false);
  let cloudServers = $state<CloudServer[]>([]);
  let nearby = $state<DiscoveredServer[]>([]);
  let connectingKey = $state('');
  const entries = $derived(mergeServers(cloudServers, nearby));
  const showServers = $derived(mode === 'client-worker' && !!cloudAccount && !addressMode);
  const explain = connectionError;

  onMount(() => {
    if (!native) return;
    void (async () => {
      try {
        const account = await invoke<CloudAccount | null>('cloud_account');
        oncloudaccount(account);
        if (account) await loadServers();
      } catch { /* no cloud account: the address form is shown */ }
    })();
  });
  async function loadServers() {
    loadingServers = true; failure = '';
    const [cloud, lan] = await Promise.allSettled([invoke<CloudServer[]>('cloud_servers'), invoke<DiscoveredServer[]>('discover_servers')]);
    if (cloud.status === 'fulfilled') cloudServers = cloud.value ?? [];
    else { failure = explain(cloud.reason); if (String(cloud.reason) === 'cloud_account_signed_out') { oncloudaccount(null); } }
    nearby = lan.status === 'fulfilled' ? lan.value ?? [] : [];
    loadingServers = false;
  }
  async function cloudSignIn() {
    if (!native || cloudBusy) return;
    cloudBusy = true; failure = ''; notice = 'Finish signing in to Frameleaf Cloud in your browser…';
    try {
      const account = await invoke<CloudAccount>('cloud_sign_in', { cloudUrl: CLOUD_URL });
      oncloudaccount(account); addressMode = false; notice = '';
      await loadServers();
    } catch (error) { notice = ''; failure = explain(error); }
    finally { cloudBusy = false; }
  }
  async function cloudSignOut() {
    if (!native || cloudBusy) return;
    cloudBusy = true; failure = '';
    try { await invoke('cloud_sign_out'); oncloudaccount(null); cloudServers = []; }
    catch (error) { failure = explain(error); }
    finally { cloudBusy = false; }
  }
  async function connect(event: SubmitEvent) {
    event.preventDefault();
    if (!native || busy) return;
    busy = true; failure = ''; notice = '';
    const secret = password; password = '';
    try { onconnected(await invoke<Connection>('connect_server', { server, email, password: secret, deviceName })); }
    catch (error) { failure = explain(error); }
    finally { busy = false; }
  }
  async function connectCloud(entry: ServerEntry) {
    if (!native || busy || !entry.instanceId) return;
    busy = true; connectingKey = entry.key; failure = ''; notice = '';
    try { onconnected(await invoke<Connection>('connect_cloud_server', { instanceId: entry.instanceId, deviceName })); }
    catch (error) { failure = explain(error); }
    finally { busy = false; connectingKey = ''; }
  }
  function signInTo(entry: ServerEntry) {
    server = entry.nearby?.url ?? entry.cloud?.connections?.[0]?.uri ?? '';
    addressMode = true; failure = ''; notice = entry.action === 'setup' ? `“${entry.name}” has no administrator yet. Open it in a browser to finish its setup, then sign in here.` : '';
  }
  async function findServer() {
    if (!native || discovering) return;
    discovering = true; failure = ''; notice = '';
    try {
      found = await invoke<DiscoveredServer[]>('discover_servers');
      if (found.length === 0) notice = 'No Frameleaf server answered on this network. Enter its address instead.';
      else if (found.length === 1) { server = found[0]!.url; notice = `Found “${found[0]!.name}” at ${found[0]!.url}.`; }
      else picker = true;
    } catch (error) { failure = explain(error); }
    finally { discovering = false; }
  }
  function pick(entry: DiscoveredServer) { server = entry.url; picker = false; notice = `Using “${entry.name}” at ${entry.url}.`; }
</script>

{#if managerOnly}
  {#key managerRevision}<ManagerPanel onback={() => { managerOnly = false; }} onstate={onmanagerstate} />{/key}
{:else}
<div class="welcome">
  <header class="tbar" data-tauri-drag-region><h1 data-tauri-drag-region>Frameleaf Setup</h1></header>
  <div class="wrap">
    <div class="logo"><img src={mark} alt="" /><span>Frameleaf</span></div>
    {#if showServers}
      <h2>Choose a server</h2>
      <p class="sub"><span class="av" aria-hidden="true">{initials(cloudAccount?.name || cloudAccount?.email)}</span>Signed in to Frameleaf Cloud as {cloudAccount?.email} <button class="btn quiet small" type="button" disabled={cloudBusy} onclick={cloudSignOut}>Switch account</button></p>
    {:else}
      <h2>Welcome</h2>
      <p class="sub">Keep everything on this {computer}, or connect to your server and put this {computer} to work.</p>
      <div class="opts" role="radiogroup" aria-label="How would you like to use Frameleaf?">
        <button class="opt" class:on={mode === 'client-worker'} role="radio" aria-checked={mode === 'client-worker'} type="button" disabled={busy || hostActive} onclick={() => { mode = 'client-worker'; }}>
          <span class="ic" aria-hidden="true"><Icon name="server" /></span>
          <span><b>Connect to my server</b><small>Photos, server management and help with AI processing.</small></span>
        </button>
        <button class="opt" class:on={mode === 'local-server'} role="radio" aria-checked={mode === 'local-server'} type="button" disabled={busy} onclick={() => { mode = 'local-server'; }}>
          <span class="ic" aria-hidden="true"><Icon name="computer" /></span>
          <span><b>Run Frameleaf here</b><small>Host your photo library on this {computer}.</small></span>
        </button>
      </div>
    {/if}
    {#if failure}<div class="inline-msg error notice" class:wide={showServers} role="alert"><p>{failure}</p><button class="btn small quiet" type="button" onclick={() => { failure = ''; }}>Dismiss</button></div>{/if}
    {#if notice}<div class="inline-msg notice" class:wide={showServers} role="status"><p>{notice}</p><button class="btn small quiet" type="button" onclick={() => { notice = ''; }}>Dismiss</button></div>{/if}

    {#if mode === 'local-server'}
      <div class="section">
        <LocalHost onactive={onhostactive} {onmanagerchange} />
        {#key managerRevision}<ManagerPanel embedded onstate={onmanagerstate} />{/key}
      </div>
    {:else if showServers}
      <div class="list" role="list" aria-label="Your servers" aria-busy={loadingServers}>
        {#if loadingServers && entries.length === 0}
          <div class="empty"><span class="spin" aria-hidden="true"></span> Looking for your servers…</div>
        {:else if entries.length === 0}
          <div class="empty">No servers are linked to this account yet, and none answered on this network.</div>
        {/if}
        {#each entries as entry (entry.key)}
          <div class="srv" role="listitem">
            <span class="ic" class:dim={!entry.online} aria-hidden="true"><Icon name={entry.source === 'nearby' ? 'radar' : entry.online ? 'server' : 'computer'} /></span>
            <span class="l"><b>{entry.name}</b><small>{entry.detail}</small></span>
            <span class="pill {entry.pill.tone}"><i aria-hidden="true"></i>{entry.pill.label}</span>
            {#if entry.action === 'connect'}
              <button class="btn" class:primary={entry === entries[0]} type="button" disabled={busy || !entry.online || entry.cloud?.status === 'revoked'} onclick={() => connectCloud(entry)}>{connectingKey === entry.key ? 'Connecting…' : 'Connect'}</button>
            {:else}
              <button class="btn" type="button" disabled={busy} onclick={() => signInTo(entry)}>{entry.action === 'setup' ? 'Set Up…' : 'Sign In…'}</button>
            {/if}
          </div>
        {/each}
      </div>
      <div class="wfoot wide">
        <p>Servers come from your Frameleaf Cloud account and from Bonjour on this network. Connecting picks the fastest path automatically: home network, then direct, then relay.</p>
        <button class="btn quiet" type="button" disabled={loadingServers} onclick={loadServers}>Refresh</button>
        <button class="btn quiet" type="button" onclick={() => { addressMode = true; }}>Enter an address…</button>
        <button class="btn" type="button" disabled={busy} onclick={() => { mode = 'local-server'; }}>Run Frameleaf on this {computer}</button>
      </div>
    {:else}
      <form class="form" id="connect-form" aria-label="Connect to your server" onsubmit={connect}>
        <div class="form-row"><label for="srv">Server address</label><span class="with-button"><input id="srv" type="url" placeholder="https://photos.home.example" bind:value={server} required disabled={busy} autocomplete="url" /><button class="btn" type="button" disabled={busy || discovering || !native} onclick={findServer}><Icon name="radar" />{discovering ? 'Searching…' : 'Find My Server'}</button></span></div>
        <div class="form-row"><label for="em">Account</label><span class="two"><input id="em" type="email" placeholder="Email" bind:value={email} required disabled={busy} autocomplete="username" /><input id="pw" type="password" placeholder="Password" aria-label="Password" bind:value={password} required disabled={busy} autocomplete="current-password" /></span></div>
        <div class="form-row"><label for="nm">This {computer}’s name</label><input id="nm" type="text" bind:value={deviceName} required maxlength="128" disabled={busy} autocomplete="off" /></div>
      </form>
      <div class="wfoot">
        <p>Your password is used only to sign in and is never saved. Signing in lets this {computer} help your server process photos when compatible workers are available. Local photo folders are connected separately.</p>
        {#if cloudAccount}<button class="btn quiet" type="button" onclick={() => { addressMode = false; }}>Back to your servers</button>{/if}
        <button class="btn quiet" type="button" disabled={busy} onclick={() => { managerOnly = true; }}>Pair a Manager instead…</button>
        <button class="btn primary" type="submit" form="connect-form" disabled={busy || !native || !server || !email || !password}>{busy ? 'Connecting…' : 'Connect'}</button>
      </div>
    {/if}
  </div>
  <footer class="bar">
    {#if showServers}
      No Frameleaf Cloud account? You can still sign in to a server by address.
    {:else}
      <Icon name="lock" />
      Session and device key stay in {platform === 'mac' ? 'the macOS Keychain' : platform === 'windows' ? 'Windows Credential Manager' : 'your secure credential store'}.
    {/if}
    <span class="sp"></span>
    {#if mode === 'client-worker' && !cloudAccount}<button class="btn quiet" type="button" disabled={cloudBusy || !native} onclick={cloudSignIn}><Icon name="cloud" />{cloudBusy ? 'Waiting for your browser…' : 'Sign in with Frameleaf Cloud'}</button>{/if}
    Version {version}
  </footer>
</div>
{/if}
{#if picker}
  <Sheet title="Several servers answered" onclose={() => { picker = false; }}>
    <p>Choose the server to sign in to. Its address fills the form; you still sign in with your email and password.</p>
    <div class="list">
      {#each found as entry (entry.id || entry.url)}
        <div class="row">
          <span class="ic" aria-hidden="true"><Icon name="server" /></span>
          <span class="l"><b>{entry.name}</b><small>{entry.url}{entry.setup === 'needed' ? ' · needs its first administrator' : ''}{entry.linked ? ' · linked to Frameleaf Cloud' : ''}</small></span>
          <button class="btn" type="button" onclick={() => pick(entry)}>Use</button>
        </div>
      {/each}
    </div>
    {#snippet actions()}<button class="btn" type="button" onclick={() => { picker = false; }}>Cancel</button>{/snippet}
  </Sheet>
{/if}
