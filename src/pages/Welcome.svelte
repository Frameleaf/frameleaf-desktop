<script lang="ts">
  import ErrorText from '../ErrorText.svelte';
  import { onMount } from 'svelte';
  import { invoke } from '@tauri-apps/api/core';
  import mark from '../mark.svg';
  import Icon from '../Icon.svelte';
  import Sheet from '../Sheet.svelte';
  import LocalHost from '../LocalHost.svelte';
  import ManagerPanel from '../ManagerPanel.svelte';
  import ServerSignIn from '../ServerSignIn.svelte';
  import FrameleafAccount from '../FrameleafAccount.svelte';
  import { connectionError, savedSignInNeedsRecovery } from '../errors';
  import { mergeServers, initials, computerWord, platformFromUserAgent, nearbySignIn, type ServerEntry } from '../ui-state';
  import type { Connection, CloudAccount, CloudServer, DiscoveredServer, SignInOptions, SignInOutcome } from '../server-types';

  let { native, hostActive, cloudAccount, managerRevision, onlocked, onconnected, oncloudaccount, onhostactive, onmanagerchange, onmanagerstate }: {
    native: boolean; hostActive: boolean; cloudAccount: CloudAccount | null; managerRevision: number;
    onlocked: () => void; onconnected: (connection: Connection) => void; oncloudaccount: (account: CloudAccount | null) => void;
    onhostactive: (active: boolean) => void; onmanagerchange: () => void; onmanagerstate: (paired: boolean) => void;
  } = $props();
  const platform = platformFromUserAgent(navigator.userAgent);
  const computer = computerWord(platform);
  // Set from package.json by vite.config.ts.
  const version = import.meta.env.VITE_APP_VERSION as string;
  let mode = $state<'client-worker' | 'local-server'>('client-worker');
  // start: Welcome (or your servers); address: enter an address; server: that server's sign-in.
  let step = $state<'start' | 'address' | 'server' | 'account'>('start');
  let resumeFrameleaf = $state(false);
  let signIn = $state<SignInOptions | null>(null);
  let looking = $state(false);
  let lookingUp = $state(false);
  // Kept here so the name typed on a server's screen survives a detour through the Frameleaf account sign-in.
  let deviceName = $state('My computer');
  let managerOnly = $state(false);
  let server = $state('');
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
  const showServers = $derived(mode === 'client-worker' && !!cloudAccount && step === 'start');
  const explain = connectionError;

  let cloudLocked = $state(false);
  let cloudDamaged = $state(false);
  async function restoreCloud(retry = false) {
    if (retry) failure = '';
    cloudBusy = true;
    try {
      const account = await invoke<CloudAccount | null>('cloud_account', { retry });
      cloudLocked = false; cloudDamaged = false;
      oncloudaccount(account);
      if (account) await loadServers();
    } catch (error) {
      cloudDamaged = String(error) === 'credential_record_invalid';
      cloudLocked = !cloudDamaged;
      failure = explain(error);
    } finally { cloudBusy = false; }
  }
  onMount(() => { if (native) { void restoreCloud(); void lookNearby(); } });
  async function lookNearby() {
    looking = true;
    try { nearby = await invoke<DiscoveredServer[]>('discover_servers') ?? []; } catch { nearby = []; }
    finally { looking = false; }
  }
  /** Asks the server at `address` how one signs in, then shows its sign-in screen. Nothing secret is sent. */
  async function openServer(address: string) {
    if (!native || lookingUp || !address) return;
    lookingUp = true; failure = ''; notice = '';
    try { signIn = await invoke<SignInOptions>('server_sign_in_options', { server: address.trim() }); step = 'server'; }
    catch (error) { failure = explain(error); }
    finally { lookingUp = false; }
  }
  function createAccount() { failure = ''; notice = ''; step = 'account'; }
  /** Signed in to the Frameleaf account: show the account's servers. */
  function accountSignedIn(account: CloudAccount) { oncloudaccount(account); failure = ''; notice = ''; step = 'start'; void loadServers(); }
  /** The server's own sign-in, for a server that has no Frameleaf account behind it: its address comes first. */
  function ownSignIn() { step = 'address'; failure = ''; notice = ''; }
  function lookUp(event: SubmitEvent) { event.preventDefault(); void openServer(server); }
  async function loadServers() {
    loadingServers = true; failure = '';
    const [cloud, lan] = await Promise.allSettled([invoke<CloudServer[]>('cloud_servers'), invoke<DiscoveredServer[]>('discover_servers')]);
    if (cloud.status === 'fulfilled') cloudServers = cloud.value ?? [];
    else { failure = explain(cloud.reason); if (String(cloud.reason) === 'cloud_sign_in_required') { oncloudaccount(null); cloudServers = []; } }
    nearby = lan.status === 'fulfilled' ? lan.value ?? [] : [];
    loadingServers = false;
  }
  // Sign in with Frameleaf, the standard way in: Frameleaf Cloud's own sign-in page in the browser, which
  // takes a Passkey and every other way to sign in. Every sign-in entry point starts here.
  async function cloudSignIn(create = false, stay = false): Promise<CloudAccount | null> {
    if (!native || cloudBusy) return null;
    cloudBusy = true; failure = '';
    notice = create ? 'Create your Frameleaf account in your browser, then come back here.' : 'Finish signing in to Frameleaf in your browser…';
    try {
      const account = await invoke<CloudAccount>('cloud_sign_in');
      oncloudaccount(account); notice = '';
      if (!stay) { step = 'start'; await loadServers(); }
      return account;
    } catch (error) { cloudLocked = savedSignInNeedsRecovery(error); notice = ''; failure = explain(error); return null; }
    finally { cloudBusy = false; }
  }
  async function cloudSignOut() {
    if (!native || cloudBusy) return;
    cloudBusy = true; failure = '';
    try { await invoke('cloud_sign_out'); oncloudaccount(null); cloudServers = []; cloudDamaged = false; cloudLocked = false; failure = ''; }
    catch (error) { failure = explain(error); }
    finally { cloudBusy = false; }
  }
  async function connectCloud(entry: ServerEntry) {
    if (!native || busy || !entry.instanceId) return;
    busy = true; connectingKey = entry.key; failure = ''; notice = '';
    try {
      const outcome = await invoke<SignInOutcome>('connect_cloud_server', { instanceId: entry.instanceId, deviceName, server: null });
      if (outcome.status === 'done') onconnected(outcome.connection);
      // The server wants its own Password or authenticator first: its sign-in screen asks for it.
      else { resumeFrameleaf = true; await openServer(outcome.server ?? entry.nearby?.url ?? entry.cloud?.connections?.[0]?.uri ?? ''); }
    }
    catch (error) {
      if (savedSignInNeedsRecovery(error)) onlocked();
      // Cloud has no approval on record for this server: its own sign-in screen is the way on.
      if (String(error) === 'cloud_exchange_interaction_required') await openServer(entry.nearby?.url ?? entry.cloud?.connections?.[0]?.uri ?? '');
      failure = explain(error); if (String(error) === 'cloud_sign_in_required') { oncloudaccount(null); cloudServers = []; }
    }
    finally { busy = false; connectingKey = ''; }
  }
  function signInTo(entry: ServerEntry) {
    server = entry.nearby?.url ?? entry.cloud?.connections?.[0]?.uri ?? '';
    void openServer(server);
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
    {:else if mode === 'client-worker' && step === 'address'}
      <h2>Server address</h2>
      <p class="sub">The address you open your Frameleaf server at in a browser.</p>
    {:else if mode === 'client-worker' && step === 'server'}
      <h2>Sign in to your server</h2>
    {:else if mode === 'client-worker' && step === 'account'}
      <!-- FrameleafAccount names its own screen: it switches between sign-in, create and code. -->
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
    {#if failure}<div class="inline-msg error notice" class:wide={showServers} role="alert"><p><ErrorText text={failure} /></p><button class="btn small quiet" type="button" onclick={() => { failure = ''; }}>Dismiss</button></div>{/if}
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
        <p>Choose a server from your account or your local network.</p>
        <button class="btn quiet" type="button" disabled={loadingServers} onclick={loadServers}>Refresh</button>
        <button class="btn quiet" type="button" onclick={() => { step = 'address'; }}>Enter an address…</button>
        <button class="btn" type="button" disabled={busy} onclick={() => { mode = 'local-server'; }}>Run Frameleaf on this {computer}</button>
      </div>
    {:else if step === 'server' && signIn}
      <ServerSignIn options={signIn} {native} {computer} {cloudAccount} {onconnected} {onlocked} autostart={resumeFrameleaf} bind:deviceName
        oncloudsignin={async () => !!(await cloudSignIn(false, true))}
        onback={() => { step = 'start'; signIn = null; resumeFrameleaf = false; failure = ''; }} />
    {:else if step === 'account'}
      <FrameleafAccount start="create" {native}
        onsignedin={account => accountSignedIn(account)}
        onbrowser={async () => { const account = await cloudSignIn(false, true); if (account) accountSignedIn(account); }}
        onownlogin={ownSignIn}
        onback={() => { step = 'start'; }} />
    {:else if step === 'address'}
      <form class="form" id="address-form" aria-label="Server address" onsubmit={lookUp}>
        <div class="form-row"><label for="srv">Server address</label><span class="with-button"><!-- Plain text, not type="url": an address with no scheme, such as 192.168.1.20:2283, must be accepted. --><input id="srv" type="text" inputmode="url" autocapitalize="off" autocorrect="off" spellcheck="false" placeholder="192.168.1.20:2283 or https://photos.example.com" bind:value={server} required disabled={lookingUp} autocomplete="url" /><button class="btn" type="button" disabled={lookingUp || discovering || !native} onclick={findServer}><Icon name="radar" />{discovering ? 'Searching…' : 'Find My Server'}</button></span></div>
      </form>
      <div class="wfoot">
        <p>Copy it from your browser’s address bar when you have your server’s page open, or ask whoever runs the server.</p>
        <button class="btn quiet" type="button" onclick={() => { step = 'start'; failure = ''; notice = ''; void lookNearby(); }}>{cloudAccount ? 'Back to your servers' : 'Look on this network again'}</button>
        <button class="btn primary" type="submit" form="address-form" disabled={lookingUp || !native || !server}>{lookingUp ? 'Checking…' : 'Continue'}</button>
      </div>
    {:else}
      <div class="start">
        <button class="btn primary" type="button" disabled={cloudBusy || !native} onclick={() => cloudLocked ? restoreCloud(true) : cloudSignIn()}><Icon name="cloud" />{cloudLocked ? 'Restore Saved Frameleaf Sign-In' : 'Sign In with Frameleaf'}</button>
        <button class="btn" type="button" disabled={cloudBusy || !native} onclick={createAccount}>Create a Frameleaf Account</button>
        <p class="sub">One free Frameleaf account signs you in to your servers from home or away. Your photos stay on your own server. Accounts are made at Frameleaf, never on someone’s server.</p>
        <button class="btn quiet" type="button" onclick={ownSignIn}>Sign In with a Server Password Instead</button>
      </div>
      <div class="list" role="list" aria-label="Servers on this network" aria-busy={looking}>
        <div class="sec">Servers on this network{looking ? ' · Looking…' : ''}</div>
        {#each nearby as entry (entry.id || entry.url)}
          <div class="srv" role="listitem">
            <span class="ic" aria-hidden="true"><Icon name="radar" /></span>
            <span class="l"><b>{entry.name}</b><small>{nearbySignIn(entry)} · {entry.host}</small></span>
            <button class="btn" type="button" disabled={lookingUp || !native} onclick={() => openServer(entry.url)}>{entry.setup === 'needed' && !entry.linked ? 'Set Up…' : 'Sign In…'}</button>
          </div>
        {:else}
          <div class="empty" role="listitem">{looking ? 'Looking…' : 'None found yet'}</div>
        {/each}
        <div class="srv" role="listitem">
          <span class="ic" aria-hidden="true"><Icon name="globe" /></span>
          <span class="l"><b>Another server</b><small>Enter its address</small></span>
          <button class="btn" type="button" onclick={ownSignIn}>Enter Address…</button>
        </div>
      </div>
      <div class="wfoot">
        <p>Signing in lets this {computer} help your server process photos when compatible workers are available. Local photo folders are connected separately.</p>
        <button class="btn quiet" type="button" disabled={looking} onclick={lookNearby}>Look Again</button>
        <button class="btn quiet" type="button" disabled={busy} onclick={() => { managerOnly = true; }}>Pair a Manager instead…</button>
      </div>
    {/if}
  </div>
  <footer class="bar">
    {#if showServers}
      Can’t find your server? Enter its address to connect.
    {:else}
      <Icon name="lock" />
      Your sign-in is saved securely on this {computer}.
    {/if}
    <span class="sp"></span>
    {#if cloudDamaged}<button class="btn quiet" type="button" disabled={cloudBusy || !native} onclick={cloudSignOut}>Clear unreadable Cloud sign-in</button>{/if}
    Version {version}
  </footer>
</div>
{/if}
{#if picker}
  <Sheet title="Several servers answered" onclose={() => { picker = false; }}>
    <p>Choose the server to sign in to. Its address fills the form, then Continue shows how you can sign in.</p>
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
