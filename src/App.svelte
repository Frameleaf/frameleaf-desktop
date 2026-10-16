<script lang="ts">
  import { onMount } from 'svelte';
  import { invoke, isTauri } from '@tauri-apps/api/core';
  import { listen, type UnlistenFn } from '@tauri-apps/api/event';
  import { workerStatus } from './mode-state';
  import mark from './mark.svg';

  type Connection = { server: string; name: string; mode: string; state: string; features: { worker: boolean; workerSession: boolean; enrollment: boolean; nativeHost: boolean; sources: boolean } };
  let mode = $state<'client-worker' | 'local-server'>('client-worker');
  let connection = $state<Connection | null>(null);
  let server = $state('');
  let email = $state('');
  let password = $state('');
  let deviceName = $state('My computer');
  let busy = $state(false);
  let notice = $state('');
  let failure = $state('');
  type SetupStatus = { state: string; code: string | null; control: 'running' | 'paused' | 'stopped' };
  let setup = $state<SetupStatus | null>(null);
  const setupState = $derived(setup?.state || connection?.state || '');
  const setupDetail = $derived(setup?.code === 'runtime_pack_unavailable'
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
    ? 'AI setup could not finish. Photos remain available. Retry setup when your server and network are ready.' : '');
  const native = isTauri();
  const errors: Record<string, string> = {
    worker_setup_unavailable: 'Your server could not authorize AI processing. Check its connection and permissions, then try Resume again.',
    server_requires_https_origin: 'Enter your server’s HTTPS address without a path or sign-in details.',
    server_address_invalid: 'Enter a valid HTTPS server address.',
    server_identity_not_confirmed: 'Sign in again to confirm this server’s identity. Clear the saved sign-in first.',
    server_unreachable_or_certificate_invalid: 'Could not securely connect. Check the server address, network and certificate.',
    server_http_401: 'Sign-in expired or the email and password are incorrect. Sign out and try again.',
    server_http_403: 'Your server did not permit this sign-in.',
    credential_store_locked_or_unavailable: 'Unlock your computer’s credential store, then try again.',
    credential_store_unavailable: 'The secure credential store is unavailable on this computer.',
    sign_out_before_switching_servers: 'Sign out before connecting to another server.',
    account_identity_changed: 'This session no longer matches the saved account. Sign out before continuing.',
    device_details_invalid: 'Enter a computer name between 1 and 128 characters.',
  };
  function explain(error: unknown) { return errors[String(error)] ?? 'This operation could not finish. Check your connection and try again.'; }
  onMount(() => {
    if (!native) return;
    let disposed = false;
    let unlisten: UnlistenFn | undefined;
    void (async () => {
      busy = true;
      try {
        unlisten = await listen<SetupStatus>('worker-setup', event => { setup = event.payload; });
        if (disposed) { unlisten(); return; }
        connection = await invoke<Connection | null>('restore_connection');
        setup = await invoke<SetupStatus>('worker_setup_status');
      } catch (error) { failure = explain(error); }
      finally { busy = false; }
    })();
    return () => { disposed = true; unlisten?.(); };
  });
  async function connect(event: SubmitEvent) {
    event.preventDefault(); busy = true; failure = ''; notice = '';
    const secret = password; password = ''; setup = null;
    try { connection = await invoke<Connection>('connect_server', { server, email, password: secret, deviceName }); }
    catch (error) { failure = explain(error); }
    finally { busy = false; }
  }
  async function photos() {
    failure = '';
    try { await invoke('open_photos'); } catch (error) { failure = explain(error); }
  }
  async function signOut() {
    busy = true; failure = '';
    try {
      const result = await invoke<{ remoteRevoked: boolean; localCleared: boolean; photosCleared: boolean }>('sign_out'); connection = null; setup = null;
      notice = !result.localCleared ? 'The secure credential store could not remove your saved sign-in. Unlock it and clear the saved sign-in again.' : !result.photosCleared ? 'Sign-in stopped, but the Photos window could not be cleared. Close it and clear this server’s browsing data.' : result.remoteRevoked ? 'Signed out. Local credentials were removed.' : 'Signed out on this computer. The server was unreachable; revoke this computer from your server when it is available.';
    } catch (error) { failure = explain(error); }
    finally { busy = false; }
  }
  async function controlWorker(control: 'running' | 'paused' | 'stopped') {
    busy = true; failure = '';
    try { setup = await invoke<SetupStatus>('control_worker', { control }); }
    catch (error) {
      failure = explain(error);
      setup = await invoke<SetupStatus>('worker_setup_status').catch(() => setup);
    }
    finally { busy = false; }
  }
  async function prepareModels(allowDownload: boolean) {
    busy = true; failure = '';
    try { await invoke('prepare_models', { allowDownload }); }
    catch (error) { failure = explain(error); }
    finally { busy = false; }
  }
</script>

<svelte:head><title>Frameleaf</title></svelte:head>
<div class="app">
  <aside>
    <div class="brand"><img src={mark} alt="" /><span>Frameleaf</span></div>
    <div class="rail-label">On your computer</div>
    <div class="rail-item active">{connection ? 'My computer' : 'Get started'}</div>
    <div class="rail-footer">Your photos.<br />Your server.<br />A little more power.</div>
  </aside>
  <main>
    {#if !native}<p class="preview" role="status">Desktop setup preview. Open the installed app to connect securely.</p>{/if}
    {#if failure}<div class="message error" role="alert">{failure}<button class="text-button" disabled={busy || !native} onclick={signOut}>Clear saved sign-in</button></div>{/if}
    {#if notice}<p class="message" role="status">{notice}</p>{/if}
    {#if connection}
      <p class="eyebrow">Connected to {connection.server}</p>
      <h1>Welcome back,<br />{connection.name}.</h1>
      <p class="intro">Your photos and server are right here. This computer’s processing status stays visible below.</p>
      <section class="status-panel" aria-label="Computer processing status">
        <div class="status-heading"><span class="status-dot"></span><h2>{connection.state === 'offline' ? 'Server unavailable' : connection.state === 'identity-changed' ? 'Server identity changed' : connection.state === 'enrollment-failed' ? 'Computer setup needs attention' : workerStatus({ state: setupState, workerSupported: connection.features.worker })}</h2></div>
        <p>{setupDetail || (connection.state === 'identity-changed' ? 'Processing is stopped. Verify the server before signing in again.' : connection.state === 'worker-setup-failed' ? 'Photos are available, but this computer could not complete worker setup. Reopen the app to retry.' : connection.state === 'credential-store-unavailable' ? 'Unlock your computer’s credential store and reopen the app to finish setup.' : connection.state === 'enrollment-failed' ? 'Photo sign-in succeeded, but this computer could not be enrolled. Reopen the app to retry setup.' : 'AI processing starts only after the server supports desktop workers and the selected models pass qualification.')}</p>
        {#if setup?.state === 'model-download-required'}<button class="secondary" disabled={busy} onclick={() => prepareModels(true)}>Download selected AI models</button>{/if}
        {#if setup?.state === 'setup-needs-attention'}<button class="text-button" disabled={busy} onclick={() => prepareModels(false)}>Retry AI setup</button>{/if}
        {#if connection.mode === 'client-worker' && connection.features.workerSession}
          <div class="actions" aria-label="AI worker controls">
            {#if setup?.control === 'paused' || setup?.control === 'stopped'}
              <button class="secondary" disabled={busy} onclick={() => controlWorker('running')}>Resume AI processing</button>
            {:else}
              <button class="secondary" disabled={busy} onclick={() => controlWorker('paused')}>Pause after current task</button>
            {/if}
            <button class="text-button" disabled={busy || setup?.control === 'stopped'} onclick={() => controlWorker('stopped')}>Stop now</button>
          </div>
        {/if}
        <div class="facts"><div><span>Connection</span><strong>Encrypted</strong></div><div><span>AI processing</span><strong>{setupState === 'working' ? 'Available' : setupState === 'pausing' ? 'Finishing current task' : 'Not running'}</strong></div></div>
      </section>
      <div class="actions"><button class="primary" onclick={photos} disabled={busy || connection.state === 'identity-changed'}>Open Frameleaf Photos</button><button class="secondary" onclick={signOut} disabled={busy}>Sign out</button></div>
      <p class="footnote">Server administration uses your existing Frameleaf permissions inside Photos. Host controls require a separately paired Manager.</p>
    {:else}
      <p class="eyebrow">Frameleaf Desktop</p>
      <h1>Make yourself<br />at home.</h1>
      <p class="intro">Keep everything on this computer, or connect to your server and put your computer to work.</p>
      <fieldset class="modes" disabled={busy}>
        <legend>How would you like to use Frameleaf?</legend>
        <label class:selected={mode === 'client-worker'}><input type="radio" bind:group={mode} value="client-worker" /><span><strong>Connect to my server</strong><small>Photos, server management and help with AI processing.</small></span></label>
        <label class:selected={mode === 'local-server'}><input type="radio" bind:group={mode} value="local-server" /><span><strong>Run Frameleaf here</strong><small>Host your photo library on this computer.</small></span></label>
      </fieldset>
      {#if mode === 'local-server'}
        <section class="message"><h2>Local hosting is being prepared</h2><p>This preview does not include the native server runtime yet. Connect to an existing server to use the desktop client.</p></section>
      {:else}
        <form onsubmit={connect}>
          <label for="server">Server address</label><input id="server" type="url" placeholder="https://photos.home.example" bind:value={server} required disabled={busy} autocomplete="url" />
          <div class="form-row"><div><label for="email">Email</label><input id="email" type="email" bind:value={email} required disabled={busy} autocomplete="username" /></div><div><label for="password">Password</label><input id="password" type="password" bind:value={password} required disabled={busy} autocomplete="current-password" /></div></div>
          <label for="computer">Computer name</label><input id="computer" bind:value={deviceName} required maxlength="128" disabled={busy} autocomplete="off" />
          <p class="consent">Signing in sets up this computer to help your server process photos when compatible workers are available. Local photo folders are connected separately.</p>
          <button class="primary" type="submit" disabled={busy || !native}>{busy ? 'Connecting…' : 'Connect to Frameleaf'}</button>
          <p class="footnote">Your password is used to sign in and is never saved. The session and device key stay in your computer’s secure credential store.</p>
        </form>
      {/if}
    {/if}
  </main>
</div>
