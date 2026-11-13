<script lang="ts">
  import ErrorText from './ErrorText.svelte';
  import { onMount, tick } from 'svelte';
  import { invoke, isTauri } from '@tauri-apps/api/core';
  import { listen, type UnlistenFn } from '@tauri-apps/api/event';
  import mark from './mark.svg';
  import Icon from './Icon.svelte';
  import Sheet from './Sheet.svelte';
  import LibrarySwitcher from './LibrarySwitcher.svelte';
  import Welcome from './pages/Welcome.svelte';
  import Overview from './pages/Overview.svelte';
  import PhotoSourcesPage from './pages/PhotoSources.svelte';
  import PhotoDrop from './PhotoDrop.svelte';
  import Manager from './pages/Manager.svelte';
  import Backups from './pages/Backups.svelte';
  import Cloud from './pages/Cloud.svelte';
  import Wallet from './pages/Wallet.svelte';
  import Remote from './pages/Remote.svelte';
  import { initials, hostOf } from './ui-state';
  import { connectionError, errorCopy } from './errors';
  import StepUp from './StepUp.svelte';
  import { keptVerification, savedSignInState, savedSignInView, type Restored } from './connection-state';
  import type { Connection, SetupStatus, ServerSummary, CloudAccount } from './server-types';
  import { noStepUp, stepUpDismissed, summaryStepUpAfter, verificationRequired, type StepOffer, type StepUpState } from './sign-in-steps';
  import { availablePage, pages, restoredPage, shortcutPage, type Page } from './navigation';

  const lastPageKey = 'frameleaf.last-page.v1';
  const native = isTauri();
  const mac = document.documentElement.classList.contains('platform-mac');
  let connection = $state<Connection | null>(null);
  let importReady = $state(false);
  let setup = $state<SetupStatus | null>(null);
  let summary = $state<ServerSummary | null>(null);
  let cloudAccount = $state<CloudAccount | null>(null);
  let hostActive = $state(false);
  let managerRevision = $state(0);
  let managerPaired = $state(false);
  let page = $state<Page>('overview');
  let navigationRevision = 0;
  let content: HTMLElement;
  let accountButton = $state<HTMLButtonElement>();
  let busy = $state(false);
  let failure = $state('');
  let notice = $state('');
  let updateVersion = $state<string | null>(null);
  let installingUpdate = $state(false);
  let updateError = $state('');
  let accountMenu = $state(false);
  let signOutSheet = $state(false);
  let librariesOpen = $state(false);
  let libraryRevision = $state(0);
  // A sign-in left in the credential store with no connection shown (restore failed, or sign-out could not delete it):
  // native connect refuses until it is cleared, so the clear action stays reachable.
  let staleSignIn = $state(false);
  let connectionLocked = $state(false);
  // The saved sign-in is kept while the server is unreachable or wants Two-Step Verification.
  let keptSignIn = $state<'reconnecting' | 'needs-verification' | null>(null);
  const kept = $derived(savedSignInView(connection ? null : keptSignIn));
  const isAdmin = $derived(summary?.me?.isAdmin === true);
  const attentionCount = $derived((summary?.attention?.items ?? []).filter(item => !(summary?.attention?.dismissed ?? []).includes(item.id)).length);
  const explain = connectionError;
  let summaryRequest = 0; // bumped per request and on every sign-in and sign-out: only the latest reply applies
  // The server can refuse the summary until Two-Step Verification; Overview shows the Verify prompt for it.
  let summaryStepUp = $state<StepUpState>(noStepUp);
  async function loadSummary() {
    if (!native || !connection) { summary = null; summaryStepUp = noStepUp; return; }
    // A superseded reply (a newer refresh, or a sign-in or sign-out since) is dropped.
    const asked = ++summaryRequest;
    let result: ServerSummary | null = null;
    let failed: unknown;
    try { result = await invoke<ServerSummary>('server_summary'); }
    catch (error) { failed = error; }
    if (summaryRequest === asked) {
      summary = result;
      summaryStepUp = summaryStepUpAfter(summaryStepUp, result, failed, () => { summaryStepUp = noStepUp; void loadSummary(); });
      if (result && !availablePage(page, result.me?.isAdmin === true)) page = 'overview';
    }
    void invoke('tray_refresh').catch(() => {});
  }
  async function offlinePhotos() {
    try { await invoke('open_offline_photos'); }
    catch (error) {
      notice = explain(error);
    }
  }

  // The saved sign-in was restored, by this window or by the backend's own reconnect attempt.
  async function showRestored(restored: Connection | null) {
    connection = restored;
    connectionLocked = false; staleSignIn = false; keptSignIn = null;
    const scope = connection?.navigationScope;
    const revision = navigationRevision;
    setup = await invoke<SetupStatus>('worker_setup_status');
    await loadSummary();
    if (scope && connection?.navigationScope === scope && summary?.me && navigationRevision === revision) {
      try { page = restoredPage(localStorage.getItem(lastPageKey), scope, isAdmin); }
      catch { /* The default page is available without storage. */ }
    }
  }
  // While the server does not answer, the backend keeps trying by itself, window shown or not;
  // this window only shows the state and hears the outcome as `connection-restored`.
  function showRestoreFailure(error: unknown) {
    const state = savedSignInState(error);
    connectionLocked = state === 'locked';
    staleSignIn = !connection && state === 'stale';
    keptSignIn = !connection && (state === 'reconnecting' || state === 'needs-verification') ? state : null;
    if (!keptSignIn) failure = explain(error);
    if (keptSignIn === 'needs-verification') void askKeptOffer();
  }
  // What the server asks for before the kept sign-in continues, so the person can verify on that screen.
  // `restore_connection` answers with a bare code; the offer (methods and a transaction) is asked for here.
  let keptOffer = $state<StepOffer | null>(null);
  let keptOfferAsked = $state(false);
  const verify = $derived(keptSignIn === 'needs-verification' && !connection ? keptVerification(keptOffer, keptOfferAsked) : null);
  let keptOfferRequest = 0;
  async function askKeptOffer() {
    const asked = ++keptOfferRequest;
    keptOffer = null; keptOfferAsked = false;
    let offer: StepOffer | null = null;
    let answered = true;
    // No refusal means the server no longer asks: Check again restores the sign-in.
    try { await invoke('saved_sign_in_verification'); answered = false; }
    catch (error) { offer = verificationRequired(error); }
    if (asked !== keptOfferRequest || keptSignIn !== 'needs-verification' || connection) return;
    keptOffer = offer; keptOfferAsked = answered;
  }
  // `background` is an attempt nobody pressed a button for: it leaves the buttons and messages alone.
  async function restoreSaved(retry = false, background = false) {
    if (!background) { busy = true; failure = ''; }
    try { await showRestored(await invoke<Connection | null>('restore_connection', { retry })); }
    catch (error) { showRestoreFailure(error); }
    finally { if (!background) busy = false; }
  }
  // The kept-sign-in screen replaces whatever was shown: its title takes focus so it is read out, again
  // when it changes from reconnecting to needing Two-Step Verification.
  let keptTitle = $state<HTMLHeadingElement>();
  $effect(() => { if (keptSignIn && !connection) void tick().then(() => keptTitle?.focus()); });
  async function retryKept(event: MouseEvent) {
    const button = event.currentTarget as HTMLButtonElement;
    const before = keptSignIn;
    await restoreSaved(true);
    // The button is disabled while Frameleaf tries, which drops keyboard focus: give it back, unless the
    // screen changed and its new title has taken it.
    await tick();
    if (keptSignIn === before && button.isConnected) button.focus();
  }
  function networkBack() {
    if (!connection && keptSignIn === 'reconnecting') void restoreSaved(false, true);
  }
  onMount(() => {
    if (!native) return;
    let disposed = false;
    void invoke<string | null>('check_desktop_update')
      .then(version => { if (!disposed) updateVersion = version; })
      .catch(() => {});
    const unlisten: UnlistenFn[] = [];
    void (async () => {
      busy = true;
      try {
        unlisten.push(await listen<SetupStatus>('worker-setup', event => { setup = event.payload; }));
        unlisten.push(await listen<string>('tray-action-failed', event => {
          if (event.payload === 'media_copy_exit_blocked') {
            notice = explain(event.payload);
            return;
          }
          failure = explain(event.payload);
          void invoke<SetupStatus>('worker_setup_status').then(value => { setup = value; }).catch(() => {});
        }));
        unlisten.push(await listen<Restored<Connection>>('connection-restored', event => {
          // Signed in or out since the backend started trying: its answer is about a sign-in that is gone.
          if (connection || keptSignIn !== 'reconnecting') return;
          if (event.payload.error) showRestoreFailure(event.payload.error);
          else void showRestored(event.payload.connection).catch(error => { failure = explain(error); });
        }));
        if (disposed) { unlisten.forEach(stop => stop()); return; }
        const host = await invoke<{ backgroundActive: boolean }>('local_host_status');
        hostActive = host.backgroundActive;
        await restoreSaved();
      } catch (error) { failure = explain(error); }
      finally { busy = false; importReady = !disposed; }
    })();
    return () => { disposed = true; unlisten.forEach(stop => stop()); };
  });
  async function installUpdate() {
    if (!updateVersion || installingUpdate) return;
    installingUpdate = true;
    updateError = '';
    try {
      await invoke('install_desktop_update', { version: updateVersion });
    } catch (error) {
      if (error === 'update_changed') {
        updateVersion = await invoke<string | null>('check_desktop_update').catch(() => null);
      }
      updateError = error === 'update_host_active'
        ? 'Stop the local server before installing the update.'
        : error === 'update_library_not_idle'
          ? errorCopy('update_library_not_idle') ?? 'Frameleaf couldn’t install the update. Try again.'
        : typeof error === 'string' && error.startsWith('update_library_stop_')
          ? errorCopy(error) ?? 'Frameleaf couldn’t install the update. Try again.'
        : error === 'update_media_copy_active'
          ? 'Finish or cancel the media copy before installing the update.'
          : error === 'update_changed'
            ? updateVersion
              ? `The latest release changed to Frameleaf ${updateVersion}.`
              : 'That update is no longer available.'
            : 'Frameleaf couldn’t install the update. Try again.';
      installingUpdate = false;
    }
  }
  function connected(view: Connection) {
    const revision = ++libraryRevision;
    librariesOpen = false;
    keptSignIn = null;
    summaryRequest += 1; connection = view; setup = null; summary = null; summaryStepUp = noStepUp; failure = ''; notice = ''; page = 'overview'; staleSignIn = false; connectionLocked = false;
    void loadSummary();
    void invoke<SetupStatus>('worker_setup_status').then(value => {
      if (libraryRevision === revision) setup = value;
    }).catch(() => {});
  }
  async function signOut() {
    busy = true; failure = '';
    try {
      const result = await invoke<{ remoteRevoked: boolean; localCleared: boolean; photosCleared: boolean }>('sign_out');
      try { localStorage.removeItem(lastPageKey); } catch { /* Sign-out still succeeds. */ }
      libraryRevision += 1;
      keptSignIn = null;
      summaryRequest += 1; connection = null; setup = null; summary = null; summaryStepUp = noStepUp; signOutSheet = false; accountMenu = false; page = 'overview'; staleSignIn = !result.localCleared;
      notice = !result.localCleared ? 'Desktop could not finish clearing this computer’s saved sign-in or this library’s offline copies. Unlock the secure credential store and check local storage; Desktop clears leftover offline copies the next time it starts.' : !result.photosCleared ? 'Sign-in stopped, but the Photos window could not be cleared. Close it and clear this server’s browsing data.' : result.remoteRevoked ? 'Signed out. Local credentials were removed.' : 'Signed out on this computer. The server was unreachable; revoke this computer from your server when it is available.';
      void invoke('tray_refresh').catch(() => {});
      void tick().then(focusContent);
    } catch (error) { failure = explain(error); }
    finally { busy = false; }
  }
  async function photos() {
    failure = '';
    try { await invoke('open_photos'); } catch (error) { failure = explain(error); }
  }
  function focusContent() {
    const heading = content.querySelector<HTMLElement>('h1');
    heading?.setAttribute('tabindex', '-1');
    (heading ?? content).focus();
  }
  function go(target: string, focus = false) {
    const next = availablePage(target, isAdmin);
    if (!next) return;
    navigationRevision += 1;
    page = next;
    accountMenu = false;
    if (connection?.navigationScope) {
      try { localStorage.setItem(lastPageKey, JSON.stringify({ scope: connection.navigationScope, page })); }
      catch { /* Navigation works without storage. */ }
    }
    if (focus) void tick().then(focusContent);
  }
  function keydown(event: KeyboardEvent) {
    if (event.defaultPrevented || event.isComposing || document.querySelector('dialog:modal')) return;
    if (event.key === 'Escape' && accountMenu) {
      event.preventDefault();
      accountMenu = false;
      accountButton?.focus();
      return;
    }
    if (!connection || (event.target instanceof HTMLElement &&
      (event.target.isContentEditable || event.target.closest('input, textarea, select')))) return;
    const target = shortcutPage(event, mac);
    if (!target || !availablePage(target, isAdmin)) return;
    event.preventDefault();
    go(target, true);
  }
  const nav: { section: string; items: { id: Page; label: string; icon: string }[]; admin?: boolean }[] = [
    { section: 'My computer', items: [{ id: 'overview', label: 'Overview', icon: 'overview' }, { id: 'sources', label: 'Photo sources', icon: 'sources' }, { id: 'ai', label: 'AI processing', icon: 'ai' }] },
    { section: 'Server', items: [{ id: 'manager', label: 'Manager', icon: 'server' }, { id: 'backups', label: 'Backups', icon: 'backup' }] },
    { section: 'Frameleaf Cloud', admin: true, items: [{ id: 'cloud', label: 'Account & plan', icon: 'cloud' }, { id: 'wallet', label: 'AI credit', icon: 'wallet' }, { id: 'remote', label: 'Remote access', icon: 'globe' }] },
  ];
</script>

<svelte:head><title>Frameleaf</title></svelte:head>
<svelte:window onkeydown={keydown} ononline={networkBack} onpointerdown={event => { if (accountMenu && !(event.target as Element | null)?.closest?.('.acct-wrap')) accountMenu = false; }} />
<a class="skip-link" href="#main-content" onclick={event => { event.preventDefault(); focusContent(); }}>Skip to main content</a>
<div class="app">
  {#if connection}
    <nav class="sidebar" aria-label="Sidebar">
      <div class="drag" data-tauri-drag-region></div>
      <div class="brand" data-tauri-drag-region><img src={mark} alt="" />Frameleaf</div>
      <div class="nav-list">
        {#each nav as group (group.section)}
          {#if !group.admin || isAdmin}
            <div class="sec">{group.section}</div>
            {#each group.items as item (item.id)}
              <button class="nav-item" class:on={page === item.id} aria-current={page === item.id ? 'page' : undefined} aria-keyshortcuts={`${mac ? 'Meta' : 'Control'}+${pages.indexOf(item.id) + 1}`} onclick={event => go(item.id, event.detail === 0)}>
                <Icon name={item.icon} />{item.label}
                {#if item.id === 'manager' && managerPaired}<span class="dot" aria-label="Paired"></span>{/if}
                {#if item.id === 'overview' && attentionCount}<span class="badge" aria-label="{attentionCount} items need attention">{attentionCount}</span>{/if}
              </button>
            {/each}
          {/if}
        {/each}
        <div class="acct-wrap" style="margin-top:auto;position:relative">
          <button class="acct" aria-controls="account-actions" aria-expanded={accountMenu} bind:this={accountButton} onclick={() => { accountMenu = !accountMenu; }}>
            <span class="av" aria-hidden="true">{initials(connection.name)}</span>
            <span class="who"><b>{connection.name}</b><small>{hostOf(connection.server)}</small></span>
          </button>
          <div id="account-actions" class="acct-menu" hidden={!accountMenu}>
            <div class="acct-info">{connection.name}{summary?.me?.email ? ` · ${summary.me.email}` : ''}<br />{connection.server}{isAdmin ? ' · Administrator' : ''}</div>
            <button onclick={() => { accountMenu = false; accountButton?.focus(); void photos(); }} disabled={busy || connection.state === 'identity-changed'}>Open Photos</button>
            <button onclick={() => { accountMenu = false; accountButton?.focus(); void offlinePhotos(); }} disabled={busy || connection.state === 'identity-changed'}>Offline Albums</button>
            <button onclick={() => { accountMenu = false; accountButton?.focus(); librariesOpen = true; }} disabled={busy || !native}>Switch library…</button>
            <button onclick={() => { accountMenu = false; accountButton?.focus(); signOutSheet = true; }} disabled={busy}>Sign out…</button>
          </div>
        </div>
      </div>
    </nav>
  {/if}
  <main id="main-content" class="content" tabindex="-1" bind:this={content}>
    {#if updateVersion || updateError}
      <div class="inline-msg" style="margin:12px 24px 0">
        <p role="status">{updateError || (installingUpdate ? 'Installing the update…' : `Frameleaf ${updateVersion} is available.`)}</p>
        {#if updateVersion}<button class="btn small" disabled={installingUpdate} onclick={installUpdate}>Install and restart</button>{/if}
        <button class="btn small quiet" disabled={installingUpdate} onclick={() => { updateVersion = null; updateError = ''; }}>Dismiss</button>
      </div>
    {/if}
    {#if (connectionLocked || staleSignIn) && !connection}<button class="btn" disabled={busy} onclick={() => restoreSaved(true)}>Restore saved server sign-in</button>{/if}
    {#if (connectionLocked || staleSignIn) && !connection}<button class="btn" disabled={busy} onclick={offlinePhotos}>Offline Albums</button>{/if}
    {#if !native}<p class="preview" role="status">Desktop setup preview. Open the installed app to connect securely.</p>{/if}
    {#if failure}<div class="inline-msg error" role="alert" style="margin:12px 24px 0"><p><ErrorText text={failure} /></p>{#if connection || staleSignIn}<button class="btn small" disabled={busy || !native} onclick={() => { signOutSheet = true; }}>Clear saved sign-in</button>{/if}<button class="btn small quiet" onclick={() => { failure = ''; }}>Dismiss</button></div>{/if}
    {#if notice}<div class="inline-msg" role="status" style="margin:12px 24px 0"><p><ErrorText text={notice} /></p>{#if staleSignIn && !connection && !failure}<button class="btn small" disabled={busy || !native} onclick={() => { signOutSheet = true; }}>Clear saved sign-in</button>{/if}<button class="btn small quiet" onclick={() => { notice = ''; }}>Dismiss</button></div>{/if}
    {#if staleSignIn && !connection && !failure && !notice}<div class="inline-msg" role="status" style="margin:12px 24px 0"><p>A saved sign-in is still on this computer. Clear it before connecting to a server.</p><button class="btn small" disabled={busy || !native} onclick={() => { signOutSheet = true; }}>Clear saved sign-in</button></div>{/if}
    {#if !connection && native && !hostActive}
      <div style="margin:12px 24px 0">
        <button class="btn" disabled={busy} onclick={() => { librariesOpen = true; }}>Approved libraries…</button>
      </div>
    {/if}
    {#key libraryRevision}
    {#if native && importReady}
      {#key !!connection}
        <PhotoDrop connected={!!connection} visible={!!connection && page === 'sources'} />
      {/key}
    {/if}
    {#if kept.panel}
      <div class="welcome">
        <header class="tbar" data-tauri-drag-region><h1 data-tauri-drag-region>Frameleaf</h1></header>
        <div class="wrap" data-saved-sign-in={keptSignIn}>
          <div class="logo"><img src={mark} alt="" /><span>Frameleaf</span></div>
          <h2 tabindex="-1" bind:this={keptTitle}>{kept.panel.title}</h2>
          <p class="sub" role="status">{kept.panel.detail}</p>
          {#if verify?.hint}<p class="sub" role="status">{verify.hint}</p>{/if}
          {#if verify && keptOffer}
            {#key keptOffer.transaction}<StepUp offer={keptOffer} retry={() => { void restoreSaved(true); }} onclose={() => { keptOffer = null; keptOfferAsked = false; }} />{/key}
          {/if}
          <p>
            <button class="btn" class:primary={!verify?.verifyHere && !verify?.signOutFirst} disabled={busy} onclick={retryKept}>{kept.panel.retry}</button>
            <button class="btn" disabled={busy} onclick={offlinePhotos}>Offline Albums</button>
            <button class="btn" class:quiet={!verify?.signOutFirst} class:primary={verify?.signOutFirst} disabled={busy} onclick={() => { signOutSheet = true; }}>Sign out…</button>
          </p>
        </div>
      </div>
    {:else if !connection}
      <Welcome {native} {hostActive} {cloudAccount} onlocked={() => { connectionLocked = true; }} onconnected={connected} oncloudaccount={account => { cloudAccount = account; }} onhostactive={active => { hostActive = active; }} onmanagerchange={() => { managerRevision += 1; }} {managerRevision} onmanagerstate={paired => { managerPaired = paired; }} />
    {:else if page === 'overview' || page === 'ai'}
      <Overview {connection} {setup} {summary} {native} stepUp={summaryStepUp.request} onstepupclose={() => { summaryStepUp = stepUpDismissed; }} section={page === 'ai' ? 'ai' : 'all'} onsetup={value => { setup = value; }} onconnection={value => { connection = value; }} onrefresh={loadSummary} onsignout={() => { signOutSheet = true; }} onopen={target => go(target, true)} />
    {:else if page === 'sources'}
      <PhotoSourcesPage />
    {:else if page === 'manager'}
      {#key managerRevision}<Manager onstate={paired => { managerPaired = paired; }} />{/key}
    {:else if page === 'backups'}
      {#key managerRevision}<Backups onstate={paired => { managerPaired = paired; }} />{/key}
    {:else if page === 'cloud'}
      <Cloud {native} {summary} />
    {:else if page === 'wallet'}
      <Wallet {native} />
    {:else if page === 'remote'}
      <Remote {native} {summary} {connection} onrefresh={loadSummary} />
    {/if}
    {/key}
  </main>
</div>
{#if librariesOpen}<LibrarySwitcher onclose={() => { librariesOpen = false; }} onactivate={connected} />{/if}
{#if signOutSheet}
  <Sheet title={connection ? `Sign out of “${hostOf(connection.server)}”?` : 'Clear the saved sign-in?'} kind="warning" {busy} onclose={() => { signOutSheet = false; }} onsubmit={signOut}>
    <p>Desktop removes the saved sign-in for this library and asks the server to revoke this computer’s session. Photo imports and AI processing for this library stop, and Desktop removes its offline copies.</p>
    {#snippet actions()}
      <button class="btn" type="button" disabled={busy} onclick={() => { signOutSheet = false; }}>Cancel</button>
      <button class="btn danger" type="submit" disabled={busy || !native}>{busy ? 'Signing out…' : 'Sign Out'}</button>
    {/snippet}
  </Sheet>
{/if}
