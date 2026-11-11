<script lang="ts">
  import { onMount, tick } from 'svelte';
  import { invoke, isTauri } from '@tauri-apps/api/core';
  import { listen, type UnlistenFn } from '@tauri-apps/api/event';
  import mark from './mark.svg';
  import Icon from './Icon.svelte';
  import Sheet from './Sheet.svelte';
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
  import { connectionError, savedSignInNeedsRecovery } from './errors';
  import type { Connection, SetupStatus, ServerSummary, CloudAccount } from './server-types';
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
  // A sign-in left in the credential store with no connection shown (restore failed, or sign-out could not delete it):
  // native connect refuses until it is cleared, so the clear action stays reachable.
  let staleSignIn = $state(false);
  let connectionLocked = $state(false);
  const isAdmin = $derived(summary?.me?.isAdmin === true);
  const attentionCount = $derived((summary?.attention?.items ?? []).filter(item => !(summary?.attention?.dismissed ?? []).includes(item.id)).length);
  const explain = connectionError;
  let summaryRequest = 0; // bumped per request and on every sign-in and sign-out: only the latest reply applies
  async function loadSummary() {
    if (!native || !connection) { summary = null; return; }
    // A superseded reply (a newer refresh, or a sign-in or sign-out since) is dropped.
    const asked = ++summaryRequest;
    const result = await invoke<ServerSummary>('server_summary').catch(() => null);
    if (summaryRequest === asked) {
      summary = result;
      if (result && !availablePage(page, result.me?.isAdmin === true)) page = 'overview';
    }
    void invoke('tray_refresh').catch(() => {});
  }
  async function restoreSaved(retry = false) {
    busy = true;
    try {
      failure = '';
      connection = await invoke<Connection | null>('restore_connection', { retry });
      connectionLocked = false; staleSignIn = false;
      const scope = connection?.navigationScope;
      const revision = navigationRevision;
      setup = await invoke<SetupStatus>('worker_setup_status');
      await loadSummary();
      if (scope && connection?.navigationScope === scope && summary?.me && navigationRevision === revision) {
        try { page = restoredPage(localStorage.getItem(lastPageKey), scope, isAdmin); }
        catch { /* The default page is available without storage. */ }
      }
    } catch (error) {
      connectionLocked = savedSignInNeedsRecovery(error);
      staleSignIn = !connection && !connectionLocked;
      failure = explain(error);
    } finally { busy = false; }
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
          failure = explain(event.payload);
          void invoke<SetupStatus>('worker_setup_status').then(value => { setup = value; }).catch(() => {});
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
        : error === 'update_changed'
          ? updateVersion
            ? `The latest release changed to Frameleaf ${updateVersion}.`
            : 'That update is no longer available.'
          : 'Frameleaf couldn’t install the update. Try again.';
      installingUpdate = false;
    }
  }
  function connected(view: Connection) {
    summaryRequest += 1; connection = view; setup = null; summary = null; failure = ''; notice = ''; page = 'overview'; staleSignIn = false; connectionLocked = false;
    void loadSummary();
    void invoke<SetupStatus>('worker_setup_status').then(value => { setup = value; }).catch(() => {});
  }
  async function signOut() {
    busy = true; failure = '';
    try {
      const result = await invoke<{ remoteRevoked: boolean; localCleared: boolean; photosCleared: boolean }>('sign_out');
      try { localStorage.removeItem(lastPageKey); } catch { /* Sign-out still succeeds. */ }
      summaryRequest += 1; connection = null; setup = null; summary = null; signOutSheet = false; accountMenu = false; page = 'overview'; staleSignIn = !result.localCleared;
      notice = !result.localCleared ? 'The secure credential store could not remove your saved sign-in. Unlock it and clear the saved sign-in again.' : !result.photosCleared ? 'Sign-in stopped, but the Photos window could not be cleared. Close it and clear this server’s browsing data.' : result.remoteRevoked ? 'Signed out. Local credentials were removed.' : 'Signed out on this computer. The server was unreachable; revoke this computer from your server when it is available.';
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
<svelte:window onkeydown={keydown} onpointerdown={event => { if (accountMenu && !(event.target as Element | null)?.closest?.('.acct-wrap')) accountMenu = false; }} />
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
    {#if !native}<p class="preview" role="status">Desktop setup preview. Open the installed app to connect securely.</p>{/if}
    {#if failure}<div class="inline-msg error" role="alert" style="margin:12px 24px 0"><p>{failure}</p>{#if connection || staleSignIn}<button class="btn small" disabled={busy || !native} onclick={() => { signOutSheet = true; }}>Clear saved sign-in</button>{/if}<button class="btn small quiet" onclick={() => { failure = ''; }}>Dismiss</button></div>{/if}
    {#if notice}<div class="inline-msg" role="status" style="margin:12px 24px 0"><p>{notice}</p>{#if staleSignIn && !connection && !failure}<button class="btn small" disabled={busy || !native} onclick={() => { signOutSheet = true; }}>Clear saved sign-in</button>{/if}<button class="btn small quiet" onclick={() => { notice = ''; }}>Dismiss</button></div>{/if}
    {#if staleSignIn && !connection && !failure && !notice}<div class="inline-msg" role="status" style="margin:12px 24px 0"><p>A saved sign-in is still on this computer. Clear it before connecting to a server.</p><button class="btn small" disabled={busy || !native} onclick={() => { signOutSheet = true; }}>Clear saved sign-in</button></div>{/if}
    {#if native && importReady}
      {#key !!connection}
        <PhotoDrop connected={!!connection} visible={!!connection && page === 'sources'} />
      {/key}
    {/if}
    {#if !connection}
      <Welcome {native} {hostActive} {cloudAccount} onlocked={() => { connectionLocked = true; }} onconnected={connected} oncloudaccount={account => { cloudAccount = account; }} onhostactive={active => { hostActive = active; }} onmanagerchange={() => { managerRevision += 1; }} {managerRevision} onmanagerstate={paired => { managerPaired = paired; }} />
    {:else if page === 'overview' || page === 'ai'}
      <Overview {connection} {setup} {summary} {native} section={page === 'ai' ? 'ai' : 'all'} onsetup={value => { setup = value; }} onconnection={value => { connection = value; }} onrefresh={loadSummary} onsignout={() => { signOutSheet = true; }} onopen={target => go(target, true)} />
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
  </main>
</div>
{#if signOutSheet}
  <Sheet title={connection ? `Sign out of “${hostOf(connection.server)}”?` : 'Clear the saved sign-in?'} kind="warning" {busy} onclose={() => { signOutSheet = false; }} onsubmit={signOut}>
    <p>This computer’s session and device key are removed from the secure credential store, and the server is asked to revoke them. Photo folder permissions and AI processing on this computer stop.</p>
    {#snippet actions()}
      <button class="btn" type="button" disabled={busy} onclick={() => { signOutSheet = false; }}>Cancel</button>
      <button class="btn danger" type="submit" disabled={busy || !native}>{busy ? 'Signing out…' : 'Sign Out'}</button>
    {/snippet}
  </Sheet>
{/if}
