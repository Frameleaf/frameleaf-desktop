<script lang="ts">
  import { onMount } from 'svelte';
  import { invoke, isTauri } from '@tauri-apps/api/core';
  import { listen, type UnlistenFn } from '@tauri-apps/api/event';
  import mark from './mark.svg';
  import Icon from './Icon.svelte';
  import Sheet from './Sheet.svelte';
  import Welcome from './pages/Welcome.svelte';
  import Overview from './pages/Overview.svelte';
  import PhotoSourcesPage from './pages/PhotoSources.svelte';
  import Manager from './pages/Manager.svelte';
  import Backups from './pages/Backups.svelte';
  import Cloud from './pages/Cloud.svelte';
  import Wallet from './pages/Wallet.svelte';
  import Remote from './pages/Remote.svelte';
  import { initials, hostOf } from './ui-state';
  import { connectionError } from './errors';
  import type { Connection, SetupStatus, ServerSummary, CloudAccount } from './server-types';

  type Page = 'overview' | 'sources' | 'ai' | 'manager' | 'backups' | 'cloud' | 'wallet' | 'remote';
  const native = isTauri();
  let connection = $state<Connection | null>(null);
  let setup = $state<SetupStatus | null>(null);
  let summary = $state<ServerSummary | null>(null);
  let cloudAccount = $state<CloudAccount | null>(null);
  let hostActive = $state(false);
  let managerRevision = $state(0);
  let managerPaired = $state(false);
  let page = $state<Page>('overview');
  let busy = $state(false);
  let failure = $state('');
  let notice = $state('');
  let accountMenu = $state(false);
  let signOutSheet = $state(false);
  const isAdmin = $derived(summary?.me?.isAdmin === true);
  const attentionCount = $derived((summary?.attention?.items ?? []).filter(item => !(summary?.attention?.dismissed ?? []).includes(item.id)).length);
  const explain = connectionError;
  async function loadSummary() {
    if (!native || !connection) { summary = null; return; }
    try { summary = await invoke<ServerSummary>('server_summary'); }
    catch { summary = null; }
    void invoke('tray_refresh').catch(() => {});
  }
  onMount(() => {
    if (!native) return;
    let disposed = false;
    let unlisten: UnlistenFn | undefined;
    void (async () => {
      busy = true;
      try {
        unlisten = await listen<SetupStatus>('worker-setup', event => { setup = event.payload; });
        if (disposed) { unlisten(); return; }
        const host = await invoke<{ backgroundActive: boolean }>('local_host_status');
        hostActive = host.backgroundActive;
        connection = await invoke<Connection | null>('restore_connection');
        setup = await invoke<SetupStatus>('worker_setup_status');
        await loadSummary();
      } catch (error) { failure = explain(error); }
      finally { busy = false; }
    })();
    return () => { disposed = true; unlisten?.(); };
  });
  function connected(view: Connection) {
    connection = view; setup = null; failure = ''; notice = ''; page = 'overview';
    void loadSummary();
    void invoke<SetupStatus>('worker_setup_status').then(value => { setup = value; }).catch(() => {});
  }
  async function signOut() {
    busy = true; failure = '';
    try {
      const result = await invoke<{ remoteRevoked: boolean; localCleared: boolean; photosCleared: boolean }>('sign_out');
      connection = null; setup = null; summary = null; signOutSheet = false; accountMenu = false; page = 'overview';
      notice = !result.localCleared ? 'The secure credential store could not remove your saved sign-in. Unlock it and clear the saved sign-in again.' : !result.photosCleared ? 'Sign-in stopped, but the Photos window could not be cleared. Close it and clear this server’s browsing data.' : result.remoteRevoked ? 'Signed out. Local credentials were removed.' : 'Signed out on this computer. The server was unreachable; revoke this computer from your server when it is available.';
      void invoke('tray_refresh').catch(() => {});
    } catch (error) { failure = explain(error); }
    finally { busy = false; }
  }
  async function photos() {
    failure = '';
    try { await invoke('open_photos'); } catch (error) { failure = explain(error); }
  }
  function go(target: Page) { page = target; accountMenu = false; }
  const nav: { section: string; items: { id: Page; label: string; icon: string }[]; admin?: boolean }[] = [
    { section: 'My computer', items: [{ id: 'overview', label: 'Overview', icon: 'overview' }, { id: 'sources', label: 'Photo sources', icon: 'sources' }, { id: 'ai', label: 'AI processing', icon: 'ai' }] },
    { section: 'Server', items: [{ id: 'manager', label: 'Manager', icon: 'server' }, { id: 'backups', label: 'Backups', icon: 'backup' }] },
    { section: 'Frameleaf Cloud', admin: true, items: [{ id: 'cloud', label: 'Account & plan', icon: 'cloud' }, { id: 'wallet', label: 'AI credit', icon: 'wallet' }, { id: 'remote', label: 'Remote access', icon: 'globe' }] },
  ];
</script>

<svelte:head><title>Frameleaf</title></svelte:head>
<svelte:window onpointerdown={event => { if (accountMenu && !(event.target as Element | null)?.closest?.('.acct-wrap')) accountMenu = false; }} />
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
              <button class="nav-item" class:on={page === item.id} aria-current={page === item.id ? 'page' : undefined} onclick={() => go(item.id)}>
                <Icon name={item.icon} />{item.label}
                {#if item.id === 'manager' && managerPaired}<span class="dot" aria-label="Paired"></span>{/if}
                {#if item.id === 'overview' && attentionCount}<span class="badge" aria-label="{attentionCount} items need attention">{attentionCount}</span>{/if}
              </button>
            {/each}
          {/if}
        {/each}
        <div class="acct-wrap" style="margin-top:auto;position:relative">
          {#if accountMenu}
            <div class="acct-menu" role="menu">
              <div class="acct-info">{connection.name}{summary?.me?.email ? ` · ${summary.me.email}` : ''}<br />{connection.server}{isAdmin ? ' · Administrator' : ''}</div>
              <button role="menuitem" onclick={() => { accountMenu = false; void photos(); }} disabled={busy || connection.state === 'identity-changed'}>Open Photos</button>
              <button role="menuitem" onclick={() => { accountMenu = false; signOutSheet = true; }} disabled={busy}>Sign out…</button>
            </div>
          {/if}
          <button class="acct" aria-haspopup="menu" aria-expanded={accountMenu} onclick={() => { accountMenu = !accountMenu; }}>
            <span class="av" aria-hidden="true">{initials(connection.name)}</span>
            <span class="who"><b>{connection.name}</b><small>{hostOf(connection.server)}</small></span>
          </button>
        </div>
      </div>
    </nav>
  {/if}
  <main class="content">
    {#if !native}<p class="preview" role="status">Desktop setup preview. Open the installed app to connect securely.</p>{/if}
    {#if failure}<div class="inline-msg error" role="alert" style="margin:12px 24px 0"><p>{failure}</p>{#if connection}<button class="btn small" disabled={busy || !native} onclick={() => { signOutSheet = true; }}>Clear saved sign-in</button>{/if}<button class="btn small quiet" onclick={() => { failure = ''; }}>Dismiss</button></div>{/if}
    {#if notice}<div class="inline-msg" role="status" style="margin:12px 24px 0"><p>{notice}</p><button class="btn small quiet" onclick={() => { notice = ''; }}>Dismiss</button></div>{/if}
    {#if !connection}
      <Welcome {native} {hostActive} {cloudAccount} onconnected={connected} oncloudaccount={account => { cloudAccount = account; }} onhostactive={active => { hostActive = active; }} onmanagerchange={() => { managerRevision += 1; }} {managerRevision} onmanagerstate={paired => { managerPaired = paired; }} />
    {:else if page === 'overview' || page === 'ai'}
      <Overview {connection} {setup} {summary} {native} section={page === 'ai' ? 'ai' : 'all'} onsetup={value => { setup = value; }} onconnection={value => { connection = value; }} onrefresh={loadSummary} onsignout={() => { signOutSheet = true; }} onopen={target => go(target as Page)} />
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
{#if signOutSheet && connection}
  <Sheet title="Sign out of “{hostOf(connection.server)}”?" kind="warning" {busy} onclose={() => { signOutSheet = false; }} onsubmit={signOut}>
    <p>This computer’s session and device key are removed from the secure credential store, and the server is asked to revoke them. Photo folder permissions and AI processing on this computer stop.</p>
    {#snippet actions()}
      <button class="btn" type="button" disabled={busy} onclick={() => { signOutSheet = false; }}>Cancel</button>
      <button class="btn danger" type="submit" disabled={busy || !native}>{busy ? 'Signing out…' : 'Sign Out'}</button>
    {/snippet}
  </Sheet>
{/if}
