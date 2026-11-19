<script lang="ts">
  // FD-77: Computer backup, as approved in the prototype (Frameleaf/frameleaf-prototype PR 78, FL-1714).
  // The backend does the work (src-tauri/src/computer_backup*.rs); this page shows its status and asks.
  import { onMount } from 'svelte';
  import { invoke } from '@tauri-apps/api/core';
  import Icon from '../Icon.svelte';
  import Sheet from '../Sheet.svelte';
  import ErrorText from '../ErrorText.svelte';
  import { explainError } from '../errors';
  import {
    clock, credentialStore, formatBytes, health, nextBackup, ownerCheck, pills, progress, protectedTotals, runRow, shownPath, when,
    type BackupDate, type ComputerBackupView, type Item, type Schedule,
  } from '../computer-backup';

  let { native = true }: { native?: boolean } = $props();
  const TABS = [['overview', 'Overview'], ['folders', 'Folders'], ['schedule', 'Schedule'], ['restore', 'Restore'], ['key', 'Recovery key'], ['settings', 'Settings']] as const;
  const STEPS = ['Connect Cloud', 'Choose folders', 'Save your key', 'Schedule'];
  type Tab = typeof TABS[number][0];

  let view = $state<ComputerBackupView | null>(null);
  let tab = $state<Tab>('overview');
  let step = $state(0);
  let sheet = $state<'restore' | 'delete' | 'disconnect' | 'passphrase' | null>(null);
  let busy = $state(false);
  let failure = $state('');
  let notice = $state('');
  const fail = (error: unknown) => { failure = explainError(error); };

  async function load() {
    try { view = await invoke<ComputerBackupView>('computer_backup_status'); }
    catch (error) { fail(error); }
  }
  onMount(() => {
    void load();
    void invoke('computer_backup_refresh').then(load).catch(() => {});
    // Progress and the browser approval come from elsewhere: asked for every second while they matter.
    let ticks = 0;
    const timer = setInterval(() => {
      ticks += 1;
      if (view?.running || view?.connecting || ticks % 10 === 0) void load();
      if (view?.connecting && ticks % 5 === 0) void poll();
    }, 1000);
    return () => clearInterval(timer);
  });

  const status = $derived(view ? health(view) : 'off');
  const off = $derived(status === 'off' || status === 'noplan');
  const pill = $derived(pills[status]);
  const totals = $derived(view ? protectedTotals(view.folders) : { bytes: 0, files: 0, count: 0 });

  async function act(work: () => Promise<unknown>) {
    busy = true; failure = '';
    try { await work(); await load(); }
    catch (error) { fail(error); }
    finally { busy = false; }
  }

  // ---- set-up
  let on = $state<Record<string, boolean>>({});
  let key = $state('');
  let saved = $state(false);
  let draft = $state<Schedule | null>(null);
  function begin() {
    step = view?.connected ? 2 : 1;
    on = Object.fromEntries((view?.folders ?? []).map(folder => [folder.id, folder.on]));
    draft = view ? { ...view.schedule } : null;
  }
  async function poll() {
    try {
      const answer = await invoke<string>('computer_backup_connect_poll');
      if (answer === 'linked') { step = 2; await load(); }
      if (answer === 'noplan') { step = 0; await load(); }
    } catch (error) { fail(error); await load(); }
  }
  async function next() {
    if (step === 1) { if (view?.connected) step = 2; else await act(() => invoke('computer_backup_connect')); return; }
    if (step === 2) { await act(saveFolders); if (!failure) { step = 3; key = await invoke<string>('computer_backup_setup_key').catch(error => { fail(error); return ''; }); } return; }
    if (step === 3) { await act(() => invoke('computer_backup_key_saved')); if (!failure) step = 4; return; }
    await act(async () => { await invoke('computer_backup_set_schedule', { schedule: draft }); await invoke('computer_backup_finish'); });
    if (!failure) { step = 0; tab = 'overview'; }
  }
  function back() {
    if (step === 1) { void invoke('computer_backup_cancel_connect').then(load); step = 0; }
    else step -= 1;
  }
  const saveFolders = () => invoke('computer_backup_set_folders', { folders: Object.entries(on).map(([id, value]) => ({ id, on: value })) });
  async function addFolder() {
    await act(async () => {
      if (await invoke<boolean>('computer_backup_add_folder')) {
        await load();
        on = { ...Object.fromEntries((view?.folders ?? []).map(folder => [folder.id, folder.on])), ...on };
        for (const folder of view?.folders ?? []) if (!(folder.id in on) || folder.on) on[folder.id] = on[folder.id] || folder.on;
      }
    });
  }
  async function copy(text: string) {
    try { await navigator.clipboard.writeText(text); notice = 'Copied.'; } catch { notice = ''; }
  }

  // ---- restore
  let dates = $state<BackupDate[]>([]);
  let chosen = $state('');
  let path = $state<string[]>([]);
  let items = $state<Item[]>([]);
  let ticked = $state<Record<string, string[]>>({});
  let where = $state<'original' | 'other'>('original');
  const count = $derived(Object.keys(ticked).length);
  async function openRestore() {
    tab = 'restore';
    await act(async () => {
      dates = await invoke<BackupDate[]>('computer_backup_backups');
      chosen = dates[0]?.key ?? '';
      await browse([]);
    });
  }
  async function browse(next: string[]) {
    if (!chosen) { items = []; return; }
    items = await invoke<Item[]>('computer_backup_browse', { backup: chosen, path: next });
    path = next;
  }
  async function restore() {
    await act(async () => {
      let target: string | null = null;
      if (where === 'other') {
        target = await invoke<string | null>('computer_backup_choose_target');
        if (!target) return;
      }
      const result = await invoke<{ files: number; renamed: number }>('computer_backup_restore', { backup: chosen, items: Object.values(ticked), target });
      sheet = null; ticked = {};
      notice = `Restored ${result.files.toLocaleString()} file${result.files === 1 ? '' : 's'}${result.renamed ? `. ${result.renamed} already there ${result.renamed === 1 ? 'was' : 'were'} kept and renamed with today’s date` : ''}.`;
    });
  }

  // ---- recovery key and settings
  let shown = $state('');
  let passphrase = $state('');
  async function show() { await act(async () => { shown = await invoke<string>('computer_backup_show_key'); }); }
  async function lockedCopy() {
    if (!view?.lockedCopy) { passphrase = ''; sheet = 'passphrase'; return; }
    await act(() => invoke('computer_backup_locked_copy', { passphrase: null }));
  }
  async function confirmSheet() {
    if (sheet === 'restore') return restore();
    if (sheet === 'passphrase') return act(async () => { await invoke('computer_backup_locked_copy', { passphrase }); sheet = null; });
    if (sheet === 'delete') return act(async () => { await invoke('computer_backup_delete'); sheet = null; });
    if (sheet === 'disconnect') return act(async () => { await invoke('computer_backup_disconnect'); sheet = null; tab = 'overview'; });
  }
  const sheetTitle = $derived(sheet === 'restore' ? 'Where should they go?' : sheet === 'delete' ? `Delete “${view?.computer}” backups?` : sheet === 'passphrase' ? 'Lock the copy with a passphrase' : `Disconnect “${view?.computer}”?`);
  const until = (iso: string) => new Date(iso).toLocaleDateString([], { day: 'numeric', month: 'long' });
  const times = [0, 60, 120, 180, 720, 1080, 1260];
</script>

{#snippet row(icon: string | null, title: string, sub: string | null)}
  {#if icon}<span class="ic" aria-hidden="true"><Icon name={icon} /></span>{/if}
  <span class="l"><b>{title}</b>{#if sub}<small>{sub}</small>{/if}</span>
{/snippet}

{#snippet fullDiskAccess()}
  <div class="inline-msg" role="status">
    <p>Frameleaf needs Full Disk Access to read your Desktop and Documents. Turn it on in System Settings, then come back.</p>
    <span class="sp"></span>
    <button class="btn small" onclick={() => act(() => invoke('computer_backup_open_full_disk_access'))}>Open System Settings…</button>
  </div>
{/snippet}

{#snippet folderList()}
  {#if view}
    {@const photos = view.folders.find(folder => folder.photos)}
    {#if view.os === 'mac' && !view.fullDiskAccess}{@render fullDiskAccess()}{/if}
    <div>
      <div class="group-head"><h2 class="group-title">Folders to back up</h2></div>
      <div class="group">
        {#each view.folders.filter(folder => !folder.photos || on[folder.id]) as folder (folder.id)}
          <div class="row">
            {@render row('folder', folder.name, `${shownPath(folder.path, view.os)}${folder.size !== null ? ` · ${formatBytes(folder.size)} · ${(folder.files ?? 0).toLocaleString()} files` : ''}${folder.photos ? ' · stored twice: Cloud Backup already has it' : ''}`)}
            <button class="toggle" class:on={on[folder.id]} role="switch" aria-checked={!!on[folder.id]} aria-label={`Back up ${folder.name}`} onclick={() => { on = { ...on, [folder.id]: !on[folder.id] }; }}></button>
          </div>
        {/each}
        <div class="row">
          {@render row('plus', 'Another folder', 'Any folder on this computer or an attached drive.')}
          <button class="btn" disabled={busy || !native} onclick={addFolder}>Choose…</button>
        </div>
      </div>
      <p class="foot">{view.os === 'windows' ? 'Files that are open are read through a Windows snapshot, so they’re backed up as they were at that moment.' : 'Caches, system files and apps are skipped.'}</p>
    </div>
    {#if photos && !on[photos.id]}
      <div>
        <div class="group-head"><h2 class="group-title">Left out</h2></div>
        <div class="group">
          <div class="row">
            {@render row('sources', `${photos.name}${photos.size !== null ? ` · ${formatBytes(photos.size)}` : ''}`, 'Your photo library is already protected by Cloud Backup. Adding it here stores it twice and uses more of your plan’s storage.')}
            <button class="btn quiet" onclick={() => { on = { ...on, [photos.id]: true }; }}>Add Anyway</button>
          </div>
        </div>
      </div>
    {/if}
  {/if}
{/snippet}

{#snippet scheduleRows()}
  {#if draft}
    <div>
      <div class="group-head"><h2 class="group-title">When to back up</h2></div>
      <div class="group">
        <div class="row">
          {@render row(null, 'Back up', 'Only what changed is sent, usually in minutes.')}
          <div class="seg">
            <button class:on={draft.every === 'hour'} aria-pressed={draft.every === 'hour'} onclick={() => { draft!.every = 'hour'; }}>Every hour</button>
            <button class:on={draft.every === 'day'} aria-pressed={draft.every === 'day'} onclick={() => { draft!.every = 'day'; }}>Every day</button>
          </div>
          {#if draft.every === 'day'}
            <select style="width:auto;flex:none" aria-label="Time" bind:value={draft.at}>
              {#each times as time (time)}<option value={time}>{clock(time)}</option>{/each}
            </select>
          {/if}
        </div>
        <div class="row">
          {@render row(null, 'Stop by', 'A long first backup pauses here and picks up the next day.')}
          {#if draft.stopBy !== null}
            <select style="width:auto;flex:none" aria-label="Stop time" bind:value={draft.stopBy}>
              {#each [360, 420, 480] as time (time)}<option value={time}>{clock(time)}</option>{/each}
            </select>
          {/if}
          <button class="toggle" class:on={draft.stopBy !== null} role="switch" aria-checked={draft.stopBy !== null} aria-label="Stop by a time" onclick={() => { draft!.stopBy = draft!.stopBy === null ? 420 : null; }}></button>
        </div>
        <div class="row">
          {@render row(null, 'Upload speed limit', 'Leave room for video calls and streaming.')}
          {#if draft.limitMbps !== null}
            <input type="number" min="1" max="10000" aria-label="Mbit/s" style="width:56px;flex:none" bind:value={draft.limitMbps} />
            <span class="muted">Mbit/s</span>
          {/if}
          <button class="toggle" class:on={draft.limitMbps !== null} role="switch" aria-checked={draft.limitMbps !== null} aria-label="Limit upload speed" onclick={() => { draft!.limitMbps = draft!.limitMbps === null ? 20 : null; }}></button>
        </div>
        <div class="row">
          {@render row(null, 'Wait while on battery', 'Back up once this computer is plugged in.')}
          <button class="toggle" class:on={draft.waitOnBattery} role="switch" aria-checked={draft.waitOnBattery} aria-label="Wait while on battery" onclick={() => { draft!.waitOnBattery = !draft!.waitOnBattery; }}></button>
        </div>
        <div class="row">
          {@render row(null, 'Keep earlier versions for', 'Every backup for 90 days, then one a month for a year.')}
          <select style="width:auto;flex:none" aria-label="Keep earlier versions" bind:value={draft.keep}>
            <option value="recommended">Recommended</option><option value="30d">30 days</option><option value="1y">1 year</option><option value="forever">Forever</option>
          </select>
        </div>
      </div>
      <p class="foot">Backups run in the background while Frameleaf is closed. A backup that’s cut short carries on next time.</p>
    </div>
  {/if}
{/snippet}

<section class="page" aria-labelledby="cb-title">
  <header class="toolbar" data-tauri-drag-region>
    <h1 id="cb-title" data-tauri-drag-region>Computer backup</h1>
    <span class="pill {pill[0]}"><i aria-hidden="true"></i>{pill[1]}</span>
    <span class="sp" data-tauri-drag-region></span>
    {#if !off && !step}
      <div class="seg" role="tablist" aria-label="Computer backup">
        {#each TABS as [id, label] (id)}
          <button role="tab" aria-selected={tab === id} class:on={tab === id} onclick={() => {
            if (id === 'restore') void openRestore();
            else { tab = id; if (id === 'folders') on = Object.fromEntries((view?.folders ?? []).map(f => [f.id, f.on])); if (id === 'schedule') draft = view ? { ...view.schedule } : null; }
          }}>{label}</button>
        {/each}
      </div>
    {/if}
  </header>
  <div class="body">
    {#if failure}<div class="inline-msg error" role="alert"><p><ErrorText text={failure} /></p><span class="sp"></span><button class="btn small quiet" onclick={() => { failure = ''; }}>Dismiss</button></div>{/if}
    {#if notice}<div class="inline-msg" role="status"><p>{notice}</p><span class="sp"></span><button class="btn small quiet" onclick={() => { notice = ''; }}>Dismiss</button></div>{/if}
    {#if !view}
      <p class="muted" role="status">Loading…</p>
    {:else if step}
      <div class="path" aria-label="Set-up steps">
        {#each STEPS as label, index (label)}<span class:on={index + 1 === step}>{index + 1 < step ? '✓ ' : `${index + 1}. `}{label}</span>{/each}
      </div>
      {#if step === 1}
        <div>
          <div class="group">
            <div class="row">
              {#if view.connecting}
                {@render row('open', 'Finish in your browser', `Frameleaf Cloud opened in your browser. Sign in and approve this computer. Check the code matches: ${view.connecting}`)}
                <span class="pill wait"><i aria-hidden="true"></i>Waiting…</span>
                <button class="btn quiet" onclick={() => act(() => invoke('computer_backup_connect_again'))}>Open Again</button>
              {:else if view.connected}
                {@render row('check', 'Connected to Frameleaf Cloud', `“${view.computer}” backs up to your Frameleaf account as its own computer.`)}
              {:else}
                {@render row('cloud', 'Connect to Frameleaf Cloud', `Sign in to your Frameleaf account in your browser to add “${view.computer}”. The app never sees your Cloud password.`)}
                <button class="btn primary" disabled={busy || !native} onclick={() => act(() => invoke('computer_backup_connect'))}>Continue in Browser…</button>
              {/if}
            </div>
          </div>
          <p class="foot">This computer gets its own connection to Frameleaf Cloud. Backups keep running when Frameleaf is closed or the server is off.</p>
        </div>
      {:else if step === 2}
        {@render folderList()}
      {:else if step === 3}
        <div>
          <div class="group-head"><h2 class="group-title">Your recovery key</h2></div>
          <div class="group">
            <div class="row">
              {@render row('key', key || '…', 'Made on this computer and kept in its secure credential store.')}
              <button class="btn quiet" disabled={!key} onclick={() => copy(key)}><Icon name="copy" />Copy</button>
              <button class="btn" disabled={!key || busy} onclick={() => act(() => invoke('computer_backup_download_kit'))}>Download Recovery Kit…</button>
            </div>
            <div class="row"><label class="check"><input type="checkbox" bind:checked={saved} />I’ve saved my recovery key somewhere other than this computer</label></div>
          </div>
          <p class="foot">Keep it away from this computer: printed, or in a password manager. Without it nobody, including Frameleaf, can open your backups.</p>
        </div>
      {:else}
        {@render scheduleRows()}
      {/if}
      <div class="actions end">
        <button class="btn quiet" disabled={busy} onclick={back}>{step === 1 ? 'Cancel' : 'Back'}</button>
        <button class="btn primary" disabled={busy || (step === 1 && !!view.connecting) || (step === 3 && (!saved || !key))} onclick={next}>{step === 4 ? 'Start First Backup' : 'Continue'}</button>
      </div>
    {:else if off}
      <div>
        <div class="group">
          <div class="row">
            {@render row('cloud', 'Back up this computer to Frameleaf Cloud', 'Your documents, desktop and downloads, kept safe and restorable by date. Bring back one file, a folder or everything.')}
            {#if status === 'noplan'}
              <button class="btn primary" disabled={!native} onclick={() => act(() => invoke('computer_backup_open_plans'))}>See Cloud plans…</button>
            {:else}
              <button class="btn primary" disabled={!native} onclick={begin}>Set Up Computer Backup…</button>
            {/if}
          </div>
        </div>
        <p class="foot">Encrypted on this computer before it leaves. File names and contents open only with your recovery key; Frameleaf never receives it.</p>
      </div>
      <div>
        <div class="group-head"><h2 class="group-title">What you need</h2></div>
        <div class="group">
          <div class="tile">
            <div><span>Frameleaf Cloud plan</span><b class={status === 'noplan' ? 'bad' : 'good'}>{status === 'noplan' ? 'Not on this account' : 'Included'}</b><small>{status === 'noplan' ? 'Computer backup comes with a Cloud plan' : 'No Server licence needed'}</small></div>
            <div><span>Storage</span><b>Shared with your plan</b><small>{view.usage ? `${formatBytes(view.usage[1])} of ${formatBytes(view.usage[2])} used` : 'Counted with your photos’ Cloud Backup'}</small></div>
            <div><span>Your photo library</span><b>Left out</b><small>Cloud Backup already protects it</small></div>
          </div>
        </div>
      </div>
    {:else if tab === 'folders'}
      {@render folderList()}
      <div class="actions end"><button class="btn primary" disabled={busy} onclick={() => act(async () => { await saveFolders(); notice = 'Saved. The next backup uses these folders.'; })}>Save</button></div>
    {:else if tab === 'schedule'}
      {@render scheduleRows()}
      <div class="actions end"><button class="btn primary" disabled={busy} onclick={() => act(async () => { await invoke('computer_backup_set_schedule', { schedule: draft }); notice = 'Saved.'; })}>Save</button></div>
    {:else if tab === 'restore'}
      <div>
        <div class="group">
          <div class="row">
            {@render row('restart', 'As it was on', 'Every backup is a date you can open. Folders show what they held then.')}
            <select style="width:auto;flex:none" aria-label="Backup date" bind:value={chosen} onchange={() => { ticked = {}; void act(() => browse(path)).catch(() => browse([])); }}>
              {#each dates as date (date.key)}<option value={date.key}>{when(date.time)}</option>{/each}
              {#if !dates.length}<option value="">No backups yet</option>{/if}
            </select>
          </div>
        </div>
      </div>
      <div class="path" aria-label="Folder">
        <span onclick={() => act(() => browse([]))} onkeydown={event => { if (event.key === 'Enter') void act(() => browse([])); }} role="button" tabindex="0">{view.computer}</span>
        {#each path as name, index (index)}
          <span class:on={index === path.length - 1} onclick={() => act(() => browse(path.slice(0, index + 1)))} onkeydown={event => { if (event.key === 'Enter') void act(() => browse(path.slice(0, index + 1))); }} role="button" tabindex="0">{name}</span>
        {/each}
      </div>
      <div class="group">
        {#each items as item (item.name)}
          {@const at = [...path, item.name]}
          {@const id = at.join('/')}
          <div class="row">
            <input type="checkbox" checked={id in ticked} aria-label={`Select ${item.name}`} onchange={event => {
              const next = { ...ticked };
              if ((event.currentTarget as HTMLInputElement).checked) next[id] = at; else delete next[id];
              ticked = next;
            }} />
            <span class="ic" aria-hidden="true"><Icon name={item.folder ? 'folder' : 'copy'} /></span>
            <span class="l"><b>{item.name}</b>{#if !item.folder}<small>Changed {when(item.changed)}</small>{/if}</span>
            {#if item.folder}
              <button class="btn quiet small" aria-label={`Open ${item.name}`} onclick={() => act(() => browse(at))}><Icon name="chevron" /></button>
            {:else}
              <span class="muted">{formatBytes(item.size)}</span>
            {/if}
          </div>
        {:else}
          <div class="row"><span class="l"><small>{dates.length ? 'This folder was empty.' : 'Nothing is backed up yet.'}</small></span></div>
        {/each}
      </div>
      <div class="actions end">
        <span class="muted">{count ? `${count} selected` : 'Nothing selected'}</span>
        <span class="sp"></span>
        <button class="btn primary" disabled={!count || busy} onclick={() => { where = 'original'; sheet = 'restore'; }}>Restore…</button>
      </div>
    {:else if tab === 'key'}
      <div>
        <div class="group-head"><h2 class="group-title">Recovery key</h2></div>
        <div class="group">
          <div class="row">{@render row('key', shown || 'Kept on this computer only', `In ${credentialStore(view.os)}.${view.keySavedAt ? ` You confirmed saving it ${when(view.keySavedAt)}.` : ''} Frameleaf never receives it.`)}</div>
          <div class="row">{@render row('copy', 'Recovery kit', 'A printable page with the key and how to restore.')}<button class="btn" disabled={busy} onclick={() => act(() => invoke('computer_backup_download_kit'))}>Download…</button></div>
          <div class="row">
            {@render row('lock', 'Show the recovery key', view.os === 'windows' ? 'Confirm with Windows Hello to see it.' : 'Confirm with Touch ID or your Mac password to see it.')}
            {#if shown}<button class="btn quiet" onclick={() => copy(shown)}><Icon name="copy" />Copy</button>{:else}<button class="btn" disabled={busy} onclick={show}>Show…</button>{/if}
          </div>
          <div class="row">
            {@render row('cloud', 'Keep a locked copy in Frameleaf Cloud', view.lockedCopy ? 'On. Locked with your passphrase before it leaves this computer. Frameleaf can’t open it.' : 'Off. If you turn it on, the key is locked with a passphrase only you know before it leaves this computer.')}
            <button class="toggle" class:on={view.lockedCopy} role="switch" aria-checked={view.lockedCopy} aria-label="Keep a locked copy in Frameleaf Cloud" disabled={busy} onclick={lockedCopy}></button>
          </div>
        </div>
        <p class="foot">The only way to open your backups on another computer.</p>
      </div>
    {:else if tab === 'settings'}
      {#if view.purge}
        <div class="inline-msg error" role="status">
          <p>This computer’s backups are deleted and stay restorable for 30 more days, until {until(view.purge)}.</p>
          <span class="sp"></span>
          <button class="btn small" disabled={busy} onclick={() => act(() => invoke('computer_backup_keep'))}>Keep My Backups</button>
        </div>
      {/if}
      <div>
        <div class="group-head"><h2 class="group-title">This computer</h2></div>
        <div class="group">
          <div class="row">{@render row('computer', view.computer, 'Backs up to your Frameleaf account as its own computer.')}<span class="pill ok"><i aria-hidden="true"></i>Connected</span></div>
          <div class="row">{@render row(null, 'Disconnect', 'Stops backups and removes this computer from your account. What’s stored is kept, read-only, for 30 days.')}<button class="btn" disabled={busy} onclick={() => { sheet = 'disconnect'; }}>Disconnect…</button></div>
          <div class="row">{@render row(null, 'Delete this computer’s backups', 'Backups stop. What’s stored stays restorable for 30 days, then is deleted for good. Your photos’ Cloud Backup isn’t affected.')}<button class="btn danger" disabled={busy || !!view.purge} onclick={() => { sheet = 'delete'; }}>Delete Backups…</button></div>
        </div>
      </div>
      <div>
        <div class="group-head"><h2 class="group-title">Restore on a new computer</h2></div>
        <div class="group">
          <div class="row">{@render row('restart', 'Restore from a backup you already have', 'Bring another computer’s folders here, then carry on its backups.')}<button class="btn" onclick={openRestore}>Restore…</button></div>
        </div>
        <p class="foot">Install Frameleaf, choose Computer backup › Restore from a backup you already have, sign in and enter your recovery key.</p>
      </div>
    {:else}
      {#if status === 'warning'}
        <div class="inline-msg error" role="alert">
          <p>The last backup didn’t finish: <ErrorText text={explainError(view.problem)} /> The next backup carries on from where it got to.</p>
          <span class="sp"></span>
          <button class="btn small" disabled={busy} onclick={() => act(() => invoke('computer_backup_run_now'))}>Back Up Now</button>
        </div>
      {/if}
      {#if status === 'offline'}<div class="inline-msg" role="status"><p>This computer is offline. Backups carry on when it’s connected again.</p></div>{/if}
      {#if view.os === 'mac' && !view.fullDiskAccess}{@render fullDiskAccess()}{/if}
      <div>
        <div class="group">
          {#if view.running}
            {@const p = progress(view.running)}
            <div class="row top">
              {@render row('cloud', `Backing up · ${p.percent}%`, `${formatBytes(view.running.bytes)} of ${formatBytes(view.running.totalBytes)} · ${p.left}`)}
              <button class="btn" disabled={busy} onclick={() => act(() => invoke('computer_backup_stop'))}><Icon name="stop" />Stop</button>
            </div>
            <div class="row">
              <span class="progress" role="progressbar" aria-valuenow={p.percent} aria-valuemin="0" aria-valuemax="100" aria-label="Backup progress" style="flex:1"><span style="width:{p.percent}%"></span></span>
            </div>
          {:else}
            <div class="row">
              {@render row('check', view.lastSuccess ? `Last backup ${when(view.lastSuccess)}` : 'No backup yet', `${formatBytes(totals.bytes)} protected in ${totals.count} folders · next backup ${nextBackup(view.schedule, view.runs.find(run => run.kind === 'backup')?.at ?? null)}`)}
              <button class="btn" disabled={busy || status === 'offline'} onclick={() => act(() => invoke('computer_backup_run_now'))}>Back Up Now</button>
            </div>
          {/if}
          <div class="tile">
            <div><span>Protected</span><b>{formatBytes(totals.bytes)}</b><small>{totals.files.toLocaleString()} files</small></div>
            <div><span>This computer in Cloud</span><b>{view.usage ? formatBytes(view.usage[0]) : '—'}</b><small>after removing repeats</small></div>
            <div><span>Plan storage</span><b>{view.usage ? `${formatBytes(view.usage[1])} of ${formatBytes(view.usage[2])}` : '—'}</b><small>shared with your photos’ Cloud Backup</small></div>
          </div>
        </div>
      </div>
      <div>
        <div class="group-head"><h2 class="group-title">Folders</h2></div>
        <div class="group">
          {#each view.folders.filter(folder => folder.on) as folder (folder.id)}
            <div class="row">{@render row('folder', folder.name, folder.files !== null ? `${folder.files.toLocaleString()} files` : shownPath(folder.path, view.os))}<span class="muted">{folder.size !== null ? formatBytes(folder.size) : ''}</span></div>
          {/each}
          <div class="row"><span class="sp"></span><button class="btn quiet" onclick={() => { on = Object.fromEntries(view!.folders.map(f => [f.id, f.on])); tab = 'folders'; }}>Change Folders…</button></div>
        </div>
      </div>
      {#if view.runs.length}
        <div>
          <div class="group-head"><h2 class="group-title">Recent</h2></div>
          <div class="group">
            {#each view.runs.slice(0, 6) as run (run.at)}
              {@const line = runRow(run, code => explainError(code))}
              <div class="row">{@render row(null, line.title, line.detail)}<span class="pill {line.tone}"><i aria-hidden="true"></i>{line.label}</span></div>
            {/each}
          </div>
        </div>
      {/if}
    {/if}
  </div>
</section>

{#if sheet && view}
  <Sheet title={sheetTitle} {busy} onclose={() => { sheet = null; }} onsubmit={confirmSheet}>
    {#if sheet === 'restore'}
      <label class="check"><input type="radio" name="where" checked={where === 'original'} onchange={() => { where = 'original'; }} />Back where they were. A file already there is kept and renamed with today’s date.</label>
      <label class="check"><input type="radio" name="where" checked={where === 'other'} onchange={() => { where = 'other'; }} />Into another folder. Your folders aren’t touched.</label>
      <p class="muted">Nothing is deleted, and your backups aren’t changed.</p>
    {:else if sheet === 'delete'}
      <p>Backups stop now. What’s stored stays restorable for 30 days; until then, Keep My Backups calls it off. After that it’s deleted for good. Confirm with {ownerCheck(view.os)} to continue.</p>
    {:else if sheet === 'passphrase'}
      <p>The recovery key is locked with this passphrase on this computer before it’s sent. Frameleaf can’t open it, and can’t recover the passphrase.</p>
      <input type="password" aria-label="Passphrase" minlength="12" autocomplete="new-password" bind:value={passphrase} />
      <p class="muted">At least 12 characters.</p>
    {:else}
      <p>Backups stop and this computer is removed from your Frameleaf account. What’s stored is kept, read-only, for 30 days, and Frameleaf emails you before deleting it.</p>
    {/if}
    {#snippet actions()}
      <button class="btn" type="button" disabled={busy} onclick={() => { sheet = null; }}>Cancel</button>
      <button class="btn {sheet === 'restore' || sheet === 'passphrase' ? 'primary' : 'danger'}" type="submit" disabled={busy || (sheet === 'passphrase' && passphrase.length < 12)}>
        {sheet === 'restore' ? `Restore ${count} Item${count === 1 ? '' : 's'}` : sheet === 'delete' ? 'Delete Backups' : sheet === 'passphrase' ? 'Turn On' : 'Disconnect'}
      </button>
    {/snippet}
  </Sheet>
{/if}
