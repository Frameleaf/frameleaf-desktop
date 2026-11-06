<script lang="ts">
  import { onMount } from 'svelte';
  import { invoke, isTauri } from '@tauri-apps/api/core';
  import { listen, type UnlistenFn } from '@tauri-apps/api/event';
  import { managerError, localProfilePending, profileSetupCopy } from './manager-state';
  import Icon from './Icon.svelte';
  type Installation = { manifestSha256: string; controllerSha256: string; version?: string | null; library?: boolean };
  type View = { state: string; code: string | null; backgroundActive: boolean; profileSetupAvailable: boolean; profileRequiresAuthorization: boolean; origin: string | null; installation: Installation | null };
  let { onactive, onmanagerchange }: { onactive: (active: boolean) => void; onmanagerchange: () => void } = $props();
  const native = isTauri();
  let installations = $state<Installation[]>([]);
  let selected = $state('');
  let view = $state<View | null>(null);
  let busy = $state(false);
  let starting = $state(false);
  let provisioning = $state(false);
  const profilePending = $derived(localProfilePending(view?.state, provisioning));
  const profileCopy = $derived(profileSetupCopy(view?.profileRequiresAuthorization !== false));
  let disposed = false;
  let failure = $state('');
  let notice = $state('');
  let managerPassword = $state('');
  let allowManagement = $state(false);
  let allowRecovery = $state(false);
  let authorized = $state(false);
  const headline = $derived(profilePending ? 'Preparing your server profile…' : starting ? 'Preparing local management…' : busy ? 'Checking local management…' : view?.state === 'manager-ready' ? 'Local Manager is ready' : 'Run your library on this computer');
  const pill = $derived(view?.state === 'manager-ready' ? { label: authorized ? 'Authorized' : 'Ready', tone: 'ok' } : profilePending || starting || busy ? { label: 'Working', tone: 'wait' } : view?.state === 'needs-attention' ? { label: 'Needs attention', tone: 'bad' } : view?.backgroundActive ? { label: 'Active', tone: 'wait' } : { label: 'Not started', tone: 'off' });
  function explain(code: unknown): string {
    const value = String(code);
    if (value.startsWith('manager_') || value === 'native_manager_not_ready' || value === 'native_host_busy') return managerError(value);
    if (value === 'host_install_platform_unsupported') return 'Native server installation is not available on this platform in this build. You can connect to an existing server.';
    if (value === 'host_install_profile_required') return 'Run the server component installer while signed in to this computer, then try again.';
    if (value === 'host_install_linux_profile_required' || value === 'host_install_windows_profile_required') return 'Prepare a private server profile for your account before starting local management.';
    if (value.startsWith('host_profile_legacy_')) return 'An existing server profile must be migrated before setup can continue. Your library and saved credentials have been preserved.';
    if (value === 'host_profile_authorization_cancelled') return 'System authorization was cancelled. You can try again.';
    if (value === 'host_profile_authorization_unavailable') return 'System authorization is unavailable. Check your desktop’s authorization service, then try again.';
    if (value === 'host_profile_prepare_failed') return 'The server profile could not be prepared. Check that your installed Frameleaf components are up to date. Your existing library has been preserved.';
    if (value === 'host_package_maintenance' || value === 'host_package_busy') return 'Server component maintenance is unfinished or the component is in use. Local management is unavailable until maintenance completes.';
    if (value.startsWith('host_package_')) return 'The server component installation could not be verified. Local management is blocked; your existing library has been preserved.';
    if (value === 'native_manager_start_cancelled') return 'Local setup was cancelled.';
    if (value === 'host_upgrade_downgrade_refused') return 'This library already uses a newer server package. Choose that package to continue.';
    if (value === 'host_upgrade_previous_package_missing') return 'Keep the server package this library last used installed until it has started once with the new package, then try again.';
    if (value === 'host_restore_activation_pending') return 'A restore is waiting to finish with the package this library last used. Finish it in Manager with that package, then try the new package again.';
    if (value === 'host_upgrade_operation_pending') return 'Finish or discard the unfinished backup or restore with the package this library last used, then try the new package again.';
    if (value === 'host_update_requires_manager') return 'This library’s server package record does not match the selected package. If a move to a newer package was interrupted, start it with that newer package to finish. Your library has been preserved.';
    if (value.startsWith('host_controller_') || value.startsWith('host_recovery_') || value.startsWith('host_process_') || value === 'host_already_owned') return 'Stop the photo server in Manager before stopping local management. If its last shutdown was interrupted, recover it in Manager first.';
    if (value.startsWith('credential_')) return 'Unlock your computer’s secure credential store and try again.';
    if (value.startsWith('native_profile_')) return 'The existing library needs recovery. Its saved credentials and database were preserved.';
    return 'Local setup could not finish. Check the server installation and secure credential store, then retry.';
  }
  function show(value: View) {
    if (disposed) return;
    const ready = value.state === 'manager-ready' && view?.state !== 'manager-ready';
    if (value.state !== 'manager-ready') authorized = false;
    view = value; onactive(value.backgroundActive);
    if (ready) onmanagerchange();
  }
  async function refresh() {
    failure = ''; busy = true;
    try {
      const [records, current] = await Promise.all([invoke<Installation[]>('installed_local_hosts'), invoke<View>('local_host_status')]);
      installations = records; show(current);
      selected = current.installation?.manifestSha256 ?? records.find(record => record.library)?.manifestSha256 ?? (records.length === 1 ? records[0]!.manifestSha256 : '');
      if (current.code) failure = explain(current.code);
    } catch (error) { failure = explain(error); }
    finally { busy = false; }
  }
  onMount(() => {
    if (!native) return;
    let unlisten: UnlistenFn | undefined;
    void listen('native-host-exit-blocked', () => { notice = profilePending ? profileCopy.quit : 'Stop the photo server in Manager, then stop local management before quitting. Closing this window keeps local management running.'; }).then(stop => { if (disposed) stop(); else unlisten = stop; }).catch(() => { notice = 'Use Stop local management before quitting this app.'; });
    void refresh();
    return () => { disposed = true; unlisten?.(); };
  });
  async function prepare() {
    if (busy || !native || !selected) return;
    busy = true; starting = true; onactive(true); failure = ''; notice = '';
    try { show(await invoke<View>('prepare_local_host', { manifestSha256: selected })); }
    catch (error) { failure = explain(error); const current = await invoke<View>('local_host_status').catch(() => null); if (current) show(current); }
    finally { busy = false; starting = false; }
  }
  async function authorize(event: SubmitEvent) {
    event.preventDefault();
    if (busy || !native || !allowManagement) return;
    const password = managerPassword; managerPassword = '';
    busy = true; failure = ''; notice = '';
    try {
      await invoke('authorize_local_manager', { password, allowManagement, allowRecovery });
      authorized = true; onmanagerchange();
      notice = 'Local management is authorized. Use the server controls below to start your photo server.';
    } catch (error) {
      failure = explain(error);
      const current = await invoke<View>('local_host_status').catch(() => null); if (current) show(current);
    } finally { busy = false; }
  }
  async function provisionProfile() {
    if (busy || !native || !selected) return;
    busy = true; provisioning = true; onactive(true); failure = ''; notice = '';
    try {
      show(await invoke<View>('provision_local_host_profile', { manifestSha256: selected }));
      notice = 'Your private server profile is ready. Check installation to continue.';
    } catch (error) {
      failure = explain(error);
      const current = await invoke<View>('local_host_status').catch(() => null); if (current) show(current);
    } finally { busy = false; provisioning = false; }
  }
  async function photos() {
    busy = true; failure = ''; notice = '';
    try { await invoke('open_local_photos'); }
    catch (error) { failure = String(error) === 'photo_window_unavailable' ? 'The Photos window could not open. Try again.' : explain(error); }
    finally { busy = false; }
  }
  async function cancel() {
    try { await invoke('cancel_local_host_start'); notice = 'Cancelling local setup after the current verification finishes.'; }
    catch (error) { failure = explain(error); }
  }
  async function stop() {
    busy = true; failure = ''; notice = '';
    try { show(await invoke<View>('stop_local_host_manager')); }
    catch (error) { failure = explain(error); const current = await invoke<View>('local_host_status').catch(() => null); if (current) show(current); }
    finally { busy = false; }
  }
</script>

<div aria-label="Local library setup" aria-busy={busy}>
  <div class="group-head">
    <h2 class="group-title">Run Frameleaf here</h2>
    {#if starting}<button class="btn quiet" disabled={!native} onclick={cancel}>Cancel setup</button>{/if}
    <button class="btn quiet" disabled={busy || !native} onclick={refresh}>Check installation</button>
  </div>
  <div class="group">
    <div class="row">
      <span class="ic" aria-hidden="true"><Icon name="computer" /></span>
      <span class="l"><b>{headline}</b><small>Keep your photo library here and manage it from Frameleaf. Server management and photo-server startup are separate steps.</small></span>
      <span class="pill {pill.tone}"><i aria-hidden="true"></i>{pill.label}</span>
      {#if !view?.backgroundActive || view?.state === 'needs-attention'}<button class="btn primary" disabled={busy || !native || !selected} onclick={prepare}>Prepare local Manager</button>{/if}
      {#if view?.backgroundActive && !profilePending}<button class="btn" disabled={busy || !native} onclick={stop}>Stop local management</button>{/if}
    </div>
    {#if failure}<div class="row"><p class="danger-text" role="alert" style="flex:1">{failure}</p></div>{/if}
    {#if notice}<div class="row"><p role="status" style="flex:1">{notice}</p></div>{/if}
    {#if profilePending}<div class="row"><span class="spin" aria-hidden="true"></span><p role="status" style="flex:1">{profileCopy.pending}</p></div>{/if}
    {#if view?.profileSetupAvailable && installations.length > 0 && !view.code?.startsWith('host_profile_legacy_') && (view.state === 'idle' || view.state === 'needs-attention')}
      <div class="row"><span class="l"><b>Prepare my server profile</b><small>{profileCopy.preparation}</small></span><button class="btn primary" disabled={busy || !native || !selected} onclick={provisionProfile}>Prepare Profile</button></div>
    {/if}
    {#if native && view && !busy && !failure && installations.length === 0}
      <div class="row"><span class="ic dim" aria-hidden="true"><Icon name="warn" /></span><span class="l"><b>Server component not installed</b><small>Install the Frameleaf server component, then check again. Your existing photo folders are kept separate.</small></span></div>
    {/if}
    {#if installations.length > 1 && !view?.backgroundActive}
      <div class="form-row"><label for="local-package">Installed server package</label>
        <select id="local-package" bind:value={selected} disabled={busy}>
          <option value="">Choose an installed package</option>
          {#each installations as installation (installation.manifestSha256)}<option value={installation.manifestSha256}>Library {installation.version ?? 'version unknown'}{installation.library ? ' (this library)' : ''} · {installation.manifestSha256.slice(0, 12)}</option>{/each}
        </select>
      </div>
      <small>Starting your library with a newer package moves it to that package. It cannot go back to an older one afterwards.</small>
    {/if}
    {#if view?.state === 'manager-ready'}
      <div class="row">
        <span class="ic" aria-hidden="true"><Icon name="server" /></span>
        <span class="l"><b>Management is listening at {view.origin}</b><small role="status">{authorized ? 'Start your server using the controls below, then open Photos. For a new library, Photos guides you through creating your first administrator. Your Photos account is separate from your Manager password.' : 'The photo server has not been started by this setup step.'}</small></span>
        {#if authorized}<button class="btn primary" disabled={busy || !native} onclick={photos}><Icon name="open" />Open local Photos</button>{/if}
      </div>
      {#if !authorized}
        <form aria-label="Local Manager authorization" onsubmit={authorize}>
          <div class="form-row"><label for="local-manager-password">Local Manager password</label><span>
            <input id="local-manager-password" type="password" bind:value={managerPassword} required minlength="14" maxlength="256" disabled={busy || !native} autocomplete="current-password" />
            <p class="hint">For a new library, choose a Manager password of at least 14 characters. If you have already set one, use that password.</p>
          </span></div>
          <div class="form-row top"><label for="local-allow">Permissions</label><span>
            <label class="check"><input id="local-allow" type="checkbox" bind:checked={allowManagement} required disabled={busy || !native} />Allow this computer to manage this local server.</label>
            <label class="check" style="margin-top:8px"><input type="checkbox" bind:checked={allowRecovery} disabled={busy || !native} />Also allow backup recovery reviews and restore operations.</label>
          </span></div>
          <div class="form-row"><span></span><span class="actions"><button class="btn primary" disabled={busy || !native || !allowManagement || managerPassword.length < 14}>Authorize local management</button></span></div>
        </form>
      {/if}
    {/if}
  </div>
  <p class="foot">{profilePending ? profileCopy.quit : 'Closing the window keeps explicitly started local management running. Stopping local management preserves your library and saved credentials.'}{view?.state === 'manager-ready' && !authorized ? ' Keep this password for recovery. The app saves a separate management grant in your secure credential store.' : ''}</p>
</div>
