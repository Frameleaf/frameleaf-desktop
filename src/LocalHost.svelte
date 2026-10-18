<script lang="ts">
  import { onMount } from 'svelte';
  import { invoke, isTauri } from '@tauri-apps/api/core';
  import { listen, type UnlistenFn } from '@tauri-apps/api/event';
  import { managerError, localProfilePending } from './manager-state';
  type Installation = { manifestSha256: string; controllerSha256: string };
  type View = { state: string; code: string | null; backgroundActive: boolean; profileSetupAvailable: boolean; origin: string | null; installation: Installation | null };
  let { onactive, onmanagerchange }: { onactive: (active: boolean) => void; onmanagerchange: () => void } = $props();
  const native = isTauri();
  let installations = $state<Installation[]>([]);
  let selected = $state('');
  let view = $state<View | null>(null);
  let busy = $state(false);
  let starting = $state(false);
  let provisioning = $state(false);
  const profilePending = $derived(localProfilePending(view?.state, provisioning));
  let disposed = false;
  let failure = $state('');
  let notice = $state('');
  let managerPassword = $state('');
  let allowManagement = $state(false);
  let allowRecovery = $state(false);
  let authorized = $state(false);
  function explain(code: unknown): string {
    const value = String(code);
    if (value.startsWith('manager_') || value === 'native_manager_not_ready' || value === 'native_host_busy') return managerError(value);
    if (value === 'host_install_platform_unsupported') return 'Native server installation is not available on this platform in this build. You can connect to an existing server.';
    if (value === 'host_install_profile_required') return 'Run the server component installer while signed in to this computer, then try again.';
    if (value === 'host_install_linux_profile_required') return 'Prepare a private server profile for your account before starting local management.';
    if (value === 'host_profile_authorization_cancelled') return 'System authorization was cancelled. You can try again.';
    if (value === 'host_profile_authorization_unavailable') return 'System authorization is unavailable. Check your desktop’s authorization service, then try again.';
    if (value === 'host_profile_prepare_failed') return 'The server profile could not be prepared. Check that your installed Frameleaf components are up to date. Your existing library has been preserved.';
    if (value === 'host_package_maintenance' || value === 'host_package_busy') return 'Server component maintenance is unfinished or the component is in use. Local management is unavailable until maintenance completes.';
    if (value.startsWith('host_package_')) return 'The server component installation could not be verified. Local management is blocked; your existing library has been preserved.';
    if (value === 'native_manager_start_cancelled') return 'Local setup was cancelled.';
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
      selected = current.installation?.manifestSha256 ?? (records.length === 1 ? records[0]!.manifestSha256 : '');
      if (current.code) failure = explain(current.code);
    } catch (error) { failure = explain(error); }
    finally { busy = false; }
  }
  onMount(() => {
    if (!native) return;
    let unlisten: UnlistenFn | undefined;
    void listen('native-host-exit-blocked', () => { notice = profilePending ? 'Finish or dismiss the system authorization request before quitting.' : 'Stop the photo server in Manager, then stop local management before quitting. Closing this window keeps local management running.'; }).then(stop => { if (disposed) stop(); else unlisten = stop; }).catch(() => { notice = 'Use Stop local management before quitting this app.'; });
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

<section class="status-panel" aria-label="Local library setup" aria-busy={busy}>
  <h2>{profilePending ? 'Preparing your server profile…' : starting ? 'Preparing local management…' : busy ? 'Checking local management…' : view?.state === 'manager-ready' ? 'Local Manager is ready' : 'Run your library on this computer'}</h2>
  <p>Keep your photo library here and manage it from Frameleaf. Server management and photo-server startup are separate steps.</p>
  {#if failure}<p class="message error" role="alert">{failure}</p>{/if}
  {#if notice}<p class="message" role="status">{notice}</p>{/if}
  {#if profilePending}<p role="status">Finish or dismiss the system authorization request, then check installation to continue.</p>{/if}
  {#if (view?.profileSetupAvailable && installations.length > 0 && (view.state === 'idle' || view.state === 'needs-attention')) || view?.code === 'host_install_linux_profile_required' || view?.code?.startsWith('host_profile_')}
    <p>Your system may ask for administrator authorization to create private server folders for your account. Frameleaf does not receive your administrator password. This step does not start the photo server.</p>
    <button class="primary" disabled={busy || !native || !selected} onclick={provisionProfile}>Prepare my server profile</button>
  {/if}
  {#if native && !busy && !failure && installations.length === 0}
    <p>Install the Frameleaf server component, then check again. Your existing photo folders are kept separate.</p>
  {/if}
  {#if installations.length > 1 && !view?.backgroundActive}
    <label for="local-package">Installed server package</label>
    <select id="local-package" bind:value={selected} disabled={busy}>
      <option value="">Choose an installed package</option>
      {#each installations as installation}<option value={installation.manifestSha256}>Package {installation.manifestSha256.slice(0, 12)}</option>{/each}
    </select>
  {/if}
  {#if view?.state === 'manager-ready'}
    <p role="status">Management is listening at {view.origin}. The photo server has not been started by this setup step.</p>
    {#if authorized}
      <p>Start your server using the controls below, then open Photos. For a new library, Photos guides you through creating your first administrator. Your Photos account is separate from your Manager password.</p>
      <button class="primary" disabled={busy || !native} onclick={photos}>Open local Photos</button>
    {/if}
    {#if !authorized}
      <form aria-label="Local Manager authorization" onsubmit={authorize}>
        <p>For a new library, choose a Manager password. If you have already set one, use that password.</p>
        <label for="local-manager-password">Local Manager password</label>
        <input id="local-manager-password" type="password" bind:value={managerPassword} required minlength="14" maxlength="256" disabled={busy || !native} autocomplete="current-password" />
        <label class="check"><input type="checkbox" bind:checked={allowManagement} required disabled={busy || !native} />Allow this computer to manage this local server.</label>
        <label class="check"><input type="checkbox" bind:checked={allowRecovery} disabled={busy || !native} />Also allow backup recovery reviews and restore operations.</label>
        <button class="primary" disabled={busy || !native || !allowManagement || managerPassword.length < 14}>Authorize local management</button>
        <p class="footnote">Keep this password for recovery. The app saves a separate management grant in your secure credential store.</p>
      </form>
    {/if}
  {/if}
  <div class="actions">
    {#if !view?.backgroundActive || view?.state === 'needs-attention'}<button class="primary" disabled={busy || !native || !selected} onclick={prepare}>Prepare local Manager</button>{/if}
    {#if starting}<button class="secondary" disabled={!native} onclick={cancel}>Cancel setup</button>{/if}
    {#if view?.backgroundActive && !profilePending}<button class="secondary" disabled={busy || !native} onclick={stop}>Stop local management</button>{/if}
    <button class="text-button" disabled={busy || !native} onclick={refresh}>Check installation</button>
  </div>
  <p class="footnote">{profilePending ? 'Finish or dismiss the system authorization request before quitting.' : 'Closing the window keeps explicitly started local management running. Stopping local management preserves your library and saved credentials.'}</p>
</section>

<style>
  .check { display: flex; align-items: flex-start; gap: 10px; line-height: 1.55; margin: 18px 0; }
  .check input { flex: 0 0 16px; width: 16px; height: 16px; padding: 0; margin: 3px 0 0; accent-color: var(--accent); }
</style>
