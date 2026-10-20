<script lang="ts">
  import { onMount } from 'svelte';
  import { invoke, isTauri } from '@tauri-apps/api/core';
  import { listen, type UnlistenFn } from '@tauri-apps/api/event';
  import { managerError, localProfilePending, profileSetupCopy, type ManagerView, type ManagerStatus, type Operation } from './manager-state';
  type Installation = { manifestSha256: string; controllerSha256: string };
  type InstalledPackage = Installation & { version?: string; epoch?: number; sourceRevision?: string; code?: string | null };
  type PendingUpdate = { operationId: string; fromManifestSha256: string; toManifestSha256: string; phase: string };
  type View = { pendingUpdate?: PendingUpdate | null; state: string; code: string | null; backgroundActive: boolean; profileSetupAvailable: boolean; profileRequiresAuthorization: boolean; origin: string | null; installation: Installation | null };
  let { onactive, onmanagerchange, onmaintenance }: { onactive: (active: boolean) => void; onmanagerchange: () => void; onmaintenance: (active: boolean) => void } = $props();
  const native = isTauri();
  let installations = $state<InstalledPackage[]>([]);
  let selected = $state('');
  let view = $state<View | null>(null);
  let busy = $state(false);
  let starting = $state(false);
  let statusChecked = $state(false);
  let updating = $state(false);
  let updateReviewed = $state(false);
  let updateTarget = $state('');
  let updateBackup = $state('');
  let updateBackups = $state<Operation[]>([]);
  let migrationsApproved = $state(false);
  let updateNeedsAuth = $state(false);
  let updatePassword = $state('');
  const updatePending = $derived(!!view?.pendingUpdate || view?.state === 'update-pending' || view?.state === 'updating');
  const currentPackage = $derived(installations.find(record => record.manifestSha256 === view?.installation?.manifestSha256));
  const updateTargets = $derived(installations.filter(record =>
    !record.code && !currentPackage?.code &&
    typeof record.epoch === 'number' && typeof currentPackage?.epoch === 'number' &&
    record.epoch > currentPackage.epoch
  ).sort((a, b) => b.epoch! - a.epoch!));
  $effect(() => { onmaintenance(updating || updatePending || !statusChecked); });
  let provisioning = $state(false);
  const profilePending = $derived(localProfilePending(view?.state, provisioning));
  const profileCopy = $derived(profileSetupCopy(view?.profileRequiresAuthorization !== false));
  let disposed = false;
  let failure = $state('');
  let notice = $state('');
  let managerPassword = $state('');
  let creatingAccount = $state(false);
  let administratorName = $state('');
  let managerPasswordConfirmation = $state('');
  let allowManagement = $state(false);
  let allowRecovery = $state(false);
  let allowUpdates = $state(false);
  let authorized = $state(false);
  function explain(code: unknown): string {
    const value = String(code);
    if (value === 'host_update_discovery_invalid') return 'The interrupted update record could not be verified. Keep your existing library and server profile. Repair the installed server components before continuing.';
    if (value === 'host_update_new_approval_required') return 'Cancel this interrupted update, then review and approve the update again.';
    if (value === 'host_update_cancel_unsafe') return 'This update has already been approved. Resume it to finish safely; cancellation is no longer available.';
    if (value.startsWith('host_update_') || value.startsWith('native_host_update_')) return 'The server update did not finish. Check installation and use the interrupted update controls before starting another action. Your original library has been preserved.';
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
    if (value.startsWith('host_controller_') || value.startsWith('host_recovery_') || value.startsWith('host_process_') || value === 'host_already_owned') return 'Stop the photo server in Manager before stopping local management. If its last shutdown was interrupted, recover it in Manager first.';
    if (value.startsWith('credential_')) return 'Unlock your computer’s secure credential store and try again.';
    if (value.startsWith('native_profile_')) return 'The existing library needs recovery. Its saved credentials and database were preserved.';
    return 'Local setup could not finish. Check the server installation and secure credential store, then retry.';
  }
  function show(value: View) {
    if (disposed) return;
    const ready = value.state === 'manager-ready' && view?.state !== 'manager-ready';
    if (value.state !== 'manager-ready') {
      authorized = false; creatingAccount = false;
      managerPassword = ''; managerPasswordConfirmation = '';
    }
    view = value; statusChecked = true; onactive(value.backgroundActive);
    if (ready) onmanagerchange();
  }
  async function refresh() {
    failure = ''; busy = true; statusChecked = false;
    try {
      const [records, status] = await Promise.allSettled([invoke<InstalledPackage[]>('installed_local_hosts'), invoke<View>('local_host_status')]);
      installations = records.status === 'fulfilled' ? records.value : [];
      if (status.status === 'rejected') throw status.reason;
      const current = status.value;
      show(current);
      const usable = installations.filter(record => !record.code);
      selected = current.installation?.manifestSha256 ?? (usable.length === 1 ? usable[0]!.manifestSha256 : '');
      if (current.code) failure = explain(current.code);
      else if (records.status === 'rejected') failure = explain(records.reason);
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
    if (busy || !native || !selected || !statusChecked || updatePending) return;
    busy = true; starting = true; onactive(true); failure = ''; notice = '';
    try { show(await invoke<View>('prepare_local_host', { manifestSha256: selected })); }
    catch (error) { failure = explain(error); const current = await invoke<View>('local_host_status').catch(() => null); if (current) show(current); }
    finally { busy = false; starting = false; }
  }
  async function authorize(event: SubmitEvent) {
    event.preventDefault();
    if (busy || !native || !allowManagement) return;
    if (creatingAccount && (!administratorName.trim() || managerPassword !== managerPasswordConfirmation)) return;
    const password = managerPassword;
    const name = creatingAccount ? administratorName.trim() : null;
    managerPassword = ''; managerPasswordConfirmation = '';
    busy = true; failure = ''; notice = '';
    try {
      await invoke('authorize_local_manager', { password, administratorName: name, allowManagement, allowRecovery, allowUpdates });
      creatingAccount = false; administratorName = '';
      allowUpdates = false; allowRecovery = false;
      authorized = true; onmanagerchange();
      notice = 'Local management is authorized. Use the server controls below to start your photo server.';
    } catch (error) {
      const code = error instanceof Error ? error.message : String(error);
      if (name !== null && code !== 'manager_account_details_invalid' && code !== 'manager_login_details_invalid') creatingAccount = false;
      failure = explain(error);
      const current = await invoke<View>('local_host_status').catch(() => null); if (current) show(current);
    } finally { busy = false; }
  }
  function chooseAccount(create: boolean) {
    creatingAccount = create;
    managerPassword = ''; managerPasswordConfirmation = ''; failure = ''; notice = '';
  }
  async function provisionProfile() {
    if (busy || !native || !selected || !statusChecked || updatePending) return;
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
    if (busy || !native || updatePending || !statusChecked) return;
    busy = true; failure = ''; notice = '';
    try { await invoke('open_local_photos'); }
    catch (error) { failure = String(error) === 'photo_window_unavailable' ? 'The Photos window could not open. Try again.' : explain(error); }
    finally { busy = false; }
  }
  async function cancel() {
    try { await invoke('cancel_local_host_start'); notice = updating ? 'Stopping after the current verification finishes. Check installation afterward to see whether recovery is needed.' : 'Cancelling local setup after the current verification finishes.'; }
    catch (error) { failure = explain(error); }
  }
  async function stop() {
    if (busy || !native || updatePending || !statusChecked) return;
    busy = true; failure = ''; notice = '';
    try { show(await invoke<View>('stop_local_host_manager')); }
    catch (error) { failure = explain(error); const current = await invoke<View>('local_host_status').catch(() => null); if (current) show(current); }
    finally { busy = false; }
  }
  async function reviewUpdate() {
    if (busy || !native || updatePending || !statusChecked || view?.state !== 'manager-ready') return;
    busy = true; failure = ''; notice = ''; updateReviewed = false; updateBackups = [];
    updateTarget = ''; updateBackup = ''; migrationsApproved = false; updateNeedsAuth = false; updatePassword = '';
    try {
      const manager = await invoke<ManagerView | null>('manager_view');
      if (!manager || manager.origin !== view.origin) throw 'manager_pairing_required';
      if (!manager.scopes.includes('update')) throw 'manager_update_approval_required';
      const status = await invoke<ManagerStatus>('manager_request', { command: { kind: 'status' } });
      if (status.operations.some(operation => operation.state !== 'complete')) throw 'manager_operation_in_progress';
      updateBackups = status.operations.filter(operation => operation.kind === 'backup' && operation.state === 'complete' && !operation.error);
      updateReviewed = true;
    } catch (error) { failure = explain(error); }
    finally { busy = false; }
  }
  async function changeServer(recover = false, cancelUpdate = false) {
    const pending = view?.pendingUpdate;
    if (busy || !native || !statusChecked) return;
    if (recover ? !pending : updatePending || !updateReviewed || !updateTarget || !updateBackup || !migrationsApproved) return;
    busy = true; updating = true; onactive(true); failure = ''; notice = ''; updateNeedsAuth = false; updatePassword = '';
    managerPassword = ''; managerPasswordConfirmation = '';
    try {
      const result = recover
        ? await invoke<View>('recover_local_host_update', { manifestSha256: pending!.toManifestSha256, cancelUpdate })
        : await invoke<View>('update_local_host', { manifestSha256: updateTarget, backupOperationId: updateBackup, migrationsApproved });
      show(result);
      const manager = await invoke<ManagerView | null>('manager_view').catch(() => null);
      authorized = !!manager && manager.origin === result.origin && manager.expiresAt > Date.now() && manager.scopes.includes('status');
      onmanagerchange();
      updateReviewed = false; updateBackups = []; updateBackup = ''; migrationsApproved = false;
      notice = cancelUpdate ? 'Interrupted update cancelled. Your original server is ready to manage.' : 'Server update completed. Start your server below when ready.';
    } catch (error) {
      failure = explain(error);
      updateNeedsAuth = !recover && String(error) === 'manager_recent_auth_required';
      const current = await invoke<View>('local_host_status').catch(() => null);
      if (current) show(current); else statusChecked = false;
    } finally { busy = false; updating = false; }
  }
  async function authorizeUpdate(event: SubmitEvent) {
    event.preventDefault();
    if (busy || !native || !updateNeedsAuth || !updatePassword) return;
    const password = updatePassword; updatePassword = ''; busy = true; failure = '';
    try { await invoke('reauthenticate_manager', { password }); }
    catch (error) { failure = explain(error); return; }
    finally { busy = false; }
    await changeServer();
  }

</script>

<section class="status-panel" aria-label="Local library setup" aria-busy={busy}>
  <h2>{updating ? 'Updating local server…' : updatePending ? 'An interrupted update needs attention' : profilePending ? 'Preparing your server profile…' : starting ? 'Preparing local management…' : busy ? 'Checking local management…' : view?.state === 'manager-ready' ? 'Local Manager is ready' : 'Run your library on this computer'}</h2>
  <p>Keep your photo library here and manage it from Frameleaf. Server management and photo-server startup are separate steps.</p>
  {#if failure}<p class="message error" role="alert">{failure}</p>{/if}
  {#if notice}<p class="message" role="status">{notice}</p>{/if}
  {#if installations.some(record => record.code)}<p role="status">An installed server package needs repair. It cannot be selected for an update. Your running server can still be managed.</p>{/if}
  {#if profilePending}<p role="status">{profileCopy.pending}</p>{/if}
  {#if statusChecked && !updatePending && view?.profileSetupAvailable && installations.length > 0 && !view.code?.startsWith('host_profile_legacy_') && (view.state === 'idle' || view.state === 'needs-attention')}
    <p>{profileCopy.preparation}</p>
    <button class="primary" disabled={busy || !native || !selected} onclick={provisionProfile}>Prepare my server profile</button>
  {/if}
  {#if native && !busy && !failure && installations.length === 0}
    <p>Install the Frameleaf server component, then check again. Your existing photo folders are kept separate.</p>
  {/if}
  {#if statusChecked && !updatePending && installations.length > 1 && !view?.backgroundActive}
    <label for="local-package">Installed server package</label>
    <select id="local-package" bind:value={selected} disabled={busy}>
      <option value="">Choose an installed package</option>
      {#each installations as installation}<option value={installation.manifestSha256} disabled={!!installation.code}>{installation.code ? 'Server package needs repair' : `Frameleaf ${installation.version} · package ${installation.epoch}`}</option>{/each}
    </select>
  {/if}
  {#if statusChecked && !updatePending && view?.state === 'manager-ready'}
    <p role="status">Management is listening at {view.origin}. The photo server has not been started by this setup step.</p>
    {#if authorized}
      <p>Start your server using the controls below, then open Photos. For a new library, Photos guides you through creating your first administrator. Your Photos account is separate from your Manager password.</p>
      <button class="primary" disabled={busy || !native} onclick={photos}>Open local Photos</button>
    {/if}
    {#if !authorized}
      <form aria-label="Local Manager authorization" onsubmit={authorize}>
        {#if creatingAccount}
          <p>Create the first administrator account for this local Manager. Your Photos account is separate.</p>
          <label for="local-manager-name">Administrator name</label>
          <input id="local-manager-name" type="text" bind:value={administratorName} required maxlength="120" disabled={busy || !native} autocomplete="username" />
        {:else}<p>Sign in with your existing Manager password.</p>{/if}
        <label for="local-manager-password">Local Manager password</label>
        <input id="local-manager-password" type="password" bind:value={managerPassword} required minlength="14" maxlength="256" disabled={busy || !native} autocomplete={creatingAccount ? 'new-password' : 'current-password'} />
        {#if creatingAccount}
          <label for="local-manager-password-confirmation">Confirm Manager password</label>
          <input id="local-manager-password-confirmation" type="password" bind:value={managerPasswordConfirmation} required minlength="14" maxlength="256" disabled={busy || !native} autocomplete="new-password" />
          {#if managerPasswordConfirmation && managerPassword !== managerPasswordConfirmation}<p class="message" role="status">The passwords do not match.</p>{/if}
        {/if}
        <label class="check"><input type="checkbox" bind:checked={allowManagement} required disabled={busy || !native} />Allow this computer to manage this local server.</label>
        <label class="check"><input type="checkbox" bind:checked={allowRecovery} disabled={busy || !native} />Also allow backup recovery reviews and restore operations.</label>
        <label class="check"><input type="checkbox" bind:checked={allowUpdates} disabled={busy || !native} />Also allow requests for server updates.</label>
        <button class="primary" disabled={busy || !native || !allowManagement || managerPassword.length < 14 || (creatingAccount && (!administratorName.trim() || managerPassword !== managerPasswordConfirmation))}>{creatingAccount ? 'Create account and authorize' : 'Authorize local management'}</button>
        <button class="text-button" type="button" disabled={busy || !native} onclick={() => chooseAccount(!creatingAccount)}>{creatingAccount ? 'I already have a Manager account' : 'Create a local Manager account'}</button>
        <p class="footnote">Keep this password for recovery. The app saves a separate management grant in your secure credential store. Authorizing again keeps existing permissions. Disconnect Manager and pair again to change them.</p>
      </form>
    {/if}
  {/if}
  {#if updatePending}
    <p role="status">Your existing library is preserved. Finish this interrupted update before starting the server or preparing another profile.</p>
    {#if view?.pendingUpdate}
      {#if view.pendingUpdate.phase === 'approvalConsumed'}
        <p>The update was approved. Resume it to finish verification; the photo server stays stopped.</p>
        <button class="primary" disabled={busy || !native} onclick={() => changeServer(true)}>Resume interrupted update</button>
      {:else if ['reserved', 'preparingCredentials', 'credentialsPrepared'].includes(view.pendingUpdate.phase)}
        <p>This update did not reach approval. Cancel it, then review and approve a new update.</p>
        <button class="secondary" disabled={busy || !native} onclick={() => changeServer(true, true)}>Cancel interrupted update</button>
      {:else}<p>Check the installed server components before continuing. This update state cannot be resumed from this window.</p>{/if}
    {/if}
  {:else if statusChecked && view?.state === 'manager-ready' && updateTargets.length > 0}
    <h3>Update this server</h3>
    <p>Stop the photo server and create a database backup using the controls below first. Updating requires server update permission. Photos and videos are kept in their existing folders.</p>
    <button class="secondary" disabled={busy || !native} onclick={reviewUpdate}>Review server update</button>
    {#if updateReviewed}
      <label for="update-package">Server package for update</label>
      <select id="update-package" bind:value={updateTarget} disabled={busy}>
        <option value="">Choose an installed server package</option>
        {#each updateTargets as installation}<option value={installation.manifestSha256}>Frameleaf {installation.version} · package {installation.epoch}</option>{/each}
      </select>
      <label for="update-backup">Completed database backup</label>
      <select id="update-backup" bind:value={updateBackup} disabled={busy}>
        <option value="">Choose a completed database backup</option>
        {#each updateBackups as backup}<option value={backup.id}>{new Date(backup.updatedAt).toLocaleString()}</option>{/each}
      </select>
      {#if updateBackups.length === 0}<p>Create a database backup below, then review the update again.</p>{/if}
      <label class="check"><input type="checkbox" bind:checked={migrationsApproved} disabled={busy} />I approve this server update and its database migrations.</label>
      {#if updateNeedsAuth}
        <form aria-label="Authorize server update" onsubmit={authorizeUpdate}>
          <label for="update-password">Manager password for update</label>
          <input id="update-password" type="password" bind:value={updatePassword} required maxlength="256" autocomplete="current-password" disabled={busy} />
          <button class="primary" disabled={busy || !updatePassword}>Authorize update</button>
        </form>
      {:else}<button class="primary" disabled={busy || !native || !updateTarget || !updateBackup || !migrationsApproved} onclick={() => changeServer()}>Update local server</button>{/if}
    {/if}
  {/if}
  <div class="actions">
    {#if statusChecked && !updatePending && (!view?.backgroundActive || view?.state === 'needs-attention')}<button class="primary" disabled={busy || !native || !selected} onclick={prepare}>Prepare local Manager</button>{/if}
    {#if updating}<button class="secondary" disabled={!native} onclick={cancel}>Stop after current step</button>{/if}
    {#if starting}<button class="secondary" disabled={!native} onclick={cancel}>Cancel setup</button>{/if}
    {#if statusChecked && !updatePending && view?.backgroundActive && !profilePending}<button class="secondary" disabled={busy || !native} onclick={stop}>Stop local management</button>{/if}
    <button class="text-button" disabled={busy || !native} onclick={refresh}>Check installation</button>
  </div>
  <p class="footnote">{profilePending ? profileCopy.quit : 'Closing the window keeps explicitly started local management running. Stopping local management preserves your library and saved credentials.'}</p>
</section>

<style>
  section > label:not(.check) { display: block; font-size: 13px; font-weight: 600; margin: 18px 0 7px; }
  select { width: 100%; min-width: 0; padding: 10px; border: 1px solid var(--border); border-radius: 7px; background: var(--panel); color: var(--text); font: inherit; }
  .check { display: flex; align-items: flex-start; gap: 10px; line-height: 1.55; margin: 18px 0; }
  .check input { flex: 0 0 16px; width: 16px; height: 16px; padding: 0; margin: 3px 0 0; accent-color: var(--accent); }
</style>
