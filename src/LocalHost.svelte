<script lang="ts">
  import { onMount, tick } from 'svelte';
  import { invoke, isTauri } from '@tauri-apps/api/core';
  import { listen, type UnlistenFn } from '@tauri-apps/api/event';
  import { managerError, localProfilePending, profileSetupCopy } from './manager-state';
  import Icon from './Icon.svelte';
  import { explainError } from './errors';
  import ErrorText from './ErrorText.svelte';
  import Sheet from './Sheet.svelte';
  type Compatibility = 'checking' | 'verified' | 'unknown' | 'refused' | 'outdated';
  const outdatedCompanion = 'This companion package does not match this version of Frameleaf. Install the companion for this version, then choose Check installation. Your library has not been changed.';
  const compatibilityCopy = {
    checking: { label: 'Checking companion package…', detail: 'This can take a moment.' },
    verified: { label: 'Companion package verified', detail: 'This package passed the checks for this version of Frameleaf.' },
    unknown: { label: 'Compatibility unknown', detail: 'Frameleaf could not finish checking this package. Choose Check installation to retry.' },
    refused: { label: 'Companion package refused', detail: 'This package did not pass verification. Choose a different installed package or install a compatible companion.' },
    outdated: { label: 'Companion update needed', detail: outdatedCompanion },
  };
  type Installation = { manifestSha256: string; controllerSha256: string; version?: string | null; library?: boolean };
  const companionInstructions = {
    mac: 'Download and open the Frameleaf Companion Server PKG for Apple silicon.',
    windows: 'Download and run the Frameleaf Companion Server EXE for Windows x64.',
    linux: 'On Ubuntu 24.04 for Intel or AMD, install both Frameleaf Companion Server DEBs (bootstrap and runtime) together, with pkexec.',
  };
  // Moving a library to a companion whose database is newer: one copy made by the earlier companion, restored by the new one.
  type Carry = { available: boolean; code: string | null; stage: 'permitted' | 'exported' | 'restored' | 'switched' | 'confirmed' | null; previousPostgres: string | null; nextPostgres: string | null; requiredBytes: number | null; availableBytes: number | null; room: 'enough' | 'short' | 'unknown' | null; previousDatabase: string | null; keepUntil: number | null };
  const carrySteps = [['export', 'Copying the database with the earlier companion'], ['restore', 'Building the new database'], ['verify', 'Checking the new database against the original'], ['switch', 'Switching your library to the new database']] as const;
  const gigabytes = (bytes: number | null) => bytes === null ? 'an unknown amount' : `${(bytes / 1e9).toFixed(1)} GB`;
  type View = { carryStep?: string | null; companionPlatform?: keyof typeof companionInstructions | null; state: string; code: string | null; backgroundActive: boolean; leaveAvailable?: boolean; certificateExpiresInDays?: number | null; certificateRenewable?: boolean; profileSetupAvailable: boolean; profileRequiresAuthorization: boolean; origin: string | null; installation: Installation | null };
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
  let quitOffered = $state(false);
  // What the stop and quit controls are about, read out with them: the failure, else the notice.
  const describedBy = $derived(failure ? 'local-host-failure' : notice ? 'local-host-notice' : undefined);
  let managerPassword = $state('');
  let allowManagement = $state(false);
  let allowRecovery = $state(false);
  let authorized = $state(false);
  let packageChange = $state<Installation | null>(null);
  let carry = $state<Carry | null>(null);
  let carryReview = $state(false);
  let carrying = $state(false);
  let carryRequest = 0;
  let compatibility = $state<{ manifestSha256: string; controllerSha256: string; state: Compatibility } | null>(null);
  let checkRequest = 0;
  const libraryPackage = $derived(installations.find(record => record.library));
  const selectedPackage = $derived(installations.find(record => record.manifestSha256 === selected));
  const packageCheck = $derived(compatibility?.manifestSha256 === selectedPackage?.manifestSha256
    && compatibility?.controllerSha256 === selectedPackage?.controllerSha256 ? compatibility?.state : undefined);
  const checking = $derived(packageCheck === 'checking');
  const packageVerified = $derived(packageCheck === 'verified');
  const profileRequired = $derived(view?.code === 'host_install_windows_profile_required' || view?.code === 'host_install_linux_profile_required');
  const needsProfile = $derived(!!view?.profileSetupAvailable && !view.backgroundActive && (
    profileRequired || (!libraryPackage && view.state === 'idle' && !view.installation) ||
    (view.state === 'needs-attention' && (view.code === 'host_profile_prepare_failed' || view.code?.startsWith('host_profile_authorization_')))
  ));
  const changingPackage = $derived(!!libraryPackage && !!selectedPackage && selected !== libraryPackage.manifestSha256);
  const canMovePackage = $derived(view?.companionPlatform === 'mac' || view?.companionPlatform === 'linux');
  // Offered only when the backend names both database versions: otherwise the ordinary package change applies.
  const carryOffered = $derived(!!carry?.previousPostgres && !!carry.nextPostgres && !carry.previousDatabase && canMovePackage && changingPackage);
  const carryStepIndex = $derived(carrySteps.findIndex(([name]) => name === view?.carryStep));
  const headline = $derived(carrying ? 'Moving your library to the new database…' : profilePending ? 'Preparing your server profile…' : starting ? 'Preparing local management…' : busy ? 'Checking local management…' : view?.state === 'manager-ready' ? 'Local Manager is ready' : 'Run your library on this computer');
  const pill = $derived(view?.state === 'manager-ready' ? { label: authorized ? 'Authorized' : 'Ready', tone: 'ok' } : profilePending || starting || busy ? { label: 'Working', tone: 'wait' } : view?.state === 'needs-attention' ? { label: 'Needs attention', tone: 'bad' } : view?.backgroundActive ? { label: 'Active', tone: 'wait' } : { label: 'Not started', tone: 'off' });
  function explain(code: unknown): string {
    const value = String(code);
    if (value.startsWith('manager_') || value === 'native_manager_not_ready' || value === 'native_host_busy') return managerError(value);
    // Wording for codes that mean something narrower on this screen than their shared copy in errors.ts
    // says: the busy port is one this library needs and the library is known to be untouched, a companion
    // built for another version is fixed by installing the right one, and every credential-store failure
    // here has the same remedy. Every other code takes the shared copy.
    const port = /^local_port_in_use_(\d+)$/.exec(value);
    if (port) return `Another program on this computer is using port ${port[1]}, which your library needs. Close that program or change its port, then try again. Your library has not been changed.`;
    if (value === 'host_manifest_incompatible') return outdatedCompanion;
    if (value.startsWith('credential_')) return 'Unlock your computer’s secure credential store and try again.';
    return explainError(value, 'Local setup could not finish. Check the server installation and secure credential store, then retry.');
  }
  // Where keyboard and screen-reader focus goes when the control that had it is replaced by a new state.
  let title = $state<HTMLElement>();
  let quitButton = $state<HTMLButtonElement>();
  let leaveButton = $state<HTMLButtonElement>();
  function focusOn(target: () => HTMLElement | null | undefined) {
    void tick().then(() => { if (!disposed) (target() ?? title)?.focus(); });
  }
  function show(value: View) {
    if (disposed) return;
    const ready = value.state === 'manager-ready' && view?.state !== 'manager-ready';
    if (value.state !== 'manager-ready') authorized = false;
    view = value; onactive(value.backgroundActive);
    if (!value.backgroundActive) quitOffered = false;
    if (ready) onmanagerchange();
  }
  async function checkSelected() {
    const record = selectedPackage;
    const request = ++checkRequest;
    compatibility = null;
    if (!native || !record || (view?.backgroundActive && view.state !== 'needs-attention')) return;
    const { manifestSha256, controllerSha256 } = record;
    compatibility = { manifestSha256, controllerSha256, state: 'checking' };
    const result = await invoke<Compatibility>('check_local_host_package', { manifestSha256, controllerSha256 }).catch(() => 'unknown');
    if (disposed || checkRequest !== request) return;
    compatibility = { manifestSha256, controllerSha256, state: result === 'verified' || result === 'refused' || result === 'outdated' ? result : 'unknown' };
    if (result === 'verified') await checkCarry(manifestSha256);
  }
  async function checkCarry(manifestSha256: string) {
    const request = ++carryRequest;
    carry = null;
    const result = await invoke<Carry>('local_host_carry_status', { manifestSha256 }).catch(() => null);
    if (!disposed && carryRequest === request && selected === manifestSha256) carry = result;
  }
  async function moveLibrary() {
    if (busy || !native || !selectedPackage || !carry?.available) return;
    carryReview = false; busy = true; carrying = true; onactive(true); failure = ''; notice = '';
    const manifestSha256 = selected;
    const watch = setInterval(() => { void invoke<View>('local_host_status').then(current => { if (carrying) show(current); }).catch(() => {}); }, 1000);
    try {
      show(await invoke<View>('carry_local_host_library', { manifestSha256 }));
      notice = 'Your library has been moved to the new database. Choose Prepare local Manager to start it.';
    } catch (error) {
      failure = explain(error);
      const current = await invoke<View>('local_host_status').catch(() => null); if (current) show(current);
    } finally {
      clearInterval(watch); busy = false; carrying = false;
      installations = await invoke<Installation[]>('installed_local_hosts').catch(() => installations);
      await checkCarry(manifestSha256);
      focusOn(() => title);
    }
  }
  async function confirmCarry() {
    if (busy || !native || !selected) return;
    busy = true; failure = '';
    try { carry = await invoke<Carry>('confirm_local_host_carry', { manifestSha256: selected }); }
    catch (error) { failure = explain(error); }
    finally { busy = false; }
  }
  function selectPackage(event: Event & { currentTarget: HTMLSelectElement }) {
    selected = event.currentTarget.value;
    void checkSelected();
  }
  async function refresh() {
    if (busy || checking) return;
    failure = ''; busy = true; compatibility = null;
    try {
      const [records, current] = await Promise.all([invoke<Installation[]>('installed_local_hosts'), invoke<View>('local_host_status')]);
      installations = records; show(current);
      selected = records.find(record => record.manifestSha256 === current.installation?.manifestSha256)?.manifestSha256 ?? records.find(record => record.library)?.manifestSha256 ?? (records.length === 1 ? records[0]!.manifestSha256 : '');
      if (current.code) failure = explain(current.code);
      await checkSelected();
    } catch (error) { failure = explain(error); }
    finally { busy = false; }
  }
  onMount(() => {
    if (!native) return;
    let unlisten: UnlistenFn | undefined;
    void listen('native-host-exit-blocked', () => { quitOffered = !profilePending; if (quitOffered) focusOn(() => quitButton); notice = profilePending ? profileCopy.quit : 'Local management is still running. Choose Stop and quit to close it and leave Frameleaf. Closing this window keeps local management running.'; }).then(stop => { if (disposed) stop(); else unlisten = stop; }).catch(() => { notice = 'Use Stop local management before quitting this app.'; });
    void refresh();
    return () => { disposed = true; unlisten?.(); };
  });
  async function openDownloads() {
    failure = '';
    try { await invoke('open_external', { url: 'https://github.com/Frameleaf/frameleaf-desktop/releases' }); }
    catch { failure = 'The download page could not open. Try again.'; }
  }
  function prepareSelected() {
    if (busy || !selectedPackage || !packageVerified) return;
    if (changingPackage) {
      if (canMovePackage) packageChange = selectedPackage;
    } else void prepare();
  }
  function confirmPackageChange() {
    const target = packageChange;
    packageChange = null;
    if (canMovePackage && target?.manifestSha256 === selected) void prepare();
  }
  async function prepare() {
    if (busy || !native || !selectedPackage || !packageVerified) return;
    busy = true; starting = true; onactive(true); failure = ''; notice = '';
    try { show(await invoke<View>('prepare_local_host', { manifestSha256: selected })); focusOn(() => document.getElementById('local-manager-password')); }
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
    if (busy || !native || !selected || !packageVerified) return;
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
    catch (error) { failure = explain(error); }
    finally { busy = false; }
  }
  async function cancel() {
    try { await invoke('cancel_local_host_start'); notice = 'Cancelling local setup after the current verification finishes.'; }
    catch (error) { failure = explain(error); }
  }
  async function stop() {
    busy = true; failure = ''; notice = '';
    try {
      show(await invoke<View>('stop_local_host_manager'));
      // The Stop button is gone with the state it stopped.
      if (!view?.backgroundActive) focusOn(() => title);
      if (!packageVerified) await checkSelected();
    }
    catch (error) { failure = explain(error); const current = await invoke<View>('local_host_status').catch(() => null); if (current) show(current); }
    finally { busy = false; }
  }
  async function stopAndQuit(leaveRunning = false) {
    busy = true; failure = ''; notice = '';
    try { await invoke('quit_local_host', { leaveRunning }); }
    catch (error) {
      const current = await invoke<View>('local_host_status').catch(() => null); if (current) show(current);
      failure = !leaveRunning && String(error) === 'native_manager_shutdown_unconfirmed' && current?.leaveAvailable ? 'Local management did not stop in time. Try again, or choose Quit anyway: it keeps running, and Frameleaf will try to stop it the next time it opens.' : explain(error);
      // Quit anyway is new on screen; otherwise stay on the control that was tried, or the heading if it went.
      focusOn(() => !leaveRunning && current?.leaveAvailable ? leaveButton : leaveRunning ? leaveButton ?? quitButton : quitButton); }
    finally { busy = false; }
  }
</script>

<section aria-label="Local library setup" aria-busy={busy || checking}>
  <div class="group-head">
    <h2 class="group-title" tabindex="-1" bind:this={title}>Run Frameleaf here</h2>
    {#if starting}<button class="btn quiet" disabled={!native} onclick={cancel}>Cancel setup</button>{/if}
    {#if canMovePackage && libraryPackage && !view?.backgroundActive}
      <button class="btn quiet" disabled={busy || !native} onclick={openDownloads}>Find companion updates</button>
    {/if}
    <button class="btn quiet" disabled={busy || checking || !native} onclick={refresh}>Check installation</button>
  </div>
  <div class="group">
    <div class="row">
      <span class="ic" aria-hidden="true"><Icon name="computer" /></span>
      <span class="l"><b>{headline}</b><small>Keep your photo library on this computer. Frameleaf prepares private storage for your account.</small></span>
      <span class="pill {pill.tone}"><i aria-hidden="true"></i><span class="visually-hidden">Local management: </span>{pill.label}</span>
      {#if view?.backgroundActive && !profilePending}<button class="btn" aria-describedby={describedBy} disabled={busy || !native} onclick={stop}>Stop local management</button>{/if}
      {#if quitOffered && view?.backgroundActive && !profilePending}<button class="btn" aria-label="Stop local management and quit Frameleaf" aria-describedby={describedBy} bind:this={quitButton} disabled={busy || !native} onclick={() => stopAndQuit()}>Stop and quit</button>{/if}
      {#if view?.leaveAvailable && view.backgroundActive && !profilePending}<button class="btn" aria-label="Quit Frameleaf and leave local management running" aria-describedby={describedBy} bind:this={leaveButton} disabled={busy || !native} onclick={() => stopAndQuit(true)}>Quit anyway</button>{/if}
    </div>
    {#if failure}<div class="row"><span class="ic dim" aria-hidden="true"><Icon name="warn" /></span><p id="local-host-failure" class="danger-text" role="alert" style="flex:1"><ErrorText text={failure} /></p></div>{/if}
    {#if notice}<div class="row"><p id="local-host-notice" role="status" style="flex:1">{notice}</p></div>{/if}
    {#if view?.certificateExpiresInDays}
      <div class="row">
        <span class="ic dim" aria-hidden="true"><Icon name="warn" /></span>
        <span class="l" role="status"><b>Local Manager’s security certificate expires in {view.certificateExpiresInDays} {view.certificateExpiresInDays === 1 ? 'day' : 'days'}</b><small>{view.certificateRenewable ? 'Frameleaf renews it the next time local management starts: stop local management here, then start it again. Your photos and library are not affected.' : 'After that, local management on this computer will not start until the certificate is renewed, which needs an update to Frameleaf and its companion. Your photos and library are not affected. Check for updates before then.'}</small></span>
      </div>
    {/if}
    {#if profilePending}<div class="row"><span class="spin" aria-hidden="true"></span><p role="status" style="flex:1">{profileCopy.pending}</p></div>{/if}
    {#if packageCheck && (!view?.backgroundActive || view?.state === 'needs-attention')}
      {@const check = compatibilityCopy[packageCheck]}
      <div class="row">
        <span class="l" role="status"><b>{check.label}</b><small>{check.detail}</small></span>
        {#if (packageCheck === 'refused' || packageCheck === 'outdated') && view?.companionPlatform}<button class="btn quiet" onclick={openDownloads}>Open companion downloads</button>{/if}
      </div>
    {/if}
    {#if selectedPackage && needsProfile}
      <div class="row"><span class="l"><b>Prepare my server profile</b><small>{profileCopy.preparation}</small></span><button class="btn primary" disabled={busy || !native || !packageVerified} onclick={provisionProfile}>Prepare Profile</button></div>
    {/if}
    {#if native && view && !busy && installations.length === 0}
      <div class="row">
        <span class="ic dim" aria-hidden="true"><Icon name="warn" /></span>
        <span class="l"><b>Server component not installed</b>
          <small>{view.companionPlatform ? `${companionInstructions[view.companionPlatform]} When it finishes, return here and choose Check installation.` : 'A companion installer is unavailable for this computer. You can connect to an existing server.'}</small>
        </span>
        {#if view.companionPlatform}<button class="btn primary" onclick={openDownloads}><Icon name="open" />Open companion downloads</button>{/if}
      </div>
    {/if}
    {#if installations.length > 1 && !view?.backgroundActive}
      <div class="form-row"><label for="local-package">Installed server package</label>
        <select id="local-package" value={selected} onchange={selectPackage} disabled={busy || checking}>
          <option value="">Choose an installed package</option>
          {#each installations as installation (installation.manifestSha256)}<option value={installation.manifestSha256}>Library {installation.version ?? 'version unknown'}{installation.library ? ' (this library)' : ''}</option>{/each}
        </select>
      </div>
    {/if}
    {#if carrying}
      <div class="row"><span class="spin" aria-hidden="true"></span>
        <ol role="status" aria-label="Moving your library" style="flex:1;margin:0;padding-left:18px">
          {#each carrySteps as [name, label], index (name)}<li aria-current={index === carryStepIndex ? 'step' : undefined}>{#if index === carryStepIndex}<b>{label}…</b>{:else}{label}{index < carryStepIndex ? ' (done)' : ''}{/if}</li>{/each}
        </ol>
        <button class="btn quiet" disabled={!native} onclick={cancel}>Stop the move</button>
      </div>
    {:else if carry?.previousDatabase && carry.stage === 'switched'}
      <div class="row">
        <span class="l" role="status"><b>Your library now uses a new database</b><small>It was moved from Postgres {carry.previousPostgres} to Postgres {carry.nextPostgres}. The earlier database folder was not changed and is kept at {carry.previousDatabase}{carry.keepUntil ? ` until at least ${new Date(carry.keepUntil * 1000).toLocaleDateString()}` : ''}, together with the earlier companion, so the move can be undone with help from Frameleaf support. Frameleaf does not delete it. When you have checked that your photos, albums and people are all here, confirm below.</small></span>
        <button class="btn" disabled={busy || !native} onclick={confirmCarry}>My library is all here</button>
      </div>
    {:else if carryOffered && carry && selectedPackage && !needsProfile && (!view?.backgroundActive || view?.state === 'needs-attention')}
      <div class="row">
        <span class="l"><b>Move your library to this companion</b>
          <small>{#if carry.available}This companion uses a newer database (Postgres {carry.nextPostgres}) than the one your library last ran with (Postgres {carry.previousPostgres}), so the library has to be moved before it can start. {carry.stage && carry.stage !== 'permitted' ? 'An earlier move was not finished; it continues from where it stopped.' : 'Your photos are not touched.'}{:else}<ErrorText text={explain(carry.code ?? 'host_carry_failed')} />{#if carry.room === 'short'} The move needs {gigabytes(carry.requiredBytes)} free and this computer has {gigabytes(carry.availableBytes)}.{/if}{/if}</small>
        </span>
        <button class="btn primary" disabled={busy || !native || !packageVerified || !carry.available} onclick={() => { carryReview = true; }}>Review the move</button>
      </div>
    {:else if changingPackage && !canMovePackage}
      <div class="row"><span class="l"><b>Choose this library’s current package</b><small>Moving an existing library to another package is unavailable on this computer.</small></span></div>
    {:else if selectedPackage && !needsProfile && (!view?.backgroundActive || view?.state === 'needs-attention')}
      <div class="row">
        <span class="l"><b>{changingPackage ? 'Move your library to this package' : 'Set up local management'}</b>
          <small>{changingPackage ? 'Keep the package your library last used installed until the server starts with the new package.' : 'Prepare Manager so you can start and stop the photo server from this app.'}</small>
        </span>
        <button class="btn primary" disabled={busy || !native || !packageVerified} onclick={prepareSelected}>{changingPackage ? 'Review package change' : 'Prepare local Manager'}</button>
      </div>
    {/if}
    {#if view?.state === 'manager-ready'}
      <div class="row">
        <span class="ic" aria-hidden="true"><Icon name="server" /></span>
        <span class="l"><b>{authorized ? 'Start your photo library' : 'Authorize local management'}</b><small role="status">{authorized ? 'Start your server using the controls below, then open Photos. For a new library, Photos guides you through creating your first administrator. Your Photos account is separate from your Manager password.' : 'The photo server has not been started by this setup step.'}</small></span>
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
</section>

{#if carryReview && carry}
  <Sheet title="Move this library to the new database?" kind="warning" onclose={() => { carryReview = false; }} onsubmit={moveLibrary}>
    <p>Postgres {carry.previousPostgres} → Postgres {carry.nextPostgres}</p>
    <p>Frameleaf starts the earlier companion once, only to copy your library’s database. Photos cannot be opened, nobody can sign in, and nothing can connect from other devices while it runs. The new companion then builds a new database folder from that copy and checks it against the original: every table, the people and search indexes, and the database’s own checksums.</p>
    <p>Only when every check passes does your library switch to the new folder. If anything fails before that, nothing changes and your library still opens with the version of Frameleaf it last ran with. Your photo files are never copied, moved or changed. The earlier database folder and the earlier companion are kept afterwards.</p>
    <p>This needs {gigabytes(carry.requiredBytes)} of free space; this computer has {gigabytes(carry.availableBytes)}. It can take a while for a large library, and Frameleaf cannot be updated until it finishes.</p>
    {#snippet actions()}
      <button class="btn" type="button" onclick={() => { carryReview = false; }}>Cancel</button>
      <button class="btn primary" type="submit">Move my library</button>
    {/snippet}
  </Sheet>
{/if}
{#if packageChange}
  <Sheet title="Move this library to another package?" kind="warning" onclose={() => { packageChange = null; }} onsubmit={confirmPackageChange}>
    {#if libraryPackage?.version && packageChange.version}<p>Current Library {libraryPackage.version} → Library {packageChange.version}</p>{/if}
    <p>Moving to a newer package keeps your photos and saved sign-in. Once the library starts with the new package, it cannot go back to an older one.</p>
    {#snippet actions()}
      <button class="btn" type="button" onclick={() => { packageChange = null; }}>Cancel</button>
      <button class="btn primary" type="submit">Continue with this package</button>
    {/snippet}
  </Sheet>
{/if}
