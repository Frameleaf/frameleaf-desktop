<script lang="ts">
  import { onMount } from 'svelte';
  import { invoke, isTauri } from '@tauri-apps/api/core';
  import { controlIntent, restoreIntent, intentKey, managerError, type Control, type Intent, type ManagerView, type ManagerStatus, type Operation } from './manager-state';
  const native = isTauri();
  const labels: Record<Control, string> = { start: 'Start server', stop: 'Stop server', restart: 'Restart server', backup: 'Create database backup' };
  const outcomes: Record<Control, string> = { start: 'Start operation completed. Check Photos to confirm it is ready.', stop: 'Server stop completed.', restart: 'Restart operation completed. Check Photos to confirm it is ready.', backup: 'Database backup completed. Photos and videos are not included.' };
  const steps: Record<string, string> = {
    start: 'Starting the server', stop: 'Stopping the server', restart: 'Restarting the server',
    'database-backup': 'Creating the database backup',
    'native-backup-start-database': 'Preparing the database for backup',
    'native-backup-start-cleanup': 'Preparing verified backup cleanup',
    'native-backup-checkpoint': 'Creating the database checkpoint',
    'native-backup-stage': 'Preparing recovery metadata',
    'native-backup-encrypt': 'Encrypting the database backup',
    'native-backup-verified': 'Restoring and verifying the encrypted backup',
    'native-backup-owner-cleaned': 'Retiring the temporary checkpoint',
    'native-backup-stage-cleaned': 'Removing temporary backup files',
    'native-backup-stop-database': 'Confirming the backup database has stopped',
  };
  let manager = $state<ManagerView | null>(null);
  let status = $state<ManagerStatus | null>(null);
  let pending = $state<Intent | null>(null);
  let operation = $state<Operation | null>(null);
  let origin = $state('');
  let password = $state('');
  let pem = $state('');
  let fingerprint = $state('');
  let fingerprintPem = $state('');
  let certificateApproved = $state(false);
  let allowManagement = $state(false);
  let busy = $state(false);
  let failure = $state('');
  let notice = $state('');
  let confirmation = $state<Control | null>(null);
  let authorization = $state<'authorize' | 'disconnect' | null>(null);
  let checkedAt = $state<number | null>(null);
  let deviceChanged = $state(false);
  const active = $derived(!!pending || (!!operation && operation.state !== 'complete'));
  const expired = $derived(!!manager && manager.expiresAt <= Date.now());
  const library = $derived(status?.installation.name || 'your server');

  async function perform(work: () => Promise<void>) {
    if (busy || !native) return;
    busy = true; failure = ''; notice = '';
    try { await work(); }
    catch (error) {
      failure = managerError(error);
      if (error === 'manager_recent_auth_required') authorization = 'authorize';
      if (error === 'manager_device_changed') { deviceChanged = true; confirmation = null; authorization = 'disconnect'; }
    } finally { busy = false; }
  }
  function saveIntent(value: Intent) {
    if (!manager) throw Error('manager_pairing_required');
    try { localStorage.setItem(intentKey(manager), JSON.stringify(value)); }
    catch { throw Error('manager_local_state_unavailable'); }
    pending = value;
  }
  function showOperation(value: Operation) {
    operation = value;
    if (value.state === 'complete') {
      if (value.error) failure = managerError(value.error);
      else notice = outcomes[value.kind];
      if (manager && pending) {
        try { localStorage.removeItem(intentKey(manager)); pending = null; }
        catch { failure = managerError('manager_local_state_unavailable'); }
      }
    }
  }
  async function pollOperation() {
    if (!pending?.id) return;
    showOperation(await invoke<Operation>('manager_request', { command: { kind: 'operation', id: pending.id } }));
  }
  async function checkStatus() {
    checkedAt = null; status = null;
    const latest = await invoke<ManagerStatus>('manager_request', { command: { kind: 'status' } });
    status = latest; checkedAt = Date.now(); deviceChanged = false;
    if (pending?.id) await pollOperation();
    else if (!pending) {
      const unfinished = latest.operations.find(value => value.state !== 'complete');
      operation = unfinished || latest.operations[0] || null;
      if (unfinished && manager?.scopes.includes(unfinished.kind)) {
        saveIntent({ ...controlIntent(manager, unfinished.kind, null), id: unfinished.id });
      }
    }
  }
  async function restore() {
    manager = await invoke<ManagerView | null>('manager_view');
    if (!manager) return;
    origin = manager.origin;
    try { pending = restoreIntent(localStorage.getItem(intentKey(manager)), manager); }
    catch { throw Error('manager_local_state_unavailable'); }
    await checkStatus();
  }
  onMount(() => { if (native) void perform(restore); });
  async function reviewCertificate() {
    await perform(async () => {
      const snapshot = pem;
      const value = await invoke<string>('manager_certificate_fingerprint', { pem: snapshot });
      if (pem === snapshot) { fingerprint = value; fingerprintPem = snapshot; certificateApproved = false; }
    });
  }
  async function pair(event: SubmitEvent) {
    event.preventDefault();
    const secret = password; password = '';
    await perform(async () => {
      if (pem.trim() && (!certificateApproved || !fingerprint || pem !== fingerprintPem)) throw Error('manager_certificate_approval_required');
      manager = await invoke<ManagerView>('pair_manager', { origin, password: secret, certificate: pem.trim() ? { pem, sha256: fingerprint } : null, allowManagement });
      pem = ''; fingerprint = ''; fingerprintPem = ''; certificateApproved = false;
      pending = restoreIntent(localStorage.getItem(intentKey(manager)), manager);
      await checkStatus();
      notice = 'This computer is paired with Manager. Its access works independently of photo sign-in.';
    });
  }
  async function sendPending() {
    if (!pending) return;
    if (pending.id) { await pollOperation(); return; }
    const accepted = await invoke<{ id: string }>('manager_request', { command: { kind: 'control', action: pending.action, key: pending.key } });
    const acknowledged = { ...pending, id: accepted.id };
    pending = acknowledged;
    try { saveIntent(acknowledged); }
    catch { failure = managerError('manager_local_state_unavailable'); }
    notice = 'Request accepted. Check its operation below for the latest progress.';
    await pollOperation();
  }
  async function begin(action: Control) {
    confirmation = null;
    await perform(async () => {
      if (!manager) return;
      const intent = controlIntent(manager, action, pending);
      const isNew = !pending;
      saveIntent(intent); // Persist the original request key before any server effect.
      if (isNew) operation = null;
      await sendPending();
    });
  }
  async function resume() {
    if (!pending?.id) return;
    await invoke('manager_request', { command: { kind: 'resume', action: pending.action, id: pending.id } });
    await pollOperation();
  }
  async function authorize(event: SubmitEvent) {
    event.preventDefault();
    const secret = password; password = '';
    await perform(async () => {
      if (authorization === 'disconnect') {
        await invoke('disconnect_manager', { password: secret });
        manager = null; status = null; pending = null; operation = null; checkedAt = null; allowManagement = false;
        notice = 'Manager access was revoked and removed from this computer.';
      } else {
        await invoke('reauthenticate_manager', { password: secret });
        authorization = null;
        if (pending && (operation?.state === 'failed' || operation?.state === 'interrupted')) await resume();
        else if (pending) await sendPending();
        else notice = 'Manager actions authorized. Choose the action you need.';
      }
      authorization = null;
    });
  }
</script>

<section class="manager" aria-labelledby="manager-title">
  <h2 id="manager-title">Server management</h2>
  <p class="detail">Pair this computer with Frameleaf Manager to control your server, including when Photos is stopped.</p>
  {#if !native}<p class="footnote">Open the installed desktop app to pair securely with Manager.</p>{/if}
  {#if failure}<p class="message error" role="alert">{failure}</p>{/if}
  {#if notice}<p class="message" role="status">{notice}</p>{/if}
  {#if manager}
    <div class="manager-identity">
      <strong>{status?.installation.name || 'Paired Manager'}</strong>
      <span>{manager.origin}</span>
      <span>{checkedAt ? `Manager checked at ${new Date(checkedAt).toLocaleTimeString()}` : 'Manager connection has not been confirmed.'}</span>
      <span>Access expires {new Date(manager.expiresAt).toLocaleDateString()}.</span>
      {#if manager.certificateSha256}<span>Approved certificate <code>{manager.certificateSha256}</code></span>{/if}
    </div>
    <p class="footnote">These controls manage the server. They do not stop this computer’s AI worker. Database backups do not include photos or videos.</p>
    <div class="manager-actions" aria-label="Manager server controls">
      {#each ['start', 'stop', 'restart', 'backup'] as value}
        {@const action = value as Control}
        <button class="secondary" disabled={busy || active || expired || deviceChanged || !manager.scopes.includes(action)} onclick={() => action === 'stop' || action === 'restart' ? confirmation = action : begin(action)}>{labels[action]}</button>
      {/each}
    </div>
    {#if confirmation}
      <div class="confirmation" role="group" id="manager-confirmation" aria-label="Confirm server action" aria-live="polite">
        <p>{confirmation === 'stop' ? `Stop ${library}? Photos and server processing will be unavailable until the server is started again.` : `Restart ${library}? Photos and server processing will be briefly unavailable.`}</p>
        <div class="manager-actions"><button class="primary" disabled={busy || deviceChanged} onclick={() => begin(confirmation!)}>Confirm {confirmation === 'stop' ? 'stop' : 'restart'}</button><button class="secondary" disabled={busy} onclick={() => confirmation = null}>Cancel</button></div>
      </div>
    {/if}
    {#if pending || operation}
      <div class="operation" aria-label="Manager operation">
        <h3>{labels[pending?.action || operation!.kind]}</h3>
        <p role="status">{operation ? operation.state === 'complete' ? operation.error ? 'Finished with a condition that needs review.' : 'Completed' : operation.state === 'failed' ? 'Needs attention' : operation.state === 'interrupted' ? 'Interrupted' : 'In progress' : pending?.id ? 'Waiting for operation state' : 'Request outcome has not been confirmed'}</p>
        {#if operation?.step}<p class="footnote">{Object.hasOwn(steps, operation.step) ? steps[operation.step] : 'Manager is processing this operation.'}</p>{/if}
        {#if operation?.error}<p class="error">{managerError(operation.error)}</p>{/if}
        {#if pending?.id || operation?.id}<p class="footnote">Operation <code>{pending?.id || operation?.id}</code></p>{/if}
        {#if pending}
          <div class="manager-actions">
            <button class="secondary" disabled={busy || deviceChanged} onclick={() => perform(pending?.id ? pollOperation : sendPending)}>{pending.id ? 'Check operation' : 'Retry existing request'}</button>
            {#if operation?.state === 'failed' || operation?.state === 'interrupted'}<button class="secondary" disabled={busy || expired || deviceChanged} onclick={() => perform(resume)}>Resume operation</button>{/if}
          </div>
          <p class="footnote">An accepted request can still be in progress. Retrying keeps this request’s original identity.</p>
        {/if}
      </div>
    {/if}
    <div class="manager-actions">
      <button class="text-button" disabled={busy} onclick={() => perform(checkStatus)}>Refresh Manager</button>
      <button class="text-button" disabled={busy || expired || deviceChanged} onclick={() => { password = ''; authorization = 'authorize'; }}>Authorize actions</button>
      <button class="text-button" disabled={busy} onclick={() => { password = ''; authorization = 'disconnect'; }}>Disconnect Manager</button>
    </div>
    {#if authorization}
      <form onsubmit={authorize} class="authorization">
        <p>{authorization === 'disconnect' ? 'Revoke this computer’s Manager access? Server operations continue, and your photo sign-in stays separate.' : pending ? 'Enter your Manager password to authorize and continue this operation.' : 'Enter your Manager password to authorize server actions for five minutes.'}</p>
        <label for="manager-authorization-password">Manager password</label>
        <input id="manager-authorization-password" type="password" bind:value={password} required maxlength="256" autocomplete="current-password" disabled={busy} />
        <div class="manager-actions"><button class="primary" disabled={busy}>{authorization === 'disconnect' ? 'Revoke and disconnect' : pending ? 'Authorize and continue' : 'Authorize actions'}</button><button class="secondary" type="button" disabled={busy} onclick={() => { authorization = null; password = ''; }}>Cancel</button></div>
      </form>
    {/if}
  {:else}
    <form onsubmit={pair}>
      <fieldset disabled={busy || !native}>
        <label for="manager-origin">Manager HTTPS address</label>
        <input id="manager-origin" type="url" bind:value={origin} placeholder="https://nas.home.example:9443" required autocomplete="url" />
        <label for="manager-password">Manager password</label>
        <input id="manager-password" type="password" bind:value={password} required maxlength="256" autocomplete="current-password" />
        <details>
          <summary>Use a certificate for a private Manager</summary>
          <p class="footnote">Use Manager’s public PEM certificate when it is not trusted by your computer. Never paste a private key.</p>
          <label for="manager-certificate">Public certificate</label>
          <textarea id="manager-certificate" rows="5" maxlength="16384" bind:value={pem} oninput={() => { fingerprint = ''; fingerprintPem = ''; certificateApproved = false; }} spellcheck="false"></textarea>
          <button class="secondary" type="button" disabled={!pem.trim()} onclick={reviewCertificate}>Review certificate fingerprint</button>
          {#if fingerprint}
            <p class="fingerprint"><strong>SHA-256 fingerprint</strong><code>{fingerprint}</code></p>
            <p class="footnote">Compare this with Manager’s certificate using a trusted connection. Approve only if it matches.</p>
            <label class="check"><input type="checkbox" bind:checked={certificateApproved} />I verified this certificate fingerprint.</label>
          {/if}
        </details>
        <label class="check"><input type="checkbox" bind:checked={allowManagement} required />Allow this computer to start, stop and restart this server, and create database backups.</label>
        <button class="primary" disabled={!allowManagement || (!!pem.trim() && (!fingerprint || !certificateApproved))}>{busy ? 'Pairing…' : 'Pair with Manager'}</button>
        <p class="footnote">Your Manager password is used for this sign-in and is not saved. The separate management grant stays in your computer’s secure credential store.</p>
      </fieldset>
    </form>
    <button class="text-button" disabled={busy || !native} onclick={() => perform(restore)}>Restore saved Manager access</button>
  {/if}
</section>

<style>
  .manager { margin-top: 42px; padding-top: 28px; border-top: 1px solid var(--border); }
  .detail { color: var(--muted); line-height: 1.6; margin: 12px 0 22px; }
  fieldset { border: 0; padding: 0; margin: 0; min-width: 0; }
  fieldset > label, details > label:not(.check) { display: block; font-size: 13px; font-weight: 600; margin-bottom: 7px; }
  textarea { width: 100%; padding: 10px; border: 1px solid var(--border); border-radius: 7px; background: var(--panel); color: var(--text); font: inherit; resize: vertical; margin: 8px 0 14px; }
  details { margin: 4px 0 22px; }
  summary { cursor: pointer; font-size: 14px; }
  .check { display: flex; align-items: flex-start; gap: 10px; font-size: 13px; line-height: 1.55; margin: 20px 0; }
  .check input { flex: 0 0 16px; width: 16px; height: 16px; margin: 3px 0 0; accent-color: var(--accent); }
  .manager-actions { display: flex; flex-wrap: wrap; gap: 10px 16px; margin: 18px 0; }
  .manager-identity { display: grid; gap: 8px; overflow-wrap: anywhere; }
  .manager-identity span { color: var(--muted); font-size: 13px; }
  code { font-size: 12px; overflow-wrap: anywhere; }
  .fingerprint { display: grid; gap: 8px; }
  .confirmation, .authorization, .operation { margin-top: 22px; padding: 18px 0 0; border-top: 1px solid var(--border); }
  .confirmation p, .authorization p, .operation p { line-height: 1.6; }
  h3 { font-size: 15px; margin: 0 0 10px; }
</style>
