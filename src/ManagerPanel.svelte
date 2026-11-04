<script lang="ts">
  import { onMount } from 'svelte';
  import { invoke, isTauri } from '@tauri-apps/api/core';
  import { controlIntent, restoreIntent, intentKey, managerError, type Control, type Intent, type ManagerView, type ManagerStatus, type Operation, backupReviewIntent, restoreBackupReview, backupReviewKey, type BackupEntry, type BackupReviewIntent, type BackupReview, createBackupRestoreIntent, parseBackupRestoreIntent, backupRestoreKey, type BackupRestoreIntent, type BackupRestoreOperation } from './manager-state';
  import { countdown, formatWhen, formatDate, relativeTime, shortId, fingerprintShort, hostOf } from './ui-state';
  import Icon from './Icon.svelte';
  import Sheet from './Sheet.svelte';
  let { focus = 'manager', embedded = false, onback = undefined, onstate = undefined }: { focus?: 'manager' | 'backups'; embedded?: boolean; onback?: (() => void) | undefined; onstate?: ((paired: boolean) => void) | undefined } = $props();
  const native = isTauri();
  const labels: Record<Control, string> = { start: 'Start server', stop: 'Stop server', restart: 'Restart server', backup: 'Create database backup' };
  const outcomes: Record<Control, string> = { start: 'Start operation completed. Check Photos to confirm it is ready.', stop: 'Server stop completed.', restart: 'Restart operation completed. Check Photos to confirm it is ready.', backup: 'Database backup completed. Photos and videos are not included.' };
  const steps: Record<string, string> = {
    'native-restore-verify': 'Verifying the restored database',
    'native-restore-selection-request': 'Selecting the verified database',
    'native-restore-finalization-request': 'Confirming the restored database is safe to use',
    'native-restore-start-server': 'Starting the restored server',
    'native-restore-started': 'The restored server is ready',
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
  const backupSteps = ['native-backup-start-database', 'native-backup-start-cleanup', 'native-backup-checkpoint', 'native-backup-stage', 'native-backup-encrypt', 'native-backup-verified', 'native-backup-owner-cleaned', 'native-backup-stage-cleaned', 'native-backup-stop-database'];
  let manager = $state<ManagerView | null>(null);
  let status = $state<ManagerStatus | null>(null);
  let pending = $state<Intent | null>(null);
  let operation = $state<Operation | null>(null);
  let origin = $state('');
  const http = $derived.by(() => {
    try { return new URL(origin.trim()).protocol === 'http:'; }
    catch { return false; }
  });
  let password = $state('');
  let pem = $state('');
  let fingerprint = $state('');
  let fingerprintPem = $state('');
  let certificateApproved = $state(false);
  let allowManagement = $state(false);
  let allowRecovery = $state(false);
  let backups = $state<BackupEntry[]>([]);
  let backupsChecked = $state(false);
  let selectedBackup = $state('');
  let recoveryIntent = $state<BackupReviewIntent | null>(null);
  let recovery = $state<BackupReview | null>(null);
  let restorePending = $state<BackupRestoreIntent | null>(null);
  let restoreOperation = $state<BackupRestoreOperation | null>(null);
  let restoreConfirmation = $state(false);
  let restoreApproved = $state(false);
  let restoreAuthorization = $state<'send' | 'resume' | null>(null);
  let busy = $state(false);
  let failure = $state('');
  let notice = $state('');
  let confirmation = $state<Control | null>(null);
  let authorization = $state<'authorize' | 'disconnect' | null>(null);
  let recoveryAuthorization = $state(false);
  let checkedAt = $state<number | null>(null);
  let deviceChanged = $state(false);
  let authorizedUntil = $state<number | null>(null);
  let now = $state(Date.now());
  let showCertificate = $state(false);
  const active = $derived(!!restorePending || !!pending || (!!operation && operation.state !== 'complete'));
  const expired = $derived(!!manager && manager.expiresAt <= Date.now());
  const library = $derived(status?.installation.name || 'your server');
  const authorized = $derived(authorizedUntil !== null && authorizedUntil > now);
  const lastKind = $derived.by(() => { const done = status?.operations.find(value => value.state === 'complete' && !value.error && value.kind !== 'backup'); return done?.kind ?? null; });
  const serverPill = $derived(!manager ? { label: 'Not paired', tone: 'off' } : deviceChanged ? { label: 'Device changed', tone: 'bad' } : expired ? { label: 'Access expired', tone: 'off' } : !status ? { label: checkedAt === null && busy ? 'Checking' : 'Unreachable', tone: 'wait' } : active ? { label: 'Busy', tone: 'wait' } : lastKind === 'stop' ? { label: 'Stopped', tone: 'off' } : lastKind ? { label: 'Running', tone: 'ok' } : { label: 'Paired', tone: 'ok' });
  const operationProgress = $derived.by(() => {
    if (!operation || operation.state === 'complete') return null;
    if (operation.kind !== 'backup' || !operation.step) return null;
    const index = backupSteps.indexOf(operation.step);
    return index < 0 ? null : { step: index + 1, total: backupSteps.length, percent: Math.round(((index + 1) / backupSteps.length) * 100) };
  });
  $effect(() => { onstate?.(!!manager); });
  $effect(() => {
    const timer = setInterval(() => { now = Date.now(); if (authorizedUntil !== null && authorizedUntil <= now) authorizedUntil = null; }, 1000);
    return () => clearInterval(timer);
  });

  async function perform(work: () => Promise<void>, recoveryAction = false, restoreAction: 'send' | 'resume' | null = null) {
    if (busy || !native) return;
    busy = true; failure = ''; notice = '';
    try { await work(); }
    catch (error) {
      failure = managerError(error);
      if (error === 'manager_recent_auth_required') { authorizedUntil = null; authorization = 'authorize'; recoveryAuthorization = recoveryAction; restoreAuthorization = restoreAction; }
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
    try { recoveryIntent = restoreBackupReview(localStorage.getItem(backupReviewKey(manager)), manager); }
    catch { throw Error('manager_local_state_unavailable'); }
    if (recoveryIntent) selectedBackup = recoveryIntent.snapshot;
    try { restorePending = parseBackupRestoreIntent(localStorage.getItem(backupRestoreKey(manager)), manager); }
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
      if (!http && pem.trim() && (!certificateApproved || !fingerprint || pem !== fingerprintPem)) throw Error('manager_certificate_approval_required');
      manager = await invoke<ManagerView>('pair_manager', { origin, password: secret, certificate: !http && pem.trim() ? { pem, sha256: fingerprint } : null, allowManagement, allowRecovery });
      pem = ''; fingerprint = ''; fingerprintPem = ''; certificateApproved = false;
      pending = restoreIntent(localStorage.getItem(intentKey(manager)), manager);
      await restore();
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
  async function beginWork(action: Control) {
    if (!manager) return;
    if (restorePending) throw Error('manager_restore_pending');
    const intent = controlIntent(manager, action, pending);
    const isNew = !pending;
    saveIntent(intent); // Persist the original request key before any server effect.
    if (isNew) operation = null;
    await sendPending();
  }
  async function begin(action: Control) {
    confirmation = null;
    await perform(() => beginWork(action));
  }
  /** The stop/restart sheet: an optional Manager password authorizes first, then the request is sent. */
  async function confirmControl() {
    const action = confirmation; if (!action) return;
    const secret = password; password = ''; confirmation = null;
    await perform(async () => {
      if (secret) { await invoke('reauthenticate_manager', { password: secret }); authorizedUntil = Date.now() + 5 * 60_000; now = Date.now(); }
      await beginWork(action);
    });
  }
  async function resume() {
    if (!pending?.id) return;
    await invoke('manager_request', { command: { kind: 'resume', action: pending.action, id: pending.id } });
    await pollOperation();
  }
  async function authorize() {
    const secret = password; password = '';
    await perform(async () => {
      if (authorization === 'disconnect') {
        await invoke('disconnect_manager', { password: secret });
        manager = null; status = null; pending = null; operation = null; checkedAt = null; allowManagement = false; allowRecovery = false; backups = []; backupsChecked = false; recoveryIntent = null; recovery = null; selectedBackup = ''; restorePending = null; restoreOperation = null; restoreConfirmation = false; restoreApproved = false; restoreAuthorization = null; authorizedUntil = null;
        notice = 'Manager access was revoked and removed from this computer.';
      } else {
        await invoke('reauthenticate_manager', { password: secret });
        authorizedUntil = Date.now() + 5 * 60_000; now = Date.now();
        authorization = null;
        if (restoreAuthorization) { const action = restoreAuthorization; restoreAuthorization = null; if (action === 'resume') await resumeBackupRestore(); else await sendBackupRestore(); }
        else if (recoveryAuthorization) { recoveryAuthorization = false; if (recoveryIntent) await checkReview(); else await listBackups(); }
        else if (pending && (operation?.state === 'failed' || operation?.state === 'interrupted')) await resume();
        else if (pending) await sendPending();
        else if (recoveryIntent) await checkReview();
        else notice = 'Manager actions authorized. Choose the action you need.';
      }
      authorization = null;
    }, recoveryAuthorization, restoreAuthorization);
  }
  async function listBackups() {
    backups = await invoke<BackupEntry[]>('manager_request', { command: { kind: 'backups' } });
    backupsChecked = true;
    if (!recoveryIntent) selectedBackup = backups[0]?.id || '';
  }
  async function checkReview() {
    if (!manager || !recoveryIntent) return;
    await invoke('manager_request', { command: { kind: 'review-restore', snapshot: recoveryIntent.snapshot, key: recoveryIntent.key } });
    recovery = await invoke<BackupReview>('manager_request', { command: { kind: 'restore-review', id: recoveryIntent.key, snapshot: recoveryIntent.snapshot } });
  }
  async function beginReview() {
    if (!manager) return;
    const intent = backupReviewIntent(manager, selectedBackup, recoveryIntent);
    try { localStorage.setItem(backupReviewKey(manager), JSON.stringify(intent)); }
    catch { throw Error('manager_local_state_unavailable'); }
    recoveryIntent = intent;
    recovery = null;
    await checkReview();
  }
  function clearReview() {
    if (!manager) return;
    if (restorePending) throw Error('manager_restore_pending');
    try { localStorage.removeItem(backupReviewKey(manager)); }
    catch { throw Error('manager_local_state_unavailable'); }
    recoveryIntent = null; recovery = null; restoreConfirmation = false; restoreApproved = false;
  }
  function saveBackupRestore(value: BackupRestoreIntent) {
    if (!manager) throw Error('manager_pairing_required');
    try { localStorage.setItem(backupRestoreKey(manager), JSON.stringify(value)); }
    catch { throw Error('manager_local_state_unavailable'); }
    restorePending = value;
  }
  async function sendBackupRestore() {
    if (!restorePending) return;
    if (!restorePending.id) {
      let accepted: { id: string };
      try { accepted = await invoke<{ id: string }>('manager_request', { command: { kind: 'restore', reviewId: restorePending.reviewId, key: restorePending.key } }); }
      catch (error) {
        // Manager checks this exact request key before refusing a new review; transport errors stay pending.
        if (['native_restore_review_expired','native_restore_review_not_ready','native_restore_runtime_change_required'].includes(String(error)) && manager) {
          try { localStorage.removeItem(backupRestoreKey(manager)); } catch { throw Error('manager_local_state_unavailable'); }
          restorePending = null;
        }
        throw error;
      }
      const acknowledged = { ...restorePending, id: accepted.id };
      restorePending = acknowledged;
      try { saveBackupRestore(acknowledged); } catch { failure = managerError('manager_local_state_unavailable'); }
    }
    restoreOperation = await invoke<BackupRestoreOperation>('manager_request', { command: { kind: 'restore-operation', id: restorePending.id } });
    if (restoreOperation.error) failure = managerError(restoreOperation.error);
  }
  async function confirmBackupRestore() {
    if (!manager || !recovery || !restoreApproved) return;
    if (pending || active) throw Error('manager_operation_pending');
    const intent = createBackupRestoreIntent(manager, recovery, null);
    saveBackupRestore(intent);
    restoreConfirmation = false; restoreApproved = false;
    await sendBackupRestore();
  }
  async function resumeBackupRestore() {
    if (!restorePending?.id) return;
    await invoke('manager_request', { command: { kind: 'resume-restore', id: restorePending.id } });
    await sendBackupRestore();
  }
  function finishBackupRestore() {
    if (!manager || restoreOperation?.state !== 'complete') return;
    try { localStorage.removeItem(backupRestoreKey(manager)); }
    catch { throw Error('manager_local_state_unavailable'); }
    restorePending = null; restoreOperation = null;
    clearReview(); notice = 'Database restore completed and the server reported ready. Open Photos to check your library.';
  }
  function reviewBackup(id: string) {
    selectedBackup = id;
    void perform(beginReview, true);
  }
  function openRestore() {
    void perform(async () => { await checkReview(); if (manager && recovery) { createBackupRestoreIntent(manager, recovery, null); restoreApproved = false; restoreConfirmation = true; } }, true);
  }
  function reviewPill(id: string): { label: string; tone: string } {
    if (operation && operation.kind === 'backup' && operation.state !== 'complete' && backups[0]?.id === id) return { label: 'In progress', tone: 'wait' };
    if (restorePending?.snapshot === id) return { label: restoreOperation?.state === 'complete' ? 'Restored' : 'Restoring', tone: 'wait' };
    if (recoveryIntent?.snapshot !== id) return { label: 'Not reviewed', tone: 'off' };
    if (!recovery) return { label: 'Review not checked', tone: 'wait' };
    if (recovery.state === 'preparing') return { label: 'Reviewing', tone: 'wait' };
    if (recovery.state === 'prepared') return recovery.requiresRuntimeChange ? { label: 'Needs runtime change', tone: 'off' } : { label: `Review ready · ${countdown(recovery.expires, now).replace(/:\d\d$/, '')} min`, tone: 'ok' };
    if (recovery.state === 'expired') return { label: 'Review expired', tone: 'off' };
    if (recovery.state === 'interrupted') return { label: 'Review interrupted', tone: 'off' };
    return { label: 'Review failed', tone: 'bad' };
  }
  const title = $derived(focus === 'backups' ? 'Backups' : status?.installation.name || (manager ? 'Manager' : 'Server management'));
</script>

<section class="page" class:embedded aria-labelledby="manager-title">
  <header class="toolbar">
    {#if onback}<button class="btn quiet" onclick={onback} aria-label="Back to setup"><Icon name="back" />Back</button>{/if}
    <h1 id="manager-title">{title}</h1>
    <span class="pill {serverPill.tone}"><i aria-hidden="true"></i>{serverPill.label}</span>
    <span class="sp"></span>
    {#if manager}
      {#if focus === 'manager'}
        <button class="btn" disabled={busy || active || expired || deviceChanged || !manager.scopes.includes('start')} onclick={() => begin('start')}><Icon name="play" />Start</button>
        <button class="btn" disabled={busy || active || expired || deviceChanged || !manager.scopes.includes('stop')} onclick={() => { password = ''; confirmation = 'stop'; }}><Icon name="stop" />Stop</button>
        <button class="btn" disabled={busy || active || expired || deviceChanged || !manager.scopes.includes('restart')} onclick={() => { password = ''; confirmation = 'restart'; }}><Icon name="restart" />Restart</button>
      {/if}
      <button class="btn" disabled={busy || active || expired || deviceChanged || !manager.scopes.includes('backup')} onclick={() => begin('backup')}><Icon name="backup" />Back up</button>
      {#if authorized}
        <span class="pill wait" style="margin-left:6px" title="Manager actions are authorized for five minutes"><Icon name="key" />Authorized · {countdown(authorizedUntil ?? 0, now)}</span>
      {:else}
        <button class="btn quiet" style="margin-left:6px" disabled={busy || expired || deviceChanged} onclick={() => { password = ''; recoveryAuthorization = false; restoreAuthorization = null; authorization = 'authorize'; }}><Icon name="key" />Authorize…</button>
      {/if}
    {/if}
  </header>
  <div class="body">
    {#if !native}<p class="foot" style="margin:0">Open the installed desktop app to pair securely with Manager.</p>{/if}
    {#if failure}<div class="inline-msg error" role="alert"><p>{failure}</p><button class="btn small quiet" onclick={() => { failure = ''; }}>Dismiss</button></div>{/if}
    {#if notice}<div class="inline-msg" role="status"><p>{notice}</p><button class="btn small quiet" onclick={() => { notice = ''; }}>Dismiss</button></div>{/if}
    {#if manager}
      <div>
        <div class="group">
          <div class="row">
            <span class="ic" aria-hidden="true"><Icon name="server" /></span>
            <span class="l"><b>{status?.installation.name || 'Paired Manager'}</b><small>{hostOf(manager.origin)}{status ? ` · Frameleaf ${status.installation.release.replace(/^frameleaf-v?/, '')}` : ''}{checkedAt ? ` · Checked ${relativeTime(checkedAt, now)}` : ' · Manager connection has not been confirmed'}</small></span>
            <button class="btn" disabled={busy} onclick={() => perform(checkStatus)}>Refresh</button>
            <button class="btn quiet" disabled={busy} onclick={() => { password = ''; authorization = 'disconnect'; }}>Disconnect…</button>
          </div>
          <div class="kv">
            <div><span>Manager access</span><b class:danger-text={expired}>{expired ? 'Expired' : `Until ${formatDate(manager.expiresAt)}`}</b></div>
            <div><span>Certificate</span><b>{manager.certificateSha256 ? `Verified · ${fingerprintShort(manager.certificateSha256)}` : manager.origin.startsWith('http:') ? 'HTTP · unencrypted' : 'System trust'}</b></div>
            <div><span>Permissions</span><b>{[manager.scopes.some(scope => ['start', 'stop', 'restart'].includes(scope)) ? 'Control' : null, manager.scopes.includes('backup') ? 'backup' : null, manager.scopes.includes('restore') ? 'restore' : null].filter(Boolean).join(', ') || 'Status only'}</b></div>
          </div>
        </div>
        <p class="foot">These controls manage the server only. They do not pause this computer’s AI worker. Database backups do not include photos or videos.</p>
      </div>

      {#if pending || operation}
        <div>
          <div class="group-head"><h2 class="group-title">Current operation</h2></div>
          <div class="group" aria-label="Manager operation">
            <div class="row top">
              <span class="ic" aria-hidden="true"><Icon name={(pending?.action || operation!.kind) === 'backup' ? 'backup' : (pending?.action || operation!.kind) === 'stop' ? 'stop' : (pending?.action || operation!.kind) === 'restart' ? 'restart' : 'play'} /></span>
              <span class="l">
                <b>{labels[pending?.action || operation!.kind]}</b>
                <small style={operationProgress ? 'margin-bottom:8px' : ''}>{operation?.step ? (Object.hasOwn(steps, operation.step) ? steps[operation.step] : 'Manager is processing this operation.') : operation ? operation.state === 'complete' ? operation.error ? 'Finished with a condition that needs review.' : 'Completed' : 'In progress' : pending?.id ? 'Waiting for operation state' : 'Request outcome has not been confirmed'}{operationProgress ? ` · step ${operationProgress.step} of ${operationProgress.total}` : ''}</small>
                {#if operationProgress}<span class="progress" role="progressbar" aria-valuenow={operationProgress.percent} aria-valuemin="0" aria-valuemax="100" aria-label="Backup progress"><span style="width:{operationProgress.percent}%"></span></span>{/if}
                {#if operation?.error}<small class="danger-text" style="margin-top:8px">{managerError(operation.error)}</small>{/if}
                {#if pending?.id || operation?.id}<small style="margin-top:8px">Operation <code>{shortId(pending?.id || operation?.id, 8)}</code>{operation?.createdAt ? ` · started ${formatWhen(operation.createdAt, now)}` : ''}{pending ? ' · an accepted request can still be in progress; retrying keeps its original identity' : ''}</small>{/if}
              </span>
              <span class="pill {operation ? operation.state === 'complete' ? operation.error ? 'bad' : 'ok' : operation.state === 'failed' ? 'bad' : operation.state === 'interrupted' ? 'off' : 'wait' : 'wait'}" role="status"><i aria-hidden="true"></i>{operation ? operation.state === 'complete' ? operation.error ? 'Needs review' : 'Completed' : operation.state === 'failed' ? 'Needs attention' : operation.state === 'interrupted' ? 'Interrupted' : 'In progress' : pending?.id ? 'Checking' : 'Unconfirmed'}</span>
              {#if pending}
                <button class="btn" disabled={busy || deviceChanged} onclick={() => perform(pending?.id ? pollOperation : sendPending)}>{pending.id ? 'Check' : 'Retry'}</button>
                {#if operation?.state === 'failed' || operation?.state === 'interrupted'}<button class="btn" disabled={busy || expired || deviceChanged} onclick={() => perform(resume)}>Resume</button>{/if}
              {/if}
            </div>
          </div>
        </div>
      {/if}

      <div>
        <div class="group-head">
          <h2 class="group-title">Database backups</h2>
          {#if manager.scopes.includes('restore')}<button class="btn quiet" disabled={busy || expired || deviceChanged} onclick={() => perform(listBackups, true)}>{backupsChecked ? 'Reload backups' : 'Load backups'}</button>{/if}
        </div>
        <div class="group" aria-label="Database backup reviews">
          {#if !manager.scopes.includes('restore')}
            <div class="empty">Backup recovery permission was not granted. To review and restore backups, disconnect Manager and pair again with recovery permission.</div>
          {:else if !backupsChecked}
            <div class="empty">Load the list to review a backup before recovery.</div>
          {:else if backups.length === 0}
            <div class="empty">No database backups were found.</div>
          {:else}
            <table class="table">
              <thead><tr><th scope="col">Created</th><th scope="col">Backup</th><th scope="col">Status</th><th scope="col" class="right"><span class="sr">Actions</span></th></tr></thead>
              <tbody>
                {#each backups as backup (backup.id)}
                  {@const pill = reviewPill(backup.id)}
                  {@const reviewing = recoveryIntent?.snapshot === backup.id}
                  <tr>
                    <td>{formatWhen(backup.time, now)}</td>
                    <td><code>{shortId(backup.id)}</code></td>
                    <td><span class="pill {pill.tone}"><i aria-hidden="true"></i>{pill.label}</span></td>
                    <td class="right">
                      {#if reviewing && recovery?.state === 'prepared' && !recovery.requiresRuntimeChange && !restorePending}
                        <button class="btn" disabled={busy || expired || deviceChanged || active} onclick={openRestore}>Restore…</button>
                      {:else if reviewing && (!recovery || recovery.state === 'preparing')}
                        <button class="btn" disabled={busy || expired || deviceChanged} onclick={() => perform(checkReview, true)}>Check</button>
                      {:else if reviewing}
                        <button class="btn quiet" disabled={busy || !!restorePending} onclick={() => perform(async () => clearReview())}>Choose another</button>
                      {:else}
                        <button class="btn" disabled={busy || expired || deviceChanged || !!recoveryIntent} onclick={() => reviewBackup(backup.id)}>Review</button>
                      {/if}
                    </td>
                  </tr>
                {/each}
              </tbody>
            </table>
          {/if}
          {#if recoveryIntent}
            <div class="row top">
              <span class="ic" aria-hidden="true"><Icon name="backup" /></span>
              <span class="l">
                <b>Review of backup <code>{shortId(recoveryIntent.snapshot)}</code></b>
                <small role="status">{!recovery ? 'Review outcome has not been checked.' : recovery.state === 'preparing' ? 'Backup review is in progress. Check again when ready.' : recovery.state === 'prepared' ? `Backup review is ready. Created ${formatWhen(recovery.createdAt, now)}. ${recovery.requiresRuntimeChange ? `This backup requires a runtime change from ${recovery.targetRelease} to ${recovery.release}.` : `Backup metadata matches ${recovery.targetRelease}.`} Review valid until ${new Date(recovery.expires).toLocaleTimeString()}.` : recovery.state === 'expired' ? 'This review expired. Start a new review.' : recovery.state === 'interrupted' ? 'Manager restarted before the review finished. Start a new review.' : 'The backup could not be verified. Check the backup before starting another review.'}</small>
              </span>
              <button class="btn" disabled={busy || expired || deviceChanged} onclick={() => perform(checkReview, true)}>Check review</button>
              {#if recovery && recovery.state !== 'preparing'}<button class="btn quiet" disabled={busy || !!restorePending} onclick={() => perform(async () => clearReview())}>Choose another backup</button>{/if}
            </div>
          {/if}
          {#if restorePending}
            <div class="row top" aria-label="Database restore progress">
              <span class="ic" aria-hidden="true"><Icon name="restart" /></span>
              <span class="l">
                <b>Database restore from <code>{shortId(restorePending.snapshot)}</code></b>
                <small role="status">{!restoreOperation ? 'Restore outcome has not been checked. Keep this request to recover its status.' : restoreOperation.state === 'complete' ? 'Database restore completed. The server reported ready.' : restoreOperation.state === 'running' ? 'Database restore is running. Keep the computer and server connected.' : 'Database restore needs attention. Keep this request and check its state before resuming.'}{restoreOperation?.step ? ` · ${Object.hasOwn(steps, restoreOperation.step) ? steps[restoreOperation.step] : 'Checking database restore progress'}` : ''}</small>
              </span>
              <span class="pill {restoreOperation?.state === 'complete' ? 'ok' : restoreOperation && ['failed', 'interrupted'].includes(restoreOperation.state) ? 'bad' : 'wait'}"><i aria-hidden="true"></i>{restoreOperation?.state === 'complete' ? 'Completed' : restoreOperation?.state === 'running' ? 'Running' : restoreOperation ? 'Needs attention' : 'Unchecked'}</span>
              <button class="btn" disabled={busy || expired || deviceChanged} onclick={() => perform(sendBackupRestore, false, 'send')}>Check</button>
              {#if restoreOperation && ['failed','interrupted'].includes(restoreOperation.state)}<button class="btn" disabled={busy || expired || deviceChanged} onclick={() => perform(resumeBackupRestore, false, 'resume')}>Resume</button>{/if}
              {#if restoreOperation?.state === 'complete'}<button class="btn primary" disabled={busy} onclick={() => perform(async () => finishBackupRestore())}>Finish</button>{/if}
            </div>
          {/if}
        </div>
        <p class="foot">Backups contain the database only. Photos and videos are never included. Review a backup before restoring it.</p>
      </div>
    {:else}
      <div>
        <div class="group-head"><h2 class="group-title">Pair with Frameleaf Manager</h2></div>
        <form class="group" onsubmit={pair}>
          <fieldset disabled={busy || !native} style="border:0;padding:0;margin:0;min-width:0">
            <div class="form-row"><label for="manager-origin">Manager address</label><input id="manager-origin" type="url" bind:value={origin} placeholder="http://tower.local:2282" required autocomplete="url" /></div>
            <div class="form-row"><label for="manager-password">Manager password</label><input id="manager-password" type="password" bind:value={password} required maxlength="256" autocomplete="current-password" /></div>
            {#if http}
              <div class="form-row"><span></span><p class="hint" style="margin:0">HTTP sends sign-in and management traffic without encryption. Use a trusted network.</p></div>
            {:else}
              <div class="form-row"><span></span><span><label class="check"><input type="checkbox" bind:checked={showCertificate} />Use a certificate for a private Manager</label></span></div>
              {#if showCertificate}
                <div class="form-row top"><label for="manager-certificate">Public certificate</label><span>
                  <textarea id="manager-certificate" rows="5" maxlength="16384" bind:value={pem} oninput={() => { fingerprint = ''; fingerprintPem = ''; certificateApproved = false; }} spellcheck="false"></textarea>
                  <p class="hint">Use Manager’s public PEM certificate when it is not trusted by your computer. Never paste a private key.</p>
                  <div class="actions" style="margin-top:8px"><button class="btn" type="button" disabled={!pem.trim()} onclick={reviewCertificate}>Review certificate fingerprint</button></div>
                  {#if fingerprint}
                    <p class="hint"><b>SHA-256 fingerprint</b><br /><code>{fingerprint}</code><br />Compare this with Manager’s certificate using a trusted connection. Approve only if it matches.</p>
                    <label class="check" style="margin-top:8px"><input type="checkbox" bind:checked={certificateApproved} />I verified this certificate fingerprint.</label>
                  {/if}
                </span></div>
              {/if}
            {/if}
            <div class="form-row top"><label for="manager-allow">Permissions</label><span>
              <label class="check"><input id="manager-allow" type="checkbox" bind:checked={allowManagement} required />Allow this computer to start, stop and restart this server, and create database backups.</label>
              <label class="check" style="margin-top:8px"><input type="checkbox" bind:checked={allowRecovery} />Also allow backup recovery reviews and restore operations.</label>
            </span></div>
            <div class="form-row"><span></span><span class="actions">
              <button class="btn primary" disabled={!allowManagement || (!http && !!pem.trim() && (!fingerprint || !certificateApproved))}>{busy ? 'Pairing…' : 'Pair with Manager'}</button>
              <button class="btn quiet" type="button" disabled={busy || !native} onclick={() => perform(restore)}>Restore saved Manager access</button>
            </span></div>
          </fieldset>
        </form>
        <p class="foot">Pair this computer with Frameleaf Manager to control your server, including when Photos is stopped. Your Manager password is used for this sign-in and is not saved. The separate management grant stays in your computer’s secure credential store.</p>
      </div>
    {/if}
  </div>
</section>

{#if confirmation}
  <Sheet title={confirmation === 'stop' ? `Stop “${library}”?` : `Restart “${library}”?`} kind="warning" {busy} onclose={() => { confirmation = null; password = ''; }} onsubmit={confirmControl}>
    <p>{confirmation === 'stop' ? 'Photos and server processing will be unavailable until the server is started again.' : 'Photos and server processing will be briefly unavailable.'} This computer’s AI worker is not affected.</p>
    {#if !authorized}
      <label for="manager-confirm-password">Enter your Manager password to continue</label>
      <input id="manager-confirm-password" type="password" bind:value={password} maxlength="256" autocomplete="current-password" disabled={busy} />
    {/if}
    {#snippet actions()}
      <button class="btn" type="button" disabled={busy} onclick={() => { confirmation = null; password = ''; }}>Cancel</button>
      <button class="btn danger" type="submit" disabled={busy || deviceChanged}>{confirmation === 'stop' ? 'Stop Server' : 'Restart Server'}</button>
    {/snippet}
  </Sheet>
{/if}
{#if authorization}
  <Sheet title={authorization === 'disconnect' ? 'Disconnect Manager?' : 'Authorize Manager actions'} kind={authorization === 'disconnect' ? 'danger' : 'plain'} {busy} onclose={() => { authorization = null; password = ''; }} onsubmit={authorize}>
    <p>{authorization === 'disconnect' ? 'Revoke this computer’s Manager access? Server operations continue, and your photo sign-in stays separate.' : restoreAuthorization ? 'Enter your Manager password to continue the confirmed database restore.' : recoveryAuthorization ? 'Enter your Manager password to authorize backup review.' : pending ? 'Enter your Manager password to authorize and continue this operation.' : 'Enter your Manager password to authorize server actions for five minutes.'}</p>
    <label for="manager-authorization-password">Manager password</label>
    <input id="manager-authorization-password" type="password" bind:value={password} required maxlength="256" autocomplete="current-password" disabled={busy} />
    {#snippet actions()}
      <button class="btn" type="button" disabled={busy} onclick={() => { authorization = null; password = ''; }}>Cancel</button>
      <button class="btn {authorization === 'disconnect' ? 'danger' : 'primary'}" type="submit" disabled={busy}>{authorization === 'disconnect' ? 'Revoke and Disconnect' : restoreAuthorization ? 'Authorize Restore' : recoveryAuthorization ? 'Authorize and Review' : pending ? 'Authorize and Continue' : 'Authorize'}</button>
    {/snippet}
  </Sheet>
{/if}
{#if restoreConfirmation && !restorePending && recoveryIntent}
  <Sheet title="Restore the database for “{library}”?" kind="danger" {busy} onclose={() => { restoreConfirmation = false; restoreApproved = false; }} onsubmit={() => { void perform(confirmBackupRestore, false, 'send'); }}>
    <p>This replaces the current database with backup {shortId(recoveryIntent.snapshot)}. The server stops while the backup is restored. A verified safety backup and the original database are retained.</p>
    <p>Photos and videos are not restored or deleted. Changes made after this database backup will no longer appear in the restored database.</p>
    <label class="check"><input type="checkbox" bind:checked={restoreApproved} required disabled={busy} />I understand and want to restore this database backup.</label>
    {#snippet actions()}
      <button class="btn" type="button" disabled={busy} onclick={() => { restoreConfirmation = false; restoreApproved = false; }}>Cancel</button>
      <button class="btn danger" type="submit" disabled={busy || !restoreApproved}>Restore Database</button>
    {/snippet}
  </Sheet>
{/if}

<style>
  .embedded { flex: none; border: 1px solid var(--border); border-radius: var(--radius-group); background: var(--panel); overflow: hidden; }
  .embedded .toolbar { height: auto; min-height: 44px; padding: 6px 14px; flex-wrap: wrap; row-gap: 6px; border-bottom-color: var(--border); }
  .embedded .toolbar h1 { font-size: 13px; }
  .embedded .body { padding: 14px; gap: 16px; background: var(--canvas); }
</style>
