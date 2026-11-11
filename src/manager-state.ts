export type Control = 'start' | 'stop' | 'restart' | 'backup';
export function localProfilePending(state: string | undefined, requesting: boolean): boolean {
  return requesting || state === 'provisioning';
}
export function profileSetupCopy(authorization: boolean) {
  return authorization ? {
    pending: 'Finish or dismiss the system authorization request, then check installation to continue.',
    quit: 'Finish or dismiss the system authorization request before quitting.',
    preparation: 'Your system may ask for administrator authorization to create private server folders for your account. Frameleaf does not receive your administrator password. This step does not start the photo server.',
  } : {
    pending: 'Frameleaf is preparing your private server profile. Wait for setup to finish.',
    quit: 'Wait for server profile preparation to finish before quitting.',
    preparation: 'Prepare private server folders for your Windows account. This step does not start the photo server.',
  };
}
export type ManagerView = {
  origin: string; managerId: string; deviceId: string; installationId: string;
  expiresAt: number; scopes: string[]; certificateSha256: string | null;
};
export type Operation = {
  id: string; kind: Control; state: 'running' | 'interrupted' | 'failed' | 'complete';
  step: string | null; completed: string[]; error: string | null; createdAt: number; updatedAt: number;
};
export type ManagerStatus = {
  manager: { id: string; origin: string }; installation: { id: string; name?: string; release: string; port: number }; operations: Operation[];
};
export type Intent = Pick<ManagerView, 'origin' | 'managerId' | 'deviceId' | 'installationId'> & { action: Control; key: string; id?: string };
const controls: Control[] = ['start', 'stop', 'restart', 'backup'];
const uuid = (value: unknown): value is string => typeof value === 'string' && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(value);
export function intentKey(manager: ManagerView) { return `frameleaf.manager-control:${manager.managerId}:${manager.installationId}`; }
export function restoreIntent(raw: string | null, manager: ManagerView): Intent | null {
  try {
    if (!raw || raw.length > 2048) return null;
    const value = JSON.parse(raw);
    if (!value || Array.isArray(value) || typeof value !== 'object' || Object.keys(value).some(key => !['origin','managerId','deviceId','installationId','action','key','id'].includes(key))) return null;
    if (value.origin !== manager.origin || value.managerId !== manager.managerId || value.deviceId !== manager.deviceId || value.installationId !== manager.installationId || !controls.includes(value.action) || !uuid(value.key) || (value.id !== undefined && !uuid(value.id))) return null;
    return value;
  } catch { return null; }
}
export function controlIntent(manager: ManagerView, action: Control, prior: Intent | null): Intent {
  if (!manager.scopes.includes(action)) throw Error('manager_scope_denied');
  if (prior) {
    if (prior.action !== action || !restoreIntent(JSON.stringify(prior), manager)) throw Error('manager_operation_pending');
    return prior;
  }
  return { origin: manager.origin, managerId: manager.managerId, deviceId: manager.deviceId, installationId: manager.installationId, action, key: crypto.randomUUID() };
}
export function managerError(error: unknown): string {
  const code = error instanceof Error ? error.message : typeof error === 'string' ? error : '';
  const messages: Record<string,string> = {
    manager_already_paired: 'Disconnect the paired Manager before authorizing another installation.',
    manager_already_claimed: 'Manager is already configured. Retry with its existing password.',
    manager_claim_interrupted: 'Manager setup could not be confirmed. Retry with the same password; an existing administrator will not be replaced.',
    manager_claim_proof_changed: 'The private Manager setup proof could not be verified. Check the local installation before retrying.',
    manager_login_details_invalid: 'Enter your Manager password. New Manager passwords need at least 14 characters.',
    native_manager_not_ready: 'Prepare local Manager before authorizing management.',
    native_host_busy: 'Local management is starting or stopping. Wait for that step to finish.',
    manager_recent_auth_required: 'Enter your Manager password to authorize this action.',
    manager_invalid_credentials: 'The Manager password was not accepted. Try again.',
    manager_unreachable_or_certificate_invalid: 'Could not reach Manager. Check its address, connection and certificate, then check the existing request before starting another.',
    manager_pairing_interrupted: 'Pairing was interrupted. Check Manager and try pairing again.',
    manager_pair_again: 'This computer’s Manager access expired or was revoked. Disconnect and pair again with Manager.',
    manager_pairing_expired: 'This computer’s Manager access expired. Disconnect and pair again with Manager.',
    manager_scope_denied: 'This Manager grant does not allow that action.',
    manager_recovery_approval_required: 'Disconnect Manager, then pair again with backup recovery permission.',
    manager_recovery_unavailable: 'Backup review needs an updated native Frameleaf Manager.',
    manager_review_busy: 'Another backup review is still running. Check its existing request.',
    manager_review_changed: 'This review could not be matched to the current backup and installation.',
    manager_review_failed: 'The backup could not be verified for recovery.',
    manager_backup_unavailable: 'Database backups are not available in this Manager.',
    manager_restore_pending: 'Keep the existing database restore request until its outcome is confirmed.',
    manager_restore_review_required: 'Review this backup again before confirming a database restore.',
    native_restore_review_expired: 'The backup review expired before this restore was accepted. Review the backup again.',
    native_restore_review_not_ready: 'This backup review is not ready. Check it before restoring.',
    native_restore_runtime_change_required: 'This backup needs a different server runtime. Keep the current library and update the recovery runtime first.',
    manager_review_pending: 'Finish checking the current review before choosing another backup.',
    manager_operation_pending: 'Resolve the existing request before starting another action.',
    manager_operation_in_progress: 'Another Manager operation is active. Resolve it in Manager before starting a new action.',
    manager_operation_not_recoverable: 'This operation cannot be resumed now. Check its latest state in Manager.',
    manager_local_state_unavailable: 'The request receipt could not be saved on this computer. Keep this window open and check the existing operation.',
    manager_installation_changed: 'Manager now identifies a different installation. Verify it before pairing again.',
    manager_pairing_binding_changed: 'Manager returned different pairing details. Pairing stopped; verify the Manager installation.',
    manager_device_changed: 'This computer’s device key changed. Revoke its old Manager access with your Manager password, then pair again.',
    manager_certificate_invalid: 'Enter one valid public PEM certificate for Manager.',
    manager_certificate_approval_changed: 'The certificate changed after approval. Review its fingerprint again.',
    manager_certificate_approval_required: 'Review and approve this Manager certificate before pairing.',
    manager_grant_not_saved_revoke_in_manager: 'Manager access could not be saved. Revoke the newly created grant in Manager before retrying.',
    manager_http_certificate_invalid: 'Certificates apply to HTTPS connections. Use HTTP without a certificate or enter an HTTPS address.',
    manager_origin_invalid: 'Enter only Manager’s HTTP or HTTPS address, without a path or sign-in details.',
    server_requires_https_origin: 'Enter only Manager’s HTTP or HTTPS address, without a path or sign-in details.',
    server_address_invalid: 'Enter a valid Manager HTTPS address.',
    manager_rate_limited: 'Manager has temporarily limited requests. Wait before trying again.',
    credential_device_unlock_required: 'Your existing Frameleaf device key is locked. Retry this action and approve access on your Mac.',
    credential_unlock_required: 'Unlock your saved sign-in with Touch ID or your Mac password.',
    credential_store_locked_or_unavailable: 'Unlock your computer’s secure credential store, then try again.',
    credential_store_unavailable: 'Your computer’s secure credential store is unavailable. Manager access was not saved.',
    credential_record_invalid: 'The saved Manager record could not be read. Check your computer’s secure credential store.',
    native_runtime_busy: 'The server is starting or stopping. Let it finish before retrying the backup.',
    native_backup_owner_unavailable: 'The server process state needs review. Check Manager before retrying this backup.',
    native_backup_owner_changed: 'Server ownership changed during backup recovery. Check Manager before resuming.',
    native_shutdown_unconfirmed: 'Database shutdown was not confirmed, so this operation stays locked. Check its state, then resume to verify shutdown.',
    native_backup_journal_invalid: 'Backup recovery records could not be verified. Keep the existing operation and review it in Manager.',
    native_backup_verification_failed: 'The backup could not be verified. The operation stays locked; review it before resuming.',
    native_checkpoint_unavailable: 'The database checkpoint is unavailable. Check the native runtime and operation state in Manager.',
    native_library_identity_invalid: 'The library recovery identity could not be verified. Review the installed profile in Manager.',
    native_backup_engine_changed: 'The installed backup engine could not be verified. Repair the signed runtime before retrying.',
    recovery_key_required: 'Unlock the backup repository in Manager before creating a database backup.',
    other_media_writer_detected: 'Another application may write to this library. Resolve that condition in Manager.',
    installation_changed: 'The installation changed. Review it in Manager before retrying.',
    operation_interrupted: 'This operation was interrupted. Check its state, then resume when ready.',
  };
  return Object.hasOwn(messages, code) ? messages[code]! : 'Manager could not finish this request. Check its operation state before retrying.';
}

export type BackupEntry = { id: string; time: string };
export type BackupReviewIntent = Pick<ManagerView, 'origin' | 'managerId' | 'deviceId' | 'installationId'> & { snapshot: string; key: string };
export type BackupReview = { id: string; snapshot: string; installationId: string; expires: number } & (
  { state: 'preparing' | 'failed' | 'expired' | 'interrupted' } |
  { state: 'prepared'; libraryId: string; release: string; targetRelease: string; createdAt: number; mediaIncluded: false; requiresRuntimeChange: boolean }
);
export function backupReviewKey(manager: ManagerView) { return `frameleaf.manager-review:${manager.managerId}:${manager.installationId}`; }
export function restoreBackupReview(raw: string | null, manager: ManagerView): BackupReviewIntent | null {
  try {
    if (!raw || raw.length > 2048) return null;
    const value = JSON.parse(raw);
    if (!value || typeof value !== 'object' || Array.isArray(value) || Object.keys(value).sort().join(',') !== 'deviceId,installationId,key,managerId,origin,snapshot') return null;
    if (value.origin !== manager.origin || value.managerId !== manager.managerId || value.deviceId !== manager.deviceId || value.installationId !== manager.installationId || !uuid(value.key) || value.key === '00000000-0000-0000-0000-000000000000' || typeof value.snapshot !== 'string' || !/^[a-f0-9]{64}$/.test(value.snapshot)) return null;
    return value;
  } catch { return null; }
}
export function backupReviewIntent(manager: ManagerView, snapshot: string, prior: BackupReviewIntent | null): BackupReviewIntent {
  if (!manager.scopes.includes('restore')) throw Error('manager_scope_denied');
  if (typeof snapshot !== 'string' || !/^[a-f0-9]{64}$/.test(snapshot)) throw Error('manager_request_invalid');
  if (prior) {
    if (prior.snapshot !== snapshot || !restoreBackupReview(JSON.stringify(prior), manager)) throw Error('manager_review_pending');
    return prior;
  }
  return { origin: manager.origin, managerId: manager.managerId, deviceId: manager.deviceId, installationId: manager.installationId, snapshot, key: crypto.randomUUID() };
}

export type BackupRestoreIntent = BackupReviewIntent & { reviewId: string; id?: string };
export type BackupRestoreOperation = Omit<Operation, 'kind'> & { kind: 'restore' };
export function databaseRecoveryReady(operation: BackupRestoreOperation | null): boolean {
  return operation?.state === 'complete' && operation.error === null && operation.completed.includes('native-restore-started');
}
export function backupRestoreKey(manager: ManagerView) { return `frameleaf.manager-restore:${manager.managerId}:${manager.installationId}`; }
export function parseBackupRestoreIntent(raw: string | null, manager: ManagerView): BackupRestoreIntent | null {
  try {
    if (!raw || raw.length > 2048) return null;
    const value = JSON.parse(raw);
    if (!value || Array.isArray(value) || typeof value !== 'object' || !uuid(value.reviewId) || value.reviewId === '00000000-0000-0000-0000-000000000000' || (value.id !== undefined && (!uuid(value.id) || value.id === '00000000-0000-0000-0000-000000000000'))) return null;
    const { reviewId, id, ...binding } = value;
    if (!restoreBackupReview(JSON.stringify(binding), manager)) return null;
    return value;
  } catch { return null; }
}
export function createBackupRestoreIntent(manager: ManagerView, review: BackupReview, prior: BackupRestoreIntent | null): BackupRestoreIntent {
  if (!manager.scopes.includes('restore')) throw Error('manager_scope_denied');
  if (prior) {
    if (prior.reviewId !== review.id || prior.snapshot !== review.snapshot || !parseBackupRestoreIntent(JSON.stringify(prior), manager)) throw Error('manager_restore_pending');
    return prior;
  }
  if (review.state !== 'prepared' || review.expires <= Date.now() || review.installationId !== manager.installationId || review.requiresRuntimeChange || !uuid(review.id) || review.id === '00000000-0000-0000-0000-000000000000') throw Error('manager_restore_review_required');
  return { ...backupReviewIntent(manager, review.snapshot, null), reviewId: review.id };
}
