import { explainError } from './errors.ts';

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
/** `other` is an operation kind this Desktop version does not know. */
export type Operation = {
  id: string; kind: Control | 'other'; state: 'running' | 'interrupted' | 'failed' | 'complete';
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
  // Wording for codes that mean something narrower in Manager (its address, its saved access, its operations)
  // than their shared copy in errors.ts says. Every other code takes the shared copy.
  const messages: Record<string,string> = {
    server_requires_https_origin: 'Enter only Manager’s HTTP or HTTPS address, without a path or sign-in details.',
    server_address_invalid: 'Enter a valid Manager HTTPS address.',
    manager_response_too_large: 'Manager sent more data than Desktop accepts. Update Desktop, or review this in Manager.',
    credential_store_locked_or_unavailable: 'Unlock your computer’s secure credential store, then try again.',
    credential_store_unavailable: 'Your computer’s secure credential store is unavailable. Manager access was not saved.',
    credential_record_invalid: 'The saved Manager record could not be read. Check your computer’s secure credential store.',
    recovery_key_required: 'Unlock the backup repository in Manager before creating a database backup.',
    other_media_writer_detected: 'Another application may write to this library. Resolve that condition in Manager.',
    installation_changed: 'The installation changed. Review it in Manager before retrying.',
    operation_interrupted: 'This operation was interrupted. Check its state, then resume when ready.',
  };
  return Object.hasOwn(messages, code) ? messages[code]! : explainError(code, 'Manager could not finish this request. Check its operation state before retrying.');
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
