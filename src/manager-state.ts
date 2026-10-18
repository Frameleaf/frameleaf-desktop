export type Control = 'start' | 'stop' | 'restart' | 'backup';
export function localProfilePending(state: string | undefined, requesting: boolean): boolean {
  return requesting || state === 'provisioning';
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
    manager_unreachable_or_certificate_invalid: 'Could not securely reach Manager. Check its address, connection and certificate, then check the existing request before starting another.',
    manager_pairing_interrupted: 'Pairing was interrupted. Check Manager and try pairing again.',
    manager_pair_again: 'This computer’s Manager access expired or was revoked. Disconnect and pair again with Manager.',
    manager_pairing_expired: 'This computer’s Manager access expired. Disconnect and pair again with Manager.',
    manager_scope_denied: 'This Manager grant does not allow that action.',
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
    manager_origin_invalid: 'Enter only Manager’s HTTPS address, without a path or sign-in details.',
    server_requires_https_origin: 'Enter only Manager’s HTTPS address, without a path or sign-in details.',
    server_address_invalid: 'Enter a valid Manager HTTPS address.',
    manager_rate_limited: 'Manager has temporarily limited requests. Wait before trying again.',
    credential_store_locked_or_unavailable: 'Unlock your computer’s secure credential store, then try again.',
    credential_store_unavailable: 'Your computer’s secure credential store is unavailable. Manager access was not saved.',
    credential_record_invalid: 'The saved Manager record could not be read. Check your computer’s secure credential store.',
    recovery_key_required: 'Unlock the backup repository in Manager before creating a database backup.',
    other_media_writer_detected: 'Another application may write to this library. Resolve that condition in Manager.',
    installation_changed: 'The installation changed. Review it in Manager before retrying.',
    operation_interrupted: 'This operation was interrupted. Check its state, then resume when ready.',
  };
  return Object.hasOwn(messages, code) ? messages[code]! : 'Manager could not finish this request. Check its operation state before retrying.';
}
