import { describeError, errorCopy, workerReason, type WorkerReason } from './errors.ts';

export type DesktopMode = 'local-server' | 'client-worker';
export function safeMode(value: unknown): DesktopMode | null {
  return value === 'local-server' || value === 'client-worker' ? value : null;
}
export function workerStatus({ state, workerSupported }: { state: string; workerSupported: boolean }): string {
  if (state === 'preparing-runtime') return 'Preparing the AI runtime';
  if (state === 'preparing-models') return 'Preparing selected models';
  if (state === 'model-download-required') return 'Selected models need downloading';
  if (state === 'qualifying') return 'Checking this computer’s models';
  if (state === 'qualified') return 'Models qualified';
  if (state === 'starting-worker') return 'Starting this computer’s AI worker';
  if (state === 'working') return 'Checking for AI work';
  if (state === 'waiting-for-work') return 'Waiting for AI work';
  if (state === 'reconnecting') return 'Reconnecting to your server';
  if (state === 'pausing') return 'Finishing the current task';
  if (state === 'stopped') return 'AI processing stopped';
  if (state === 'paused') return 'AI processing paused';
  if (state === 'setup-needs-attention') return 'Computer setup needs attention';
  if (state === 'no-eligible-work') return 'No AI work is assigned to this computer';
  if (state === 'worker-setup-failed' || state === 'credential-store-unavailable') return 'Computer setup needs attention';
  if (state === 'awaiting-approval') return 'Waiting for administrator approval';
  if (!workerSupported) return 'Your server needs a desktop-worker update';
  if (state === 'incompatible') return 'This computer is not compatible with the selected models';
  return 'Preparing this computer';
}

export function runtimeRecoveryMessage(code: string | null): string | null {
  switch (code) {
    case 'runtime_epoch_credential_missing':
    case 'runtime_epoch_identity_changed':
    case 'runtime_epoch_recovery_required':
    case 'runtime_epoch_record_invalid':
    case 'runtime_epoch_binding_invalid':
    case 'runtime_epoch_identity_invalid':
      return 'AI processing needs recovery because this computer’s saved runtime history could not be verified. Photos remain available.';
    case 'runtime_epoch_rollback':
    case 'runtime_epoch_reused':
      return 'This AI runtime was rejected because it does not match this computer’s accepted runtime history. Photos remain available.';
    default:
      return null;
  }
}

// ---- what the AI processing card says -------------------------------------------------------------
/** 'waiting' continues by itself; 'needs-you' stays as it is until somebody does something. */
export type WorkerAttention = 'none' | 'waiting' | 'needs-you';
export type WorkerAction = 'retry-setup' | 'download-models' | 'check-approval' | 'check-server' | null;
export type WorkerView = {
  headline: string;
  detail: string;
  /** The code of a failure this app has no words for, shown in small text so support can identify it. */
  reference: string | null;
  attention: WorkerAttention;
  action: WorkerAction;
  pill: { label: string; tone: 'ok' | 'wait' | 'off' | 'bad' };
  /** Tasks this computer finished since AI processing last started, when the backend reports it. */
  finished: string | null;
};
type WorkerSetup = { state: string; code?: string | null; control?: string; activeWorkload?: string | null; completedTasks?: number | null };

// Setup stopped and stays stopped until the person acts: [headline, what to do].
const needsYou: Partial<Record<WorkerReason, readonly [string, string]>> = {
  storage: ['AI files could not be saved', 'Frameleaf could not save AI files on this computer, usually because the disk is full. Free up disk space, then choose Retry Setup. Photos remain available.'],
  download: ['The AI model download failed', 'The selected models could not be downloaded. Check your connection, then choose Retry Setup.'],
  network: ['Your server did not answer', 'This computer could not reach your server. If the server is only reachable on your home network, connect to that network, then choose Retry Setup.'],
  'not-enabled': ['AI work is not shared with this computer', 'Your server’s owner has not turned on AI processing for computers, or changed how it is shared. A server administrator can change this in the server’s machine learning settings. Then choose Retry Setup.'],
  removed: ['Your server no longer accepts this computer', 'This computer may have been removed from your server, or its date and time may be wrong. Signing out will not fix this. Check the date and time, then choose Retry Setup. If it still fails, ask the person who runs your server to allow this computer again.'],
  runtime: ['The AI runtime is missing', 'The AI runtime that comes with Frameleaf is missing or could not be verified. Install Frameleaf again, then choose Retry Setup. Photos remain available.'],
  restart: ['The AI runtime could not start', 'The AI runtime could not start, or stopped unexpectedly, on this computer. Quit and reopen Frameleaf, then choose Retry Setup.'],
  checks: ['This computer did not pass the model checks', 'Choose Retry Setup to run the checks again. If they keep failing, this computer may not be able to run the selected models.'],
  renewing: ['This computer’s approval ran out', 'This computer’s approval for AI work ran out or changed. Choose Retry Setup to renew it.'],
  update: ['Your server and this app are out of step', 'Your server and this app could not understand each other. Update Frameleaf and your server, then choose Retry Setup.'],
  'setup-mismatch': ['This computer needs setting up again', 'This computer’s AI setup does not match your current sign-in. Sign out and sign in again to set it up again.'],
  'credential-store': ['Unlock your credential store', 'Unlock your computer’s credential store, then choose Retry Setup.'],
};
// The worker is retrying by itself: [headline, what is happening].
const retrying: Partial<Record<WorkerReason, readonly [string, string]>> = {
  network: ['Reconnecting to your server', 'Your server is not answering. If it is only reachable on your home network, AI processing continues when this computer is back on that network. Frameleaf keeps trying by itself.'],
  download: ['Retrying the model download', 'The model download was interrupted. Frameleaf tries again by itself.'],
  renewing: ['Renewing this computer’s approval', 'This computer’s approval for AI work ran out. Frameleaf is renewing it by itself.'],
  restart: ['Restarting the AI runtime', 'The AI runtime stopped unexpectedly. Frameleaf is starting it again by itself.'],
};
// Paused until this computer can take work again.
const pausedFor: Partial<Record<WorkerReason, string>> = {
  memory: 'Waiting for free memory',
  power: 'Waiting for power',
  metered: 'Waiting for an unmetered network',
  resumed: 'Rechecking after sleep',
};
const progress: Readonly<Record<string, string>> = {
  'preparing-runtime': 'Checking the signed runtime included with this app.',
  'preparing-models': 'Verifying the selected model files. You can keep using Photos while this runs.',
  qualifying: 'Running the selected models locally and checking the results with your server.',
  qualified: 'The selected models passed this computer’s checks.',
  'starting-worker': 'Starting the checked models locally before requesting work from your server.',
};

export function workerView({ connectionState, workerSupported, computer, setup }: {
  connectionState: string; workerSupported: boolean; computer: string; setup: WorkerSetup | null;
}): WorkerView {
  const state = setup?.state || connectionState || '';
  const code = setup?.code ?? null;
  const control = setup?.control ?? 'running';
  const count = setup?.completedTasks;
  const finished = typeof count === 'number' && Number.isSafeInteger(count) && count >= 0
    ? `${count.toLocaleString()} ${count === 1 ? 'task' : 'tasks'} finished since AI processing last started`
    : null;
  const label = workerStatus({ state, workerSupported });
  const view = (headline: string, detail: string, attention: WorkerAttention, pill: WorkerView['pill'], action: WorkerAction = null, reference: string | null = null): WorkerView =>
    ({ headline, detail, reference, attention, action, pill, finished });
  const needs = (headline: string, detail: string, action: WorkerAction = null, reference: string | null = null) =>
    view(headline, detail, 'needs-you', { label: 'Needs you', tone: 'bad' }, action, reference);
  const waits = (headline: string, detail: string) => view(headline, detail, 'waiting', { label: 'Waiting', tone: 'wait' });

  // The connection itself is the problem: nothing below can run until it is fixed.
  if (connectionState === 'identity-changed') return needs('Server identity changed', 'Processing is stopped. Verify the server before signing in again.');
  if (connectionState === 'offline') return needs('Server unavailable', 'Your server did not answer when Frameleaf last checked. If it is only reachable on your home network, connect to that network, then choose Check Again.', 'check-server');
  if (connectionState === 'enrollment-failed') return needs('Computer setup needs attention', 'Photo sign-in succeeded, but this computer could not be enrolled. Reopen the app to retry setup.');

  if (setup?.activeWorkload) return view('Processing on this computer', 'This computer processes one selected AI task at a time while power, network and memory allow.', 'none', { label: 'Working', tone: 'ok' });
  switch (state) {
    // The backend reports 'working' while it asks the server for a task and 'waiting-for-work' between
    // asks; only activeWorkload (above) means a task is running.
    case 'working':
    case 'waiting-for-work':
      return view('Waiting for AI work', 'Connected and ready. This computer starts as soon as your server sends AI work.', 'none', { label: 'Idle', tone: 'ok' });
    case 'pausing':
      return view(label, 'The current bounded task will finish, then this computer will stop requesting work.', 'none', { label: 'Finishing', tone: 'wait' });
    case 'stopped':
      return view(label, 'AI processing is stopped on this computer. Resume whenever you are ready. Photos remain available.', 'none', { label: 'Stopped', tone: 'off' });
    case 'paused': {
      const reason = workerReason(code);
      if (reason === 'by-you' || (!code && control === 'paused')) return view(label, errorCopy('user_paused')!, 'none', { label: 'Paused', tone: 'off' });
      return waits((reason && pausedFor[reason]) ?? label, `${(code && errorCopy(code)) ?? 'AI processing is paused.'} It continues by itself.`);
    }
    case 'reconnecting': {
      const reason = workerReason(code);
      const [headline, detail] = (reason && retrying[reason]) ?? [label, 'Waiting to reconnect to your server. This computer will recheck its session, models and resources before processing again.'];
      return waits(headline, detail);
    }
    case 'no-eligible-work':
      return waits(label, `${errorCopy('worker_no_eligible_workloads')!} Frameleaf checks again every few minutes.`);
    case 'model-download-required':
      return needs(label, 'The selected models need downloading. Downloading waits for your permission on metered or unclassified networks. Choose Download Models to allow it.', 'download-models');
    case 'setup-needs-attention': {
      const history = runtimeRecoveryMessage(code);
      if (history) return needs('AI processing needs recovery', history, 'retry-setup');
      // Only a newer macOS changes this, so there is nothing to retry.
      if (code === 'runtime_os_unsupported') return needs('This Mac’s macOS is too old for AI processing', errorCopy(code)!);
      const reason = workerReason(code);
      // This build ships without a runtime: installing it again would not change that.
      const known = code === 'runtime_pack_unavailable' ? null : reason && needsYou[reason];
      if (known) return needs(known[0], known[1], 'retry-setup');
      const { message, reference } = describeError(code ?? '', 'AI setup could not finish. Photos remain available. Retry setup when your server and network are ready.');
      return needs(label, message, 'retry-setup', reference);
    }
    case 'awaiting-approval':
      return needs(label, 'An administrator on your server needs to approve this computer for AI processing. Choose Check Approval once they have.', 'check-approval');
    case 'worker-setup-failed':
      return needs(label, 'Photos are available, but this computer could not complete worker setup. Reopen the app to retry.');
    case 'credential-store-unavailable':
      return needs(label, 'Unlock your computer’s credential store and reopen the app to finish setup.');
  }
  const preparing = Object.hasOwn(progress, state);
  if (state === 'unsupported-server' || (!preparing && !workerSupported)) return needs('Your server needs a desktop-worker update','Your server does not accept AI processing from this computer yet. Update the server. Photos remain available.');
  return view(label, preparing ? progress[state]! : `Processing starts only after the selected models pass qualification on this ${computer}. Pausing finishes the current task first.`, 'none',
    preparing ? { label: state === 'qualified' ? 'Ready' : 'Setting up', tone: state === 'qualified' ? 'ok' : 'wait' }
      : control === 'paused' ? { label: 'Paused', tone: 'off' } : control === 'stopped' ? { label: 'Stopped', tone: 'off' } : { label: 'Not running', tone: 'off' });
}

/** Why one kind of AI work is unavailable on this computer, when the worker reported a reason. */
export function workloadReason(code: string | null | undefined): string | null {
  return code ? errorCopy(code) : null;
}
