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
  /** While this computer takes work: how many tasks run now, how many may, and what sets that. */
  atOnce: string | null;
  /** While a task runs: how fast tasks finish here, and how long the last one took. */
  pace: string | null;
  /** What the AI runtime said when it last stopped by itself, shown in small text while there is a problem. */
  diagnostic: string | null;
};
type WorkerSetup = {
  state: string; code?: string | null; control?: string; activeWorkload?: string | null; completedTasks?: number | null; detail?: string | null;
  concurrentTasks?: number | null; concurrentLimit?: string | null; runningTasks?: number | null;
  pace?: { tasks: number; seconds: number } | null; lastTaskMs?: number | null;
};
const count = (value: unknown): value is number => typeof value === 'number' && Number.isSafeInteger(value) && value >= 0;
// What sets how many tasks run at once (the backend's `concurrent_limit`), after "set by".
const limitWords: Readonly<Record<string, string>> = {
  server: 'the Jobs setting on your server',
  memory: 'the free memory on this computer',
  graphics: 'the most Frameleaf runs at once on a graphics card',
  processor: 'this computer’s processor',
  'memory-shortfall': 'Frameleaf, after tasks running together failed on this computer',
  'one-at-a-time': 'your server, which sends each computer one task at a time',
};
function atOnceText(setup: WorkerSetup | null): string | null {
  const taking = !!setup?.activeWorkload || ['working', 'waiting-for-work'].includes(setup?.state ?? '');
  const allowed = setup?.concurrentTasks;
  if (!taking || !count(allowed) || allowed < 1) return null;
  const running = count(setup?.runningTasks) ? setup!.runningTasks! : 0;
  const most = allowed === 1 ? 'one at a time' : `up to ${allowed.toLocaleString()} at once`;
  const by = setup?.concurrentLimit ? limitWords[setup.concurrentLimit] : undefined;
  return `${running.toLocaleString()} running now · ${most}${by ? `, set by ${by}` : ''}`;
}
function duration(ms: number): string {
  if (ms < 10_000) return `${(Math.max(ms, 100) / 1000).toFixed(1)} seconds`;
  if (ms < 120_000) return `${Math.round(ms / 1000)} seconds`;
  return `${Math.round(ms / 60_000)} minutes`;
}
function paceText(setup: WorkerSetup | null): string | null {
  if (!setup?.activeWorkload) return null;
  const pace = setup.pace;
  const last = count(setup.lastTaskMs) ? setup.lastTaskMs : null;
  let rate: string | null = null;
  if (pace && count(pace.tasks) && pace.tasks > 0 && count(pace.seconds) && pace.seconds > 0) {
    const perMinute = (pace.tasks * 60) / pace.seconds;
    rate = perMinute >= 1
      ? `About ${perMinute >= 10 ? Math.round(perMinute).toLocaleString() : Number(perMinute.toFixed(1)).toLocaleString()} tasks a minute`
      : `About 1 task every ${Math.round(1 / perMinute)} minutes`;
  }
  if (rate && last !== null) return `${rate} · the last one took ${duration(last)}`;
  if (rate) return rate;
  return last !== null ? `The last task took ${duration(last)}` : null;
}

// Setup stopped and stays stopped until the person acts: [headline, what to do].
const needsYou: Partial<Record<WorkerReason, readonly [string, string]>> = {
  storage: ['AI files could not be saved', 'Frameleaf could not save AI files on this computer, usually because the disk is full. Free up disk space, then choose Retry Setup. Photos remain available.'],
  download: ['The AI model download failed', 'The selected models could not be downloaded. Check your connection, then choose Retry Setup.'],
  network: ['Your server did not answer', 'This computer could not reach your server. If the server is only reachable on your home network, connect to that network, then choose Retry Setup.'],
  'not-enabled': ['AI work is not shared with this computer', 'Your server’s owner has not turned on AI processing for computers, or has no AI task turned on that this computer can run. A server administrator can change this in the server’s machine learning settings. Then choose Retry Setup.'],
  removed: ['Your server no longer accepts this computer', 'This computer may have been removed from your server, or its date and time may be wrong. Signing out will not fix this. Check the date and time, then choose Retry Setup. If it still fails, ask the person who runs your server to allow this computer again.'],
  runtime: ['The AI runtime is missing', 'The AI runtime that comes with Frameleaf is missing or could not be verified. Install Frameleaf again, then choose Retry Setup. Photos remain available.'],
  restart: ['The AI runtime could not start', 'The AI runtime could not start, or stopped unexpectedly, on this computer. Quit and reopen Frameleaf, then choose Retry Setup.'],
  checks: ['This computer did not pass the model checks', 'Choose Retry Setup to run the checks again. If they keep failing, this computer may not be able to run the selected models.'],
  renewing: ['This computer’s approval ran out', 'This computer’s approval for AI work ran out or changed. Choose Retry Setup to renew it.'],
  update: ['Your server and this app are out of step', 'Your server and this app could not understand each other. Update Frameleaf and your server, then choose Retry Setup.'],
  'setup-mismatch': ['This computer needs setting up again', 'This computer’s AI setup does not match your current sign-in. Sign out and sign in again to set it up again.'],
  'credential-store': ['Unlock your credential store', 'Unlock your computer’s credential store, then choose Retry Setup.'],
};
// Stop reasons whose own words say more than their family's: what happened and what to do.
const ownCopy: Readonly<Record<string, string>> = Object.fromEntries([
  'runtime_qualification_timeout', 'worker_qualification_refused', 'worker_device_refused', 'worker_sign_in_required',
  'model_disk_space_insufficient', 'runtime_store_busy', 'runtime_store_lock_failed',
].map(code => [code, errorCopy(code) ?? '']));
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
function retryingCopy(code: string): string | null {
  if (['runtime_process_stopped', 'runtime_not_ready', 'runtime_prediction_interrupted', 'worker_qualification_restart', 'worker_challenge_busy'].includes(code)) return errorCopy(code);
  if (/^server_http_5\d\d$/.test(code) || code === 'server_http_429') return `${errorCopy(code)!.replace(/ (Try again|Wait a minute, then try again|Check that it is online, then try again)[^.]*\.$/, '.')} Frameleaf keeps trying by itself.`;
  return null;
}
const progress: Readonly<Record<string, string>> = {
  'preparing-runtime': 'Checking the signed runtime included with this app.',
  'preparing-models': 'Verifying the selected model files. You can keep using Photos while this runs.',
  qualifying: 'Running the selected models locally and checking the results with your server.',
  qualified: 'The selected models passed this computer’s checks.',
  'starting-worker': 'Starting the checked models locally before requesting work from your server.',
};

export function workerView({ connectionState, connectionCode, workerSupported, computer, setup }: {
  connectionState: string; connectionCode?: string | null; workerSupported: boolean; computer: string; setup: WorkerSetup | null;
}): WorkerView {
  const state = setup?.state || connectionState || '';
  const code = setup?.code ?? null;
  const control = setup?.control ?? 'running';
  const done = setup?.completedTasks;
  const finished = count(done)
    ? `${done.toLocaleString()} ${done === 1 ? 'task' : 'tasks'} finished since AI processing last started`
    : null;
  const label = workerStatus({ state, workerSupported });
  const view = (headline: string, detail: string, attention: WorkerAttention, pill: WorkerView['pill'], action: WorkerAction = null, reference: string | null = null): WorkerView =>
    ({
      headline, detail, reference, attention, action, pill, finished,
      atOnce: attention === 'none' ? atOnceText(setup) : null,
      pace: attention === 'none' ? paceText(setup) : null,
      diagnostic: attention === 'none' ? null : setup?.detail?.trim() || null,
    });
  const needs = (headline: string, detail: string, action: WorkerAction = null, reference: string | null = null) =>
    view(headline, detail, 'needs-you', { label: 'Needs you', tone: 'bad' }, action, reference);
  const waits = (headline: string, detail: string) => view(headline, detail, 'waiting', { label: 'Waiting', tone: 'wait' });

  // The connection itself is the problem: nothing below can run until it is fixed.
  if (connectionState === 'identity-changed') return needs('Server identity changed', 'Processing is stopped. Verify the server before signing in again.');
  if (connectionState === 'offline') return needs('Server unavailable', 'Your server did not answer when Frameleaf last checked. If it is only reachable on your home network, connect to that network, then choose Check Again.', 'check-server');
  if (connectionState === 'enrollment-failed') {
    const why = connectionCode ? errorCopy(connectionCode) : null;
    return needs('Computer setup needs attention', why ? `Photo sign-in succeeded, but this computer could not be enrolled. ${why}` : 'Photo sign-in succeeded, but this computer could not be enrolled. Reopen the app to retry setup.');
  }

  if (setup?.activeWorkload) {
    const most = count(setup.concurrentTasks) && setup.concurrentTasks > 1 ? `up to ${setup.concurrentTasks.toLocaleString()} selected AI tasks at once` : 'one selected AI task at a time';
    return view('Processing on this computer', `This computer processes ${most} while power, network and memory allow.`, 'none', { label: 'Working', tone: 'ok' });
  }
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
      // A reason with words of its own (a busy server, a runtime that stopped) says them.
      return waits(headline, (code && retryingCopy(code)) || detail);
    }
    case 'no-eligible-work':
      if (code === 'server_update_required') return waits('Your server needs an update', errorCopy(code)!);
      return waits(label, `${errorCopy('worker_no_eligible_workloads')!} Frameleaf checks again every few minutes.`);
    case 'model-download-required':
      return needs(label, 'The selected models need downloading. Downloading waits for your permission on metered or unclassified networks. Choose Download Models to allow it.', 'download-models');
    case 'setup-needs-attention': {
      const history = runtimeRecoveryMessage(code);
      if (history) return needs('AI processing needs recovery', history, 'retry-setup');
      // Only a newer macOS changes this, so there is nothing to retry.
      if (code === 'runtime_os_unsupported') return needs('This Mac’s macOS is too old for AI processing', errorCopy(code)!);
      // This build ships without a runtime: retrying, or installing it again, would not change that.
      if (code === 'runtime_pack_unavailable') return needs('AI processing is not included in this version', errorCopy(code)!);
      if (code === 'runtime_crash_loop') return needs('The AI runtime keeps stopping', errorCopy(code)!, 'retry-setup');
      if (code === 'clock_invalid') return needs('This computer’s date and time look wrong', `${errorCopy(code)!} Then choose Retry Setup.`, 'retry-setup');
      const reason = workerReason(code);
      const known = reason && needsYou[reason];
      // The headline names the kind of problem; the detail is this code's own.
      if (known) return needs(known[0], (code && ownCopy[code]) || known[1], 'retry-setup');
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
