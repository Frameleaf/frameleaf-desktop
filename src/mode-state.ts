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
  if (state === 'worker-setup-failed' || state === 'credential-store-unavailable') return 'Computer setup needs attention';
  if (state === 'awaiting-approval') return 'Waiting for administrator approval';
  if (state === 'revoked') return 'This computer’s access was revoked';
  if (!workerSupported) return 'Your server needs a desktop-worker update';
  if (state === 'incompatible') return 'This computer is not compatible with the selected models';
  return 'Preparing this computer';
}
