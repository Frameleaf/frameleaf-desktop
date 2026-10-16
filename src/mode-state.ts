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
  if (state === 'paused') return 'AI processing paused';
  if (state === 'setup-needs-attention') return 'Computer setup needs attention';
  if (state === 'worker-setup-failed' || state === 'credential-store-unavailable') return 'Computer setup needs attention';
  if (state === 'awaiting-approval') return 'Waiting for administrator approval';
  if (state === 'revoked') return 'This computer’s access was revoked';
  if (!workerSupported) return 'Your server needs a desktop-worker update';
  if (state === 'incompatible') return 'This computer is not compatible with the selected models';
  return 'Preparing this computer';
}
