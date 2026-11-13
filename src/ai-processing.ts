export type AiQueue = {
  name: string;
  state?: string | null;
  unavailable?: boolean | null;
  isPaused: boolean;
  heldForNight?: boolean | null;
  resumesAt?: string | null;
  active: number;
  waiting: number;
  processed: number;
  total: number;
};

export type ProcessingOrder = {
  order: string[];
  workloads: { workload: string; sources: string[] }[];
};

export type LibraryAiProcessing = { queues: AiQueue[] | null; processingOrder: ProcessingOrder | null };

export const queueNames: Readonly<Record<string, string>> = {
  faceDetection: 'Find faces',
  facialRecognition: 'Group faces',
  smartSearch: 'Smart search',
  ocr: 'Text recognition',
  imageEnrichment: 'Photo enrichment',
  imageDescription: 'Photo descriptions',
  nsfwDetection: 'Content safety',
};

export function queueProgress(queue: AiQueue): { finished: string; counts: string; percent: number | null } | null {
  if (queue.unavailable || ![queue.processed, queue.active, queue.waiting, queue.total]
    .every(value => Number.isSafeInteger(value) && value >= 0)
    || queue.processed + queue.active + queue.waiting !== queue.total) return null;
  return {
    finished: `${queue.processed.toLocaleString()} of ${queue.total.toLocaleString()} finished`,
    counts: `${queue.active.toLocaleString()} running · ${queue.waiting.toLocaleString()} waiting`,
    percent: queue.total > 0 ? Math.floor(queue.processed / queue.total * 100) : null,
  };
}

export function queueState(queue: AiQueue): string {
  if (queue.unavailable) return 'Status unknown';
  if (queue.heldForNight) {
    const time = queue.resumesAt ? Date.parse(queue.resumesAt) : NaN;
    return Number.isFinite(time)
      ? `Waiting for quiet hours · resumes ${new Date(time).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' })}`
      : 'Waiting for quiet hours';
  }
  if (queue.isPaused) return 'Paused on the Library';
  switch (queue.state) {
    case 'running': return 'Processing';
    case 'waiting': return 'Waiting to start';
    case 'blocked': return 'Waiting for a dependency';
    case 'delayed': return 'Scheduled for later';
    case 'retrying': return 'Waiting to retry';
    case 'unavailable': return 'No worker available';
    default: return 'Wait reason unknown';
  }
}

export function processingPlaces(sources: string[]): string {
  if (!sources.length) return 'Off';
  const names: Record<string, string> = { local: 'Library server', desktops: 'Your computers', cloud: 'Frameleaf Cloud' };
  return sources.map(source => names[source] ?? 'Unknown').join(' → ');
}

/** FD-52: the provider a workload runs on here, as the backend chose it. */
export type WorkloadProvider = { workload: string; provider: string; fallback: string | null };

export const providerNames: Readonly<Record<string, string>> = {
  CPUExecutionProvider: 'CPU',
  CoreMLExecutionProvider: 'CoreML',
  CUDAExecutionProvider: 'NVIDIA CUDA',
  OpenVINOExecutionProvider: 'Intel OpenVINO',
};

/** Why the processor stands in for a GPU provider this app could have used. */
function fallbackReason(code: string): string {
  if (code === 'provider_device_ineligible') return 'this computer has no supported GPU';
  if (code === 'provider_driver_outdated') return 'the NVIDIA driver is too old; update it to use the GPU';
  if (code === 'provider_slower') return 'the processor is faster for this on this computer';
  if (code === 'provider_speed_unknown') return 'its speed could not be measured this time';
  if (code === 'worker_qualification_refused' || code.startsWith('workload_desktop_')) return 'the Library did not accept it';
  if (code.startsWith('runtime_qualification_') || code === 'runtime_process_stopped' || code === 'runtime_not_ready' || code === 'provider_failed')
    return 'it did not pass its check on this computer';
  return 'it could not be prepared on this computer';
}

/** "Runs on CoreML", or "Runs on CPU (GPU acceleration is not used: …)" after a fallback. Empty when the backend has not chosen. */
export function workloadProvider(providers: WorkloadProvider[] | null | undefined, workload: string): string {
  const chosen = providers?.find(item => item.workload === workload);
  if (!chosen) return '';
  const name = providerNames[chosen.provider];
  if (!name) return '';
  return chosen.fallback ? `Runs on ${name} (GPU acceleration is not used: ${fallbackReason(chosen.fallback)})` : `Runs on ${name}`;
}
