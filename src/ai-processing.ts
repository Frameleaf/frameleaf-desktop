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

/** FD-60: the GPU runtime pack this computer can download, as the backend reports it. */
export type AcceleratedPack = {
  state: 'none' | 'available' | 'downloading' | 'unpacking' | 'ready' | 'failed' | string;
  provider: string | null; bytes: number; receivedBytes: number; code: string | null; declined: boolean; metered: boolean;
};
export type AcceleratedPackAction = 'download' | 'decline' | 'cancel' | 'retry-provider';
export type AcceleratedPackView = {
  title: string; detail: string;
  /** Percent of the download received, while one runs. */
  progress: number | null;
  /** The first action is the main one. */
  actions: AcceleratedPackAction[];
  tone: 'ok' | 'wait' | 'bad' | 'off';
};

const deviceNames: Readonly<Record<string, string>> = {
  CUDAExecutionProvider: 'NVIDIA graphics card',
  OpenVINOExecutionProvider: 'Intel graphics',
};
const deviceShortNames: Readonly<Record<string, string>> = {
  CUDAExecutionProvider: 'NVIDIA graphics',
  OpenVINOExecutionProvider: 'Intel graphics',
};

/**
 * What the AI page says about the downloadable GPU pack, or null when this computer has none to
 * offer. Nothing is downloaded until the person chooses Download. `size` formats a byte count and
 * `reason` gives the words for a failure code; `providers` is what the worker chose for each workload.
 */
export function acceleratedPackView(
  pack: AcceleratedPack | null | undefined, providers: WorkloadProvider[] | null | undefined,
  size: (bytes: number) => string, reason: (code: string) => string,
): AcceleratedPackView | null {
  if (!pack || !pack.provider || !deviceNames[pack.provider]) return null;
  const device = deviceNames[pack.provider]!;
  const short = deviceShortNames[pack.provider]!;
  switch (pack.state) {
    case 'available':
      return pack.declined
        ? { title: `Faster processing with your ${device}`, detail: `Not downloaded (${size(pack.bytes)}). AI processing uses the processor.`, progress: null, actions: ['download'], tone: 'off' }
        : {
            title: `Faster processing available for your ${device}`,
            detail: `Download ${size(pack.bytes)} to use it for AI processing on this computer. Until then, AI processing uses the processor.${pack.metered ? ' This connection may be metered.' : ''}`,
            progress: null, actions: ['download', 'decline'], tone: 'wait',
          };
    case 'downloading': {
      const percent = pack.bytes > 0 ? Math.min(100, Math.floor(pack.receivedBytes / pack.bytes * 100)) : 0;
      return { title: `Downloading support for your ${device}`, detail: `${size(pack.receivedBytes)} of ${size(pack.bytes)}. AI processing continues on the processor.`, progress: percent, actions: ['cancel'], tone: 'wait' };
    }
    case 'unpacking':
      return { title: `Checking the download for your ${device}`, detail: 'Every file is verified before it is used. This can take a few minutes.', progress: null, actions: [], tone: 'wait' };
    case 'failed':
      return {
        title: `Faster processing for your ${device} could not be set up`,
        detail: `${reason(pack.code ?? '')} AI processing continues on the processor.`,
        progress: null, actions: ['download'], tone: 'bad',
      };
    case 'ready': {
      const chosen = providers ?? [];
      if (chosen.some(item => item.provider === pack.provider))
        return { title: `Using ${short}`, detail: `AI processing on this computer runs on your ${device} where it is faster than the processor.`, progress: null, actions: [], tone: 'ok' };
      const fallback = chosen.find(item => item.fallback)?.fallback;
      if (fallback)
        return { title: `${short} not in use`, detail: `AI processing uses the processor: ${fallbackReason(fallback)}.`, progress: null, actions: ['retry-provider'], tone: 'off' };
      return { title: `Support for your ${device} is downloaded`, detail: 'It is checked on this computer when AI processing next starts.', progress: null, actions: [], tone: 'wait' };
    }
    default:
      return null;
  }
}
