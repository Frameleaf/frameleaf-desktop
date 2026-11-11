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
