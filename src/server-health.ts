import type { AttentionItem, ServerStorage, ServerSummary } from './server-types';
import { formatBytes, relativeTime } from './ui-state.ts';

function headroom(available: unknown, total: unknown): string | null {
  if (typeof available !== 'number' || typeof total !== 'number' ||
      !Number.isFinite(available) || !Number.isFinite(total) ||
      available < 0 || total <= 0 || available > total) return null;
  return `${formatBytes(available)} free of ${formatBytes(total)}`;
}

export function libraryHeadroom(storage: ServerStorage | null | undefined) {
  const capacity = headroom(storage?.diskAvailableRaw, storage?.diskSizeRaw);
  const used = storage?.diskUsagePercentage;
  return {
    capacity,
    usedPercent: capacity && typeof used === 'number' && Number.isFinite(used) && used >= 0 && used <= 100
      ? Math.round(used) : null,
  };
}

export function backupHealth(summary: ServerSummary | null) {
  if (summary?.me?.isAdmin !== true) return null;
  const attention = summary.attention;
  const check = attention?.checks?.find(check => check.kind === 'backup')?.state;
  // Dismissal hides an alert, not the underlying condition.
  if (check === 'attention' || attention?.items?.some(item => item.kind === 'backup')) {
    return { label: 'Needs attention', tone: 'wait' };
  }
  if (check === 'ok') return { label: 'No warnings reported', tone: 'ok' };
  if (check === 'off') return { label: 'Off', tone: 'off' };
  return { label: 'Unknown', tone: 'off' };
}

export function storageWarning(item: AttentionItem) {
  const drive = item.storage?.drive;
  const volume = drive === 'thumbnails' ? 'Thumbnail drive' : drive === 'library' ? 'Library drive' : 'Server storage';
  return {
    title: `${volume} ${item.reason === 'out-of-space' ? 'is out of space' : 'is nearly full'}`,
    detail: headroom(item.storage?.availableBytes, item.storage?.totalBytes) ?? 'Available space is unknown.',
  };
}

export function backupWarning(item: AttentionItem) {
  const place = item.backup?.place;
  const destination = place === 'cloud' ? 'Cloud Backup' : place === 'buddy' ? 'Buddy Backup' : place === 'local' ? 'Library data backup' : 'Backup';
  const lastSuccess = relativeTime(item.backup?.lastSuccessAt);
  if (item.reason === 'not-backed-up') {
    return {
      title: 'No Cloud or Buddy Backup is set up',
      detail: 'Set up a backup to keep a separate copy of your photos.',
      page: 'cloud',
    };
  }
  return {
    title: `${destination} ${item.reason === 'backup-failed' ? 'failed' : 'is behind'}`,
    detail: lastSuccess === 'never' ? 'No successful backup time reported.' : `Last successful backup ${lastSuccess}.`,
    page: place === 'cloud' ? 'cloud' : 'photos',
  };
}
