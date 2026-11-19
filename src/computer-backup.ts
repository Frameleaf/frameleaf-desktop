// FD-77: what the Computer backup page shows, worked out from `computer_backup_status`. Kept apart from
// the page so it can be tested without a window.

export type Folder = { id: string; name: string; path: string; on: boolean; photos: boolean; size: number | null; files: number | null };
export type Schedule = { every: 'hour' | 'day'; at: number; stopBy: number | null; limitMbps: number | null; waitOnBattery: boolean; keep: 'recommended' | '30d' | '1y' | 'forever' };
export type Running = { startedAt: number; files: number; bytes: number; totalFiles: number; totalBytes: number; storedBytes: number };
export type Run = { at: number; kind: 'backup' | 'restore'; ok: boolean; files: number; bytes: number; tookMs: number; problem: string | null; from: string | null; original: boolean | null };
export type ComputerBackupView = {
  os: 'mac' | 'windows' | 'linux'; computer: string; connected: boolean; connecting: string | null; plan: boolean | null; enabled: boolean;
  folders: Folder[]; schedule: Schedule; running: Running | null; runs: Run[]; lastSuccess: number | null; problem: string | null;
  offline: boolean; skipped: number; usage: [number, number, number] | null; fullDiskAccess: boolean; keySavedAt: string | null;
  lockedCopy: boolean; purge: string | null;
};
export type Item = { name: string; folder: boolean; size: number; changed: number; files: number | null };
export type BackupDate = { key: string; time: string; files: number; bytes: number };

export function formatBytes(value: number): string {
  const unit = Math.min(4, Math.max(0, Math.floor(Math.log(Math.max(value, 1)) / Math.log(1024))));
  return `${Number((value / 1024 ** unit).toFixed(1)).toLocaleString()} ${['B', 'KB', 'MB', 'GB', 'TB'][unit]}`;
}

export function when(time: number | string, now = Date.now()): string {
  const date = new Date(time);
  const clock = date.toLocaleTimeString([], { hour: 'numeric', minute: '2-digit' });
  const day = (d: Date) => new Date(d.getFullYear(), d.getMonth(), d.getDate()).getTime();
  const days = Math.round((day(new Date(now)) - day(date)) / 86_400_000);
  if (days === 0) return `Today, ${clock}`;
  if (days === 1) return `Yesterday, ${clock}`;
  if (days > 1 && days < 7) return `${date.toLocaleDateString([], { weekday: 'long' })}, ${clock}`;
  return `${date.toLocaleDateString([], { day: 'numeric', month: 'short' })}, ${clock}`;
}

/** 120 → "2:00 AM", in the person's own clock style. */
export function clock(minutes: number): string {
  const date = new Date(2000, 0, 1, Math.floor(minutes / 60), minutes % 60);
  return date.toLocaleTimeString([], { hour: 'numeric', minute: '2-digit' });
}

/** "tomorrow at 2:00 AM", "today at 2:00 AM" or "in about an hour". */
export function nextBackup(schedule: Schedule, lastAttempt: number | null, now = Date.now()): string {
  if (schedule.every === 'hour') return lastAttempt && now - lastAttempt < 3_600_000 ? `in ${Math.max(1, Math.round((lastAttempt + 3_600_000 - now) / 60_000))} minutes` : 'in a few minutes';
  const today = new Date(now);
  today.setHours(Math.floor(schedule.at / 60), schedule.at % 60, 0, 0);
  const ranToday = lastAttempt !== null && lastAttempt >= today.getTime();
  return now < today.getTime() || !ranToday ? (now < today.getTime() ? `today at ${clock(schedule.at)}` : 'in a few minutes') : `tomorrow at ${clock(schedule.at)}`;
}

export type Health = 'off' | 'noplan' | 'running' | 'warning' | 'offline' | 'on';

export function health(view: ComputerBackupView): Health {
  if (view.plan === false) return 'noplan';
  if (!view.enabled) return 'off';
  if (view.running) return 'running';
  if (view.offline) return 'offline';
  if (view.problem && view.problem !== 'computer_backup_stopped') return 'warning';
  return 'on';
}

export const pills: Record<Health, [string, string]> = {
  off: ['off', 'Off'], noplan: ['off', 'Off'], running: ['wait', 'Backing up'], warning: ['bad', 'Needs attention'], offline: ['off', 'Offline'], on: ['ok', 'On'],
};

const minutes = (ms: number) => {
  const n = Math.max(1, Math.round(ms / 60_000));
  return `${n} minute${n === 1 ? '' : 's'}`;
};

/** One line of Recent. */
export function runRow(run: Run, explain: (code: string) => string, now = Date.now()): { title: string; detail: string; tone: 'ok' | 'bad'; label: string } {
  if (run.kind === 'restore') {
    const from = run.from ? `, from ${new Date(run.from).toLocaleDateString([], { weekday: 'long' })}’s backup` : '';
    return { title: `Restored ${run.files.toLocaleString()} file${run.files === 1 ? '' : 's'}`, detail: `${when(run.at, now)} · ${run.original ? 'Back where they were' : 'Into another folder'}${from}`, tone: 'ok', label: 'Done' };
  }
  if (run.ok) return { title: 'Backed up', detail: `${when(run.at, now)} · ${formatBytes(run.bytes)} new · ${run.files.toLocaleString()} files · took ${minutes(run.tookMs)}`, tone: 'ok', label: 'Done' };
  if (run.problem === 'computer_backup_stopped') return { title: 'Stopped', detail: `${when(run.at, now)} · The next backup carries on from where this one got to.`, tone: 'bad', label: 'Stopped' };
  return { title: 'Didn’t finish', detail: `${when(run.at, now)} · ${explain(run.problem ?? '')} The next backup carried on from where this one got to.`, tone: 'bad', label: 'Stopped' };
}

/** The folders a backup covers, their bytes and files. */
export function protectedTotals(folders: Folder[]): { bytes: number; files: number; count: number } {
  const on = folders.filter(folder => folder.on);
  return { bytes: on.reduce((sum, f) => sum + (f.size ?? 0), 0), files: on.reduce((sum, f) => sum + (f.files ?? 0), 0), count: on.length };
}

export function progress(running: Running): { percent: number; left: string } {
  const percent = running.totalBytes ? Math.min(99, Math.floor((running.bytes / running.totalBytes) * 100)) : 0;
  const elapsed = Date.now() - running.startedAt;
  const rest = percent > 2 ? (elapsed * (100 - percent)) / percent : null;
  return { percent, left: rest === null ? 'working out the time left' : rest < 90_000 ? 'about a minute left' : `about ${minutes(rest)} left` };
}

/** "C:\Users\Pat\Documents" → "~/Documents"-style display on a Mac only; Windows keeps its own form. */
export function shownPath(path: string, os: string): string {
  if (os !== 'mac') return path;
  return path.replace(/^\/Users\/[^/]+/, '~');
}

export const credentialStore = (os: string) => os === 'windows' ? 'Windows Credential Manager' : os === 'mac' ? 'your Mac’s Keychain' : 'your secure credential store';
export const ownerCheck = (os: string) => os === 'windows' ? 'Windows Hello' : 'Touch ID';
