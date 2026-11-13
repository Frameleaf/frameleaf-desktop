// Pure helpers for the desktop UI. No DOM, no Tauri: everything here is unit-tested in test/ui-state.test.ts.
import type { CloudServer, DiscoveredServer, RemoteConnection, SignInOptions } from './server-types';

export type Platform = 'mac' | 'windows' | 'linux';
export function platformFromUserAgent(userAgent: string): Platform {
  const ua = userAgent.toLowerCase();
  if (/macintosh|mac os x|iphone|ipad/.test(ua)) return 'mac';
  if (/windows/.test(ua)) return 'windows';
  return 'linux';
}
export function platformClass(userAgent: string): string { return `platform-${platformFromUserAgent(userAgent)}`; }
export function computerWord(platform: Platform): string { return platform === 'mac' ? 'Mac' : platform === 'windows' ? 'PC' : 'computer'; }

/** Count distinct verified completions in the current sign-in's retained import history. */
export function verifiedImportCount(entries: readonly {
  runId: string; status: string; verified: number; albumPending: boolean;
}[]): number {
  return new Set(entries
    .filter(entry => entry.status === 'complete' && entry.verified > 0 && !entry.albumPending)
    .map(entry => entry.runId)).size;
}

// ---- money ------------------------------------------------------------------------------------
const usdFormat = new Intl.NumberFormat('en-US', { style: 'currency', currency: 'USD', minimumFractionDigits: 2, maximumFractionDigits: 2 });
/** USD as the server sends it (a double). Unknown values render as an em dash, never as "$NaN". */
export function formatUsd(value: unknown): string {
  const amount = typeof value === 'string' && value.trim() !== '' ? Number(value) : value;
  if (typeof amount !== 'number' || !Number.isFinite(amount)) return '—';
  const text = usdFormat.format(Math.abs(amount) < 0.005 ? 0 : amount);
  return text.startsWith('-$') ? `−$${text.slice(2)}` : text;
}
/** Micro-USD integers (1,000,000 = $1.00) as the cloud ledger keeps them; bigint and numeric strings are accepted. */
export function formatMicroUsd(value: unknown): string {
  if (typeof value === 'bigint') return formatUsd(Number(value) / 1_000_000);
  const micro = typeof value === 'string' && value.trim() !== '' ? Number(value) : value;
  if (typeof micro !== 'number' || !Number.isFinite(micro)) return '—';
  return formatUsd(micro / 1_000_000);
}
/** "$31.40" or "$20" for whole-dollar caps shown in segmented controls. */
export function formatUsdShort(value: number): string {
  return Number.isInteger(value) ? `$${value.toLocaleString('en-US')}` : formatUsd(value);
}

// ---- bytes ------------------------------------------------------------------------------------
/** Decimal units, the way the server reports storage ("1 GB = 1,000,000,000 bytes"). */
export function formatBytes(bytes: unknown): string {
  const value = typeof bytes === 'bigint' ? Number(bytes) : bytes;
  if (typeof value !== 'number' || !Number.isFinite(value) || value < 0) return '—';
  if (value >= 1e12) return `${trim(value / 1e12)} TB`;
  if (value >= 1e9) return `${trim(value / 1e9)} GB`;
  if (value >= 1e6) return `${trim(value / 1e6)} MB`;
  if (value >= 1e3) return `${trim(value / 1e3)} kB`;
  return `${Math.round(value)} ${value === 1 ? 'byte' : 'bytes'}`;
}
function trim(value: number): string {
  const fixed = value >= 100 ? value.toFixed(0) : value.toFixed(1);
  return fixed.endsWith('.0') ? fixed.slice(0, -2) : fixed;
}
export function percent(part: unknown, total: unknown): number {
  if (typeof part !== 'number' || typeof total !== 'number' || !(total > 0) || !Number.isFinite(part)) return 0;
  return Math.max(0, Math.min(100, Math.round((part / total) * 100)));
}

// ---- time -------------------------------------------------------------------------------------
function toMillis(value: unknown): number | null {
  if (typeof value === 'number' && Number.isFinite(value)) return value;
  if (typeof value === 'string' && value) { const ms = Date.parse(value); return Number.isNaN(ms) ? null : ms; }
  if (value instanceof Date) return value.getTime();
  return null;
}
/** "just now", "2 minutes ago", "3 days ago", or "in 4 hours" for future times. */
export function relativeTime(value: unknown, now: number = Date.now()): string {
  const ms = toMillis(value);
  if (ms === null) return 'never';
  const diff = now - ms;
  const abs = Math.abs(diff);
  const future = diff < 0;
  const unit = (n: number, word: string) => `${n} ${word}${n === 1 ? '' : 's'}`;
  let text: string;
  if (abs < 45_000) return 'just now';
  else if (abs < 3_600_000) text = unit(Math.max(1, Math.round(abs / 60_000)), 'minute');
  else if (abs < 86_400_000) text = unit(Math.max(1, Math.round(abs / 3_600_000)), 'hour');
  else if (abs < 30 * 86_400_000) text = unit(Math.max(1, Math.round(abs / 86_400_000)), 'day');
  else if (abs < 365 * 86_400_000) text = unit(Math.max(1, Math.round(abs / (30 * 86_400_000))), 'month');
  else text = unit(Math.max(1, Math.round(abs / (365 * 86_400_000))), 'year');
  return future ? `in ${text}` : `${text} ago`;
}
/** "Today, 10:42", "Yesterday, 02:00", "Nov 1, 02:00" or "Oct 31, 2025, 02:00" for another year. */
export function formatWhen(value: unknown, now: number = Date.now(), locale = 'en-US'): string {
  const ms = toMillis(value);
  if (ms === null) return '—';
  const date = new Date(ms), today = new Date(now);
  const time = date.toLocaleTimeString(locale, { hour: '2-digit', minute: '2-digit' });
  const sameDay = (a: Date, b: Date) => a.getFullYear() === b.getFullYear() && a.getMonth() === b.getMonth() && a.getDate() === b.getDate();
  if (sameDay(date, today)) return `Today, ${time}`;
  const yesterday = new Date(now); yesterday.setDate(yesterday.getDate() - 1);
  if (sameDay(date, yesterday)) return `Yesterday, ${time}`;
  const day = date.toLocaleDateString(locale, { month: 'short', day: 'numeric', ...(date.getFullYear() !== today.getFullYear() ? { year: 'numeric' } : {}) });
  return `${day}, ${time}`;
}
export function formatDate(value: unknown, locale = 'en-US'): string {
  const ms = toMillis(value);
  return ms === null ? '—' : new Date(ms).toLocaleDateString(locale, { month: 'short', day: 'numeric', year: 'numeric' });
}
/** "4:32" for the time left on a five-minute Manager authorization; "0:00" once it has passed. */
export function countdown(untilMs: number, now: number = Date.now()): string {
  const left = Math.max(0, Math.ceil((untilMs - now) / 1000));
  return `${Math.floor(left / 60)}:${String(left % 60).padStart(2, '0')}`;
}

// ---- names ------------------------------------------------------------------------------------
export function initials(name: unknown): string {
  const text = typeof name === 'string' ? name.trim() : '';
  if (!text) return '?';
  const parts = text.split(/[\s._@-]+/).filter(Boolean);
  const letters = parts.length >= 2 ? parts[0]![0]! + parts[1]![0]! : text.slice(0, 2);
  return letters.toUpperCase();
}
export function connectionTransport(server: string): string {
  try {
    const { protocol } = new URL(server);
    if (protocol === 'https:') return 'Encrypted connection';
    if (protocol === 'http:') return 'Unencrypted connection';
  } catch { /* Saved addresses may be invalid. */ }
  return 'Connection type unknown';
}
export function hostOf(url: unknown): string {
  if (typeof url !== 'string') return '';
  try { return new URL(url).host; } catch { return url.replace(/^[a-z]+:\/\//i, '').replace(/\/.*$/, ''); }
}

// ---- connection paths ---------------------------------------------------------------------------
export type PathKind = 'local' | 'direct' | 'ipv6' | 'custom' | 'relay';
export type PathEntry = { kind: PathKind; label: string; uri: string; verified: boolean; current: boolean; detail: string };
export type ConnectionPath = { current: PathKind | null; currentLabel: string; entries: PathEntry[] };
const pathLabels: Record<PathKind, string> = { local: 'Home network', direct: 'Direct', ipv6: 'IPv6', custom: 'Your domain', relay: 'Relay' };
export function pathKind(connection: Pick<RemoteConnection, 'kind'> & Partial<RemoteConnection>): PathKind {
  if (connection.custom) return 'custom';
  if (connection.relay || connection.kind === 'relay') return 'relay';
  if (connection.ipv6 || connection.kind === 'ipv6') return 'ipv6';
  if (connection.local || connection.kind === 'local') return 'local';
  return 'direct';
}
function sameOrigin(a: string, b: string): boolean {
  try {
    const x = new URL(a), y = new URL(b);
    return x.protocol === y.protocol && x.hostname.toLowerCase() === y.hostname.toLowerCase() && (x.port || defaultPort(x.protocol)) === (y.port || defaultPort(y.protocol));
  } catch { return false; }
}
function defaultPort(protocol: string): string { return protocol === 'https:' ? '443' : protocol === 'http:' ? '80' : ''; }
/**
 * Labels the server's connection candidates (GET /server/connections) and marks the one this computer is signed in
 * through. `currentServer` is the saved connection's base URL; when it matches no candidate the current path is null
 * ("Unknown") so the indicator never claims a path it cannot prove.
 */
export function connectionPath(connections: unknown, currentServer: string | null | undefined): ConnectionPath {
  const list = Array.isArray(connections) ? connections : (connections && typeof connections === 'object' && Array.isArray((connections as { connections?: unknown }).connections)) ? (connections as { connections: unknown[] }).connections : [];
  const entries: PathEntry[] = [];
  for (const raw of list) {
    if (!raw || typeof raw !== 'object' || typeof (raw as RemoteConnection).uri !== 'string') continue;
    const connection = raw as RemoteConnection;
    const kind = pathKind(connection);
    const current = !!currentServer && sameOrigin(connection.uri, currentServer);
    const detail = kind === 'direct' && typeof connection.port === 'number' ? `public, port ${connection.port}` : kind === 'relay' ? 'fallback' : kind === 'custom' ? (connection.relay ? 'relay only' : 'verified by Frameleaf Cloud') : kind === 'local' ? 'this network' : '';
    entries.push({ kind, label: pathLabels[kind], uri: connection.uri, verified: connection.verified === true, current, detail });
  }
  const now = entries.find(entry => entry.current);
  return { current: now?.kind ?? null, currentLabel: now ? now.label : 'Unknown', entries };
}
/** The three-step indicator the Remote page shows: Home network → Direct → Relay (IPv6 and custom hostnames count as Direct). */
export function pathIndicator(current: PathKind | null): { key: 'local' | 'direct' | 'relay'; label: string; on: boolean }[] {
  const active = current === 'local' ? 'local' : current === 'relay' ? 'relay' : current === null ? null : 'direct';
  return [
    { key: 'local', label: 'Home network', on: active === 'local' },
    { key: 'direct', label: 'Direct', on: active === 'direct' },
    { key: 'relay', label: 'Relay', on: active === 'relay' },
  ];
}

// ---- server list -------------------------------------------------------------------------------
export type ServerEntry = {
  key: string;
  name: string;
  source: 'cloud' | 'nearby';
  instanceId: string | null;
  cloud: CloudServer | null;
  nearby: DiscoveredServer | null;
  online: boolean;
  detail: string;
  pill: { label: string; tone: 'ok' | 'wait' | 'off' };
  action: 'connect' | 'sign-in' | 'setup';
};
const roleWords: Record<string, string> = { owner: 'Owner', admin: 'Admin', editor: 'Member', viewer: 'Viewer' };
/**
 * Merges the account's servers (GET /v1/instances) with Bonjour finds. A discovered server whose TXT id matches an
 * account server marks that entry "on your home network"; a discovered server the account does not list becomes a
 * "Nearby" entry with a Sign In action (or Set up, while it still has no administrator).
 */
export function mergeServers(cloud: readonly CloudServer[] | null | undefined, discovered: readonly DiscoveredServer[] | null | undefined, now: number = Date.now()): ServerEntry[] {
  const nearbyById = new Map<string, DiscoveredServer>();
  for (const found of discovered ?? []) if (found && typeof found.id === 'string' && found.id) nearbyById.set(found.id, found);
  const entries: ServerEntry[] = [];
  const claimed = new Set<string>();
  for (const server of cloud ?? []) {
    if (!server || typeof server.instance_id !== 'string') continue;
    const nearby = nearbyById.get(server.instance_id) ?? null;
    if (nearby) claimed.add(server.instance_id);
    const online = server.presence === 'online' || !!nearby;
    const kinds = new Set((server.connections ?? []).map(connection => connection.kind));
    const where = nearby || kinds.has('local') && online ? 'on your home network' : online ? (server.remote_entitled === false ? 'away from home, no remote access' : kinds.has('relay') ? 'away from home, via relay' : 'away from home') : server.last_seen_at ? `last seen ${relativeTime(server.last_seen_at, now)}` : 'not seen yet';
    const parts = [roleWords[server.role ?? ''] ?? (server.role || 'Member'), server.version ? `Frameleaf ${server.version}` : null, where, server.status === 'suspended' ? 'suspended' : server.status === 'revoked' ? 'unlinked' : null].filter(Boolean);
    entries.push({
      key: `cloud:${server.instance_id}`, name: server.name || nearby?.name || server.instance_id, source: 'cloud', instanceId: server.instance_id, cloud: server, nearby,
      online, detail: parts.join(' · '),
      pill: online ? { label: 'Online', tone: 'ok' } : { label: 'Offline', tone: 'off' },
      action: 'connect',
    });
  }
  for (const found of nearbyById.values()) {
    if (claimed.has(found.id)) continue;
    const setup = found.setup === 'needed';
    entries.push({
      key: `nearby:${found.id}`, name: found.name || found.host || found.url, source: 'nearby', instanceId: found.linked ? found.id : null, cloud: null, nearby: found,
      online: true, detail: setup ? 'Found on this network · needs its first administrator' : found.linked ? 'Found on this network · linked to another account' : 'Found on this network · not linked to your account yet',
      pill: { label: 'Nearby', tone: 'wait' }, action: setup ? 'setup' : 'sign-in',
    });
  }
  return entries;
}

// ---- AI worker rows -----------------------------------------------------------------------------
export const workloadNames: Record<string, string> = { clip: 'Smart search', ocr: 'Text recognition', face: 'Face recognition', enrichment: 'Photo descriptions and safety', restoration: 'Photo restoration', video: 'Video restoration', transcription: 'Speech to text', tts: 'Speech', description: 'Photo descriptions' };
export function workloadName(workload: string): string { return workloadNames[workload] ?? workload; }
export function workloadPill(state: string): { label: string; tone: 'ok' | 'wait' | 'off'; detail: string } {
  switch (state) {
    case 'ready': return { label: 'Ready', tone: 'ok', detail: 'Ready to help' };
    case 'qualifying': return { label: 'Checking', tone: 'wait', detail: 'Checking this computer' };
    case 'eligible': return { label: 'Waiting', tone: 'wait', detail: 'Waiting for qualification' };
    case 'disabled': return { label: 'Off', tone: 'off', detail: 'Disabled on your server' };
    case 'pinned': return { label: 'Server', tone: 'off', detail: 'Uses your chosen server destination' };
    case 'legacy': return { label: 'Server', tone: 'off', detail: 'Uses your existing server destination' };
    case 'unavailable': return { label: 'Unavailable', tone: 'off', detail: 'Unavailable on this computer; other tasks can continue' };
    case 'unsupported': return { label: 'Unsupported', tone: 'off', detail: 'Selected model is not supported on this computer yet' };
    default: return { label: state, tone: 'off', detail: state };
  }
}
export function workerTone(state: string): 'ok' | 'wait' | 'off' {
  if (['working', 'waiting-for-work', 'qualified'].includes(state)) return 'ok';
  if (['stopped', 'paused', 'revoked', 'incompatible', 'setup-needs-attention', 'no-eligible-work', 'worker-setup-failed', 'credential-store-unavailable', 'identity-changed', 'offline', 'enrollment-failed'].includes(state)) return 'off';
  return 'wait';
}

// ---- misc ---------------------------------------------------------------------------------------
export function shortId(value: unknown, length = 12): string { return typeof value === 'string' ? value.slice(0, length) : ''; }
export function fingerprintShort(value: unknown): string {
  if (typeof value !== 'string' || value.length < 8) return '';
  const hex = value.replace(/[^0-9a-f]/gi, '').toUpperCase();
  return hex.length >= 8 ? `${hex.slice(0, 4)}…${hex.slice(-4)}` : value;
}
export function clamp(value: number, min: number, max: number): number { return Math.min(max, Math.max(min, value)); }

/** The sign-in methods to show for a server: Frameleaf only when linked, the OAuth provider's name when it has one. */
export function signInMethods(options: Pick<SignInOptions, 'frameleafSignIn' | 'linked' | 'passwordLogin' | 'oauth' | 'oauthButtonText'>): { frameleaf: boolean; password: boolean; oauth: string } {
  return {
    frameleaf: options.frameleafSignIn && options.linked,
    password: options.passwordLogin,
    oauth: options.oauth ? options.oauthButtonText.trim() || 'Sign In with Single Sign-On' : '',
  };
}

/** How one signs in to a server found on this network, as the Welcome list says it. */
export function nearbySignIn(server: Pick<DiscoveredServer, 'linked' | 'setup'>): string {
  if (server.linked) return 'Frameleaf or its own sign-in';
  return server.setup === 'needed' ? 'New server' : 'Its own sign-in';
}

// Region codes Intl names that are not places a person lives (the EU, the UN, "Unknown Region", pseudo-locales).
const NOT_COUNTRIES = new Set(['EU', 'EZ', 'UN', 'ZZ', 'QO', 'XA', 'XB']);
/** Every country or region the platform can name, in the person's language, sorted by name. */
export function countryOptions(locale: string): { code: string; name: string }[] {
  let names: Intl.DisplayNames;
  try { names = new Intl.DisplayNames([locale, 'en'], { type: 'region', fallback: 'none' }); } catch { names = new Intl.DisplayNames(['en'], { type: 'region', fallback: 'none' }); }
  const letters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
  const options: { code: string; name: string }[] = [];
  for (const a of letters) for (const b of letters) {
    const code = a + b;
    const name = NOT_COUNTRIES.has(code) ? undefined : names.of(code);
    if (name && name !== code) options.push({ code, name });
  }
  return options.sort((x, y) => x.name.localeCompare(y.name, locale));
}
/** The region in a BCP 47 tag (`en-CA` → `CA`), or the United States. */
export function defaultCountry(locale: string): string {
  try { return new Intl.Locale(locale).maximize().region ?? 'US'; } catch { return 'US'; }
}

/** Progress of the whole import when its folder is copied in several batches (`photo-import`'s `overall`). */
export type OverallProgress = { total: number; completed: number; totalBytes: number; completedBytes: number };
export type ImportProgress = { completed: number; total: number; bytes: { completed: number; total: number } | null };

/**
 * What an import's progress bar and counts show. A folder over one batch (10,000 files) reports
 * the whole import in `overall`: its files and bytes across every batch, so the bar does not start
 * again with each batch. Any other import shows its one batch.
 */
export function importProgress(job: { completed: number; total: number; overall?: OverallProgress | null }): ImportProgress {
  const overall = job.overall;
  if (!overall || !(overall.total > 0)) return { completed: job.completed, total: job.total, bytes: null };
  const total = Math.max(overall.total, overall.completed);
  const totalBytes = Math.max(overall.totalBytes, overall.completedBytes);
  return { completed: overall.completed, total, bytes: totalBytes > 0 ? { completed: overall.completedBytes, total: totalBytes } : null };
}

/** "12,000 of 25,001 copies confirmed", with the bytes done of the total when the import has several batches. */
export function importProgressText(job: { completed: number; total: number; overall?: OverallProgress | null }): string {
  const progress = importProgress(job);
  const files = `${progress.completed.toLocaleString()} of ${progress.total.toLocaleString()} copies confirmed`;
  return progress.bytes ? `${files} · ${formatBytes(progress.bytes.completed)} of ${formatBytes(progress.bytes.total)}` : files;
}

// ---- where a chosen folder's files are (photo sources) ---------------------------------------------
/** The backend's snapshot of a chosen folder, from file metadata: how many files are where. */
export type Availability = { available: number; needsDownload: number; notReady: number; unknown: number; pinned: number; downloadBytes: number };
/**
 * That snapshot in plain words, leaving out whatever there is none of; empty when there is nothing to say.
 * The counts come from file metadata, not from reading the files, so the wording stays cautious.
 */
export function availabilityText(value: Availability): string {
  const files = (count: number, one: string, many: string) => `${count.toLocaleString()} ${count === 1 ? one : many}`;
  const parts = [
    value.available > 0 && `${files(value.available, 'file is', 'files are')} on this computer`,
    value.needsDownload > 0 && `${files(value.needsDownload, 'file is stored online and needs', 'files are stored online and need')} downloading first${value.downloadBytes > 0 ? ` (${formatBytes(value.downloadBytes)})` : ''}`,
    value.notReady > 0 && `${files(value.notReady, 'file', 'files')} can’t be opened until your cloud storage app finishes syncing`,
    value.unknown > 0 && `${files(value.unknown, 'file', 'files')} could not be checked and may also need downloading`,
    value.pinned > 0 && `${files(value.pinned, 'file is', 'files are')} set to always stay on this computer`,
  ].filter((part): part is string => !!part);
  return parts.length ? `${parts.join('. ')}. This can change before a copy starts.` : '';
}

// ---- cloud backup (Frameleaf Cloud page) -----------------------------------------------------------
/**
 * How the last cloud backup ended, in words. The server's status and error are tokens
 * (`waiting-for-key`, an error code): a status this app does not know reads "Not finished", and an
 * error is shown only when `explain` has words for it.
 */
export function backupRunText(run: { status: string; error?: string | null }, explain: (code: string) => string | null): string {
  switch (run.status) {
    case 'completed': return 'Done';
    case 'failed': { const reason = run.error ? explain(run.error) : null; return reason ? `Failed · ${reason}` : 'Failed'; }
    case 'waiting-for-key': return 'Waiting for your backup key';
    case 'cancelled': case 'canceled': return 'Cancelled';
    default: return 'Not finished';
  }
}
/** Where the key that encrypts cloud backups is kept, or '' for a mode this app does not know. */
export function backupKeyText(keyMode: string | null | undefined): string {
  switch (keyMode) {
    case 'server': return 'backup key kept on your server';
    case 'own-stored': return 'your own backup key, saved on your server';
    case 'own-memory': return 'your own backup key, entered again after each server restart';
    default: return '';
  }
}

/** Find OneDrive Folders looks where OneDrive keeps its folders on Windows and macOS. Linux has no such place. */
export function oneDriveDiscovery(platform: Platform): boolean { return platform !== 'linux'; }
