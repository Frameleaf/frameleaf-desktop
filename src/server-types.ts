// Small TypeScript shapes for the JSON the Rust commands pass through from the server and from Frameleaf Cloud.
// Every field the UI reads is optional or nullable: a missing field renders as unknown, never as a crash.
// Sources: frameleaf-app server/src/dtos/{frameleaf-cloud,cloud-ml,frameleaf-remote-access,server,attention,
// frameleaf-license,cloud-backup}.dto.ts and frameleaf-cloud packages/contracts/src/instance/access.ts.

export type Json = null | boolean | number | string | Json[] | { [key: string]: Json };

// ---- discover_servers / cloud account -----------------------------------------------------------
export type DiscoveredServer = {
  name: string; id: string; url: string; host: string; port: number; addresses: string[];
  setup: 'needed' | 'complete' | string; linked: boolean; cloud: 'available' | 'unavailable' | string;
};
export type CloudAccount = { email: string; name: string; cloud_url: string };
export type CloudServerConnection = { kind: 'local' | 'wan' | 'relay' | 'ipv6' | string; uri: string; verified: boolean };
export type CloudServer = {
  instance_id: string; name: string; version?: string | null; status?: 'linked' | 'suspended' | 'revoked' | string;
  role?: 'owner' | 'admin' | 'editor' | 'viewer' | string; presence?: 'online' | 'offline' | string; last_seen_at?: string | null;
  connections?: CloudServerConnection[]; remote_entitled?: boolean;
};

// ---- the photo connection (connect_server / restore_connection / connect_cloud_server) ------------
export type ConnectionFeatures = { worker: boolean; workerSession: boolean; enrollment: boolean; nativeHost: boolean; sources: boolean };
export type Connection = { server: string; name: string; mode: string; state: string; features: ConnectionFeatures };
export type Workload = { workload: string; state: string; modelNames: string[]; code: string | null };
export type SetupStatus = { state: string; code: string | null; control: 'running' | 'paused' | 'stopped'; workloads: Workload[] };

// ---- server_summary --------------------------------------------------------------------------------
export type Me = { id?: string; name?: string; email?: string; isAdmin?: boolean };
export type RemoteConnection = {
  kind: 'local' | 'wan' | 'relay' | 'ipv6' | string; uri: string; protocol?: 'http' | 'https'; address?: string; port?: number;
  local?: boolean; relay?: boolean; ipv6?: boolean; custom?: boolean; dnsRebindingProtection?: boolean; httpsRequired?: boolean; verified?: boolean;
};
export type ServerConnections = { instanceId?: string | null; publicUrl?: string | null; connections?: RemoteConnection[] };
export type ServerStorage = {
  diskSize?: string; diskUse?: string; diskAvailable?: string; diskSizeRaw?: number; diskUseRaw?: number; diskAvailableRaw?: number; diskUsagePercentage?: number;
};
export type VersionCheck = { checkedAt?: string | null; releaseVersion?: string | null };
export type AttentionItem = {
  id: string; kind: 'backup' | 'storage' | 'work' | 'version' | string; reason: string; level: 'now' | 'soon' | string; since?: string | null;
  storage?: { availableBytes: number; totalBytes: number; usedPercent: number } | null;
  backup?: { place: string | null; lastSuccessAt: string | null; days: number | null } | null;
  work?: { count: number; queues: { name: string; count: number }[] } | null;
  version?: { current: string; available: string } | null;
};
export type Attention = { checkedAt?: string; items?: AttentionItem[]; checks?: { kind: string; state: string }[]; dismissed?: string[] };
export type ServerSummary = {
  me: Me; connections: ServerConnections | null; storage: ServerStorage | null; version: VersionCheck | null; attention: Attention | null;
};

// ---- cloud_status -----------------------------------------------------------------------------------
export type CloudLinkStatus = {
  state?: 'not-configured' | 'unlinked' | 'pending' | 'linked' | 'revoked' | string; configured?: boolean; cloudHost?: string | null; instanceId?: string | null;
  account?: { id: string | null; label: string | null } | null; dataRegion?: string | null; linkedAt?: string | null; lastContactAt?: string | null;
  permissions?: { allowRemoteEnable?: boolean; allowBackupTrigger?: boolean; allowEntitlementRefresh?: boolean };
  revoked?: { at: string; reason: string } | null; lastError?: string | null; heartbeatFailures?: number; remoteAccessEnabled?: boolean;
  manageUrl?: string | null; signInLinkedAccounts?: number; allowOriginalsOverRelay?: boolean; allowPasswordOverRelay?: boolean;
};
export type LicenseSlot = {
  state?: string; kind?: 'server' | 'individual' | 'plan' | string; source?: string; keyHint?: string | null; activatedAt?: string; expiresAt?: string | null; graceUntil?: string | null;
};
export type LicenseStatus = {
  state?: 'none' | 'active' | 'grace' | 'expired' | 'invalid' | string; kind?: string | null; keyHint?: string | null; expiresAt?: string | null; graceUntil?: string | null;
  entitlements?: { frameleafCloud?: boolean; remoteAccess?: boolean; cloudMl?: boolean; cloudBackup?: boolean; supporter?: boolean };
  licensed?: boolean; offline?: boolean; linked?: boolean; configured?: boolean; key?: LicenseSlot | null; plan?: LicenseSlot | null;
};
export type CloudBackupStatus = {
  configured?: boolean; target?: string; managedAvailable?: boolean; endpoint?: string | null; bucket?: string | null; keyMode?: string | null; keyLoaded?: boolean;
  lastRun?: { operationId: string; status: string; startedAt: string; finishedAt: string | null; uploaded: number; skipped: number; missing: number; bytesUploaded: number; error: string | null } | null;
  lastSuccessAt?: string | null; usage?: { objects: number; bytes: number } | null;
  activeRun?: { operationId: string; task?: string; state: string; phase?: string; progress: number; uploaded: number; skipped: number; bytesUploaded: number } | null;
  managed?: { readOnly?: boolean; readOnlyReason?: string | null; quotaBytes?: number; usedBytes?: number | null; location?: { city: string; country: string } | null } | null;
  escrow?: { available: boolean; stored: boolean; storedAt: string | null; outdated: boolean };
};
export type CloudStatus = { cloud: CloudLinkStatus; license: LicenseStatus | null; backup: CloudBackupStatus | null };

// ---- wallet_status ----------------------------------------------------------------------------------
export type Wallet = {
  balanceUsd?: number; heldUsd?: number; availableUsd?: number; dailyCapUsd?: number | null; spentTodayUsd?: number;
  topUpUrl?: string | null; autoTopUp?: boolean; settingsUrl?: string | null; updatedAt?: string;
};
export type CloudMlStatus = {
  connection?: 'not-configured' | 'not-linked' | 'ready' | 'unavailable' | string; detail?: string | null; enabled?: boolean; region?: string | null;
  entitled?: boolean | null; wallet?: Wallet | null; checkedAt?: string;
};
export type Settlement = {
  cloudJobId: string; workload: string; jobName?: string | null; succeeded: boolean; costUsd: number; credits?: number | null; finishedAt: string;
  modelSku?: string | null; computeSku?: string | null; gpuSeconds?: number | null; workers?: number | null; estimateUsd?: number | null;
};
export type WalletStatus = { ml: CloudMlStatus; wallet: Wallet | null; settlements: { items?: Settlement[] } | null };

// ---- remote_status ----------------------------------------------------------------------------------
export type RemoteAccessStatus = {
  unavailableReason?: string | null; enabled?: boolean; mode?: 'relay' | 'relay-and-direct' | string; directPort?: number; portMapping?: boolean;
  publicUrlChoice?: 'frameleaf' | 'custom' | string; status?: 'off' | 'idle' | 'starting' | 'ready' | 'error' | 'unknown' | string; reason?: string | null;
  publicUrl?: string | null; frameleafAddress?: string | null; certificateName?: string | null; certificateExpiresAt?: string | null; certificateError?: string | null;
  relayConnected?: boolean; relayRegion?: string | null; relayLatencyMs?: number | null; relayLastError?: string | null; relayRevoked?: boolean; relayNeedsPlan?: boolean;
  directListening?: boolean; cgnatSuspected?: boolean; mappingMethod?: 'upnp' | 'nat-pmp' | 'manual' | string | null; mappingError?: string | null;
  directExternalIp?: string | null; wanAddress?: string | null; wanVerified?: boolean; wanProblem?: string | null;
  customHostname?: string | null; customHostnameStatus?: 'pending' | 'verified' | string | null; customHostnameProblem?: string | null;
  customHostnameRecords?: { type: string; name: string; value: string; purpose: string }[];
  candidates?: RemoteConnection[]; lastTestAt?: string | null; lastTestOk?: boolean | null; lastTestChecks?: { id: string; ok: boolean; detail: string }[];
};
export type RemoteUsage = { period?: string; periodStart?: string; periodEnd?: string; bytes?: number; limitBytes?: number; throttled?: boolean; throttleBps?: number | null; throttleUntil?: string | null };
export type RemoteStatus = { remote: RemoteAccessStatus; usage: RemoteUsage | null };
export type RemoteUpdate = { enabled?: boolean; mode?: 'relay' | 'relay-and-direct'; directPort?: number; portMapping?: boolean; publicUrl?: 'frameleaf' | 'custom'; allowOriginalsOverRelay?: boolean; allowPasswordOverRelay?: boolean };
export type RemoteTest = { ok?: boolean; checks?: { id: string; ok: boolean; detail: string }[]; lastTestAt?: string | null; lastTestOk?: boolean | null; lastTestChecks?: { id: string; ok: boolean; detail: string }[] };
