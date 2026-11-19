// FD-77: a local stand-in for Frameleaf Cloud (FC-288) and its S3 storage, for Computer backup's
// end-to-end test. It answers like Cloud on the routes a computer uses and checks what Cloud checks:
// the device flow, the computer's link, private_key_jwt client assertions, DPoP proofs (signature, htm,
// htu, ath, key binding and the per-origin nonce challenge), the run lease, repository grants, the
// signed and chained snapshot receipts, escrow and the purge hold. Storage keeps versions like Wasabi.
// Never point it at, or run it as, anything real.
//
//   node tools/computer_backup_stand_in.mjs     prints {"cloud": "...", "s3": "..."} and serves until stopped
//   import { standIn } from './computer_backup_stand_in.mjs'
import { createHash, createPublicKey, randomBytes, randomUUID, verify } from 'node:crypto';
import { createServer } from 'node:http';

const b64url = (buffer) => Buffer.from(buffer).toString('base64url');
const sha256 = (data) => createHash('sha256').update(data).digest();
const thumbprint = (x) => b64url(sha256(`{"crv":"Ed25519","kty":"OKP","x":${JSON.stringify(x)}}`));
const keyOf = (x) => createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x }, format: 'jwk' });

/** A compact JWS's header and payload, if its Ed25519 signature holds for `x` (or for its own `jwk`). */
function openJws(token, x) {
  const [head, body, signature] = String(token ?? '').split('.');
  if (!signature) return null;
  try {
    const header = JSON.parse(Buffer.from(head, 'base64url'));
    const payload = JSON.parse(Buffer.from(body, 'base64url'));
    const key = x ?? header.jwk?.x;
    if (!key || !verify(null, Buffer.from(`${head}.${body}`), keyOf(key), Buffer.from(signature, 'base64url'))) return null;
    return { header, payload };
  } catch {
    return null;
  }
}

export async function standIn({ plan = true } = {}) {
  const objects = new Map(); // key -> [{ version, body }]
  const uploads = new Map();
  const state = {
    plan, devices: new Map(), linkTokens: new Map(), instances: new Map(), tokens: new Map(), nonce: { token: null, api: null },
    seenJti: new Set(), lease: null, snapshots: new Map(), escrow: null, purge: null, runs: [], settings: null, credentials: new Map(), log: [],
  };
  let cloudOrigin = '';
  let s3Origin = '';

  // ---------------------------------------------------------------- S3
  const xml = (response, status, body, headers = {}) => { response.writeHead(status, { 'content-type': 'application/xml', ...headers }); response.end(body); };
  const s3 = createServer(async (request, response) => {
    const parts = [];
    try { for await (const part of request) parts.push(part); } catch { return; }
    const body = Buffer.concat(parts);
    const url = new URL(request.url, 'http://s3');
    const access = /^AWS4-HMAC-SHA256 Credential=([^/]+)\//.exec(request.headers.authorization ?? '')?.[1];
    const credential = state.credentials.get(access);
    if (!credential || request.headers['x-amz-security-token'] !== credential.sessionToken || request.headers['x-amz-content-sha256'] !== sha256(body).toString('hex')) {
      return xml(response, 403, '<Error><Code>SignatureDoesNotMatch</Code></Error>');
    }
    const [, bucket, ...rest] = decodeURIComponent(url.pathname).split('/');
    const key = rest.join('/');
    if (bucket !== credential.bucket) return xml(response, 403, '<Error><Code>AccessDenied</Code></Error>');
    const query = url.searchParams;
    const write = request.method === 'PUT' || (request.method === 'POST' && query.has('uploadId'));
    // Upload writes; prune only deletes and reads (FC-284); restore only reads.
    if (write && (credential.operation !== 'upload' || state.purge?.status === 'held')) return xml(response, 403, '<Error><Code>AccessDenied</Code></Error>');
    if (request.method === 'DELETE' && !query.has('uploadId') && credential.operation !== 'prune') return xml(response, 403, '<Error><Code>AccessDenied</Code></Error>');
    const current = (name) => objects.get(name)?.at(-1);
    const put = (name, data) => {
      const version = randomBytes(8).toString('hex');
      objects.set(name, [...(objects.get(name) ?? []), { version, body: data }]);
      return version;
    };
    if (request.method === 'GET' && !key) {
      const prefix = query.get('prefix') ?? '';
      if (!prefix.startsWith('r/')) return xml(response, 403, '<Error><Code>AccessDenied</Code></Error>');
      const keys = [...objects.keys()].filter((name) => name.startsWith(prefix) && current(name)?.body).sort();
      const from = Number(query.get('continuation-token') ?? 0);
      const page = keys.slice(from, from + 100);
      const more = from + 100 < keys.length;
      return xml(response, 200, `<ListBucketResult><IsTruncated>${more}</IsTruncated>${page.map((name) => `<Contents><Key>${name}</Key><LastModified>2026-01-01T00:00:00.000Z</LastModified><Size>${current(name).body.length}</Size></Contents>`).join('')}${more ? `<NextContinuationToken>${from + 100}</NextContinuationToken>` : ''}</ListBucketResult>`);
    }
    const uploadId = query.get('uploadId');
    if (request.method === 'POST' && query.has('uploads')) {
      const id = randomBytes(6).toString('hex');
      uploads.set(id, []);
      return xml(response, 200, `<InitiateMultipartUploadResult><UploadId>${id}</UploadId></InitiateMultipartUploadResult>`);
    }
    if (request.method === 'PUT' && uploadId) {
      uploads.get(uploadId)[Number(query.get('partNumber')) - 1] = body;
      return xml(response, 200, '', { etag: `"${sha256(body).toString('hex').slice(0, 8)}"` });
    }
    if (request.method === 'POST' && uploadId) {
      const version = put(key, Buffer.concat(uploads.get(uploadId)));
      uploads.delete(uploadId);
      return xml(response, 200, '<CompleteMultipartUploadResult></CompleteMultipartUploadResult>', { 'x-amz-version-id': version });
    }
    if (request.method === 'DELETE' && uploadId) { uploads.delete(uploadId); return xml(response, 204, ''); }
    if (request.method === 'PUT') {
      if (request.headers['if-none-match'] === '*' && current(key)?.body) return xml(response, 412, '<Error><Code>PreconditionFailed</Code></Error>');
      return xml(response, 200, '', { etag: '"whole"', 'x-amz-version-id': put(key, body) });
    }
    if (request.method === 'DELETE') {
      // A delete marker: older versions stay, as on versioned storage.
      if (objects.has(key)) objects.get(key).push({ version: randomBytes(8).toString('hex'), body: null });
      return xml(response, 204, '');
    }
    const stored = current(key)?.body;
    if (!stored) return xml(response, 404, '<Error><Code>NoSuchKey</Code></Error>');
    const range = /^bytes=(\d*)-(\d*)$/.exec(request.headers.range ?? '');
    const slice = !range ? stored : range[1] === '' ? stored.subarray(Math.max(0, stored.length - Number(range[2]))) : stored.subarray(Number(range[1]), Number(range[2]) + 1);
    response.writeHead(range ? 206 : 200);
    response.end(slice);
  });

  // ---------------------------------------------------------------- Cloud
  const send = (response, status, body, headers = {}) => {
    response.writeHead(status, { 'content-type': 'application/json', 'cache-control': 'no-store', ...headers });
    response.end(body === undefined ? '' : JSON.stringify(body));
  };
  const refuse = (response, status, code, headers = {}) => send(response, status, { code, message: code, retryable: false, requestId: `req_${randomUUID()}` }, headers);

  /** Checks a DPoP proof as Cloud does; answers the refusal itself and returns null when it fails. */
  function proof(request, response, url, { origin, x, token, oauth }) {
    const opened = openJws(request.headers.dpop);
    const fail = (code, detail) => (oauth ? send(response, 400, { error: code, error_description: detail }) : refuse(response, 401, code, { 'www-authenticate': 'DPoP algs="EdDSA Ed25519"' }), null);
    if (!opened || opened.header.typ !== 'dpop+jwt' || !['EdDSA', 'Ed25519'].includes(opened.header.alg) || opened.header.jwk?.d) return fail('invalid_dpop_proof', 'header');
    const { payload, header } = opened;
    if (x && header.jwk.x !== x) return fail('invalid_dpop_proof', 'key');
    if (payload.htm !== request.method || payload.htu !== `${cloudOrigin}${url.pathname}`) return fail('invalid_dpop_proof', 'htu');
    if (Math.abs(payload.iat - Date.now() / 1000) > 60) return fail('invalid_dpop_proof', 'iat');
    if (token && payload.ath !== b64url(sha256(token))) return fail('invalid_dpop_proof', 'ath');
    if (!token && payload.ath) return fail('invalid_dpop_proof', 'ath');
    if (state.seenJti.has(`${header.jwk.x}:${payload.jti}`)) return fail('invalid_dpop_proof', 'replayed');
    if (!state.nonce[origin] || payload.nonce !== state.nonce[origin]) {
      state.nonce[origin] = randomBytes(32).toString('base64url');
      if (oauth) send(response, 400, { error: 'use_dpop_nonce' }, { 'dpop-nonce': state.nonce[origin] });
      else refuse(response, 401, 'use_dpop_nonce', { 'dpop-nonce': state.nonce[origin], 'www-authenticate': 'DPoP error="use_dpop_nonce"' });
      return null;
    }
    state.seenJti.add(`${header.jwk.x}:${payload.jti}`);
    return header.jwk;
  }

  const routes = {
    'GET /.well-known/frameleaf-services': (q, r) => send(r, 200, { version: 1, issuer: cloudOrigin, api: cloudOrigin }),
    'POST /device/auth': (q, r, url, form) => {
      if (form.get('client_id') !== 'frameleaf-link' || !form.get('jkt')) return send(r, 400, { error: 'invalid_request' });
      const userCode = 'BCDF-GHJK';
      const deviceCode = randomBytes(16).toString('hex');
      state.devices.set(deviceCode, { userCode, jkt: form.get('jkt'), approved: false, name: form.get('instance_name') });
      send(r, 200, { device_code: deviceCode, user_code: userCode, verification_uri: `${cloudOrigin}/device`, verification_uri_complete: `${cloudOrigin}/device?user_code=${userCode}`, expires_in: 600, interval: 1 });
    },
    // The account site's approval page: here, opening it approves (the person signed in and said yes).
    'GET /device': (q, r, url) => {
      for (const device of state.devices.values()) if (device.userCode === url.searchParams.get('user_code')) device.approved = true;
      r.writeHead(200, { 'content-type': 'text/html' });
      r.end('<p>Approved</p>');
    },
    'POST /token': (q, r, url, form) => {
      if (form.get('grant_type') === 'urn:ietf:params:oauth:grant-type:device_code') {
        const device = state.devices.get(form.get('device_code'));
        if (!device) return send(r, 400, { error: 'expired_token' });
        if (!device.approved) return send(r, 400, { error: 'authorization_pending' });
        state.devices.delete(form.get('device_code'));
        const token = `link-${randomBytes(16).toString('hex')}`;
        state.linkTokens.set(token, device.jkt);
        return send(r, 200, { access_token: token, token_type: 'Bearer', expires_in: 600 });
      }
      if (form.get('grant_type') !== 'client_credentials' || form.get('client_assertion_type') !== 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer') return send(r, 400, { error: 'unsupported_grant_type' });
      const instance = state.instances.get(form.get('client_id'));
      if (!instance) return send(r, 401, { error: 'invalid_client' });
      const assertion = openJws(form.get('client_assertion'), instance.jwk.x);
      const p = assertion?.payload;
      if (!p || assertion.header.kid !== instance.jwk.kid || p.iss !== instance.id || p.sub !== instance.id || p.aud !== `${cloudOrigin}/token` || p.exp > Date.now() / 1000 + 300) return send(r, 401, { error: 'invalid_client' });
      if (form.get('resource') !== cloudOrigin) return send(r, 400, { error: 'invalid_target' });
      if (!proof(q, r, url, { origin: 'token', x: instance.jwk.x, oauth: true })) return;
      const token = `at-${randomBytes(24).toString('hex')}`;
      state.tokens.set(token, instance.id);
      send(r, 200, { access_token: token, token_type: 'DPoP', expires_in: 600, scope: 'instance' });
    },
    'POST /v1/instances': (q, r, url, form, body) => {
      const token = (q.headers.authorization ?? '').replace(/^Bearer /, '');
      const jkt = state.linkTokens.get(token);
      if (!jkt) return refuse(r, 401, 'invalid_token');
      if (body.computer && body.kind !== 'backup-machine') return refuse(r, 422, 'request-invalid');
      if (thumbprint(body.jwk?.x) !== jkt || body.jwk.kid !== jkt) return refuse(r, 401, 'invalid_token');
      if (!proof(q, r, url, { origin: 'api', x: body.jwk.x })) return;
      state.linkTokens.delete(token);
      state.instances.set(body.instanceId, { id: body.instanceId, jwk: body.jwk, name: body.name, computer: body.computer === true, linked: true });
      send(r, 201, { instanceId: body.instanceId, kind: 'backup-machine', ...(body.computer ? { computer: true } : {}), oidc: { issuer: cloudOrigin, clientId: body.instanceId, scope: 'openid email profile', roleClaim: 'frameleaf_role', storageLabelClaim: '' }, services: {}, owner: { accountId: randomUUID(), label: 'Pat', email: 'pat@example.test', dataRegion: 'na' } });
    },
  };

  /** An instance API call: a DPoP-bound token and a proof with `ath`. */
  function instanceOf(q, r, url) {
    const token = (q.headers.authorization ?? '').replace(/^DPoP /, '');
    const id = state.tokens.get(token);
    const instance = id && state.instances.get(id);
    if (!instance || !instance.linked) return refuse(r, 401, 'invalid_token'), null;
    return proof(q, r, url, { origin: 'api', x: instance.jwk.x, token }) ? instance : null;
  }

  const grant = (instance, operation) => {
    const accessKeyId = `STANDIN${randomBytes(8).toString('hex').toUpperCase()}`;
    const credential = { accessKeyId, secretAccessKey: randomBytes(20).toString('hex'), sessionToken: randomBytes(24).toString('hex'), operation, bucket: `fl-na-${instance.id}` };
    state.credentials.set(accessKeyId, credential);
    return {
      provider: 'frameleaf', region: 'us-east-1', endpoint: `${s3Origin}/`, bucket: credential.bucket, quotaBytes: 1e12, readOnly: state.purge?.status === 'held',
      versioning: true, policy: { denies: ['s3:DeleteObjectVersion', 's3:PutBucketVersioning', 's3:DeleteBucket', 's3:PutBucketPolicy', 's3:PutLifecycleConfiguration'] },
      version: 4, storageId: randomUUID(), location: { locationId: 'loc-01', cityId: 'toronto', city: 'Toronto', country: 'Canada', countryCode: 'CA' }, coverage: { scope: 'all' },
      objectFormats: { read: [{ format: 'frameleaf-repository', version: 1 }], write: [{ format: 'frameleaf-repository', version: 1 }] },
      capability: { version: 1, operation, expiresAt: new Date(Date.now() + 900_000).toISOString(), refreshAfterSec: 600, credentials: { accessKeyId, secretAccessKey: credential.secretAccessKey, sessionToken: credential.sessionToken } },
    };
  };
  const leaseRule = (body) => (body.operation === 'restore') === (body.leaseId === undefined);
  const signingInput = (d) => 'frameleaf-backup-snapshot-v2\n' + JSON.stringify({
    version: d.version, instanceId: d.instanceId, vaultId: d.vaultId, snapshotId: d.snapshotId, sequence: d.sequence, previousDigest: d.previousDigest, createdAt: d.createdAt,
    manifest: { format: d.manifest.format, formatVersion: d.manifest.formatVersion, keyVersion: d.manifest.keyVersion, objectKey: d.manifest.objectKey, versionId: d.manifest.versionId, ciphertextSha256: d.manifest.ciphertextSha256 },
    signerKid: d.signerKid,
  });

  const api = {
    'GET /v4/backup/locations': (i, r) => send(r, 200, { version: 2, locations: [{ locationId: 'loc-01', cityId: 'toronto', city: 'Toronto', country: 'Canada', countryCode: 'CA', probeUrl: `${s3Origin}/` }] }),
    'GET /v4/backup/grant': (i, r) => (i.granted ? send(r, 200, (({ capability, ...meta }) => meta)(grant(i, 'restore'))) : refuse(r, 404, 'not-found')),
    'POST /v4/backup/grant': (i, r, body) => {
      if (!body.objectFormat) return refuse(r, 426, 'backup-protocol-required');
      if (body.objectFormat !== 'frameleaf-repository/1' || !leaseRule(body) || body.locationId !== 'loc-01') return refuse(r, 422, 'request-invalid');
      if (!state.plan) return refuse(r, 402, 'entitlement-missing');
      if (body.leaseId && state.lease?.leaseId !== body.leaseId) return refuse(r, 409, 'lease-lost');
      if (body.operation === 'upload' && state.purge?.status === 'held') return refuse(r, 403, 'backup-read-only');
      const created = !i.granted;
      i.granted = true;
      send(r, created ? 201 : 200, grant(i, body.operation));
    },
    'POST /v4/backup/grant/rotate': (i, r, body) => {
      if (!i.granted || !leaseRule(body)) return refuse(r, 422, 'request-invalid');
      if (body.leaseId && state.lease?.leaseId !== body.leaseId) return refuse(r, 409, 'lease-lost');
      send(r, 200, grant(i, body.operation));
    },
    'POST /v4/backup/lease': (i, r, body) => {
      if (state.lease && state.lease.leaseId !== body.leaseId && state.lease.expires > Date.now()) return refuse(r, 409, 'lease-held');
      const fresh = state.lease?.leaseId !== body.leaseId;
      state.lease = { leaseId: body.leaseId, operation: body.operation, expires: Date.now() + 300_000 };
      send(r, fresh ? 201 : 200, { leaseId: body.leaseId, operation: body.operation, acquiredAt: new Date().toISOString(), expiresAt: new Date(state.lease.expires).toISOString(), heartbeatAfterSec: 60 });
    },
    'POST /v4/backup/lease/heartbeat': (i, r, body) => {
      if (state.lease?.leaseId !== body.leaseId) return refuse(r, 409, 'lease-lost');
      state.lease.expires = Date.now() + 300_000;
      send(r, 200, { leaseId: body.leaseId, operation: state.lease.operation, acquiredAt: new Date().toISOString(), expiresAt: new Date(state.lease.expires).toISOString(), heartbeatAfterSec: 60 });
    },
    'DELETE /v4/backup/lease': (i, r, body, url) => {
      if (state.lease?.leaseId === url.searchParams.get('leaseId')) state.lease = null;
      send(r, 204);
    },
    'POST /v1/backup/runs': (i, r, body) => { state.runs.push(body); send(r, 202, {}); },
    'PUT /v1/backup/settings': (i, r, body) => { state.settings = body; send(r, 200, body); },
    'GET /v1/backup/usage': (i, r) => {
      let bytes = 0;
      for (const versions of objects.values()) bytes += versions.at(-1).body?.length ?? 0;
      send(r, 200, { measuredAt: new Date().toISOString(), bytesCurrent: bytes, bytesNoncurrent: 0, objects: objects.size, includedBytes: 1e12, accountBytesCurrent: bytes + 4.13e11, extraBlocks: 0, allowanceBytes: 1e12, blockBytes: 1e12, readOnly: state.purge?.status === 'held', readOnlyReason: state.purge?.status === 'held' ? 'purge_hold' : null });
    },
    'PUT /v1/backup/escrow': (i, r, body) => {
      if (body.kdf?.name !== 'scrypt' || body.kdf.N !== 131072 || body.cipher !== 'aes-256-gcm') return refuse(r, 422, 'request-invalid');
      state.escrow = { ...body, updatedAt: new Date().toISOString() };
      send(r, 200, state.escrow);
    },
    'GET /v1/backup/escrow': (i, r) => (state.escrow ? send(r, 200, state.escrow) : refuse(r, 404, 'not-found')),
    'DELETE /v1/backup/escrow': (i, r) => { state.escrow = null; send(r, 204); },
    'POST /v2/backup/snapshots': (i, r, body) => {
      const d = body.descriptor;
      const head = state.snapshots.get(d?.vaultId)?.at(-1);
      const key = `r/v1/${d?.vaultId}/s/${String(d?.sequence).padStart(12, '0')}-`;
      if (!d || d.version !== 2 || d.instanceId !== i.id || d.signerKid !== i.jwk.kid || !d.manifest.objectKey.startsWith(key) || !/^[0-9a-f]{64}$/.test(d.manifest.ciphertextSha256) || !d.manifest.versionId) return refuse(r, 422, 'request-invalid');
      if (d.sequence !== (head?.descriptor.sequence ?? 0) + 1 || d.previousDigest !== (head?.digest ?? null)) return refuse(r, 409, 'snapshot-sequence-conflict');
      const bytes = Buffer.from(signingInput(d));
      if (!verify(null, bytes, keyOf(i.jwk.x), Buffer.from(body.signature, 'base64url'))) return refuse(r, 422, 'snapshot-signature-invalid');
      const stored = objects.get(d.manifest.objectKey)?.find((v) => v.version === d.manifest.versionId);
      if (!stored || sha256(stored.body).toString('hex') !== d.manifest.ciphertextSha256) return refuse(r, 422, 'snapshot-object-mismatch');
      const record = { ...body, digest: sha256(bytes).toString('hex'), signerJwk: i.jwk, receivedAt: new Date().toISOString() };
      state.snapshots.set(d.vaultId, [...(state.snapshots.get(d.vaultId) ?? []), record]);
      send(r, 201, record);
    },
    'GET /v2/backup/snapshots': (i, r, body, url) => {
      const list = state.snapshots.get(url.searchParams.get('vaultId')) ?? [];
      const head = list.at(-1);
      send(r, 200, { snapshots: list.filter((s) => s.descriptor.sequence > Number(url.searchParams.get('afterSequence') ?? 0)).slice(0, Number(url.searchParams.get('limit') ?? 100)), head: head ? { sequence: head.descriptor.sequence, digest: head.digest } : null, nextAfterSequence: null });
    },
    'POST /v1/backup/purge': (i, r) => {
      const now = Date.now();
      state.purge = { id: randomUUID(), status: 'held', requestedBy: 'instance', requestedAt: new Date(now).toISOString(), holdUntil: new Date(now + 30 * 86_400_000).toISOString(), purgeBy: new Date(now + 90 * 86_400_000).toISOString(), cancellable: true, cancelledAt: null, purgedAt: null };
      send(r, 201, state.purge);
    },
    'GET /v1/backup/purge': (i, r) => (state.purge ? send(r, 200, state.purge) : refuse(r, 404, 'not-found')),
    'DELETE /v1/backup/purge': (i, r) => {
      if (!state.purge || state.purge.status !== 'held') return refuse(r, 404, 'not-found');
      state.purge = { ...state.purge, status: 'cancelled', cancelledAt: new Date().toISOString() };
      send(r, 200, state.purge);
    },
    'DELETE /v1/instance': (i, r) => { i.linked = false; send(r, 204); },
  };

  const cloud = createServer(async (q, r) => {
    const parts = [];
    for await (const part of q) parts.push(part);
    const raw = Buffer.concat(parts).toString();
    const url = new URL(q.url, cloudOrigin);
    const route = `${q.method} ${url.pathname}`;
    state.log.push(route);
    const form = new URLSearchParams(q.headers['content-type']?.includes('form') ? raw : '');
    let body = {};
    try { body = raw && q.headers['content-type']?.includes('json') ? JSON.parse(raw) : {}; } catch { return refuse(r, 422, 'request-invalid'); }
    if (routes[route]) return routes[route](q, r, url, form, body);
    if (api[route]) {
      const instance = instanceOf(q, r, url);
      if (instance) return api[route](instance, r, body, url);
      return;
    }
    refuse(r, 404, 'not-found');
  });

  const listen = (server) => new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve(`http://127.0.0.1:${server.address().port}`)));
  cloudOrigin = await listen(cloud);
  s3Origin = await listen(s3);
  return { cloud: cloudOrigin, s3: s3Origin, state, objects, close: () => Promise.all([new Promise((d) => cloud.close(d)), new Promise((d) => s3.close(d))]) };
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const running = await standIn({ plan: process.env.STAND_IN_PLAN !== '0' });
  console.log(JSON.stringify({ cloud: running.cloud, s3: running.s3 }));
}
