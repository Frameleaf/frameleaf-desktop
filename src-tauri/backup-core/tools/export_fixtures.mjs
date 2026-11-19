// Writes tests/fixtures from the TypeScript engine: golden vectors, the cross-engine library, and a
// repository the TypeScript engine stored, for the Rust tests to read.
//
//   node tools/export_fixtures.mjs <built packages/backup-core dist folder>
//
// The dist folder is `tsc -p packages/backup-core/tsconfig.json` output from frameleaf-app.
import { createHash, hkdfSync } from 'node:crypto';
import { mkdir, rm, writeFile } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { chunker, expected, noise, packTarget, rootKey, source, versions } from './library.mjs';

const dist = process.argv[2];
if (!dist) {
  throw new Error('Usage: node tools/export_fixtures.mjs <backup-core dist folder>');
}
const core = await import(pathToFileURL(join(resolve(dist), 'index.js')).href);
const fixtures = join(dirname(fileURLToPath(import.meta.url)), '..', 'tests', 'fixtures');

const cuts = async (data, key, params) => {
  const sizes = [];
  async function* parts() {
    for (let at = 0; at < data.length; at += 7000) {
      yield data.subarray(at, at + 7000);
    }
  }
  for await (const chunk of core.chunkStream(parts(), params, core.gearTable(key))) {
    sizes.push(chunk.length);
  }
  return sizes;
};

// Manager's vaultOf, as manager/src/server-backup.ts has it.
const vaultOf = (key) => {
  const bytes = Buffer.from(hkdfSync('sha256', key, Buffer.alloc(0), 'frameleaf-server-backup vault', 16));
  bytes[6] = (bytes[6] & 0x0f) | 0x80;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = bytes.toString('hex');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
};

const keys = core.deriveKeys(Buffer.alloc(32, 1), '00000000-0000-4000-8000-000000000000');
const gear = core.gearTable(keys.cut);
const recoveryKey = Buffer.from(Array.from({ length: 32 }, (_, index) => (index * 37 + 11) & 0xff));
const descriptor = {
  version: 2,
  instanceId: '0195a1b2-0000-7000-8000-000000000001',
  vaultId: '0195a1b2-0000-7000-8000-000000000002',
  snapshotId: '0195a1b2-0000-7000-8000-000000000003',
  sequence: 7,
  previousDigest: 'b'.repeat(64),
  createdAt: '2026-11-17T00:00:00.000Z',
  manifest: {
    format: 'frameleaf-repository',
    formatVersion: 1,
    keyVersion: 1,
    objectKey: 'r/v1/0195a1b2-0000-7000-8000-000000000002/s/000000000007-0123456789abcdef',
    versionId: 'v1',
    ciphertextSha256: 'a'.repeat(64),
  },
  signerKid: 'kid',
};
const signed = core.signS3Request({
  method: 'PUT',
  host: 'localhost:9000',
  canonicalUri: '/bucket/r/v1/vault/p/%C3%BC%20x',
  query: 'partNumber=2&uploadId=a%2Fb',
  headers: { 'Content-Type': ' application/octet-stream ' },
  body: Buffer.from('hello'),
  region: 'us-east-1',
  accessKeyId: 'AKIDEXAMPLE',
  secretAccessKey: 'secret',
  sessionToken: 'token',
  now: new Date('2026-11-18T12:34:56.789Z'),
});
const escrow = await core.wrapBucketKey(Buffer.alloc(32, 7), 'correct horse battery staple', {
  salt: Buffer.alloc(16, 3),
  nonce: Buffer.alloc(12, 4),
});

await rm(fixtures, { recursive: true, force: true });
await mkdir(fixtures, { recursive: true });

// A repository the TypeScript engine stored: one snapshot per library version.
const store = core.dirStore(join(fixtures, 'ts-repo'));
const repository = await core.Repository.init(store, { rootKey, chunker });
const snapshots = [];
for (const version of versions) {
  const result = await core.backup(repository, source(version), { packTarget, time: new Date(version.time) });
  snapshots.push({ key: result.key, tree: result.snapshot.tree, stats: result.snapshot.stats, expected: expected(version) });
}

await writeFile(
  join(fixtures, 'vectors.json'),
  `${JSON.stringify(
    {
      keys: Object.fromEntries(Object.entries(keys).map(([name, value]) => [name, value.toString('hex')])),
      gearSha256: createHash('sha256')
        .update(Buffer.from(gear.buffer, gear.byteOffset, gear.byteLength))
        .digest('hex'),
      blobId: core.blobId(keys, Buffer.from('frameleaf')).toString('hex'),
      cutsDefault: await cuts(noise(100_000, 42), keys.cut, { min: 1024, avg: 4096, max: 16_384 }),
      cutsSmall: await cuts(noise(30_000, 7), keys.cut, chunker),
      recoveryCode: core.recoveryCode(recoveryKey),
      vaultId: vaultOf(Buffer.alloc(32, 7)),
      signedS3: signed,
      escrow,
      signingInputSha256: createHash('sha256').update(core.snapshotSigningInput(descriptor)).digest('hex'),
      descriptor,
    },
    null,
    2,
  )}\n`,
);
await writeFile(join(fixtures, 'library.json'), `${JSON.stringify({ chunker, packTarget, rootKey: rootKey.toString('hex'), versions }, null, 2)}\n`);
await writeFile(join(fixtures, 'ts-repo.json'), `${JSON.stringify({ snapshots }, null, 2)}\n`);
console.log(`Wrote ${fixtures}`);
