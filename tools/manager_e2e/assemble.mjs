// End-to-end run only (tools/manager_e2e/README.md). Makes a second installed companion whose
// Manager is built from a chosen server commit: the released companion's payload with
// `payload/manager` replaced, its manifest rewritten for those files and signed with a key made
// for this run. Only a Desktop built with that key added to its release trust accepts it.
//
//   node assemble.mjs --base MANIFEST --server CHECKOUT --revision COMMIT --controller FILE
//                     --key PRIVATE.pem --epoch N --desktop REPOSITORY --work DIRECTORY
import { execFileSync } from 'node:child_process';
import { createHash, createPrivateKey, sign } from 'node:crypto';
import {
  chmodSync, cpSync, existsSync, lstatSync, mkdirSync, readdirSync, readFileSync, renameSync,
  rmSync, writeFileSync,
} from 'node:fs';
import { join } from 'node:path';

const options = Object.fromEntries(
  process.argv.slice(2).reduce((pairs, value, index, all) => {
    if (index % 2 === 0) pairs.push([value.replace(/^--/, ''), all[index + 1]]);
    return pairs;
  }, []),
);
for (const name of ['base', 'server', 'revision', 'controller', 'key', 'epoch', 'desktop', 'work'])
  if (!options[name]) throw new Error(`--${name} is required`);
if (process.getuid() !== 0) throw new Error('run as root: the package is installed under /opt/frameleaf');
const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');
const BASE = '/opt/frameleaf';
const source = join(BASE, 'Runtimes', options.base);
const node = join(source, 'payload/node');

// 1. Manager, built the way a companion release builds it.
const built = join(options.work, `manager-${options.revision}`);
if (!existsSync(join(built, 'manager/package.json'))) {
  rmSync(built, { recursive: true, force: true });
  execFileSync('python3', [
    join(options.desktop, 'tools/build_host_manager.py'),
    '--source', options.server, '--revision', options.revision, '--node', node, '--output', built,
  ], { stdio: 'inherit' });
}

// 2. The released payload with that Manager in place of its own.
const staging = join(BASE, `.e2e-${options.revision}`);
rmSync(staging, { recursive: true, force: true });
mkdirSync(staging, { mode: 0o755 });
execFileSync('cp', ['-a', join(source, 'payload'), join(staging, 'payload')]);
rmSync(join(staging, 'payload/manager'), { recursive: true });
cpSync(join(built, 'manager'), join(staging, 'payload/manager'), { recursive: true });
const files = {};
const walk = (directory, prefix) => {
  chmodSync(directory, 0o755);
  for (const name of readdirSync(directory).sort()) {
    const path = join(directory, name);
    const info = lstatSync(path);
    if (info.isDirectory()) walk(path, `${prefix}${name}/`);
    else if (info.isFile()) {
      chmodSync(path, 0o644);
      const bytes = readFileSync(path);
      files[`${prefix}${name}`] = { bytes: bytes.length, sha256: sha256(bytes) };
    } else throw new Error(`unexpected entry ${path}`);
  }
};
walk(join(staging, 'payload/manager'), 'manager/');
execFileSync('chown', ['-R', 'root:root', staging]);

// 3. Its manifest: every other file exactly as released, Manager's as built, a later epoch.
const manifest = JSON.parse(readFileSync(join(source, 'manifest.json')));
for (const name of Object.keys(manifest.files)) if (name.startsWith('manager/')) delete manifest.files[name];
Object.assign(manifest.files, files);
manifest.files = Object.fromEntries(Object.entries(manifest.files).sort(([a], [b]) => (a < b ? -1 : 1)));
manifest.epoch = Number(options.epoch);
const raw = Buffer.from(JSON.stringify(manifest));
writeFileSync(join(staging, 'manifest.json'), raw, { mode: 0o644 });
writeFileSync(
  join(staging, 'manifest.sig'),
  sign(null, raw, createPrivateKey(readFileSync(options.key))),
  { mode: 0o644 },
);
const identity = sha256(raw);
const runtime = join(BASE, 'Runtimes', identity);
if (existsSync(runtime)) throw new Error(`already installed: ${identity}`);
renameSync(staging, runtime);

// 4. The controller built from this repository, installed where the package's own would be,
//    and the same finalization the package's installer runs.
const controller = readFileSync(options.controller);
const controllerIdentity = sha256(controller);
const home = join(BASE, 'Controllers', identity, controllerIdentity);
mkdirSync(home, { recursive: true, mode: 0o755 });
writeFileSync(join(home, 'frameleaf-native-host'), controller, { mode: 0o755 });
execFileSync('chown', ['-R', 'root:root', join(BASE, 'Controllers', identity)]);
const receipt = execFileSync(
  join(home, 'frameleaf-native-host'),
  ['--finalize-install', identity, controllerIdentity],
  { env: { PATH: '/usr/bin:/bin:/usr/sbin:/sbin', LC_ALL: 'C' }, encoding: 'utf8' },
);
process.stderr.write(receipt);
console.log(JSON.stringify({
  manifestSha256: identity,
  controllerSha256: controllerIdentity,
  managerVersion: JSON.parse(readFileSync(join(runtime, 'payload/manager/package.json'))).version,
  capabilities: JSON.parse(readFileSync(join(runtime, 'payload/manager/package.json'))).frameleaf?.nativeCapabilities ?? [],
}));
