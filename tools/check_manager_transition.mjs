// Runs the real Manager's own code on Windows against the descriptors Desktop fingerprints in
// `manager_host::tests::windows_descriptor_fingerprints_are_the_ones_manager_stores`:
// Manager must store exactly those fingerprints, accept the package transition Desktop sends
// from the first to the second, accept the same transition again, and refuse any other.
//
// Usage: node tools/check_manager_transition.mjs <built Manager "app/build" directory>
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";

if (process.platform !== "win32") throw new Error("These are Windows paths: run this on Windows");
const build = resolve(process.argv[2] ?? "");
const load = (name) => import(pathToFileURL(join(build, name)).href);
const { NativeService } = await load("runtime/native-service.js");
const { Store } = await load("store.js");

const FINGERPRINT = {
  previous: "18db0c2f9c9d2c6de9fa7ba619ccae542cb0f4c6509f6aa84dcfb1ce9f20c9e2",
  next: "9e4edbeab516450823bc031af37a5497c90d6a13f45d4eaff2fbf5d3b832ad25",
};
const root = "\\\\.\\GLOBALROOT\\Device\\HarddiskVolume3\\Program Files\\Frameleaf Desktop Host";
const state = "\\\\.\\GLOBALROOT\\Device\\HarddiskVolume3\\Users\\Zoë\\AppData\\Local\\Frameleaf Desktop Host\\state";
const id = "1d0ea3c5161e";
// What Desktop sends: the backup engine's path has the one forward slash Manager rewrites.
const bootstrap = (manifest, controller, revision, release, installationTransition) => ({
  protocolVersion: 2,
  installation: {
    runtime: "native",
    id,
    secureInstallationId: "c6c6b19e-000f-88a2-9241-7571029303a6",
    controller: `${root}\\Controllers\\${manifest}\\${controller}\\frameleaf-native-host.exe`,
    candidate: `${root}\\Runtimes\\${manifest}`,
    state,
    manifestSha256: manifest,
    sourceRevision: revision,
    certified: false,
    databasePort: 54329,
    apiPort: 2283,
  },
  controllerSha256: controller,
  backupEngine: {
    executable: `${root}\\Runtimes\\${manifest}\\payload\\backup/restic.exe`,
    sha256: "01143daba61a1dc8afb0cb3d03ba83e6b118f55b6b146b27473a09efc3df13d6",
  },
  name: "My Frameleaf library",
  release,
  password: "synthetic native database password",
  backupKey: "k".repeat(43),
  tls: { certificatePem: "synthetic certificate", privateKeyPem: "synthetic private key" },
  ...(installationTransition ? { installationTransition } : {}),
});
const previous = (transition) =>
  bootstrap(
    "2047575e52c6bf5f0f1c3a44a56fa7ef0e8982679c4b77848f2c6a3ebc2c6435",
    "bf2c8b0fbb382066895f40f2e7e2e10832db9ba997f99dadf685ab826b5de68b",
    "c64039743af7bb0d68b602ff842683906019de52",
    "frameleaf-v1.2.3-native.c64039743af7-1",
    transition,
  );
const next = (transition) =>
  bootstrap("b".repeat(64), "c".repeat(64), "d".repeat(40), "frameleaf-v1.2.4-native.dddddddddddd-1", transition);
// Manager never starts a host here: only what it stores and accepts at start is exercised.
const runtime = {
  status: () => ({ state: "stopped" }),
  identity: { runtime: "native", installationId: id, fingerprint: "d".repeat(64) },
};
const stored = (store) => store.get("native-installation")?.fingerprint;
const start = (store, value) => new NativeService(store, value, runtime);
const refused = (store, value) =>
  assert.throws(() => start(store, value), (error) => error?.code === "native_installation_changed");

const scratch = mkdtempSync(join(tmpdir(), "frameleaf-manager-transition-"));
try {
  const store = new Store(join(scratch, "manager"));
  start(store, previous());
  assert.equal(stored(store), FINGERPRINT.previous, "Manager stores another fingerprint for the previous package");
  // Without a transition, and with one from any other descriptor, the new package is refused
  // and Manager's record still names the previous one: it starts again.
  refused(store, next());
  refused(store, next({ operationId: "11111111-1111-4111-8111-111111111111", fromFingerprint: "e".repeat(64) }));
  assert.equal(stored(store), FINGERPRINT.previous);
  start(store, previous());
  // The transition Desktop sends: from the fingerprint it computed for the previous package.
  const transition = { operationId: "22222222-2222-4222-8222-222222222222", fromFingerprint: FINGERPRINT.previous };
  start(store, next(transition));
  assert.equal(stored(store), FINGERPRINT.next, "Manager stores another fingerprint for the new package");
  // Sent again unchanged, as a start that was not seen to finish does: accepted.
  start(store, next(transition));
  // A new transition for a move Manager already accepted is refused: Desktop must resend.
  refused(store, next({ operationId: "33333333-3333-4333-8333-333333333333", fromFingerprint: FINGERPRINT.previous }));
  // Once accepted, the previous package is refused by Manager.
  refused(store, previous());
  assert.equal(stored(store), FINGERPRINT.next);
  store.db.close();
  console.log(`Manager stores and accepts the fingerprints Desktop computes: ${FINGERPRINT.previous} -> ${FINGERPRINT.next}`);
} finally {
  rmSync(scratch, { recursive: true, force: true });
}
process.exit(0);
