// Opt-in synthetic fixture for the compiled controller test; never reads an existing profile.
import assert from "node:assert/strict";
import { createHash, randomBytes, randomUUID } from "node:crypto";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { readFile, writeFile, rm, realpath } from "node:fs/promises";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { claimState, runHost, hostEnvironment, canonicalHostPathMatches } from "../runtime/host-agent.mjs";
import { qualifyUpdatePhoto } from "./update_photo_fixture.mjs";

let input = "";
for await (const part of process.stdin) {
  input += part;
  assert.ok(input.length < 64 * 1024);
}
const config = JSON.parse(input);
const { root, manager, mode, secureInstallationId, update, ...c } = config;
assert.match(secureInstallationId, /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/);
assert.notEqual(secureInstallationId, "00000000-0000-0000-0000-000000000000");
assert.ok(canonicalHostPathMatches(await realpath(root), root));
assert.equal(c.state, join(root, "profile"));
assert.equal(resolve(c.runtime), c.runtime);
assert.equal(resolve(manager), manager);
const exec = promisify(execFile);
const env = { ...hostEnvironment(c), PGPASSWORD: c.password };
const command = async (name, args) => (await exec(join(c.runtime, c.entryPoints[name]), args,
  { cwd: root, env, timeout: 120000, maxBuffer: 2 * 1024 * 1024 })).stdout.trim();
const database = join(c.state, "database");
const connection = ["-h", "127.0.0.1", "-p", String(c.databasePort), "-U", "frameleaf"];
const sql = query => command("psql", [...connection, "-d", "frameleaf", "-XAt", "-v", "ON_ERROR_STOP=1", "-c", query]);
const stopDatabase = directory => command("pgCtl", ["-D", directory, "-m", "fast", "-w", "stop"]);
const startDatabase = directory => command("pgCtl", ["-D", directory, "-l", join(root, "fixture-postgres.log"),
  "-o", `-h 127.0.0.1 -p ${c.databasePort}`, "-w", "start"]);
if (mode === "approve-update") {
  assert.match(update.backupKey, /^[A-Za-z0-9_-]{43}$/);
  await assert.rejects(command("pgCtl", ["-D", database, "status"]), { code: 3 });
  const { Store } = await import(pathToFileURL(join(manager, "store.js")));
  const { digest } = await import(pathToFileURL(join(manager, "contracts.js")));
  const { approveNativeUpdate } = await import(pathToFileURL(join(manager, "runtime/native-update-approval.js")));
  const store = new Store(join(root, "manager"));
  try {
    const binding = store.get("native-installation");
    assert.ok(binding && digest(binding.descriptor) === binding.fingerprint);
    const installation = binding.descriptor.installation;
    assert.equal(installation.state, c.state);
    assert.equal(installation.manifestSha256, c.manifestSha256);
    assert.equal(installation.secureInstallationId, secureInstallationId);
    const runtime = { identity: { runtime: "native", installationId: installation.id, fingerprint: digest(installation) },
      status: () => ({ state: "stopped" }) };
    const result = await approveNativeUpdate(store, runtime, { managerFingerprint: binding.fingerprint, installation,
      libraryId: installation.id, name: binding.descriptor.name, release: binding.descriptor.release }, update.backupKey,
      { backupOperationId: update.backupOperationId, targetManifestSha256: update.targetManifestSha256, migrationsApproved: true, key: randomUUID() });
    console.log(JSON.stringify(result));
  } finally { store.close(); }
} else if (mode === "selected-update") {
  assert.equal(await sql("SELECT value->>'label' FROM system_metadata WHERE key='native-owner-qualification'"), "selected");
  assert.equal(await sql("SELECT value->>'label' FROM system_metadata WHERE key='native-update-migration-qualification'"), "target-only");
  await sql(`BEGIN; INSERT INTO system_metadata(key,value) VALUES('native-update-writer-qualification','{"label":"write-probe"}'); ROLLBACK;`);
  assert.equal(await sql("SELECT count(*) FROM system_metadata WHERE key='native-update-writer-qualification'"), "0");
  const proof = JSON.parse(await readFile(join(root, "photo-proof.json"), "utf8"));
  const photos = await qualifyUpdatePhoto(`http://127.0.0.1:${c.apiPort}`, c.password, proof);
  console.log(JSON.stringify({ selectedRows: true, targetMigration: true, writeTransaction: true, photos }));
} else if (mode === "selected") {
  assert.equal(await sql("SELECT value->>'label' FROM system_metadata WHERE key='native-owner-qualification'"), "selected");
  assert.equal(await sql("SELECT value->>'fixtureRow' FROM system_metadata WHERE key='native-owner-qualification'"), "original-seeded-row");
  console.log(JSON.stringify({ selectedRows: true }));
} else if (mode === "original" || mode === "original-update") {
  await startDatabase(database);
  try {
    assert.equal(await sql("SELECT value->>'label' FROM system_metadata WHERE key='native-owner-qualification'"), "original-current");
    if (mode === "original-update") assert.equal(await sql("SELECT count(*) FROM system_metadata WHERE key='native-update-migration-qualification'"), "0");
    assert.equal(await sql("SELECT value->>'fixtureRow' FROM system_metadata WHERE key='native-owner-qualification'"), "original-seeded-row");
  } finally { await stopDatabase(database); }
  console.log(JSON.stringify({ originalRows: true }));
} else {
  assert.ok(mode === "seed" || mode === "seed-update");
  if (mode === "seed-update") assert.match(update.backupKey, /^[A-Za-z0-9_-]{43}$/);
  await claimState({ ...c, mode: "database" });
  await assert.rejects(readFile(join(database, "PG_VERSION")), { code: "ENOENT" });
  const load = name => import(pathToFileURL(join(manager, name)));
  const { Store } = await load("store.js");
  const { digest } = await load("contracts.js");
  const { Backups } = await load("backups.js");
  const { command: backupCommand } = await load("docker.js");
  const { NativeService } = await load("runtime/native-service.js");
  const { prepareNativeRestoreReview } = await load("runtime/native-restore-review.js");
  const { runNativeRestorePrebackup } = await load("runtime/native-restore-operation.js");
  const store = new Store(join(root, "manager"));
  const installation = { runtime: "native", id: "a".repeat(12), secureInstallationId, controller: join(root, "unused-controller"),
    candidate: c.runtime, state: c.state, manifestSha256: c.manifestSha256, sourceRevision: c.sourceRevision,
    certified: false, databasePort: c.databasePort, apiPort: c.apiPort };
  const identity = { runtime: "native", installationId: installation.id, fingerprint: digest(installation) };
  const context = { installation, libraryId: installation.id, name: "Synthetic controller qualification", release: "frameleaf-v3.0.0-1" };
  const executable = join(c.runtime, c.entryPoints.backupEngine);
  const executableSha = createHash("sha256").update(await readFile(executable)).digest("hex");
  const component = JSON.parse(await readFile(join(c.runtime, "backup/component.json"), "utf8"));
  assert.equal(component.name, "restic");
  assert.equal(executableSha, component.artifact.binarySha256);
  const key = mode === "seed-update" ? update.backupKey : randomBytes(32).toString("base64url");
  const backups = new Backups(mode === "seed-update" ? join(root, "manager/backups/frameleaf-database") : join(root, "repository"), async () => key,
    (binary, args, options = {}) => backupCommand(binary, args, { ...options, executable,
      env: { HOME: root, XDG_CACHE_HOME: join(root, "cache"), PATH: "", GOMAXPROCS: "1",
        ...(process.platform === "win32" ? { SystemRoot: env.SystemRoot } : {}) } }));
  let stop, work, handler, phase = "stopped", initialized = false;
  const startOwner = mode => new Promise((ready, reject) => {
    const stopping = new Promise(resolve => { stop = resolve; });
    work = runHost({ ...c, mode }, stopping, value => {
      handler = value; phase = mode;
      ready({ protocolVersion: 1, state: mode === "database" ? "database-ready" : mode === "server" ? "running" : "checkpoint-cleanup-ready",
        secureInstallationId, manifestSha256: c.manifestSha256, sourceRevision: c.sourceRevision, certified: false });
    });
    void work.catch(reject);
  });
  const adapter = { identity, status: () => phase === "stopped" ? { state: "stopped" } : { state: "unknown", code: "native_database_maintenance" },
    start: async () => { throw Error("fixture must not start writers"); },
    startDatabase: () => startOwner("database"), startCheckpointCleanup: () => startOwner("checkpoint-cleanup"),
    stop: async () => { stop?.(); await work; phase = "stopped"; return { protocolVersion: 1, state: "stopped" }; },
    checkpoint: async operationId => ({ protocolVersion: 1, state: "checkpoint", ...await handler({ action: "checkpoint", operationId }) }),
    cleanupCheckpoint: async ({ protocolVersion, state, ...checkpoint }) => ({ protocolVersion: 1,
      ...await handler({ action: "cleanup-checkpoint", operationId: checkpoint.operationId, checkpoint }) }) };
  try {
    const passwordFile = join(root, "password");
    await writeFile(passwordFile, c.password, { mode: 0o600, flag: "wx" });
    await command("initdb", ["-D", database, "--username=frameleaf", "--encoding=UTF8", "--locale=C", "--data-checksums",
      "--auth-local=scram-sha-256", "--auth-host=scram-sha-256", "--pwfile=" + passwordFile]);
    initialized = true;
    await rm(passwordFile);
    await startDatabase(database);
    await command("createdb", [...connection, "frameleaf"]);
    await exec(join(c.runtime, c.entryPoints.node), [join(c.runtime, c.entryPoints.server), "frameleaf-admin", "restore-state"],
      { cwd: root, env: { ...env, DB_HOSTNAME: "127.0.0.1", DB_PORT: String(c.databasePort), DB_USERNAME: "frameleaf",
        DB_PASSWORD: c.password, DB_DATABASE_NAME: "frameleaf", FRAMELEAF_MANAGER_ORIGIN: "restored_library",
        FRAMELEAF_MANAGER_INSTALLATION: installation.id, FRAMELEAF_MANAGER_RESTORE_OPERATION_ID: randomUUID(),
        FRAMELEAF_MEDIA_LOCATION: join(c.state, "media"), FRAMELEAF_BUILD_DATA: join(c.runtime, "build"),
        FRAMELEAF_HDR_BINDING: join(c.runtime, c.entryPoints.hdr), UV_THREADPOOL_SIZE: "1" }, timeout: 120000, maxBuffer: 2 * 1024 * 1024 });
    await sql(`INSERT INTO system_metadata(key,value) VALUES('native-owner-qualification','{"label":"selected","fixtureRow":"original-seeded-row"}')`);
    await stopDatabase(database);
    if (mode === "seed-update") {
      await startOwner("server");
      try {
        const proof = await qualifyUpdatePhoto(`http://127.0.0.1:${c.apiPort}`, c.password);
        await writeFile(join(root, "photo-proof.json"), JSON.stringify(proof), { mode: 0o600, flag: "wx" });
      } finally { await adapter.stop(); }
    }
    const service = new NativeService(store, { protocolVersion: 2, installation, backupKey: key, password: c.password,
      controllerSha256: "e".repeat(64), backupEngine: { executable, sha256: executableSha },
      tls: { certificatePem: "synthetic certificate", privateKeyPem: "synthetic private key" }, name: context.name, release: context.release }, adapter, backups);
    const first = service.control("backup", randomUUID());
    assert.equal((await service.wait(first.id)).state, "complete");
    const snapshot = store.history()[0].receipts["native-backup-verified"];
    if (mode === "seed-update") {
      assert.equal(phase, "stopped");
      const backupOperationId = first.id;
      await startDatabase(database);
      try { await sql(`UPDATE system_metadata SET value='{"label":"original-current","fixtureRow":"original-seeded-row"}' WHERE key='native-owner-qualification'`); }
      finally { await stopDatabase(database); }
      console.log(JSON.stringify({ backupOperationId, snapshotId: snapshot.snapshotId }));
    } else {
    const review = await prepareNativeRestoreReview(store, backups, { installation, libraryId: installation.id, release: context.release }, snapshot.snapshotId);
    await startDatabase(database);
    await sql(`UPDATE system_metadata SET value='{"label":"original-current","fixtureRow":"original-seeded-row"}' WHERE key='native-owner-qualification'`);
    await stopDatabase(database);
    const operation = store.start("restore", randomUUID(), { reviewId: review.id, ...identity }).operation;
    const result = await runNativeRestorePrebackup(store, adapter, backups, context, operation);
    assert.equal(phase, "stopped");
    assert.equal(store.history()[0].state, "running");
    const binding = operation.receipts["native-restore-prebackup-intent"].binding;
    const { protocolVersion, state: checkpointState, ...checkpoint } = result.recovery.checkpoint;
    console.log(JSON.stringify({ binding, safety: { snapshotId: result.snapshotId,
      recoverySha256: digest(result.recovery), checkpoint } }));
    }
  } finally {
    try {
      await adapter.stop();
    } finally {
      try {
        store.close();
      } finally {
        if (initialized) {
          try { await command("pgCtl", ["-D", database, "status"]); await stopDatabase(database); }
          catch (error) { assert.equal(error.code, 3, "fixture shutdown must be confirmed"); }
        }
      }
    }
  }
}
