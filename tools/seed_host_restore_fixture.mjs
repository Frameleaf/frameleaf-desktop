// Opt-in synthetic fixture for the compiled controller test; never reads an existing profile.
import assert from "node:assert/strict";
import { createHash, randomBytes, randomUUID } from "node:crypto";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { readFile, writeFile, rm, realpath } from "node:fs/promises";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { claimState, runHost, hostEnvironment } from "../runtime/host-agent.mjs";

let input = "";
for await (const part of process.stdin) {
  input += part;
  assert.ok(input.length < 64 * 1024);
}
const config = JSON.parse(input);
const { root, manager, mode, ...c } = config;
assert.equal(await realpath(root), root);
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
if (mode === "selected") {
  assert.equal(await sql("SELECT value->>'label' FROM system_metadata WHERE key='native-owner-qualification'"), "selected");
  assert.equal(await sql("SELECT value->>'fixtureRow' FROM system_metadata WHERE key='native-owner-qualification'"), "original-seeded-row");
  console.log(JSON.stringify({ selectedRows: true }));
} else if (mode === "original") {
  await startDatabase(database);
  try {
    assert.equal(await sql("SELECT value->>'label' FROM system_metadata WHERE key='native-owner-qualification'"), "original-current");
    assert.equal(await sql("SELECT value->>'fixtureRow' FROM system_metadata WHERE key='native-owner-qualification'"), "original-seeded-row");
  } finally { await stopDatabase(database); }
  console.log(JSON.stringify({ originalRows: true }));
} else {
  assert.equal(mode, "seed");
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
  const installation = { runtime: "native", id: "a".repeat(12), controller: join(root, "unused-controller"),
    candidate: c.runtime, state: c.state, manifestSha256: c.manifestSha256, sourceRevision: c.sourceRevision,
    certified: false, databasePort: c.databasePort, apiPort: c.apiPort };
  const identity = { runtime: "native", installationId: installation.id, fingerprint: digest(installation) };
  const context = { installation, libraryId: installation.id, name: "Synthetic controller qualification", release: "frameleaf-v3.0.0-1" };
  const executable = join(c.runtime, c.entryPoints.backupEngine);
  const executableSha = createHash("sha256").update(await readFile(executable)).digest("hex");
  const component = JSON.parse(await readFile(join(c.runtime, "backup/component.json"), "utf8"));
  assert.equal(component.name, "restic");
  assert.equal(executableSha, component.artifact.binarySha256);
  const key = randomBytes(32).toString("base64url");
  const backups = new Backups(join(root, "repository"), async () => key,
    (binary, args, options = {}) => backupCommand(binary, args, { ...options, executable,
      env: { HOME: root, XDG_CACHE_HOME: join(root, "cache"), PATH: "", GOMAXPROCS: "1" } }));
  let stop, work, handler, phase = "stopped", initialized = false;
  const startOwner = mode => new Promise((ready, reject) => {
    const stopping = new Promise(resolve => { stop = resolve; });
    work = runHost({ ...c, mode }, stopping, value => {
      handler = value; phase = mode;
      ready({ protocolVersion: 1, state: mode === "database" ? "database-ready" : "checkpoint-cleanup-ready",
        manifestSha256: c.manifestSha256, sourceRevision: c.sourceRevision, certified: false });
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
    const service = new NativeService(store, { protocolVersion: 2, installation, backupKey: key, password: c.password,
      controllerSha256: "e".repeat(64), backupEngine: { executable, sha256: executableSha },
      tls: { certificatePem: "synthetic certificate", privateKeyPem: "synthetic private key" }, name: context.name, release: context.release }, adapter, backups);
    const first = service.control("backup", randomUUID());
    assert.equal((await service.wait(first.id)).state, "complete");
    const snapshot = store.history()[0].receipts["native-backup-verified"];
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
