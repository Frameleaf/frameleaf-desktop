// Opt-in proof that a library moves across companion packages with real Postgres builds.
// It runs inside the image built from ./Dockerfile; see ./README.md for the command.
// "Previous package" is Postgres 18 with pgvector, "new package" is the pinned Postgres with
// pgvector, and the library schema comes from the product server's own migrations.
import assert from "node:assert/strict";
import { test, before } from "node:test";
import { execFile, spawn } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import { once } from "node:events";
import * as fs from "node:fs/promises";
import { createConnection } from "node:net";
import { networkInterfaces } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const enabled = process.env.FRAMELEAF_CARRY_E2E === "1";
const here = dirname(fileURLToPath(import.meta.url));
const agentPath = join(here, "../../runtime/host-agent.mjs");
const agent = enabled ? await import(agentPath) : undefined;
const password = "synthetic private database password";
const libraryId = "c".repeat(12);
const PREVIOUS = { name: "previous", postgres: "/opt/postgres-previous", manifestSha256: "a".repeat(64), sourceRevision: "1".repeat(40), postgresMajor: "18", databasePort: 55432, apiPort: 52283 };
const NEXT = { name: "next", postgres: "/opt/postgres-next", manifestSha256: "b".repeat(64), sourceRevision: "2".repeat(40), postgresMajor: "19", databasePort: 55433, apiPort: 52284 };
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
const run = (file, args, options = {}) => new Promise((resolve, reject) =>
  execFile(file, args, { maxBuffer: 256 * 1024 * 1024, ...options }, (error, stdout, stderr) =>
    error ? reject(Object.assign(error, { stdout, stderr })) : resolve(stdout)));
let root, template;

/** A stand-in package directory: the layout a signed package's entry points name. */
async function runtime(pkg) {
  const directory = join(root, "package-" + pkg.name);
  await fs.mkdir(directory, { recursive: true });
  for (const [name, target] of [["pg", pkg.postgres], ["server", "/usr/src/app/server"], ["build", "/build"]])
    await fs.symlink(target, join(directory, name)).catch(error => { if (error.code !== "EEXIST") throw error; });
  await fs.mkdir(join(directory, "tools"), { recursive: true });
  await fs.symlink(process.execPath, join(directory, "tools/node")).catch(error => { if (error.code !== "EEXIST") throw error; });
  return directory;
}
function config(pkg, state, mode, extra = {}) {
  const pg = name => "pg/bin/" + name;
  return {
    mode, state, runtime: join(root, "package-" + pkg.name), manifestSha256: pkg.manifestSha256, sourceRevision: pkg.sourceRevision,
    postgresMajor: pkg.postgresMajor, password, databasePort: pkg.databasePort, apiPort: pkg.apiPort,
    entryPoints: { node: "tools/node", server: "server/dist/main.js", postgres: pg("postgres"), initdb: pg("initdb"), createdb: pg("createdb"),
      psql: pg("psql"), pgIsready: pg("pg_isready"), pgCtl: pg("pg_ctl"), pgDump: pg("pg_dump"), pgRestore: pg("pg_restore"),
      pgChecksums: pg("pg_checksums"), hdr: "server/hdr.node", ffmpeg: "media/ffmpeg", ffprobe: "media/ffprobe",
      rawRenderer: "raw/darktable-cli", rawDecoder: "raw/dcraw_emu", studioBrowser: "browser/chrome",
      studioBrowserGuard: "studio/guard", studio: "studio/main.js" },
    ...extra,
  };
}
const exportConfig = (state, permitId) => config(PREVIOUS, state, "carry-export",
  { carry: { permitId, libraryId, target: { manifestSha256: NEXT.manifestSha256, postgresVersion: "19beta4", vectorVersion: "0.8.7" } } });
const restoreConfig = (state, permitId) => config(NEXT, state, "carry-restore",
  { carry: { permitId, libraryId, source: { manifestSha256: PREVIOUS.manifestSha256, sourceRevision: PREVIOUS.sourceRevision, postgresMajor: PREVIOUS.postgresMajor } } });

async function startPostgres(pkg, data, port, options = []) {
  const child = spawn(join(pkg.postgres, "bin/postgres"), ["-D", data, "-h", "127.0.0.1", "-p", String(port), ...options], { stdio: "ignore" });
  for (let attempt = 0; attempt < 300; attempt++) {
    if (child.exitCode !== null) throw new Error("postgres exited");
    try { await run(join(pkg.postgres, "bin/pg_isready"), ["-h", "127.0.0.1", "-p", String(port)]); return child; } catch { await sleep(100); }
  }
  throw new Error("postgres not ready");
}
async function stopPostgres(pkg, data, child) {
  await run(join(pkg.postgres, "bin/pg_ctl"), ["stop", "-D", data, "-m", "fast", "-w"]);
  if (child.exitCode === null) await once(child, "exit");
}
const psql = (pkg, port, args) => run(join(pkg.postgres, "bin/psql"),
  ["-h", "127.0.0.1", "-p", String(port), "-U", "frameleaf", "-d", "frameleaf", "-X", "-v", "ON_ERROR_STOP=1", ...args], { env: { PGPASSWORD: password } });
async function initdb(pkg, data) {
  const pwfile = join(root, "pw-" + randomUUID());
  await fs.writeFile(pwfile, password, { mode: 0o600 });
  // The switches the host agent itself uses for a new library.
  await run(join(pkg.postgres, "bin/initdb"), ["-D", data, "--username=frameleaf", "--encoding=UTF8", "--locale=C", "--data-checksums",
    "--auth-local=scram-sha-256", "--auth-host=scram-sha-256", `--pwfile=${pwfile}`]);
  await fs.rm(pwfile);
}
const counts = async (pkg, port) => JSON.parse(await psql(pkg, port, ["-At", "-c",
  `SELECT json_object_agg(n, c) FROM (SELECT tablename n, (xpath('/row/c/text()', query_to_xml(format('SELECT count(*) AS c FROM %I', tablename), false, true, '')))[1]::text::bigint c FROM pg_tables WHERE schemaname = 'public') t`]));
async function previousCounts(state) {
  const data = join(state, "database");
  const child = await startPostgres(PREVIOUS, data, PREVIOUS.databasePort, ["-c", "default_transaction_read_only=on"]);
  try { return await counts(PREVIOUS, PREVIOUS.databasePort); } finally { await stopPostgres(PREVIOUS, data, child); }
}
/** One digest over every path, size and byte under a directory. */
async function treeDigest(directory) {
  const hash = createHash("sha256"), pending = [directory], files = [];
  while (pending.length) {
    const current = pending.pop();
    for (const entry of await fs.readdir(current, { withFileTypes: true })) {
      const path = join(current, entry.name);
      if (entry.isDirectory()) pending.push(path); else files.push(path);
    }
  }
  for (const path of files.sort()) {
    const bytes = await fs.readFile(path);
    hash.update(path.slice(directory.length)).update(String(bytes.length)).update(bytes);
  }
  return { digest: hash.digest("hex"), files: files.length };
}
async function library(name) {
  const directory = join(root, name);
  await fs.mkdir(directory, { mode: 0o700 });
  await run("cp", ["-a", join(template, "state"), join(directory, "state")]);
  return join(directory, "state");
}
/** Drive the agent the way the controller does: configuration on its input, one status line back, then stop. */
function agentProcess(configuration) {
  const child = spawn(process.execPath, ["--input-type=module", "--eval", `await import(${JSON.stringify(agentPath)})`],
    { env: { FRAMELEAF_HOST_AGENT: "1" }, stdio: ["pipe", "pipe", "pipe"], detached: true });
  let output = "", errors = "";
  child.stdout.on("data", chunk => { output += chunk; });
  child.stderr.on("data", chunk => { errors += chunk; });
  child.stdin.on("error", () => {});
  child.stdin.write(JSON.stringify(configuration) + "\n");
  return {
    child,
    lines: () => output.split("\n").filter(Boolean).map(line => JSON.parse(line)),
    errors: () => errors.split("\n").filter(Boolean),
    async ready(state) {
      while (child.exitCode === null && child.signalCode === null && !output.includes("\n")) await sleep(50);
      assert.deepEqual(this.lines()[0], { state }, errors);
    },
    async stop() {
      child.stdin.write("stop\n");
      if (child.exitCode === null) await once(child, "exit");
      return child.exitCode;
    },
    async exited() {
      if (child.exitCode === null && child.signalCode === null) await once(child, "exit");
      return child.exitCode;
    },
  };
}
const exists = path => fs.lstat(path).then(() => true, error => { if (error.code === "ENOENT") return false; throw error; });
const never = new Promise(() => {});
const identity = async path => { const meta = await fs.lstat(path, { bigint: true }); return `${meta.dev}:${meta.ino}`; };

before(async () => {
  if (!enabled) return;
  root = await fs.realpath(await fs.mkdtemp(join(process.env.FRAMELEAF_CARRY_WORK ?? "/home/node", "carry-")));
  await fs.chmod(root, 0o700);
  for (const pkg of [PREVIOUS, NEXT]) await runtime(pkg);
  // 1. The product server's own migrations create the schema. The server only runs on the pinned
  //    Postgres, so the schema is made there and moved to the previous Postgres as plain SQL.
  const source = join(root, "schema-source"), admin = { PATH: "/usr/local/bin:/usr/bin:/bin", HOME: root, LANG: "C", DB_HOSTNAME: "127.0.0.1",
    DB_PORT: String(NEXT.databasePort), DB_USERNAME: "frameleaf", DB_PASSWORD: password, DB_DATABASE_NAME: "frameleaf",
    FRAMELEAF_MANAGER_ORIGIN: "restored_library", FRAMELEAF_MANAGER_INSTALLATION: libraryId,
    FRAMELEAF_MANAGER_RESTORE_OPERATION_ID: randomUUID(), FRAMELEAF_MEDIA_LOCATION: join(root, "schema-media"),
    FRAMELEAF_BUILD_DATA: "/build", FRAMELEAF_STUDIO_WORKER: "false" };
  await fs.mkdir(admin.FRAMELEAF_MEDIA_LOCATION);
  await initdb(NEXT, source);
  let child = await startPostgres(NEXT, source, NEXT.databasePort);
  await run(join(NEXT.postgres, "bin/createdb"), ["-h", "127.0.0.1", "-p", String(NEXT.databasePort), "-U", "frameleaf", "frameleaf"], { env: { PGPASSWORD: password } });
  await run(process.execPath, ["/usr/src/app/server/dist/main.js", "frameleaf-admin", "restore-state"], { env: admin, cwd: root });
  const schema = join(root, "schema.sql");
  await run(join(NEXT.postgres, "bin/pg_dump"), ["-h", "127.0.0.1", "-p", String(NEXT.databasePort), "-U", "frameleaf", "--format=plain", "--no-owner", "--no-acl", "-f", schema, "frameleaf"], { env: { PGPASSWORD: password } });
  await stopPostgres(NEXT, source, child);
  await fs.rm(source, { recursive: true });
  // 2. The previous package's library: its Postgres, that schema, and a synthetic library in it.
  template = join(root, "template");
  const state = join(template, "state"), data = join(state, "database");
  await fs.mkdir(state, { recursive: true, mode: 0o700 });
  await fs.chmod(template, 0o700);
  await initdb(PREVIOUS, data);
  child = await startPostgres(PREVIOUS, data, PREVIOUS.databasePort);
  await run(join(PREVIOUS.postgres, "bin/createdb"), ["-h", "127.0.0.1", "-p", String(PREVIOUS.databasePort), "-U", "frameleaf", "frameleaf"], { env: { PGPASSWORD: password } });
  await psql(PREVIOUS, PREVIOUS.databasePort, ["-q", "-f", schema]);
  await psql(PREVIOUS, PREVIOUS.databasePort, ["-q", "-f", join(here, "library.sql")]);
  await stopPostgres(PREVIOUS, data, child);
  // The marker the previous package's agent wrote when it created this library.
  await fs.writeFile(join(state, "host-state.json"), JSON.stringify({ schemaVersion: 1, manifestSha256: PREVIOUS.manifestSha256,
    sourceRevision: PREVIOUS.sourceRevision, postgresMajor: PREVIOUS.postgresMajor }), { mode: 0o600 });
  // Originals: nothing in this work may touch them.
  await fs.mkdir(join(state, "media/library"), { recursive: true, mode: 0o700 });
  for (let index = 0; index < 25; index++)
    await fs.writeFile(join(state, "media/library", `IMG_${String(index).padStart(5, "0")}.heic`), createHash("sha512").update("original " + index).digest());
});

test("a library moves from the previous Postgres to the new one, and both the old directory and the originals are left as they were", { skip: !enabled, timeout: 1_800_000 }, async t => {
  const state = await library("success"), permitId = randomUUID();
  const original = await previousCounts(state);
  t.diagnostic(`library: ${Object.keys(original).length} tables, ${Object.values(original).reduce((a, b) => a + b, 0)} rows; asset ${original.asset}, smart_search ${original.smart_search}, face_search ${original.face_search}, album_asset ${original.album_asset}`);
  assert.equal(original.asset, 6000);
  const media = await treeDigest(join(state, "media")), originals = await treeDigest(join(state, "media/library"));

  // Export: the previous Postgres, read-only, loopback only, no photo server; then it is stopped.
  const exporting = agentProcess(exportConfig(state, permitId));
  let observed;
  while (exporting.child.exitCode === null && !observed) {
    try {
      const readOnly = (await psql(PREVIOUS, PREVIOUS.databasePort, ["-At", "-c", "SHOW default_transaction_read_only"])).trim();
      const write = await psql(PREVIOUS, PREVIOUS.databasePort, ["-c", "CREATE TABLE carry_write_probe ()"]).then(() => "accepted", () => "refused");
      const outside = Object.values(networkInterfaces()).flat().find(item => item && !item.internal && item.family === "IPv4")?.address;
      const reach = (host, port) => new Promise(resolve => {
        const socket = createConnection({ host, port, timeout: 1000 });
        socket.once("connect", () => { socket.destroy(); resolve(true); });
        for (const event of ["error", "timeout"]) socket.once(event, () => { socket.destroy(); resolve(false); });
      });
      observed = { readOnly, write, loopback: await reach("127.0.0.1", PREVIOUS.databasePort), outside: outside ? await reach(outside, PREVIOUS.databasePort) : false,
        photoServer: await reach("127.0.0.1", PREVIOUS.apiPort) };
    } catch { await sleep(20); }
  }
  assert.deepEqual(observed, { readOnly: "on", write: "refused", loopback: true, outside: false, photoServer: false });
  await exporting.ready("carry-exported");
  assert.equal(await exists(join(state, "database/postmaster.pid")), false);
  assert.equal(await exporting.stop(), 0);
  assert.deepEqual(exporting.lines(), [{ state: "carry-exported" }, { state: "stopped" }]);
  const record = JSON.parse(await fs.readFile(join(state, "carry-forward", permitId, "export.json"), "utf8"));
  assert.equal(record.source.postgresVersion, "18.7");
  assert.equal(record.source.postgresMajor, "18");
  assert.deepEqual(Object.fromEntries(record.tables.map(item => [item.name.replace(/^public\./, ""), item.rows])), original);
  assert.deepEqual(record.vectorIndexes.map(item => item.name).sort(), ["public.clip_description_index", "public.clip_index", "public.face_index", "public.video_moment_frame_index"]);
  const dump = join(state, "checkpoints", permitId, "database.dump");
  assert.equal(createHash("sha256").update(await fs.readFile(dump)).digest("hex"), record.checkpoint.dump.sha256);
  t.diagnostic(`export: ${record.checkpoint.dump.bytes} bytes, ${record.tables.length} tables counted`);

  // A used permit is read back; the previous Postgres is not started again.
  const log = (await fs.stat(join(state, "host.log"))).size;
  const again = await agent.carryHostExport(exportConfig(state, permitId), never);
  assert.equal(again.record.checkpoint.dump.sha256, record.checkpoint.dump.sha256);
  assert.equal((await fs.stat(join(state, "host.log"))).size, log);

  // From here on the old database directory must not change by a single byte.
  const old = await treeDigest(join(state, "database"));
  const restoring = agentProcess(restoreConfig(state, permitId));
  await restoring.ready("carry-restored");
  assert.equal(await restoring.stop(), 0);
  const receipt = JSON.parse(await fs.readFile(join(state, "carry-forward", permitId, "restore.json"), "utf8"));
  const rows = Object.values(original).reduce((a, b) => a + b, 0);
  assert.deepEqual(receipt.validation, { postgresMajor: 19, vectorVersion: "0.8.7", canonical: true, executionStateReconstructed: true,
    tables: Object.keys(original).length, rows, vectorIndexes: 4, vectorIndexesSearched: 2, offlineChecksums: true, schemaValidated: true });
  const target = join(state, "restore-targets", permitId, receipt.attemptId), database = join(target, "database");
  assert.equal((await fs.readFile(join(database, "PG_VERSION"), "utf8")).trim(), "19");
  assert.deepEqual(await treeDigest(join(state, "database")), old);
  assert.equal(JSON.parse(await fs.readFile(join(state, "host-state.json"), "utf8")).postgresMajor, "18");
  // Nothing was written anywhere under the media folder by the export or the restore.
  assert.deepEqual(await treeDigest(join(state, "media")), media);

  // Read-only, with the new Postgres: every table holds exactly the rows the old library has.
  const inspecting = await startPostgres(NEXT, database, NEXT.databasePort, ["-c", "default_transaction_read_only=on"]);
  try { assert.deepEqual(await counts(NEXT, NEXT.databasePort), original); } finally { await stopPostgres(NEXT, database, inspecting); }

  // The switch. In the product one journal write selects the new package and this directory;
  // here the agent is handed the reference that write would hold, and the marker it rewrites.
  await fs.writeFile(join(state, "host-state.json"), JSON.stringify({ schemaVersion: 1, manifestSha256: NEXT.manifestSha256,
    sourceRevision: NEXT.sourceRevision, postgresMajor: NEXT.postgresMajor }), { mode: 0o600 });
  const identities = [];
  for (const path of [state, join(state, "restore-targets"), join(state, "restore-targets", permitId), target, database])
    identities.push(createHash("sha256").update(await identity(path)).digest("hex"));
  const reference = { operationId: permitId, attemptId: receipt.attemptId, identities };
  // The new library starts: the product server, on the new Postgres, on the new directory.
  let stop, running, finished = false;
  const stopping = new Promise(resolve => { stop = resolve; });
  const served = agent.runHost(config(NEXT, state, "server", { databaseReference: reference }), stopping, () => { running = true; });
  served.catch(() => {}).finally(() => { finished = true; });
  for (let attempt = 0; attempt < 2400 && !running && !finished; attempt++) await sleep(100);
  assert.equal(running, true, "the photo server did not start on the carried library");
  const ping = await (await fetch(`http://127.0.0.1:${NEXT.apiPort}/api/server/ping`)).json();
  assert.equal(ping.res, "pong");
  const carried = await counts(NEXT, NEXT.databasePort);
  for (const name of ["user", "asset", "asset_exif", "asset_file", "smart_search", "asset_face", "face_search", "person", "album", "album_asset", "album_user", "tag", "tag_asset"])
    assert.equal(carried[name], original[name], name);
  const nearest = (await psql(NEXT, NEXT.databasePort, ["-At", "-c",
    `SET enable_seqscan = off; EXPLAIN SELECT "assetId" FROM smart_search ORDER BY embedding <=> (SELECT embedding FROM smart_search LIMIT 1) LIMIT 5`]));
  assert.match(nearest, /Index Scan using clip_index/);
  assert.match(await psql(NEXT, NEXT.databasePort, ["-At", "-c", "SELECT version()"]), /PostgreSQL 19beta4/);
  stop();
  await served;
  assert.equal(await exists(join(database, "postmaster.pid")), false);

  // The old library: untouched, still opens with the previous Postgres, same rows. Originals: untouched.
  assert.deepEqual(await treeDigest(join(state, "database")), old);
  assert.deepEqual(await previousCounts(state), original);
  // (The photo server adds its own folder markers beside them when it starts, as on any start.)
  assert.deepEqual(await treeDigest(join(state, "media/library")), originals);
  t.diagnostic(`restored ${receipt.validation.rows} rows in ${receipt.validation.tables} tables; old directory ${old.files} files unchanged; ${originals.files} originals unchanged`);
});

test("an export that is interrupted, by its owner going away or by being killed, leaves no export and can be run again", { skip: !enabled, timeout: 900_000 }, async () => {
  const state = await library("interrupted"), permitId = randomUUID();
  const original = await previousCounts(state);
  const staging = join(state, "checkpoints", "." + permitId + ".partial", "database.dump");
  const writing = async process => {
    while (process.child.exitCode === null && process.child.signalCode === null) {
      if ((await fs.stat(staging).catch(() => ({ size: 0 }))).size > 0) return true;
      await sleep(5);
    }
    return false;
  };
  // 1. The owner goes away while the dump is being written.
  const first = agentProcess(exportConfig(state, permitId));
  assert.equal(await writing(first), true, "the export finished before it could be interrupted");
  first.child.stdin.end();
  assert.equal(await first.exited(), 1);
  assert.deepEqual(first.errors().slice(-1), ["host_carry_cancelled"]);
  assert.deepEqual(first.lines(), []);
  assert.equal(await exists(join(state, "carry-forward", permitId, "export.json")), false);
  assert.equal(await exists(join(state, "checkpoints", permitId)), false);
  assert.equal(await exists(join(state, "database/postmaster.pid")), false);
  // 2. Everything is killed outright while the dump is being written.
  const second = agentProcess(exportConfig(state, permitId));
  assert.equal(await writing(second), true, "the export finished before it could be killed");
  process.kill(-second.child.pid, "SIGKILL");
  await second.exited();
  await sleep(500);
  assert.equal(await exists(join(state, "carry-forward", permitId, "export.json")), false);
  assert.equal(await exists(join(state, "checkpoints", permitId)), false);
  assert.equal(await exists(join(state, "database/postmaster.pid")), true);
  // A restore has nothing to restore.
  await assert.rejects(agent.carryHostRestore(restoreConfig(state, permitId), never), /host_carry_export_invalid/);
  assert.equal(await exists(join(state, "restore-targets")), false);
  // 3. The same permit runs again and completes.
  const third = agentProcess(exportConfig(state, permitId));
  await third.ready("carry-exported").catch(async error => {
    error.message += "\n" + (await fs.readFile(join(state, "host.log"), "utf8")).split("\n").slice(-25).join("\n");
    throw error;
  });
  assert.equal(await third.stop(), 0);
  const record = JSON.parse(await fs.readFile(join(state, "carry-forward", permitId, "export.json"), "utf8"));
  assert.deepEqual(Object.fromEntries(record.tables.map(item => [item.name.replace(/^public\./, ""), item.rows])), original);
  assert.deepEqual((await fs.readdir(join(state, "checkpoints"))).sort(), [permitId]);
  assert.equal(await exists(join(state, "database/postmaster.pid")), false);
});

test("a corrupted export is refused before anything is restored", { skip: !enabled, timeout: 900_000 }, async () => {
  const state = await library("corrupted"), permitId = randomUUID();
  await agent.carryHostExport(exportConfig(state, permitId), never);
  const dump = join(state, "checkpoints", permitId, "database.dump"), bytes = await fs.readFile(dump);
  const old = await treeDigest(join(state, "database"));
  for (const [name, change] of [
    ["one byte changed", async () => { const copy = Buffer.from(bytes); copy[Math.floor(copy.length / 2)] ^= 0x01; await fs.writeFile(dump, copy); }],
    ["truncated", async () => fs.writeFile(dump, bytes.subarray(0, bytes.length - 4096))],
    ["replaced by another file", async () => { await fs.rm(dump); await fs.writeFile(dump, bytes, { mode: 0o600 }); await fs.appendFile(dump, "x"); }],
  ]) {
    await change();
    await assert.rejects(agent.carryHostRestore(restoreConfig(state, permitId), never), /host_carry_export_invalid/, name);
    assert.equal(await exists(join(state, "restore-targets")), false, name);
    // The export run does not paper over it either: the permit is spent and its export is bad.
    await assert.rejects(agent.carryHostExport(exportConfig(state, permitId), never), /host_carry_export_invalid/, name);
  }
  assert.deepEqual(await treeDigest(join(state, "database")), old);
  assert.equal(JSON.parse(await fs.readFile(join(state, "host-state.json"), "utf8")).postgresMajor, "18");
});

test("a restore that does not match what was exported is not offered, and the old library still starts", { skip: !enabled, timeout: 900_000 }, async () => {
  const state = await library("mismatch"), permitId = randomUUID();
  const original = await previousCounts(state);
  await agent.carryHostExport(exportConfig(state, permitId), never);
  // The export says one more photo than the dump holds: the restore must not pass as complete.
  const path = join(state, "carry-forward", permitId, "export.json"), record = JSON.parse(await fs.readFile(path, "utf8"));
  record.tables.find(item => item.name === "public.asset").rows += 1;
  await fs.writeFile(path, JSON.stringify(record) + "\n");
  const old = await treeDigest(join(state, "database"));
  await assert.rejects(agent.carryHostRestore(restoreConfig(state, permitId), never), /host_carry_counts_mismatch/);
  assert.equal(await exists(join(state, "carry-forward", permitId, "restore.json")), false);
  const attempts = await fs.readdir(join(state, "restore-targets", permitId));
  assert.equal(attempts.length, 1);
  assert.equal(await exists(join(state, "restore-targets", permitId, attempts[0], "carry-result.json")), false);
  assert.equal(await exists(join(state, "restore-targets", permitId, attempts[0], "database/postmaster.pid")), false);
  // Nothing selected the failed directory: the library is still the previous package's, and it starts.
  assert.equal(JSON.parse(await fs.readFile(join(state, "host-state.json"), "utf8")).postgresMajor, "18");
  assert.deepEqual(await treeDigest(join(state, "database")), old);
  assert.deepEqual(await previousCounts(state), original);
});

test("too little room refuses the export and the restore before either starts anything", { skip: !enabled || !process.env.FRAMELEAF_CARRY_SMALL, timeout: 900_000 }, async () => {
  const small = await fs.realpath(process.env.FRAMELEAF_CARRY_SMALL), directory = join(small, "library-" + randomUUID());
  await fs.mkdir(directory, { mode: 0o700 });
  await run("cp", ["-a", join(template, "state"), join(directory, "state")]);
  const state = join(directory, "state"), permitId = randomUUID(), filler = join(small, "filler");
  const free = async () => { const volume = await fs.statfs(state, { bigint: true }); return Number(volume.bavail * volume.bsize); };
  const megabyte = 1024 * 1024, size = Number((await run("du", ["-sb", join(state, "database")])).split("\t")[0]);
  // Fill the volume until it is 64 MiB short of what a step needs.
  const leaveShortOf = async needed => {
    await fs.rm(filler, { force: true });
    const surplus = Math.floor((await free() - (needed - 64 * megabyte)) / megabyte);
    if (surplus > 0) await run("dd", ["if=/dev/zero", `of=${filler}`, "bs=1M", `count=${surplus}`]);
    assert.ok(await free() < needed, "the volume could not be made too small");
  };
  await leaveShortOf(size + 256 * megabyte);
  const before = await treeDigest(join(state, "database"));
  await assert.rejects(agent.carryHostExport(exportConfig(state, permitId), never), /host_carry_space_insufficient/);
  assert.deepEqual(await treeDigest(join(state, "database")), before);
  assert.equal(await exists(join(state, "host.log")), false);
  assert.equal(await exists(join(state, "checkpoints")), false);
  // With room for the export it is taken; then the volume is too small for a second database directory.
  await fs.rm(filler);
  await agent.carryHostExport(exportConfig(state, permitId), never);
  await leaveShortOf(size + 1536 * megabyte);
  const old = await treeDigest(join(state, "database"));
  await assert.rejects(agent.carryHostRestore(restoreConfig(state, permitId), never), /host_carry_space_insufficient/);
  assert.equal(await exists(join(state, "restore-targets")), false);
  assert.deepEqual(await treeDigest(join(state, "database")), old);
});
