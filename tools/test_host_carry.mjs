// The carry-forward steps of the host agent, without a database: what they refuse, and that a
// finished export is read back rather than run again. tools/carry_forward runs them for real.
import assert from "node:assert/strict";
import { test } from "node:test";
import { createHash } from "node:crypto";
import { mkdtemp, mkdir, readFile, readdir, realpath, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { carryHostExport, carryHostRestore, createHostCheckpoint, runHost, validateConfig } from "../runtime/host-agent.mjs";

const permitId = "11111111-1111-4111-8111-111111111111", libraryId = "c".repeat(12);
const previous = { manifestSha256: "a".repeat(64), sourceRevision: "1".repeat(40), postgresMajor: "18" };
const next = { manifestSha256: "b".repeat(64), sourceRevision: "2".repeat(40), postgresMajor: "19" };
const never = new Promise(() => {});
const skip = process.platform === "win32";

async function fixture(t) {
  const state = await realpath(await mkdtemp(join(tmpdir(), "frameleaf-host-carry-")));
  t.after(() => rm(state, { recursive: true, force: true }));
  const config = (pkg, mode, carry) => ({
    mode, carry, state, runtime: join(state, "no-such-runtime"), ...pkg, databasePort: 54329, apiPort: 2283,
    password: "synthetic private database password",
    entryPoints: { ...Object.fromEntries(["node", "server", "postgres", "initdb", "createdb", "psql", "pgIsready", "pgCtl", "pgDump", "pgRestore",
      "hdr", "studioBrowserGuard", "studio"].map(name => [name, "bin/" + name])), pgChecksums: "bin/pg_checksums", ffmpeg: "media/ffmpeg",
      ffprobe: "media/ffprobe", rawRenderer: "raw/darktable-cli", rawDecoder: "raw/dcraw_emu", studioBrowser: "browser/chrome" },
  });
  const exporting = (carry = { permitId, libraryId, target: { manifestSha256: next.manifestSha256, postgresVersion: "19beta4", vectorVersion: "0.8.7" } }) =>
    config(previous, "carry-export", carry);
  const restoring = (carry = { permitId, libraryId, source: { ...previous } }) => config(next, "carry-restore", carry);
  return { state, config, exporting, restoring };
}
/** What a completed export run leaves on disk, written the way the agent writes it. */
async function exported(f, change = record => record) {
  const dump = Buffer.from("synthetic custom database dump");
  const checkpoint = await createHostCheckpoint({ ...f.exporting(), mode: "database", carry: undefined, postgresMajor: "19" }, permitId,
    async args => { if (args.includes("--file")) await writeFile(args[args.indexOf("--file") + 1], dump); });
  // The receipt beside the dump names the previous package's own Postgres.
  const receipt = { ...checkpoint, postgresMajor: "18" };
  await writeFile(join(f.state, "checkpoints", permitId, "checkpoint.json"), JSON.stringify(receipt) + "\n");
  const directory = join(f.state, "carry-forward", permitId);
  await mkdir(directory, { recursive: true, mode: 0o700 });
  const record = change({ schemaVersion: 1, permitId, libraryId,
    source: { ...previous, postgresVersion: "18.7", vectorVersion: "0.8.7" },
    target: { manifestSha256: next.manifestSha256, postgresVersion: "19beta4", vectorVersion: "0.8.7" },
    checkpoint: receipt, extensions: [{ name: "vector", version: "0.8.7" }], tables: [{ name: "public.asset", rows: 3 }],
    vectorIndexes: [{ name: "public.clip_index", method: "hnsw", valid: true }] });
  await writeFile(join(directory, "export.json"), JSON.stringify(record) + "\n", { mode: 0o600 });
  return { record, dump: join(f.state, "checkpoints", permitId, "database.dump") };
}

test("only the export run may name another Postgres major, and no carry step is an ordinary host mode", { skip }, async t => {
  const f = await fixture(t);
  validateConfig(f.exporting());
  validateConfig(f.restoring());
  // The previous package's major is admitted for its export run and nowhere else.
  for (const mode of [undefined, "server", "database", "checkpoint-cleanup", "restore-prepare", "carry-restore"])
    assert.throws(() => validateConfig({ ...f.exporting(), mode }), /host_config_invalid/, String(mode));
  for (const postgresMajor of ["9", "190", "18.7", 18, undefined, "../18"])
    assert.throws(() => validateConfig({ ...f.exporting(), postgresMajor }), /host_config_invalid/, String(postgresMajor));
  // The restore step is never started as a host: it only runs through its own entry.
  await assert.rejects(runHost(f.restoring(), never, () => {}), /host_carry_config_invalid/);
  assert.deepEqual(await readdir(f.state), []);
});

test("a carry step without a well-formed permit does nothing", { skip }, async t => {
  const f = await fixture(t);
  const target = { manifestSha256: next.manifestSha256, postgresVersion: "19beta4", vectorVersion: "0.8.7" };
  for (const carry of [undefined, null, {}, { permitId, libraryId }, { permitId: "../x", libraryId, target }, { permitId, libraryId: "C".repeat(12), target },
    { permitId, libraryId, target, extra: true }, { permitId, libraryId, target: { ...target, manifestSha256: previous.manifestSha256 } },
    { permitId, libraryId, target: { ...target, postgresVersion: "../19" } }, { permitId, libraryId, target: { ...target, path: "/x" } },
    { permitId, libraryId, source: { ...previous } }])
    await assert.rejects(carryHostExport(f.config(previous, "carry-export", carry), never), /host_carry_config_invalid/, JSON.stringify(carry));
  for (const carry of [undefined, { permitId, libraryId }, { permitId, libraryId, target }, { permitId, libraryId, source: { ...previous, extra: 1 } },
    { permitId, libraryId, source: { ...previous, manifestSha256: next.manifestSha256 } }, { permitId, libraryId, source: { ...previous, sourceRevision: "x" } },
    // A dump from a newer Postgres is never restored.
    { permitId, libraryId, source: { ...previous, postgresMajor: "20" } }])
    await assert.rejects(carryHostRestore(f.config(next, "carry-restore", carry), never), /host_carry_config_invalid/, JSON.stringify(carry));
  // Each step is its own mode.
  await assert.rejects(carryHostExport({ ...f.exporting(), mode: "database", postgresMajor: "19" }, never), /host_carry_config_invalid/);
  await assert.rejects(carryHostRestore({ ...f.restoring(), mode: "restore-prepare" }, never), /host_carry_config_invalid/);
  assert.deepEqual(await readdir(f.state), []);
});

test("a finished export is the permit used: it is read back and the previous Postgres is not started again", { skip }, async t => {
  const f = await fixture(t);
  const { record, dump } = await exported(f);
  // No runtime exists at all: anything that tried to start a database would fail.
  const result = await carryHostExport(f.exporting(), never);
  assert.equal(result.state, "carry-exported");
  assert.deepEqual(result.record, record);
  assert.equal(result.exportSha256, createHash("sha256").update(await readFile(join(f.state, "carry-forward", permitId, "export.json"))).digest("hex"));
  assert.equal(result.dump, dump);
  assert.deepEqual((await readdir(f.state)).sort(), ["carry-forward", "checkpoints"]);
});

test("an export that does not verify, or is not this permit's, is refused before anything is restored", { skip }, async t => {
  const changes = {
    "another permit": record => ({ ...record, permitId: "22222222-2222-4222-8222-222222222222" }),
    "another library": record => ({ ...record, libraryId: "d".repeat(12) }),
    "another previous package": record => ({ ...record, source: { ...record.source, manifestSha256: "e".repeat(64) } }),
    "another source revision": record => ({ ...record, source: { ...record.source, sourceRevision: "3".repeat(40) } }),
    "another Postgres major": record => ({ ...record, source: { ...record.source, postgresMajor: "17" } }),
    "another target package": record => ({ ...record, target: { ...record.target, manifestSha256: "e".repeat(64) } }),
    "a receipt for other bytes": record => ({ ...record, checkpoint: { ...record.checkpoint, dump: { ...record.checkpoint.dump, sha256: "0".repeat(64) } } }),
    "no tables counted": record => ({ ...record, tables: [] }),
    "a negative count": record => ({ ...record, tables: [{ name: "public.asset", rows: -1 }] }),
    "an unknown field": record => ({ ...record, command: "x" }),
  };
  for (const [name, change] of Object.entries(changes)) {
    const f = await fixture(t);
    await exported(f, change);
    await assert.rejects(carryHostRestore(f.restoring(), never), /host_carry_export_invalid/, name);
    assert.deepEqual((await readdir(f.state)).sort(), ["carry-forward", "checkpoints"], name);
  }
  // The dump itself: changed, truncated, or missing.
  for (const [name, damage] of Object.entries({
    changed: async dump => writeFile(dump, "synthetic custom database dumq"),
    truncated: async dump => writeFile(dump, "synthetic"),
    missing: async dump => rm(dump),
    "an extra file beside it": async dump => writeFile(join(dump, "../extra"), "x", { mode: 0o600 }),
  })) {
    const f = await fixture(t);
    const { dump } = await exported(f);
    await damage(dump);
    await assert.rejects(carryHostRestore(f.restoring(), never), /host_carry_export_invalid/, name);
    await assert.rejects(carryHostExport(f.exporting(), never), /host_carry_export_invalid/, name);
    assert.deepEqual((await readdir(f.state)).sort(), ["carry-forward", "checkpoints"], name);
  }
  // With no export at all there is nothing to restore.
  const f = await fixture(t);
  await assert.rejects(carryHostRestore(f.restoring(), never), /host_carry_/);
  assert.equal((await readdir(f.state)).includes("restore-targets"), false);
});

test("a step that is told to stop before it starts changes nothing", { skip }, async t => {
  const f = await fixture(t);
  await exported(f);
  await assert.rejects(carryHostRestore(f.restoring(), Promise.resolve()), /host_carry_cancelled/);
  assert.deepEqual((await readdir(f.state)).sort(), ["carry-forward", "checkpoints"]);
});
