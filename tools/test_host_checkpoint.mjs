import assert from "node:assert/strict";
import { test } from "node:test";
import { mkdtemp, mkdir, readFile, writeFile, rm, readdir, realpath, symlink, link } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createHash } from "node:crypto";
import { renameSync, mkdirSync, writeFileSync, promises as filesystem } from "node:fs";
import { syncBuiltinESMExports } from "node:module";
import * as owner from "../runtime/host-agent.mjs";
import { checkpointRequest, createHostCheckpoint } from "../runtime/host-agent.mjs";

const operationId = "11111111-1111-4111-8111-111111111111";
const request = { protocolVersion: 1, action: "checkpoint", operationId };
test("checkpoint owner requests accept only one bounded operation identity", () => {
  assert.equal(checkpointRequest(JSON.stringify(request)), operationId);
  for (const value of [null, {}, { ...request, path: "/outside" }, { ...request, protocolVersion: 2 },
    { ...request, action: "exec" }, { ...request, operationId: "../outside" },
    { ...request, operationId: "0".repeat(36) }, { ...request, operationId: "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA" }]) {
    assert.throws(() => checkpointRequest(JSON.stringify(value)), /host_checkpoint_request_invalid/);
  }
  for (const raw of ["{", "x".repeat(1025)])
    assert.throws(() => checkpointRequest(raw), /host_checkpoint_request_invalid/);
});

async function fixture(t) {
  const state = await realpath(await mkdtemp(join(tmpdir(), "frameleaf-checkpoint-")));
  t.after(() => rm(state, { recursive: true, force: true }));
  const suffix = process.platform === "win32" ? ".exe" : "";
  const c = {
    state, runtime: join(state, "signed-runtime"), manifestSha256: "a".repeat(64), sourceRevision: "b".repeat(40),
    postgresMajor: "19", databasePort: 54329, apiPort: 2283, password: "synthetic private database password",
    entryPoints: Object.fromEntries(["node", "server", "postgres", "initdb", "createdb", "psql", "pgIsready", "pgCtl", "pgDump", "pgRestore",
      "hdr", "studioBrowserGuard", "studio"].map(name => [name, "bin/" + name + suffix])),
  };
  Object.assign(c.entryPoints, { ffmpeg: "media/ffmpeg" + suffix, ffprobe: "media/ffprobe" + suffix,
    rawRenderer: "raw/darktable-cli" + suffix, rawDecoder: "raw/dcraw_emu" + suffix, studioBrowser: "browser/chrome" + suffix });
  const calls = [];
  const bytes = Buffer.from("synthetic custom database dump");
  const execute = async (args, env) => {
    calls.push({ args, env });
    if (args[0] === join(c.runtime, c.entryPoints.pgDump)) {
      assert.equal(env.PGPASSWORD, c.password);
      assert.equal(args.includes(c.password), false);
      assert.ok(args.includes("--format=custom"));
      await writeFile(args[args.indexOf("--file") + 1], bytes);
    } else {
      assert.equal(args[0], join(c.runtime, c.entryPoints.pgRestore));
      assert.deepEqual(args.slice(1, 2), ["--list"]);
      assert.deepEqual(env, {});
    }
  };
  return { c, calls, bytes, execute, path: join(state, "checkpoints", operationId) };
}

test("checkpoint writes and verifies one private operation-bound dump, then reuses only matching bytes", async t => {
  const f = await fixture(t);
  const result = await createHostCheckpoint(f.c, operationId, f.execute);
  assert.deepEqual(result, {
    schemaVersion: 1, operationId, manifestSha256: f.c.manifestSha256, sourceRevision: f.c.sourceRevision,
    postgresMajor: "19", databaseFormat: "frameleaf-canonical",
    dump: { bytes: f.bytes.length, sha256: createHash("sha256").update(f.bytes).digest("hex") },
  });
  assert.deepEqual((await readdir(f.path)).sort(), ["checkpoint.json", "database.dump"]);
  assert.ok(!JSON.stringify(result).includes(f.c.password));
  assert.equal(f.calls.length, 2);
  assert.deepEqual(await createHostCheckpoint(f.c, operationId, f.execute), result);
  assert.equal(f.calls.length, 2);
  await writeFile(join(f.path, "database.dump"), "changed");
  await assert.rejects(createHostCheckpoint(f.c, operationId, f.execute), /host_checkpoint_changed/);
  assert.equal(f.calls.length, 2);
});

test("failed verification and cancellation publish no checkpoint and allow a clean retry", async t => {
  const f = await fixture(t);
  await assert.rejects(createHostCheckpoint(f.c, operationId, async (args, env) => {
    await f.execute(args, env);
    if (args[1] === "--list") throw Error("synthetic verifier failed");
  }));
  assert.deepEqual(await readdir(join(f.c.state, "checkpoints")), []);
  let cancelled = false;
  await assert.rejects(createHostCheckpoint(f.c, operationId, async (args, env) => {
    await f.execute(args, env); cancelled = true;
  }, () => cancelled), /host_checkpoint_cancelled/);
  assert.deepEqual(await readdir(join(f.c.state, "checkpoints")), []);
  await createHostCheckpoint(f.c, operationId, f.execute);
});

test("checkpoint refuses a different runtime receipt, unexpected files, and abandoned staging", async t => {
  const f = await fixture(t);
  await createHostCheckpoint(f.c, operationId, f.execute);
  await assert.rejects(createHostCheckpoint({ ...f.c, manifestSha256: "c".repeat(64) }, operationId, f.execute), /host_checkpoint_changed/);
  await writeFile(join(f.path, "unexpected"), "preserve fixture");
  await assert.rejects(createHostCheckpoint(f.c, operationId, f.execute), /host_checkpoint_changed/);
  assert.equal(await readFile(join(f.path, "unexpected"), "utf8"), "preserve fixture");
  const second = "22222222-2222-4222-8222-222222222222";
  await mkdir(join(f.c.state, "checkpoints", "." + second + ".partial"), { mode: 0o700 });
  await assert.rejects(createHostCheckpoint(f.c, second, f.execute));
  assert.ok((await readdir(join(f.c.state, "checkpoints"))).includes("." + second + ".partial"));
});

test("checkpoint refuses linked roots or dumps without following outside data", { skip: process.platform === "win32" }, async t => {
  const f = await fixture(t);
  const outside = join(f.c.state, "outside"); await mkdir(outside, { mode: 0o700 });
  await symlink(outside, join(f.c.state, "checkpoints"), "dir");
  await assert.rejects(createHostCheckpoint(f.c, operationId, f.execute), /host_checkpoint_not_private/);
  assert.deepEqual(await readdir(outside), []);
  await rm(join(f.c.state, "checkpoints"));
  await createHostCheckpoint(f.c, operationId, f.execute);
  await rm(join(f.path, "database.dump"));
  await writeFile(join(outside, "dump"), "preserve outside fixture");
  await symlink(join(outside, "dump"), join(f.path, "database.dump"));
  await assert.rejects(createHostCheckpoint(f.c, operationId, f.execute));
  assert.equal(await readFile(join(outside, "dump"), "utf8"), "preserve outside fixture");
});

test("a renamed checkpoint directory cannot substitute different bytes during receipt validation", { skip: process.platform === "win32" }, async t => {
  const f = await fixture(t);
  await createHostCheckpoint(f.c, operationId, f.execute);
  const record = await readFile(join(f.path, "checkpoint.json"));
  let checks = 0;
  await assert.rejects(createHostCheckpoint(f.c, operationId, f.execute, () => {
    if (++checks === 2) {
      renameSync(f.path, f.path + "-moved");
      mkdirSync(f.path, { mode: 0o700 });
      writeFileSync(join(f.path, "checkpoint.json"), record, { mode: 0o600 });
      writeFileSync(join(f.path, "database.dump"), "different fixture bytes", { mode: 0o600 });
    }
    return false;
  }), /host_checkpoint_changed/);
  assert.equal(await readFile(join(f.path, "database.dump"), "utf8"), "different fixture bytes");
});


test("retired checkpoints are removed idempotently and can never regenerate a dump", async t => {
  const f = await fixture(t);
  const receipt = await createHostCheckpoint(f.c, operationId, f.execute);
  assert.equal(typeof owner.cleanupHostCheckpoint, "function");
  assert.deepEqual(await owner.cleanupHostCheckpoint(f.c, receipt), { ...receipt, state: "checkpoint-cleaned" });
  await assert.rejects(readFile(join(f.path, "database.dump")), { code: "ENOENT" });
  assert.deepEqual(await owner.cleanupHostCheckpoint(f.c, receipt), { ...receipt, state: "checkpoint-cleaned" });
  await assert.rejects(createHostCheckpoint(f.c, operationId, f.execute), /host_checkpoint_retired/);
  assert.equal(f.calls.length, 2);
});

test("checkpoint cleanup refuses foreign receipts and altered bytes before retirement", async t => {
  const f = await fixture(t);
  const receipt = await createHostCheckpoint(f.c, operationId, f.execute);
  assert.equal(typeof owner.cleanupHostCheckpoint, "function");
  for (const changed of [{ ...receipt, sourceRevision: "e".repeat(40) },
    { ...receipt, operationId: "../outside" }, { ...receipt, secret: "unaccepted" },
    { ...receipt, dump: { ...receipt.dump, sha256: "e".repeat(64) } }]) {
    await assert.rejects(owner.cleanupHostCheckpoint(f.c, changed));
    assert.deepEqual(await readFile(join(f.path, "database.dump")), f.bytes);
  }
  await writeFile(join(f.path, "database.dump"), "changed dump");
  await assert.rejects(owner.cleanupHostCheckpoint(f.c, receipt), /host_checkpoint_changed/);
  assert.deepEqual(await readdir(join(f.c.state, "checkpoints")), [operationId]);
});

test("retirement reconciles a crash partial but preserves changed and unknown remnants", async t => {
  const f = await fixture(t);
  const receipt = await createHostCheckpoint(f.c, operationId, f.execute);
  assert.equal(typeof owner.cleanupHostCheckpoint, "function");
  await owner.cleanupHostCheckpoint(f.c, receipt);
  await mkdir(f.path, { mode: 0o700 });
  await writeFile(join(f.path, "checkpoint.json"), JSON.stringify(receipt), { mode: 0o600 });
  await owner.cleanupHostCheckpoint(f.c, receipt);
  await mkdir(f.path, { mode: 0o700 });
  await writeFile(join(f.path, "database.dump"), "foreign changed bytes", { mode: 0o600 });
  await assert.rejects(owner.cleanupHostCheckpoint(f.c, receipt), /host_checkpoint_changed/);
  assert.equal(await readFile(join(f.path, "database.dump"), "utf8"), "foreign changed bytes");
  await rm(join(f.path, "database.dump"));
  await writeFile(join(f.path, "foreign"), "keep", { mode: 0o600 });
  await assert.rejects(owner.cleanupHostCheckpoint(f.c, receipt), /host_checkpoint_changed/);
  assert.equal(await readFile(join(f.path, "foreign"), "utf8"), "keep");
  await assert.rejects(createHostCheckpoint(f.c, operationId, f.execute), /host_checkpoint_retired/);
  assert.equal(f.calls.length, 2);
});


test("cleanup rejects a linked retirement record and leaves its external bytes intact", async t => {
  const f = await fixture(t);
  const receipt = await createHostCheckpoint(f.c, operationId, f.execute);
  const outside = join(f.c.state, "external-record.json");
  await writeFile(outside, JSON.stringify(receipt), { mode: 0o600 });
  await link(outside, join(f.c.state, "checkpoints", "." + operationId + ".retired.json"));
  await assert.rejects(owner.cleanupHostCheckpoint(f.c, receipt), /host_checkpoint_changed/);
  assert.deepEqual(await readFile(join(f.path, "database.dump")), f.bytes);
  assert.deepEqual(JSON.parse(await readFile(outside, "utf8")), receipt);
});


test("a failed unlink leaves a durable retirement intent and resumes without regenerating data", async t => {
  const f = await fixture(t);
  const receipt = await createHostCheckpoint(f.c, operationId, f.execute);
  const original = filesystem.unlink;
  filesystem.unlink = async path => {
    if (path === join(f.path, "database.dump")) throw Object.assign(Error("synthetic interrupted unlink"), { code: "EIO" });
    return original(path);
  };
  syncBuiltinESMExports();
  try {
    await assert.rejects(owner.cleanupHostCheckpoint(f.c, receipt), /synthetic interrupted unlink/);
  } finally { filesystem.unlink = original; syncBuiltinESMExports(); }
  assert.deepEqual(await readdir(f.path), ["database.dump"]);
  assert.deepEqual(JSON.parse(await readFile(join(f.c.state, "checkpoints", "." + operationId + ".retired.json"), "utf8")), receipt);
  await assert.rejects(createHostCheckpoint(f.c, operationId, f.execute), /host_checkpoint_retired/);
  await owner.cleanupHostCheckpoint(f.c, receipt);
  await assert.rejects(readFile(join(f.path, "database.dump")), { code: "ENOENT" });
  assert.equal(f.calls.length, 2);
});


test("retry syncs a retirement marker interrupted before its first file sync before deleting bytes", async t => {
  const f = await fixture(t);
  const receipt = await createHostCheckpoint(f.c, operationId, f.execute);
  const marker = join(f.c.state, "checkpoints", "." + operationId + ".retired.json");
  const originalOpen = filesystem.open, originalUnlink = filesystem.unlink;
  const events = [];
  let interrupted = false;
  filesystem.open = async (...args) => {
    const file = await originalOpen(...args);
    if (args[0] === marker) {
      const sync = file.sync.bind(file);
      file.sync = async () => {
        if (!interrupted) { interrupted = true; throw Error("synthetic marker sync interruption"); }
        events.push("marker-sync");
        return sync();
      };
    }
    return file;
  };
  filesystem.unlink = async path => { events.push("unlink"); return originalUnlink(path); };
  syncBuiltinESMExports();
  try {
    await assert.rejects(owner.cleanupHostCheckpoint(f.c, receipt), /synthetic marker sync interruption/);
    assert.deepEqual(await readFile(join(f.path, "database.dump")), f.bytes);
    await owner.cleanupHostCheckpoint(f.c, receipt);
    assert.deepEqual(events, ["marker-sync", "unlink", "unlink"]);
  } finally { filesystem.open = originalOpen; filesystem.unlink = originalUnlink; syncBuiltinESMExports(); }
});


test("owner cleanup control commands bind the exact runtime receipt and accept no caller paths", async t => {
  const f = await fixture(t);
  const receipt = await createHostCheckpoint(f.c, operationId, f.execute);
  assert.equal(typeof owner.checkpointControlRequest, "function");
  const command = { protocolVersion: 1, action: "cleanup-checkpoint", operationId, checkpoint: receipt };
  assert.deepEqual(owner.checkpointControlRequest(f.c, JSON.stringify(command)), command);
  assert.deepEqual(owner.checkpointControlRequest(f.c, JSON.stringify(request)), request);
  for (const changed of [null, {}, { ...command, path: "/outside" }, { ...command, protocolVersion: 2 },
    { ...command, operationId: "22222222-2222-4222-8222-222222222222" },
    { ...command, checkpoint: { ...receipt, sourceRevision: "e".repeat(40) } },
    { ...command, checkpoint: { ...receipt, path: "/outside" } },
    { ...command, checkpoint: { ...receipt, dump: { bytes: 0, sha256: "e".repeat(64) } } }]) {
    assert.throws(() => owner.checkpointControlRequest(f.c, JSON.stringify(changed)), /host_checkpoint_request_invalid/);
  }
  for (const raw of ["{", "x".repeat(1025)])
    assert.throws(() => owner.checkpointControlRequest(f.c, raw), /host_checkpoint_request_invalid/);
  assert.deepEqual(await readFile(join(f.path, "database.dump")), f.bytes);
});
