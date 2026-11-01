import assert from "node:assert/strict";
import { test } from "node:test";
import { mkdtemp, mkdir, readFile, writeFile, rm, readdir, realpath, symlink } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createHash } from "node:crypto";
import { renameSync, mkdirSync, writeFileSync } from "node:fs";
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
