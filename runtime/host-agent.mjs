// The desktop opens the start gate only after installing OS process-tree ownership.
import { spawn } from "node:child_process";
import { constants } from "node:fs";
import * as fs from "node:fs/promises";
import { createServer } from "node:net";
import { delimiter, isAbsolute, join, dirname, basename } from "node:path";
import { createInterface } from "node:readline";
import { createHash, randomUUID } from "node:crypto";
import { isDeepStrictEqual } from "node:util";

const fail = (code) => {
  throw new Error(code);
};
// Enable only after private Chromium, fonts and installed lifecycle qualification.
const STUDIO_ENABLED = false;
const RESTORE_SESSION = Symbol("private restore session");
// Read only the dedicated child IPC channel; stdout is never readiness evidence.
export function studioReadyUntil(message, engineDigest, now = Date.now()) {
  if (!message || message.protocolVersion !== 1)
    fail("host_studio_protocol_invalid");
  const keys = Object.keys(message).sort().join(",");
  if (message.state === "qualifying" && keys === "protocolVersion,state")
    return 0;
  const expiry =
    typeof message.expiresAt === "string" ? Date.parse(message.expiresAt) : NaN;
  if (
    keys !== "engineDigest,expiresAt,protocolVersion,state" ||
    message.state !== "ready" ||
    typeof engineDigest !== "string" ||
    !/^[a-f0-9]{40}$/.test(engineDigest) ||
    message.engineDigest !== engineDigest ||
    !Number.isFinite(expiry) ||
    new Date(expiry).toISOString() !== message.expiresAt ||
    expiry <= now + 10 * 60_000
  ) {
    fail("host_studio_protocol_invalid");
  }
  // A worker renews ten minutes early; expired readiness must fail closed even if an IPC message is lost.
  return expiry - 10 * 60_000;
}
export function validateConfig(c) {
  if (
    !c ||
    (c.mode !== undefined && !["server", "database", "checkpoint-cleanup", "restore-prepare"].includes(c.mode)) ||
    !isAbsolute(c.state ?? "") ||
    !isAbsolute(c.runtime ?? "") ||
    c.state === c.runtime ||
    !/^[a-f0-9]{64}$/.test(c.manifestSha256) ||
    !/^[a-f0-9]{40}$/.test(c.sourceRevision) ||
    c.postgresMajor !== "19" ||
    typeof c.password !== "string" ||
    c.password.length < 24 ||
    c.password.length > 512 ||
    /[\r\n\0]/.test(c.password) ||
    ![c.databasePort, c.apiPort].every(
      (p) => Number.isInteger(p) && p > 0 && p <= 65535,
    ) ||
    c.databasePort === c.apiPort
  )
    fail("host_config_invalid");
  for (const name of [
    "node",
    "server",
    "postgres",
    "initdb",
    "createdb",
    "psql",
    "pgIsready",
    "pgCtl",
    "pgDump",
    "pgRestore",
    "hdr",
    "ffmpeg",
    "ffprobe",
    "rawRenderer",
    "rawDecoder",
    "studioBrowser",
    "studioBrowserGuard",
    "studio",
  ]) {
    const path = c.entryPoints?.[name];
    if (
      typeof path !== "string" ||
      !path ||
      path.includes("\\") ||
      path.includes(":") ||
      path.split("/").some((p) => !p || p === "." || p === "..")
    )
      fail("host_component_invalid");
  }
  const extension = process.platform === "win32" ? ".exe" : "";
  if (
    basename(c.entryPoints.ffmpeg) !== "ffmpeg" + extension ||
    basename(c.entryPoints.ffprobe) !== "ffprobe" + extension ||
    dirname(c.entryPoints.ffmpeg) !== dirname(c.entryPoints.ffprobe) ||
    basename(c.entryPoints.rawRenderer) !== "darktable-cli" + extension ||
    basename(c.entryPoints.rawDecoder) !== "dcraw_emu" + extension ||
    dirname(c.entryPoints.rawRenderer) !== dirname(c.entryPoints.rawDecoder)
  )
    fail("host_media_components_invalid");
}
async function stateFile(path, maximum) {
  const meta = await fs.lstat(path);
  if (!meta.isFile() || meta.isSymbolicLink() || meta.size > maximum)
    fail("host_state_file_invalid");
  const file = await fs.open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const buffer = Buffer.alloc(maximum + 1);
    const { bytesRead } = await file.read(buffer, 0, buffer.length, 0);
    if (bytesRead > maximum) fail("host_state_file_invalid");
    return buffer.subarray(0, bytesRead).toString("utf8");
  } finally {
    await file.close();
  }
}

const CHECKPOINT_ID = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
export function checkpointRequest(line) {
  try {
    if (typeof line !== "string" || Buffer.byteLength(line) > 1024) throw Error();
    const value = JSON.parse(line);
    if (!value || Object.keys(value).sort().join(",") !== "action,operationId,protocolVersion" ||
      value.protocolVersion !== 1 || value.action !== "checkpoint" ||
      typeof value.operationId !== "string" || !CHECKPOINT_ID.test(value.operationId)) throw Error();
    return value.operationId;
  } catch {
    fail("host_checkpoint_request_invalid");
  }
}
export function checkpointControlRequest(c, line) {
  try {
    if (typeof line !== "string" || Buffer.byteLength(line) > 1024) throw Error();
    const value = JSON.parse(line);
    if (value?.action === "prepare-restore") {
      if (c.mode !== "restore-prepare" || Object.keys(value).sort().join(",") !== "action,binding,operationId,protocolVersion" || value.protocolVersion !== 1) throw Error();
      const binding = restoreInputBinding(c, value.binding);
      if (binding.operationId !== value.operationId) throw Error();
      return {protocolVersion:1, action:"prepare-restore", operationId:value.operationId, binding};
    }
    if (value?.action === "checkpoint") {
      checkpointRequest(line);
      return value;
    }
    if (!value || Object.keys(value).sort().join(",") !== "action,checkpoint,operationId,protocolVersion" ||
      value.protocolVersion !== 1 || value.action !== "cleanup-checkpoint") throw Error();
    const checkpoint = retirementReceipt(c, value.checkpoint);
    if (checkpoint.operationId !== value.operationId) throw Error();
    return { protocolVersion: 1, action: "cleanup-checkpoint", operationId: value.operationId, checkpoint };
  } catch { fail("host_checkpoint_request_invalid"); }
}

async function checkpointDirectory(path, create = false) {
  if (create) await fs.mkdir(path, { mode: 0o700 }).catch(error => {
    if (error.code !== "EEXIST") throw error;
  });
  const meta = await fs.lstat(path);
  if (!meta.isDirectory() || meta.isSymbolicLink() ||
    (process.platform !== "win32" && (meta.mode & 0o077) !== 0)) fail("host_checkpoint_not_private");
}
async function checkpointHash(path, check, maximum = Number.MAX_SAFE_INTEGER) {
  const named = await fs.lstat(path, { bigint: true });
  if (!named.isFile() || named.isSymbolicLink()) fail("host_checkpoint_changed");
  const file = await fs.open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const before = await file.stat({ bigint: true });
    if (before.dev !== named.dev || before.ino !== named.ino || !before.isFile() || before.nlink !== 1n || before.size <= 0n ||
      before.size > BigInt(maximum) ||
      (process.platform !== "win32" && (before.mode & 0o077n) !== 0n)) fail("host_checkpoint_changed");
    const hash = createHash("sha256"); let bytes = 0;
    for await (const chunk of file.createReadStream({ autoClose: false, highWaterMark: Math.min(64 * 1024, maximum + 1) })) {
      check();
      bytes += chunk.length;
      if (bytes > maximum) fail("host_checkpoint_changed");
      hash.update(chunk);
    }
    const after = await file.stat({ bigint: true });
    const stillNamed = await fs.lstat(path, { bigint: true });
    if (BigInt(bytes) !== before.size || ["dev", "ino", "size", "mtimeNs", "ctimeNs", "nlink", "mode"].some(key => before[key] !== after[key]))
      fail("host_checkpoint_changed");
    if (!stillNamed.isFile() || stillNamed.isSymbolicLink() ||
      ["dev", "ino", "size", "mtimeNs", "ctimeNs", "nlink", "mode"].some(key => after[key] !== stillNamed[key]))
      fail("host_checkpoint_changed");
    return { bytes, sha256: hash.digest("hex") };
  } finally { await file.close(); }
}
async function checkpointSyncDirectory(path) {
  if (process.platform === "win32") return;
  const file = await fs.open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  try { await file.sync(); } finally { await file.close(); }
}
function retirementReceipt(c, value) {
  if (!value || typeof value.operationId !== "string" || !CHECKPOINT_ID.test(value.operationId)) fail("host_checkpoint_changed");
  const binding = { schemaVersion: 1, operationId: value.operationId, manifestSha256: c.manifestSha256,
    sourceRevision: c.sourceRevision, postgresMajor: c.postgresMajor, databaseFormat: "frameleaf-canonical" };
  if (Object.keys(value).sort().join(",") !== [...Object.keys(binding), "dump"].sort().join(",") ||
    Object.entries(binding).some(([key, item]) => value[key] !== item) ||
    !value.dump || Object.keys(value.dump).sort().join(",") !== "bytes,sha256" ||
    !Number.isSafeInteger(value.dump.bytes) || value.dump.bytes <= 0 ||
    typeof value.dump.sha256 !== "string" || !/^[a-f0-9]{64}$/.test(value.dump.sha256)) fail("host_checkpoint_changed");
  return { ...binding, dump: { bytes: value.dump.bytes, sha256: value.dump.sha256 } };
}
/** The owner retires an operation permanently before removing its verified checkpoint bytes. */
export async function cleanupHostCheckpoint(c, supplied) {
  validateConfig(c);
  const expected = retirementReceipt(c, supplied);
  await checkpointDirectory(c.state);
  if (await fs.realpath(c.state) !== c.state) fail("host_checkpoint_changed");
  const root = join(c.state, "checkpoints");
  await checkpointDirectory(root);
  if (await fs.realpath(root) !== root) fail("host_checkpoint_changed");
  const target = join(root, expected.operationId), marker = join(root, "." + expected.operationId + ".retired.json");
  let retired = false, markerIdentity;
  try {
    const named = await fs.lstat(marker);
    if (!named.isFile() || named.isSymbolicLink() || named.nlink !== 1 ||
      (process.platform !== "win32" && (named.mode & 0o077) !== 0) ||
      (await fs.realpath(marker)) !== marker) fail("host_checkpoint_changed");
    const value = retirementReceipt(c, JSON.parse(await stateFile(marker, 4096)));
    if (JSON.stringify(value) !== JSON.stringify(expected)) fail("host_checkpoint_changed");
    retired = true; markerIdentity = named;
  } catch (error) { if (error.code !== "ENOENT") throw error; }
  if (retired) {
    const file = await fs.open(marker, constants.O_RDWR | constants.O_NOFOLLOW);
    try {
      const current = await file.stat();
      if (["dev", "ino", "size", "mtimeMs", "ctimeMs", "nlink", "mode"].some(key => current[key] !== markerIdentity[key]))
        fail("host_checkpoint_changed");
      // A previous process may have written this intent but crashed before syncing its contents.
      await file.sync();
    } finally { await file.close(); }
  }
  let directory;
  try { directory = await fs.lstat(target); }
  catch (error) { if (error.code !== "ENOENT" || !retired) throw error; }
  if (directory) {
    await checkpointDirectory(target);
    if (await fs.realpath(target) !== target) fail("host_checkpoint_changed");
    const names = (await fs.readdir(target)).sort();
    if (names.some(name => !["checkpoint.json", "database.dump"].includes(name)) ||
      (!retired && names.join(",") !== "checkpoint.json,database.dump")) fail("host_checkpoint_changed");
    const files = new Map();
    for (const name of names) {
      const path = join(target, name), before = await fs.lstat(path);
      if (!before.isFile() || before.isSymbolicLink() || before.nlink !== 1 ||
        (await fs.realpath(path)) !== path) fail("host_checkpoint_changed");
      if (name === "checkpoint.json") {
        if (JSON.stringify(retirementReceipt(c, JSON.parse(await stateFile(path, 4096)))) !== JSON.stringify(expected))
          fail("host_checkpoint_changed");
      } else {
        const actual = await checkpointHash(path, () => {});
        if (actual.bytes !== expected.dump.bytes || actual.sha256 !== expected.dump.sha256) fail("host_checkpoint_changed");
      }
      files.set(name, before);
    }
    if (!retired) {
      const file = await fs.open(marker, "wx", 0o600);
      try { await file.writeFile(JSON.stringify(expected) + "\n"); await file.sync(); } finally { await file.close(); }
    }
    // Sync an existing intent too: a prior crash may have happened before its directory sync.
    await checkpointSyncDirectory(root);
    for (const name of names) {
      const freshDirectory = await fs.lstat(target), path = join(target, name), fresh = await fs.lstat(path), before = files.get(name);
      if (freshDirectory.dev !== directory.dev || freshDirectory.ino !== directory.ino ||
        !freshDirectory.isDirectory() || freshDirectory.isSymbolicLink() ||
        ["dev", "ino", "size", "mtimeMs", "ctimeMs", "nlink", "mode"].some(key => fresh[key] !== before[key]))
        fail("host_checkpoint_changed");
      await fs.unlink(path);
    }
    const freshDirectory = await fs.lstat(target);
    if (freshDirectory.dev !== directory.dev || freshDirectory.ino !== directory.ino) fail("host_checkpoint_changed");
    await fs.rmdir(target);
  }
  await checkpointSyncDirectory(root);
  return { ...expected, state: "checkpoint-cleaned" };
}

async function checkpointIdentity(path, directory = false) {
  const meta = await fs.lstat(path, { bigint: true });
  if (meta.isSymbolicLink() || (directory ? !meta.isDirectory() : !meta.isFile() || meta.nlink !== 1n) ||
    meta.ino <= 0n || (process.platform !== "win32" && (meta.mode & 0o077n) !== 0n) ||
    await fs.realpath(path) !== path) fail("host_checkpoint_changed");
  return `${meta.dev}:${meta.ino}`;
}
async function checkpointAttempt(path, binding) {
  const names = (await fs.readdir(path)).sort();
  if (!names.includes("checkpoint-attempt.json") ||
    names.some(name => !["checkpoint-attempt.json", "database.dump", ".checkpoint-record.partial", "checkpoint.json"].includes(name)) ||
    (names.includes("checkpoint.json") && (!names.includes("database.dump") || names.includes(".checkpoint-record.partial"))))
    fail("host_checkpoint_changed");
  const marker = join(path, "checkpoint-attempt.json"), identity = await checkpointIdentity(marker);
  const value = JSON.parse(await stateFile(marker, 8192));
  if (!value || Object.keys(value).sort().join(",") !== "binding,files,schemaVersion" || value.schemaVersion !== 1 ||
    !value.binding || Object.keys(value.binding).sort().join(",") !== Object.keys(binding).sort().join(",") ||
    Object.entries(binding).some(([key, item]) => value.binding[key] !== item) ||
    !value.files || Object.keys(value.files).sort().join(",") !== "directory,dump,intent,record" ||
    Object.values(value.files).some(item => typeof item !== "string" || !/^[0-9]+:[1-9][0-9]*$/.test(item)) ||
    value.files.intent !== identity || await checkpointIdentity(marker) !== identity ||
    await checkpointIdentity(path, true) !== value.files.directory) fail("host_checkpoint_changed");
  for (const name of names) {
    const key = name === "database.dump" ? "dump" : name === "checkpoint-attempt.json" ? "intent" : "record";
    if (await checkpointIdentity(join(path, name)) !== value.files[key]) fail("host_checkpoint_changed");
  }
  return { names, files: value.files };
}
async function checkpointReceipt(path, c, operationId, check) {
  const directory = await checkpointIdentity(path, true);
  const record = await checkpointIdentity(join(path, "checkpoint.json"));
  const receipt = retirementReceipt(c, JSON.parse(await stateFile(join(path, "checkpoint.json"), 4096)));
  if (receipt.operationId !== operationId) fail("host_checkpoint_changed");
  const actual = await checkpointHash(join(path, "database.dump"), check);
  check();
  if (actual.bytes !== receipt.dump.bytes || actual.sha256 !== receipt.dump.sha256 ||
    await checkpointIdentity(path, true) !== directory ||
    await checkpointIdentity(join(path, "checkpoint.json")) !== record) fail("host_checkpoint_changed");
  return receipt;
}
async function discardCheckpointAttempt(path, binding) {
  let attempt = await checkpointAttempt(path, binding);
  if (attempt.names.includes("checkpoint.json")) fail("host_checkpoint_changed");
  for (const name of ["database.dump", ".checkpoint-record.partial"]) {
    attempt = await checkpointAttempt(path, binding);
    if (attempt.names.includes(name)) await fs.unlink(join(path, name));
  }
  await checkpointAttempt(path, binding);
  await checkpointSyncDirectory(path);
  // Move the empty intent aside before removing it so a crash cannot block the canonical retry path.
  const empty = join(dirname(path), "." + binding.operationId + "." + randomUUID() + ".empty");
  await fs.rename(path, empty);
  await checkpointSyncDirectory(dirname(path));
  await checkpointAttempt(empty, binding);
  await fs.unlink(join(empty, "checkpoint-attempt.json"));
  await fs.rmdir(empty);
  await checkpointSyncDirectory(dirname(path));
}
async function finishCheckpointAttempt(path, binding) {
  await checkpointAttempt(path, binding);
  await checkpointSyncDirectory(path);
  await checkpointSyncDirectory(dirname(path));
  await fs.unlink(join(path, "checkpoint-attempt.json"));
  await checkpointSyncDirectory(path);
}

/** Called only by the live owner, which serializes requests and owns the database process tree. */
export async function createHostCheckpoint(c, operationId, execute, cancelled = () => false) {
  validateConfig(c);
  if (typeof operationId !== "string" || !CHECKPOINT_ID.test(operationId)) fail("host_checkpoint_request_invalid");
  const check = () => { if (cancelled()) fail("host_checkpoint_cancelled"); };
  check();
  await checkpointDirectory(c.state);
  const root = join(c.state, "checkpoints");
  await checkpointDirectory(root, true);
  if (await fs.realpath(c.state) !== c.state || await fs.realpath(root) !== root) fail("host_checkpoint_changed");
  await checkpointSyncDirectory(c.state);
  // Any retirement intent forbids regenerating a different live dump under the same operation ID.
  try {
    await fs.lstat(join(root, "." + operationId + ".retired.json"));
    fail("host_checkpoint_retired");
  } catch (error) { if (error.code !== "ENOENT") throw error; }
  const target = join(root, operationId), staging = join(root, "." + operationId + ".partial");
  const binding = { schemaVersion: 1, operationId, manifestSha256: c.manifestSha256,
    sourceRevision: c.sourceRevision, postgresMajor: c.postgresMajor, databaseFormat: "frameleaf-canonical" };
  let existing = false;
  try { await fs.lstat(target); existing = true; } catch (error) { if (error.code !== "ENOENT") throw error; }
  if (existing) {
    await checkpointDirectory(target);
    const names = (await fs.readdir(target)).sort().join(",");
    if (names !== "checkpoint.json,database.dump" && names !== "checkpoint-attempt.json,checkpoint.json,database.dump")
      fail("host_checkpoint_changed");
    if (names.includes("checkpoint-attempt.json")) await checkpointAttempt(target, binding);
    const receipt = await checkpointReceipt(target, c, operationId, check);
    if (names.includes("checkpoint-attempt.json")) await finishCheckpointAttempt(target, binding);
    return receipt;
  }
  let partial = false;
  try { await fs.lstat(staging); partial = true; } catch (error) { if (error.code !== "ENOENT") throw error; }
  if (partial) {
    const attempt = await checkpointAttempt(staging, binding);
    if (attempt.names.includes("checkpoint.json")) {
      const receipt = await checkpointReceipt(staging, c, operationId, check);
      await checkpointAttempt(staging, binding);
      await fs.rename(staging, target);
      await finishCheckpointAttempt(target, binding);
      return receipt;
    }
    await discardCheckpointAttempt(staging, binding);
    check();
  }
  // No database bytes enter the random preparation directory before the ownership intent is durable.
  const preparing = await fs.mkdtemp(join(root, "." + operationId + ".preparing-"));
  const files = { directory: await checkpointIdentity(preparing, true) };
  for (const [key, name] of [["dump", "database.dump"], ["record", ".checkpoint-record.partial"], ["intent", "checkpoint-attempt.json"]]) {
    const file = await fs.open(join(preparing, name), "wx", 0o600);
    try { await file.sync(); } finally { await file.close(); }
    files[key] = await checkpointIdentity(join(preparing, name));
  }
  const intent = await fs.open(join(preparing, "checkpoint-attempt.json"), constants.O_WRONLY | constants.O_NOFOLLOW);
  try { await intent.writeFile(JSON.stringify({ schemaVersion: 1, binding, files }) + "\n"); await intent.sync(); }
  finally { await intent.close(); }
  await checkpointSyncDirectory(preparing);
  await fs.rename(preparing, staging);
  await checkpointSyncDirectory(root);
  try {
    const dump = join(staging, "database.dump");
    await checkpointAttempt(staging, binding);
    await execute([join(c.runtime, c.entryPoints.pgDump), "--host", "127.0.0.1", "--port", String(c.databasePort),
      "--username", "frameleaf", "--no-password", "--format=custom", "--file", dump, "frameleaf"], { PGPASSWORD: c.password });
    check();
    await checkpointAttempt(staging, binding);
    await execute([join(c.runtime, c.entryPoints.pgRestore), "--list", dump], {});
    check();
    const file = await fs.open(dump, constants.O_RDWR | constants.O_NOFOLLOW);
    try {
      const meta = await file.stat({ bigint: true });
      if (`${meta.dev}:${meta.ino}` !== files.dump) fail("host_checkpoint_changed");
      await file.sync();
    } finally { await file.close(); }
    const receipt = { ...binding, dump: await checkpointHash(dump, check) };
    await checkpointAttempt(staging, binding);
    const record = await fs.open(join(staging, ".checkpoint-record.partial"), constants.O_WRONLY | constants.O_NOFOLLOW);
    try {
      const meta = await record.stat({ bigint: true });
      if (`${meta.dev}:${meta.ino}` !== files.record) fail("host_checkpoint_changed");
      await record.writeFile(JSON.stringify(receipt) + "\n"); await record.sync();
    } finally { await record.close(); }
    check();
    await checkpointAttempt(staging, binding);
    await fs.rename(join(staging, ".checkpoint-record.partial"), join(staging, "checkpoint.json"));
    await checkpointSyncDirectory(staging);
    await fs.rename(staging, target);
    await finishCheckpointAttempt(target, binding);
    return receipt;
  } catch (error) {
    // Completed records are immutable retry evidence; never discard them after a publication failure.
    try {
      const attempt = await checkpointAttempt(staging, binding);
      if (!attempt.names.includes("checkpoint.json")) await discardCheckpointAttempt(staging, binding);
    } catch { /* Preserve any changed or published attempt for explicit recovery. */ }
    throw error;
  }
}
export async function claimState(c) {
  validateConfig(c);
  const meta = await fs.lstat(c.state);
  if (
    !meta.isDirectory() ||
    meta.isSymbolicLink() ||
    (process.platform !== "win32" && (meta.mode & 0o077) !== 0)
  )
    fail("host_state_not_private");
  const expected = {
    schemaVersion: 1,
    manifestSha256: c.manifestSha256,
    sourceRevision: c.sourceRevision,
    postgresMajor: c.postgresMajor,
  };
  const path = join(c.state, "host-state.json");
  let raw;
  try {
    raw = await stateFile(path, 4096);
  } catch (error) {
    if (error.code !== "ENOENT") fail("host_state_invalid");
  }
  if (raw !== undefined) {
    let value;
    try {
      value = JSON.parse(raw);
    } catch {
      fail("host_state_invalid");
    }
    if (JSON.stringify(value) !== JSON.stringify(expected))
      fail("host_update_requires_manager");
    return false;
  }
  if (
    (await fs.readdir(c.state)).some(
      (name) =>
        !["lease.lock", "agent.log", "controller-state.json"].includes(name),
    )
  )
    fail("host_state_not_empty");
  const output = await fs.open(path, "wx", 0o600);
  try {
    await output.writeFile(JSON.stringify(expected));
    await output.sync();
  } finally {
    await output.close();
  }
  return true;
}
async function portFree(port) {
  const probe = createServer();
  await new Promise((resolve, reject) => {
    probe.once("error", reject);
    probe.listen(port, "127.0.0.1", resolve);
  });
  await new Promise((resolve, reject) =>
    probe.close((error) => (error ? reject(error) : resolve())),
  );
}
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
async function exited(child, ms) {
  const deadline = Date.now() + ms;
  while (
    child.pid &&
    child.exitCode === null &&
    child.signalCode === null &&
    Date.now() < deadline
  )
    await sleep(50);
  return !child.pid || child.exitCode !== null || child.signalCode !== null;
}
export function hostEnvironment(c) {
  return {
    FRAMELEAF_STUDIO_WORKER_TRUST_DIR: join(c.state, "studio-trust"),
    FRAMELEAF_STUDIO_WORKER_WORK_DIR: join(c.state, "studio-work"),
    FRAMELEAF_STUDIO_CHROMIUM: join(c.runtime, c.entryPoints.studioBrowser),
    FRAMELEAF_STUDIO_NODE: join(c.runtime, c.entryPoints.node),
    ...(process.platform === "win32"
      ? {}
      : {
          FRAMELEAF_STUDIO_BROWSER_GUARD: join(
            c.runtime,
            c.entryPoints.studioBrowserGuard,
          ),
        }),
    FRAMELEAF_RAW_DECODER_PATH: join(c.runtime, c.entryPoints.rawDecoder),
    FFMPEG_PATH: join(c.runtime, c.entryPoints.ffmpeg),
    FFPROBE_PATH: join(c.runtime, c.entryPoints.ffprobe),
    PATH: [
      dirname(join(c.runtime, c.entryPoints.ffmpeg)),
      dirname(join(c.runtime, c.entryPoints.rawRenderer)),
      dirname(join(c.runtime, c.entryPoints.node)),
      dirname(join(c.runtime, c.entryPoints.postgres)),
      process.platform === "win32"
        ? join(process.env.SystemRoot ?? "C:\\Windows", "System32")
        : "/usr/bin",
      ...(process.platform === "win32" ? [] : ["/bin"]),
    ].join(delimiter),
    HOME: join(c.state, "home"),
    LANG: "C",
    ...(process.platform === "win32"
      ? { SystemRoot: process.env.SystemRoot ?? "C:\\Windows" }
      : {}),
  };
}

/** The child inherits the host process group/Job; Chromium has its separate guardian. */
export function ownStudioWorker(child, engineDigest) {
  let readyUntil = 0,
    deadline = Date.now() + 10 * 60_000;
  let failure,
    closed = false,
    stopping = false,
    drain;
  const invalidate = (code) => {
    readyUntil = 0;
    failure ??= code;
  };
  const message = (value) => {
    if (stopping || closed || failure) return;
    try {
      const until = studioReadyUntil(value, engineDigest);
      if (until === 0 && readyUntil > 0) deadline = Date.now() + 10 * 60_000;
      readyUntil = until;
    } catch {
      invalidate("host_studio_protocol_invalid");
    }
  };
  const disconnect = () => {
    if (!stopping) invalidate("host_studio_disconnected");
  };
  const error = () => invalidate("host_studio_process_failed");
  const exit = () => {
    if (!stopping) invalidate("host_studio_process_exited");
  };
  const close = () => {
    closed = true;
    readyUntil = 0;
  };
  const inputError = () => {
    if (!stopping) invalidate("host_studio_pipe_failed");
  };
  child.on("message", message);
  child.on("disconnect", disconnect);
  child.on("error", error);
  child.on("exit", exit);
  child.on("close", close);
  child.stdin?.on("error", inputError);
  if (!child.stdin) invalidate("host_studio_pipe_failed");
  const waitClosed = async (ms) => {
    const until = Date.now() + ms;
    while (!closed && Date.now() < until) await sleep(50);
    return closed;
  };
  return {
    check() {
      if (stopping) return false;
      if (failure) fail(failure);
      if (closed || !child.connected) fail("host_studio_disconnected");
      if (readyUntil && readyUntil <= Date.now()) {
        readyUntil = 0;
        deadline = Date.now() + 10 * 60_000;
      }
      if (!readyUntil && Date.now() >= deadline) {
        invalidate("host_studio_not_ready");
        fail(failure);
      }
      return readyUntil > Date.now();
    },
    stop() {
      return (drain ??= (async () => {
        stopping = true;
        readyUntil = 0;
        let forced = false;
        try {
          if (!closed && !child.stdin)
            throw new Error("host_studio_pipe_failed");
          if (!closed && !child.stdin.destroyed && !child.stdin.writableEnded)
            child.stdin.end("stop\n");
        } catch {
          forced = true;
          child.kill("SIGKILL");
        }
        if (!(await waitClosed(forced ? 5000 : 35_000))) {
          forced = true;
          child.kill("SIGKILL");
          if (!(await waitClosed(5000))) fail("host_studio_shutdown_failed");
        }
        child.removeListener("message", message);
        child.removeListener("disconnect", disconnect);
        child.removeListener("exit", exit);
        child.removeListener("close", close);
        if (forced || child.exitCode !== 0) fail("host_studio_drain_failed");
      })());
    },
  };
}

/** The server acknowledges ownership before API readiness; the channel never carries credentials. */
export function ownHostServer(child) {
  let acknowledged = false,
    closed = false,
    stopping = false,
    failure,
    drain;
  const message = (value) => {
    if (stopping) return;
    if (value === "frameleaf:owner-ready:v1") acknowledged = true;
    else failure ??= "host_server_protocol_invalid";
  };
  const disconnected = () => {
    if (!stopping) failure ??= "host_server_disconnected";
  };
  const error = () => {
    failure ??= "host_server_process_failed";
  };
  child.on("message", message);
  child.on("disconnect", disconnected);
  child.on("error", error);
  child.once("close", () => {
    closed = true;
    acknowledged = false;
  });
  const waitClosed = async (ms) => {
    const until = Date.now() + ms;
    while (!closed && Date.now() < until) await sleep(50);
    return closed;
  };
  return {
    check() {
      if (stopping) return false;
      if (failure) fail(failure);
      if (closed || !child.connected) fail("host_server_disconnected");
      return acknowledged;
    },
    stop() {
      return (drain ??= (async () => {
        stopping = true;
        acknowledged = false;
        let controlFailed = false;
        if (!closed) {
          try {
            if (child.connected)
              child.send("frameleaf:stop", (error) => {
                if (error) controlFailed = true;
              });
          } catch {
            controlFailed = true;
          }
        }
        if (!(await waitClosed(40_000))) {
          controlFailed = true;
          child.kill("SIGKILL");
          if (!(await waitClosed(5000))) fail("host_server_shutdown_failed");
        }
        child.removeListener("message", message);
        child.removeListener("disconnect", disconnected);
        if (controlFailed || child.exitCode !== 0)
          fail("host_server_drain_failed");
      })());
    },
  };
}

/** Internal controller locator only; no caller-supplied paths and no activation authority. */
export async function readHostDatabase(profile, supplied) {
  if (supplied === undefined) return join(profile, "database");
  try {
    const reference = structuredClone(supplied);
    if (!reference || Object.keys(reference).sort().join(",") !== "attemptId,identities,operationId" ||
      typeof reference.operationId !== "string" || !CHECKPOINT_ID.test(reference.operationId) ||
      typeof reference.attemptId !== "string" || !CHECKPOINT_ID.test(reference.attemptId) ||
      !Array.isArray(reference.identities) || reference.identities.length !== 5 ||
      !reference.identities.every(value => typeof value === "string" && /^[a-f0-9]{64}$/.test(value)))
      fail("host_database_reference_invalid");
    const root = join(profile, "restore-targets"), operation = join(root, reference.operationId),
      target = join(operation, reference.attemptId), database = join(target, "database");
    const paths = [profile, root, operation, target, database];
    for (let i = 0; i < paths.length; i++) {
      await checkpointIdentity(paths[i], true);
      const meta = await fs.lstat(paths[i], { bigint: true });
      // Match the controller's native identity namespace, including Windows' high/low file index.
      const identity = process.platform === "win32"
        ? `${meta.dev}:${meta.ino >> 32n}:${meta.ino & 0xffffffffn}` : `${meta.dev}:${meta.ino}`;
      if (createHash("sha256").update(identity).digest("hex") !== reference.identities[i])
        fail("host_database_reference_invalid");
    }
    return database;
  } catch { fail("host_database_reference_invalid"); }
}

export async function runHost(c, stopping, ready, restoreSession) {
  validateConfig(c);
  if (restoreSession !== undefined && restoreSession?.[RESTORE_SESSION] !== true) fail("host_restore_authority_invalid");
  const restoreOnly = restoreSession?.[RESTORE_SESSION] === true;
  if (c.mode === "checkpoint-cleanup" || c.mode === "restore-prepare") {
    // Maintenance starts no original database; restore writes only a separate owned attempt.
    await checkpointDirectory(c.state);
    if (await fs.realpath(c.state) !== c.state) fail("host_state_not_private");
    await stateFile(join(c.state, "host-state.json"), 4096).catch(() => fail("host_state_invalid"));
    await claimState(c);
    let pending, cancelled = false;
    void stopping.then(() => { cancelled = true; });
    ready(request => {
      if (cancelled || pending || request.action !== (c.mode === "restore-prepare" ? "prepare-restore" : "cleanup-checkpoint"))
        return Promise.reject(new Error("host_checkpoint_unavailable"));
      const work = c.mode === "restore-prepare" ? restoreHostDatabase(c, request.binding, stopping) : cleanupHostCheckpoint(c, request.checkpoint);
      pending = work;
      void work.finally(() => { if (pending === work) pending = undefined; }).catch(() => {});
      return work;
    });
    try { await stopping; }
    finally { cancelled = true; await pending?.catch(() => {}); }
    return;
  }
  const databaseReference = c.databaseReference === undefined ? undefined : structuredClone(c.databaseReference);
  const data = await readHostDatabase(c.state, databaseReference);
  const selectedDatabase = databaseReference !== undefined;
  const databaseOnly = c.mode === "database";
  if (!databaseOnly && !restoreOnly) await portFree(c.apiPort);
  await portFree(c.databasePort);
  if (databaseOnly) {
    try {
      await checkpointDirectory(c.state);
      if (await fs.realpath(c.state) !== c.state) fail("host_state_not_private");
      await stateFile(join(c.state, "host-state.json"), 4096);
    } catch (error) {
      if (error.code === "ENOENT") fail("host_database_missing");
      throw error;
    }
  }
  await claimState(c);
  const previousPassword = join(c.state, "database-password.tmp");
  try {
    const meta = await fs.lstat(previousPassword);
    if (!meta.isFile() || meta.isSymbolicLink())
      fail("host_state_file_invalid");
    await fs.unlink(previousPassword);
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
  }
  for (const name of databaseOnly || restoreOnly ? ["home"] : ["home", "media", "studio-trust", "studio-work"]) {
    const path = join(c.state, name);
    try {
      await fs.mkdir(path, { mode: 0o700 });
    } catch (error) {
      if (error.code !== "EEXIST") throw error;
    }
    const meta = await fs.lstat(path);
    if (
      !meta.isDirectory() ||
      meta.isSymbolicLink() ||
      (process.platform !== "win32" && (meta.mode & 0o077) !== 0)
    )
      fail("host_state_not_private");
  }
  const executable = (name) => join(c.runtime, c.entryPoints[name]);
  const env = hostEnvironment(c);
  const logPath = join(c.state, "host.log");
  try {
    const meta = await fs.lstat(logPath);
    if (!meta.isFile() || meta.isSymbolicLink())
      fail("host_state_file_invalid");
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
  }
  const log = await fs.open(
    logPath,
    constants.O_WRONLY |
      constants.O_APPEND |
      constants.O_CREAT |
      constants.O_NOFOLLOW,
    0o600,
  );
  let pg, app, appOwner, studio, checkpointWork;
  const children = new Set();
  let cancelled = false;
  stopping.then(() => {
    cancelled = true;
  });
  function launch(args, extra = {}, stdio = ["ignore", "pipe", "pipe"], logOutput = true) {
    const child = spawn(args[0], args.slice(1), {
      cwd: c.state,
      env: { ...env, ...extra },
      stdio,
      windowsHide: true,
    });
    children.add(child);
    child.once("close", () => children.delete(child));
    child.on("error", () => {});
    if (logOutput) {
      child.stdout.on("data", (chunk) => { void log.write(chunk).catch(() => {}); });
      child.stderr.on("data", (chunk) => { void log.write(chunk).catch(() => {}); });
    }
    return child;
  }
  async function command(args, extra = {}, duringStop = false, options = {}) {
    const child = launch(args, extra, undefined, !options.quiet);
    let output = "",
      oversized = false;
    if (options.quiet) {
      child.stdout.resume(); child.stderr.resume();
    } else child.stdout.on("data", (chunk) => {
      if (Buffer.byteLength(output) + chunk.length > 65536) {
        oversized = true;
        child.kill();
      } else output += chunk.toString();
    });
    const deadline = Date.now() + (options.timeout ?? 30_000);
    while (!(await exited(child, 100))) {
      if ((cancelled && !duringStop) || Date.now() > deadline) {
        child.kill();
        if (!(await exited(child, 5000))) {
          child.kill("SIGKILL"); await exited(child, 5000);
        }
        fail("host_command_timeout");
      }
    }
    if (child.exitCode !== 0 || oversized) fail("host_command_failed");
    if (!child.stdout.readableEnded && !child.stdout.destroyed)
      await new Promise((resolve) => child.stdout.once("end", resolve));
    return output;
  }
  try {
    let initialized = false;
    try {
      const directory = await fs.lstat(data);
      if (!directory.isDirectory() || directory.isSymbolicLink())
        fail("host_database_directory_invalid");
      const version = await stateFile(join(data, "PG_VERSION"), 16);
      if (version.trim() !== c.postgresMajor)
        fail("host_database_major_mismatch");
      initialized = true;
    } catch (error) {
      if (error.code !== "ENOENT") throw error;
    }
    if (restoreOnly && initialized) fail("host_restore_target_not_empty");
    if ((databaseOnly || selectedDatabase) && !initialized) fail("host_database_missing");
    if (!initialized) {
      try {
        await fs.lstat(data);
        fail("host_database_incomplete");
      } catch (error) {
        if (error.code !== "ENOENT") throw error;
      }
      const passwordFile = join(c.state, "database-password.tmp");
      await fs.writeFile(passwordFile, c.password, { flag: "wx", mode: 0o600 });
      try {
        await command([
          executable("initdb"),
          "-D",
          data,
          "--username=frameleaf",
          "--encoding=UTF8",
          "--locale=C",
          "--data-checksums",
          "--auth-local=scram-sha-256",
          "--auth-host=scram-sha-256",
          `--pwfile=${passwordFile}`,
        ]);
      } finally {
        await fs.rm(passwordFile, { force: true });
      }
    }
    if (cancelled) fail("host_cancelled");
    if (selectedDatabase) await readHostDatabase(c.state, databaseReference);
    pg = launch([
      executable("postgres"),
      "-D",
      data,
      "-h",
      "127.0.0.1",
      "-p",
      String(c.databasePort),
      ...(databaseOnly ? ["-c", "default_transaction_read_only=on"] : []),
    ]);
    const deadline = Date.now() + 30_000;
    while (true) {
      if (
        cancelled ||
        !pg.pid ||
        pg.exitCode !== null ||
        pg.signalCode !== null ||
        Date.now() > deadline
      )
        fail("host_database_not_ready");
      try {
        await command([
          executable("pgIsready"),
          "-h",
          "127.0.0.1",
          "-p",
          String(c.databasePort),
        ]);
        break;
      } catch {
        await sleep(100);
      }
    }
    const database = await command(
      [
        executable("psql"),
        "-h",
        "127.0.0.1",
        "-p",
        String(c.databasePort),
        "-U",
        "frameleaf",
        "-d",
        "postgres",
        "-XAt",
        "-v",
        "ON_ERROR_STOP=1",
        "-c",
        "SELECT 1 FROM pg_database WHERE datname = 'frameleaf'",
      ],
      { PGPASSWORD: c.password },
    );
    if (database.trim() !== "" && database.trim() !== "1")
      fail("host_database_provisioning_failed");
    if (restoreOnly && database.trim() !== "") fail("host_restore_target_not_empty");
    if ((databaseOnly || selectedDatabase) && database.trim() === "") fail("host_database_missing");
    if (database.trim() === "")
      await command(
        [
          executable("createdb"),
          "-h",
          "127.0.0.1",
          "-p",
          String(c.databasePort),
          "-U",
          "frameleaf",
          "frameleaf",
        ],
        { PGPASSWORD: c.password },
      );
    if (restoreOnly) {
      const input = await readHostRestoreInput(restoreSession.original, restoreSession.binding);
      await command([executable("pgRestore"), "--list", input.dump], {}, false, {quiet:true, timeout:7_200_000});
      await command([executable("pgRestore"), "--no-password", "--host", "127.0.0.1", "--port", String(c.databasePort),
        "--username", "frameleaf", "--dbname", "frameleaf", "--single-transaction", "--exit-on-error", "--no-owner", "--no-acl", input.dump],
        {PGPASSWORD:c.password}, false, {quiet:true, timeout:7_200_000});
      await command([executable("node"), executable("server"), "frameleaf-admin", "restore-state"], {
        DB_HOSTNAME:"127.0.0.1", DB_PORT:String(c.databasePort), DB_USERNAME:"frameleaf", DB_PASSWORD:c.password, DB_DATABASE_NAME:"frameleaf",
        FRAMELEAF_MANAGER_ORIGIN:"restored_library", FRAMELEAF_MANAGER_INSTALLATION:restoreSession.binding.installationId,
        FRAMELEAF_MANAGER_RESTORE_OPERATION_ID:restoreSession.binding.operationId,
        FRAMELEAF_MEDIA_LOCATION:join(restoreSession.original.state,"media"), FRAMELEAF_BUILD_DATA:join(c.runtime,"build"),
        FRAMELEAF_HDR_BINDING:executable("hdr"), FRAMELEAF_STUDIO_WORKER:"false",
      }, false, {quiet:true, timeout:7_200_000});
      const validation = JSON.parse(await command([executable("psql"), "-h", "127.0.0.1", "-p", String(c.databasePort), "-U", "frameleaf", "-d", "frameleaf", "-XAt", "-v", "ON_ERROR_STOP=1", "-c",
        "SELECT json_build_object('postgresMajor',current_setting('server_version_num')::int / 10000,'vectorVersion',(SELECT extversion FROM pg_extension WHERE extname='vector'),'canonical',to_regclass('public.user') IS NOT NULL AND to_regclass('public.asset') IS NOT NULL AND to_regclass('public.album') IS NOT NULL)"], {PGPASSWORD:c.password}));
      if (validation.postgresMajor !== 19 || validation.vectorVersion !== "0.8.7" || validation.canonical !== true) fail("host_restore_database_invalid");
      restoreSession.validation = {postgresMajor:19, vectorVersion:"0.8.7", canonical:true, executionStateReconstructed:true};
    }
    if (!databaseOnly && !restoreOnly) {
      app = launch(
        [executable("node"), executable("server")],
        {
          DB_HOSTNAME: "127.0.0.1",
          DB_PORT: String(c.databasePort),
          DB_USERNAME: "frameleaf",
          DB_PASSWORD: c.password,
          DB_DATABASE_NAME: "frameleaf",
          FRAMELEAF_HOST: "127.0.0.1",
          FRAMELEAF_PORT: String(c.apiPort),
          FRAMELEAF_MEDIA_LOCATION: join(c.state, "media"),
          FRAMELEAF_BUILD_DATA: join(c.runtime, "build"),
          FRAMELEAF_HDR_BINDING: executable("hdr"),
          FRAMELEAF_WORKERS_INCLUDE: "api,microservices",
          FRAMELEAF_NATIVE_OWNER: "1",
          FRAMELEAF_STUDIO_WORKER: STUDIO_ENABLED ? "true" : "false",
        },
        ["ignore", "pipe", "pipe", "ipc"],
      );
      appOwner = ownHostServer(app);
      let markers = "",
        api = false,
        microservices = false;
      const observe = (chunk) => {
        markers = (markers + chunk.toString()).slice(-65536);
        api ||= markers.includes("Frameleaf Server is listening on");
        microservices ||= markers.includes("Frameleaf Microservices is running");
      };
      app.stdout.on("data", observe);
      app.stderr.on("data", observe);
      const startupDeadline = Date.now() + 180_000;
      while (true) {
        if (
          cancelled ||
          !app.pid ||
          !pg.pid ||
          app.exitCode !== null ||
          app.signalCode !== null ||
          pg.exitCode !== null ||
          pg.signalCode !== null ||
          Date.now() > startupDeadline
        )
          fail("host_application_not_ready");
        if (appOwner.check() && api && microservices) {
          try {
            const response = await fetch(
              `http://127.0.0.1:${c.apiPort}/api/server/ping`,
              { signal: AbortSignal.timeout(2000), redirect: "error" },
            );
            if (response.ok && (await response.json()).res === "pong") break;
          } catch {
            /* Startup may have attached the listener before its first request succeeds. */
          }
        }
        await sleep(100);
      }
      if (STUDIO_ENABLED && !cancelled) {
        const build = JSON.parse(
          await stateFile(join(c.runtime, "studio/engine-build.json"), 65536),
        );
        if (
          typeof build.upstreamCommit !== "string" ||
          !/^[a-f0-9]{40}$/.test(build.upstreamCommit)
        )
          fail("host_studio_engine_invalid");
        studio = ownStudioWorker(
          launch(
            [executable("node"), executable("studio"), "--owner-pipe"],
            {
              FRAMELEAF_STUDIO_WORKER: "true",
              FRAMELEAF_STUDIO_WORKER_SERVER_URL: `http://127.0.0.1:${c.apiPort}`,
            },
            ["pipe", "pipe", "pipe", "ipc"],
          ),
          build.upstreamCommit,
        );
      }
    }
    ready((request) => {
      if (checkpointWork || cancelled || (app && (app.exitCode !== null || app.signalCode !== null)) || pg.exitCode !== null || pg.signalCode !== null)
        return Promise.reject(new Error("host_checkpoint_unavailable"));
      const work = request.action === "cleanup-checkpoint"
        ? cleanupHostCheckpoint(c, request.checkpoint)
        : createHostCheckpoint(c, request.operationId,
          (args, extra) => command(args, extra, false, { quiet: true, timeout: 7_200_000 }),
          () => cancelled || (app && (app.exitCode !== null || app.signalCode !== null)) || pg.exitCode !== null || pg.signalCode !== null);
      checkpointWork = work;
      void work.finally(() => { if (checkpointWork === work) checkpointWork = undefined; }).catch(() => {});
      return work;
    });
    while (!cancelled) {
      if ((app && await exited(app, 100)) || (await exited(pg, 100)))
        fail("host_process_exited");
      appOwner?.check();
      studio?.check();
    }
  } finally {
    cancelled = true;
    await checkpointWork?.catch(() => {});
    let stopError, restoreStopped = false;
    try {
      await studio?.stop();
    } catch (error) {
      stopError = error;
    }
    try {
      await appOwner?.stop();
    } catch (error) {
      stopError ??= error;
    }
    if (pg && !(await exited(pg, 0))) {
      let pid;
      try {
        pid = (await stateFile(join(data, "postmaster.pid"), 8192)).split(
          "\n",
        )[0];
      } catch {
        /* A failed startup may not have published a PID file. */
      }
      if (pid === String(pg.pid)) {
        try {
          await command(
            [
              executable("pgCtl"),
              "stop",
              "-D",
              data,
              "-m",
              "fast",
              "-w",
              "-t",
              "20",
            ],
            {},
            true,
          );
          restoreStopped = true;
        } catch {
          /* The OS owner terminates any remaining processes below. */
        }
      }
    }
    for (const child of children)
      if (!(await exited(child, 0))) {
        child.kill("SIGKILL");
        await exited(child, 5000);
      }
    await log.close();
    if (restoreOnly && (!restoreStopped || pg?.exitCode !== 0 || pg?.signalCode !== null))
      stopError ??= new Error("host_restore_shutdown_unconfirmed");
    if (stopError) throw stopError;
  }
}
async function main() {
  const input = createInterface({ input: process.stdin, crlfDelay: Infinity });
  const lines = input[Symbol.asyncIterator]();
  const first = await lines.next();
  if (first.done || first.value.length > 65536) fail("host_start_gate_closed");
  let stop;
  const stopping = new Promise((resolve) => {
    stop = resolve;
  });
  process.stdin.on("end", stop);
  process.on("SIGTERM", stop);
  process.on("SIGINT", stop);
  const config = JSON.parse(first.value);
  let checkpoint, pending, protocolFailure;
  void (async () => {
    for await (const line of { [Symbol.asyncIterator]: () => lines }) {
      if (line === "stop") {
        stop();
        break;
      }
      const request = checkpointControlRequest(config, line);
      if (!checkpoint || pending) fail("host_checkpoint_unavailable");
      const cleanup = request.action === "cleanup-checkpoint", restore = request.action === "prepare-restore";
      pending = checkpoint(request)
        .then(receipt => process.stdout.write(JSON.stringify(restore ? receipt : { ...receipt, state: cleanup ? "checkpoint-cleaned" : "checkpoint" }) + "\n"))
        .catch(() => process.stdout.write(JSON.stringify({ state: restore ? "restore-prepare-failed" : cleanup ? "checkpoint-cleanup-failed" : "checkpoint-failed",
          operationId: request.operationId, code: restore ? "host_restore_failed" : cleanup ? "host_checkpoint_cleanup_failed" : "host_checkpoint_failed" }) + "\n"))
        .finally(() => { pending = undefined; });
    }
    stop();
  })().catch(() => { protocolFailure = "host_control_command_invalid"; stop(); });
  try {
    await runHost(config, stopping, (handler) => {
      checkpoint = handler;
      process.stdout.write(JSON.stringify({ state: config.mode === "restore-prepare" ? "restore-prepare-ready" : config.mode === "checkpoint-cleanup" ? "checkpoint-cleanup-ready" : config.mode === "database" ? "database-ready" : "running" }) + "\n");
    });
    await pending;
    if (protocolFailure) fail(protocolFailure);
  } finally {
    input.close();
    process.stdin.pause();
  }
}
if (process.env.FRAMELEAF_HOST_AGENT === "1") {
  main()
    .then(() => process.stdout.write('{"state":"stopped"}\n'))
    .catch((error) => {
      const code = /^host_[a-z_]+$/.test(error?.message)
        ? error.message
        : "native_host_failed";
      process.stderr.write(code + "\n");
      process.exitCode = 1;
    });
}


async function restoreInputJson(path) {
  if ((await fs.lstat(path)).size > 4096) fail("host_restore_input_invalid");
  const identity = await checkpointIdentity(path);
  const before = await checkpointHash(path, () => {}, 4096);
  const raw = await stateFile(path, 4096);
  if (Buffer.byteLength(raw) !== before.bytes || createHash("sha256").update(raw).digest("hex") !== before.sha256 ||
    JSON.stringify(await checkpointHash(path, () => {}, 4096)) !== JSON.stringify(before) || await checkpointIdentity(path) !== identity)
    fail("host_restore_input_invalid");
  return JSON.parse(raw);
}
function restoreInputBinding(c, value) {
  const keys = "installationId,libraryId,manifestSha256,operationId,recoverySha256,reviewId,runtime,schemaVersion,snapshotId,sourceRevision";
  if (!value || Object.keys(value).sort().join(",") !== keys || value.schemaVersion !== 1 || value.runtime !== "native" ||
    ![value.operationId, value.reviewId].every(id => typeof id === "string" && CHECKPOINT_ID.test(id)) ||
    ![value.installationId, value.libraryId].every(id => typeof id === "string" && /^[a-f0-9]{12}$/.test(id)) ||
    ![value.snapshotId, value.recoverySha256].every(id => typeof id === "string" && /^[a-f0-9]{64}$/.test(id)) ||
    value.manifestSha256 !== c.manifestSha256 || value.sourceRevision !== c.sourceRevision) fail("host_restore_input_invalid");
  return { schemaVersion: 1, runtime: "native", operationId: value.operationId, reviewId: value.reviewId, snapshotId: value.snapshotId,
    installationId: value.installationId, manifestSha256: value.manifestSha256, sourceRevision: value.sourceRevision,
    libraryId: value.libraryId, recoverySha256: value.recoverySha256 };
}
function restoreInputRecovery(c, value) {
  if (!value || Object.keys(value).sort().join(",") !== "checkpoint,createdAt,databaseFormat,installation,libraryId,mediaIncluded,runtime,schemaVersion" ||
    value.schemaVersion !== 1 || value.runtime !== "native" || value.mediaIncluded !== false || value.databaseFormat !== "frameleaf-canonical" ||
    typeof value.libraryId !== "string" || !/^[a-f0-9]{12}$/.test(value.libraryId) || !Number.isSafeInteger(value.createdAt) || value.createdAt < 0 ||
    !value.installation || Object.keys(value.installation).sort().join(",") !== "id,name,release" ||
    typeof value.installation.id !== "string" || !/^[a-f0-9]{12}$/.test(value.installation.id) || typeof value.installation.name !== "string" ||
    !value.installation.name.trim() || value.installation.name.trim().length > 120 || typeof value.installation.release !== "string" ||
    !/^frameleaf-v\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/.test(value.installation.release) ||
    !value.checkpoint || value.checkpoint.protocolVersion !== 1 || value.checkpoint.state !== "checkpoint" ||
    typeof value.checkpoint.manifestSha256 !== "string" || !/^[a-f0-9]{64}$/.test(value.checkpoint.manifestSha256) ||
    typeof value.checkpoint.sourceRevision !== "string" || !/^[a-f0-9]{40}$/.test(value.checkpoint.sourceRevision)) fail("host_restore_input_invalid");
  const { protocolVersion, state, ...disk } = value.checkpoint;
  const checkpoint = retirementReceipt({ ...c, manifestSha256: disk.manifestSha256, sourceRevision: disk.sourceRevision }, disk);
  return { schemaVersion: 1, runtime: "native", mediaIncluded: false, databaseFormat: "frameleaf-canonical", libraryId: value.libraryId,
    createdAt: value.createdAt, installation: { id: value.installation.id, name: value.installation.name.trim(), release: value.installation.release },
    checkpoint: { protocolVersion, state, ...checkpoint } };
}

/** Fixed-path staged input validation only; restore effects require the later exclusive controller operation. */
export async function readHostRestoreInput(c, supplied, check = () => {}) {
  try {
    check();
    validateConfig(c);
    const binding = restoreInputBinding(c, supplied), root = join(c.state, "restore-input"), target = join(root, binding.operationId), input = join(target, "input");
    const identities = new Map();
    for (const path of [c.state, root, target, input]) identities.set(path, await checkpointIdentity(path, true));
    const marker = await restoreInputJson(join(c.state, "host-state.json"));
    const expected = { schemaVersion: 1, manifestSha256: c.manifestSha256, sourceRevision: c.sourceRevision, postgresMajor: c.postgresMajor };
    if (Object.keys(marker).sort().join(",") !== Object.keys(expected).sort().join(",") || Object.entries(expected).some(([key, value]) => marker[key] !== value) ||
      (await fs.readdir(target)).sort().join(",") !== "input,restore-intent.json" || (await fs.readdir(input)).sort().join(",") !== "database.dump,recovery.json" ||
      JSON.stringify(restoreInputBinding(c, await restoreInputJson(join(target, "restore-intent.json")))) !== JSON.stringify(binding)) fail("host_restore_input_invalid");
    const recovery = restoreInputRecovery(c, await restoreInputJson(join(input, "recovery.json")));
    if (recovery.libraryId !== binding.libraryId || createHash("sha256").update(JSON.stringify(recovery)).digest("hex") !== binding.recoverySha256)
      fail("host_restore_input_invalid");
    const dump = join(input, "database.dump"), actual = await checkpointHash(dump, check);
    if (JSON.stringify(actual) !== JSON.stringify(recovery.checkpoint.dump)) fail("host_restore_input_invalid");
    for (const [path, identity] of identities) if (await checkpointIdentity(path, true) !== identity) fail("host_restore_input_invalid");
    return { binding, recovery, dump };
  } catch (error) { if (error?.message === "host_restore_cancelled") throw error; fail("host_restore_input_invalid"); }
}


/** Prepare a fresh logical target; activation is a separate reviewed, exclusive controller operation. */
export async function restoreHostDatabase(configuration, supplied, stopping) {
  const c = {...configuration, entryPoints:{...configuration.entryPoints}};
  let cancelled = false;
  void stopping.then(() => {cancelled=true;});
  const input = await readHostRestoreInput(c, supplied);
  if (cancelled) fail("host_restore_cancelled");
  if (input.recovery.checkpoint.sourceRevision !== c.sourceRevision) fail("host_restore_runtime_required");
  const profileIdentity = await checkpointIdentity(c.state, true);
  const root = join(c.state, "restore-targets"), operationRoot = join(root, input.binding.operationId);
  for (const path of [root, operationRoot]) {await checkpointDirectory(path, true); if (await fs.realpath(path) !== path) fail("host_restore_input_invalid");}
  const attemptId = randomUUID(), target = join(operationRoot, attemptId);
  await fs.mkdir(target, {mode:0o700});
  const targetIdentity = await checkpointIdentity(target, true);
  const inner = {...c, state:target, mode:"server", databaseReference:undefined};
  await claimState(inner);
  const intent = {schemaVersion:1, binding:input.binding, attemptId, profileIdentity, targetIdentity};
  const record = await fs.open(join(target,"restore-target.json"),"wx",0o600);
  try {await record.writeFile(JSON.stringify(intent)+"\n");await record.sync();} finally {await record.close();}
  await checkpointSyncDirectory(target);await checkpointSyncDirectory(operationRoot);await checkpointSyncDirectory(root);
  if (cancelled) fail("host_restore_cancelled");
  const session = {[RESTORE_SESSION]:true, original:c, binding:input.binding};
  let finish, prepared=false;
  const finished = new Promise(resolve => {finish=resolve;});
  await runHost(inner, Promise.race([stopping,finished]), () => {prepared=true;finish();}, session);
  if (!prepared || cancelled || !session.validation) fail("host_restore_cancelled");
  if (await checkpointIdentity(c.state,true) !== profileIdentity || await checkpointIdentity(target,true) !== targetIdentity) fail("host_restore_input_invalid");
  await readHostRestoreInput(c,input.binding);
  const receipt = {schemaVersion:1, state:"restore-prepared", binding:input.binding, attemptId, profileIdentity, targetIdentity,
    databaseIdentity:await checkpointIdentity(join(target,"database"),true), validation:session.validation};
  if (cancelled) fail("host_restore_cancelled");
  const result = await fs.open(join(target,"restore-result.json"),"wx",0o600);
  try {if (cancelled) fail("host_restore_cancelled");await result.writeFile(JSON.stringify(receipt)+"\n");await result.sync();} finally {await result.close();}
  await checkpointSyncDirectory(target);await checkpointSyncDirectory(operationRoot);
  if (cancelled) fail("host_restore_cancelled");
  return receipt;
}

/** Recheck prepared evidence only; exclusive activation must still verify offline database state. */
export async function readHostRestoreTarget(configuration, supplied, check = () => {}) {
  try {
    const c = {
      ...configuration,
      entryPoints: { ...configuration.entryPoints },
    };
    check();
    validateConfig(c);
    if (
      !supplied ||
      Object.keys(supplied).sort().join(",") !==
        "attemptId,binding,databaseIdentity,profileIdentity,schemaVersion,state,targetIdentity,validation" ||
      supplied.schemaVersion !== 1 ||
      supplied.state !== "restore-prepared" ||
      typeof supplied.attemptId !== "string" ||
      !CHECKPOINT_ID.test(supplied.attemptId) ||
      ![
        supplied.profileIdentity,
        supplied.targetIdentity,
        supplied.databaseIdentity,
      ].every(
        (value) =>
          typeof value === "string" &&
          value.length <= 128 &&
          /^[0-9]+:[0-9]+$/.test(value),
      ) ||
      !isDeepStrictEqual(supplied.validation, {
        postgresMajor: 19,
        vectorVersion: "0.8.7",
        canonical: true,
        executionStateReconstructed: true,
      })
    )
      fail("host_restore_target_invalid");
    const receipt = {
      schemaVersion: 1,
      state: "restore-prepared",
      binding: restoreInputBinding(c, supplied.binding),
      attemptId: supplied.attemptId,
      profileIdentity: supplied.profileIdentity,
      targetIdentity: supplied.targetIdentity,
      databaseIdentity: supplied.databaseIdentity,
      validation: {
        postgresMajor: 19,
        vectorVersion: "0.8.7",
        canonical: true,
        executionStateReconstructed: true,
      },
    };
    const root = join(c.state, "restore-targets"),
      operationRoot = join(root, receipt.binding.operationId);
    const target = join(operationRoot, receipt.attemptId),
      database = join(target, "database");
    const identities = new Map();
    for (const path of [c.state, root, operationRoot, target, database])
      identities.set(path, await checkpointIdentity(path, true));
    if (
      identities.get(c.state) !== receipt.profileIdentity ||
      identities.get(target) !== receipt.targetIdentity ||
      identities.get(database) !== receipt.databaseIdentity
    )
      fail("host_restore_target_invalid");
    const intent = {
      schemaVersion: 1,
      binding: receipt.binding,
      attemptId: receipt.attemptId,
      profileIdentity: receipt.profileIdentity,
      targetIdentity: receipt.targetIdentity,
    };
    const marker = {
      schemaVersion: 1,
      manifestSha256: c.manifestSha256,
      sourceRevision: c.sourceRevision,
      postgresMajor: c.postgresMajor,
    };
    async function verifyRecords() {
      if (
        !isDeepStrictEqual(
          await restoreInputJson(join(target, "restore-target.json")),
          intent,
        ) ||
        !isDeepStrictEqual(
          await restoreInputJson(join(target, "restore-result.json")),
          receipt,
        ) ||
        !isDeepStrictEqual(
          await restoreInputJson(join(target, "host-state.json")),
          marker,
        )
      )
        fail("host_restore_target_invalid");
      try {
        await fs.lstat(join(database, "postmaster.pid"));
        fail("host_restore_target_invalid");
      } catch (error) {
        if (error.code !== "ENOENT") throw error;
      }
      const path = join(database, "PG_VERSION"),
        before = await checkpointHash(path, check, 16),
        raw = await stateFile(path, 16);
      if (
        raw.trim() !== c.postgresMajor ||
        Buffer.byteLength(raw) !== before.bytes ||
        createHash("sha256").update(raw).digest("hex") !== before.sha256 ||
        !isDeepStrictEqual(await checkpointHash(path, () => {}, 16), before)
      )
        fail("host_restore_target_invalid");
    }
    await verifyRecords();
    const input = await readHostRestoreInput(c, receipt.binding, check);
    if (input.recovery.checkpoint.sourceRevision !== c.sourceRevision)
      fail("host_restore_target_invalid");
    for (const [path, identity] of identities)
      if ((await checkpointIdentity(path, true)) !== identity)
        fail("host_restore_target_invalid");
    await verifyRecords();
    for (const [path, identity] of identities)
      if ((await checkpointIdentity(path, true)) !== identity)
        fail("host_restore_target_invalid");
    return { receipt, target, database };
  } catch (error) {
    if (error?.message === "host_restore_cancelled") throw error;
    fail("host_restore_target_invalid");
  }
}
/** Read-only evidence under the controller's exclusive leases; this never activates a database. */
export async function verifyHostRestoreTarget(
  configuration,
  supplied,
  stopping,
) {
  let child,
    cancelled = false,
    spawnFailed = false;
  const deadline = Date.now() + 2 * 60 * 60_000;
  void stopping.then(() => {
    cancelled = true;
  });
  function check() {
    if (cancelled) fail("host_restore_cancelled");
    if (Date.now() > deadline) fail("host_restore_offline_invalid");
  }
  try {
    const c = {
      ...configuration,
      entryPoints: { ...configuration.entryPoints },
    };
    const expected = structuredClone(supplied);
    const checked = await readHostRestoreTarget(c, expected, check);
    check();
    const tool = c.entryPoints.pgChecksums;
    if (
      typeof tool !== "string" ||
      tool.includes("\\") ||
      tool.includes(":") ||
      tool.split("/").some((part) => !part || part === "." || part === "..") ||
      basename(tool) !==
        "pg_checksums" + (process.platform === "win32" ? ".exe" : "")
    )
      fail("host_restore_offline_invalid");
    async function tree() {
      const entries = new Map(),
        pending = [checked.database];
      while (pending.length) {
        check();
        const path = pending.pop(),
          meta = await fs.lstat(path, { bigint: true });
        const directory = meta.isDirectory(),
          identity = await checkpointIdentity(path, directory);
        if (identity !== meta.dev + ":" + meta.ino || entries.size >= 100_000)
          fail("host_restore_offline_invalid");
        entries.set(path, {
          identity,
          directory,
          size: meta.size,
          modified: meta.mtimeNs,
        });
        if (directory) {
          const handle = await fs.opendir(path);
          for await (const entry of handle) {
            check();
            if (entries.size + pending.length >= 100_000)
              fail("host_restore_offline_invalid");
            pending.push(join(path, entry.name));
          }
          if ((await checkpointIdentity(path, true)) !== identity)
            fail("host_restore_offline_invalid");
        }
      }
      return entries;
    }
    const before = await tree();
    check();
    child = spawn(
      join(c.runtime, tool),
      ["--check", "--pgdata", checked.database],
      {
        cwd: checked.target,
        env: hostEnvironment(c),
        stdio: "ignore",
        windowsHide: true,
      },
    );
    child.on("error", () => {
      spawnFailed = true;
    });
    while (!(await exited(child, 100))) check();
    check();
    if (spawnFailed || child.exitCode !== 0 || child.signalCode !== null)
      fail("host_restore_offline_invalid");
    if (
      !isDeepStrictEqual(await tree(), before) ||
      !isDeepStrictEqual(await readHostRestoreTarget(c, expected, check), checked)
    )
      fail("host_restore_offline_invalid");
    check();
    return { ...checked, offlineChecksums: true };
  } catch (error) {
    if (error?.message === "host_restore_cancelled") throw error;
    fail("host_restore_offline_invalid");
  } finally {
    if (child && !(await exited(child, 100))) {
      child.kill();
      if (!(await exited(child, 5000))) {
        child.kill("SIGKILL");
        if (!(await exited(child, 5000)))
          fail("host_restore_offline_stop_unconfirmed");
      }
    }
  }
}
