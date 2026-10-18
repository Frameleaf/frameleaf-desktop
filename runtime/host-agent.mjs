// The desktop opens the start gate only after installing OS process-tree ownership.
import { spawn } from "node:child_process";
import { constants } from "node:fs";
import * as fs from "node:fs/promises";
import { createServer } from "node:net";
import { delimiter, isAbsolute, join, dirname, basename } from "node:path";
import { createInterface } from "node:readline";
import { createHash } from "node:crypto";

const fail = (code) => {
  throw new Error(code);
};
// Enable only after private Chromium, fonts and installed lifecycle qualification.
const STUDIO_ENABLED = false;
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
async function checkpointDirectory(path, create = false) {
  if (create) await fs.mkdir(path, { mode: 0o700 }).catch(error => {
    if (error.code !== "EEXIST") throw error;
  });
  const meta = await fs.lstat(path);
  if (!meta.isDirectory() || meta.isSymbolicLink() ||
    (process.platform !== "win32" && (meta.mode & 0o077) !== 0)) fail("host_checkpoint_not_private");
}
async function checkpointHash(path, check) {
  const named = await fs.lstat(path, { bigint: true });
  if (!named.isFile() || named.isSymbolicLink()) fail("host_checkpoint_changed");
  const file = await fs.open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const before = await file.stat({ bigint: true });
    if (before.dev !== named.dev || before.ino !== named.ino || !before.isFile() || before.nlink !== 1n || before.size <= 0n ||
      before.size > BigInt(Number.MAX_SAFE_INTEGER) ||
      (process.platform !== "win32" && (before.mode & 0o077n) !== 0n)) fail("host_checkpoint_changed");
    const hash = createHash("sha256"); let bytes = 0;
    for await (const chunk of file.createReadStream({ autoClose: false })) {
      check();
      bytes += chunk.length; hash.update(chunk);
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
/** Called only by the live owner, which serializes requests and owns the database process tree. */
export async function createHostCheckpoint(c, operationId, execute, cancelled = () => false) {
  validateConfig(c);
  if (typeof operationId !== "string" || !CHECKPOINT_ID.test(operationId)) fail("host_checkpoint_request_invalid");
  const check = () => { if (cancelled()) fail("host_checkpoint_cancelled"); };
  check();
  await checkpointDirectory(c.state);
  const root = join(c.state, "checkpoints");
  await checkpointDirectory(root, true);
  await checkpointSyncDirectory(c.state);
  const target = join(root, operationId);
  const binding = { schemaVersion: 1, operationId, manifestSha256: c.manifestSha256,
    sourceRevision: c.sourceRevision, postgresMajor: c.postgresMajor, databaseFormat: "frameleaf-canonical" };
  let existing = false;
  try { await fs.lstat(target); existing = true; } catch (error) { if (error.code !== "ENOENT") throw error; }
  if (existing) {
    await checkpointDirectory(target);
    if ((await fs.readdir(target)).sort().join(",") !== "checkpoint.json,database.dump") fail("host_checkpoint_changed");
    const receipt = JSON.parse(await stateFile(join(target, "checkpoint.json"), 4096));
    if (!receipt || Object.keys(receipt).length !== Object.keys(binding).length + 1 ||
      Object.entries(binding).some(([key, value]) => receipt[key] !== value) ||
      !receipt.dump || Object.keys(receipt.dump).sort().join(",") !== "bytes,sha256") fail("host_checkpoint_changed");
    const actual = await checkpointHash(join(target, "database.dump"), check);
    if (actual.bytes !== receipt.dump.bytes || actual.sha256 !== receipt.dump.sha256) fail("host_checkpoint_changed");
    check(); return receipt;
  }
  const staging = join(root, "." + operationId + ".partial");
  // shortcut: crash-abandoned staging is retained; Manager recovery must verify it before cleanup and retry.
  await fs.mkdir(staging, { mode: 0o700 });
  try {
    const dump = join(staging, "database.dump");
    const reserved = await fs.open(dump, "wx", 0o600); await reserved.close();
    await execute([join(c.runtime, c.entryPoints.pgDump), "--host", "127.0.0.1", "--port", String(c.databasePort),
      "--username", "frameleaf", "--no-password", "--format=custom", "--file", dump, "frameleaf"], { PGPASSWORD: c.password });
    check();
    await execute([join(c.runtime, c.entryPoints.pgRestore), "--list", dump], {});
    check();
    const file = await fs.open(dump, constants.O_RDWR | constants.O_NOFOLLOW);
    try { await file.sync(); } finally { await file.close(); }
    const receipt = { ...binding, dump: await checkpointHash(dump, check) };
    const record = await fs.open(join(staging, "checkpoint.json"), "wx", 0o600);
    try { await record.writeFile(JSON.stringify(receipt) + "\n"); await record.sync(); } finally { await record.close(); }
    await checkpointSyncDirectory(staging); check();
    await fs.rename(staging, target);
    await checkpointSyncDirectory(root);
    return receipt;
  } finally {
    // Only paths created by this attempt are removed; an existing staging directory is never adopted.
    for (const name of ["checkpoint.json", "database.dump"]) await fs.unlink(join(staging, name)).catch(error => {
      if (error.code !== "ENOENT") throw error;
    });
    await fs.rmdir(staging).catch(error => { if (error.code !== "ENOENT") throw error; });
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

export async function runHost(c, stopping, ready) {
  validateConfig(c);
  await portFree(c.apiPort);
  await portFree(c.databasePort);
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
  for (const name of ["home", "media", "studio-trust", "studio-work"]) {
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
  const data = join(c.state, "database");
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
    pg = launch([
      executable("postgres"),
      "-D",
      data,
      "-h",
      "127.0.0.1",
      "-p",
      String(c.databasePort),
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
    ready((operationId) => {
      if (checkpointWork || cancelled || app.exitCode !== null || pg.exitCode !== null)
        return Promise.reject(new Error("host_checkpoint_unavailable"));
      const work = createHostCheckpoint(c, operationId,
        (args, extra) => command(args, extra, false, { quiet: true, timeout: 7_200_000 }),
        () => cancelled || app.exitCode !== null || pg.exitCode !== null);
      checkpointWork = work;
      void work.finally(() => { if (checkpointWork === work) checkpointWork = undefined; }).catch(() => {});
      return work;
    });
    while (!cancelled) {
      if ((await exited(app, 100)) || (await exited(pg, 100)))
        fail("host_process_exited");
      appOwner.check();
      studio?.check();
    }
  } finally {
    cancelled = true;
    await checkpointWork?.catch(() => {});
    let stopError;
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
  let checkpoint, pending, protocolFailure;
  void (async () => {
    for await (const line of { [Symbol.asyncIterator]: () => lines }) {
      if (line === "stop") {
        stop();
        break;
      }
      const operationId = checkpointRequest(line);
      if (!checkpoint || pending) fail("host_checkpoint_unavailable");
      pending = checkpoint(operationId)
        .then(receipt => process.stdout.write(JSON.stringify({ state: "checkpoint", ...receipt }) + "\n"))
        .catch(() => process.stdout.write(JSON.stringify({ state: "checkpoint-failed", operationId, code: "host_checkpoint_failed" }) + "\n"))
        .finally(() => { pending = undefined; });
    }
    stop();
  })().catch(() => { protocolFailure = "host_control_command_invalid"; stop(); });
  try {
    await runHost(JSON.parse(first.value), stopping, (handler) => {
      checkpoint = handler;
      process.stdout.write('{"state":"running"}\n');
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
