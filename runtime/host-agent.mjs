// The desktop opens the start gate only after installing OS process-tree ownership.
import { spawn } from "node:child_process";
import { constants } from "node:fs";
import * as fs from "node:fs/promises";
import { createServer } from "node:net";
import { delimiter, isAbsolute, join, dirname, basename } from "node:path";
import { createInterface } from "node:readline";

const fail = (code) => {
  throw new Error(code);
};
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
    "hdr",
    "ffmpeg",
    "ffprobe",
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
    dirname(c.entryPoints.ffmpeg) !== dirname(c.entryPoints.ffprobe)
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
      (name) => !["lease.lock", "agent.log"].includes(name),
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
    FFMPEG_PATH: join(c.runtime, c.entryPoints.ffmpeg),
    FFPROBE_PATH: join(c.runtime, c.entryPoints.ffprobe),
    PATH: [
      dirname(join(c.runtime, c.entryPoints.ffmpeg)),
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
  for (const name of ["home", "media"]) {
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
  let pg, app;
  const children = new Set();
  let cancelled = false;
  stopping.then(() => {
    cancelled = true;
  });
  function launch(args, extra = {}) {
    const child = spawn(args[0], args.slice(1), {
      cwd: c.state,
      env: { ...env, ...extra },
      stdio: ["ignore", "pipe", "pipe"],
      windowsHide: true,
    });
    children.add(child);
    child.on("error", () => {});
    child.stdout.on("data", (chunk) => {
      void log.write(chunk).catch(() => {});
    });
    child.stderr.on("data", (chunk) => {
      void log.write(chunk).catch(() => {});
    });
    return child;
  }
  async function command(args, extra = {}, duringStop = false) {
    const child = launch(args, extra);
    let output = "",
      oversized = false;
    child.stdout.on("data", (chunk) => {
      if (Buffer.byteLength(output) + chunk.length > 65536) {
        oversized = true;
        child.kill();
      } else output += chunk.toString();
    });
    const deadline = Date.now() + 30_000;
    while (!(await exited(child, 100))) {
      if ((cancelled && !duringStop) || Date.now() > deadline) {
        child.kill();
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
    app = launch([executable("node"), executable("server")], {
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
      FRAMELEAF_STUDIO_WORKER: "false",
    });
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
      if (api && microservices) {
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
    ready();
    while (!cancelled) {
      if ((await exited(app, 100)) || (await exited(pg, 100)))
        fail("host_process_exited");
    }
  } finally {
    if (app && !(await exited(app, 0))) {
      // shortcut: Windows SIGTERM is forceful; require a tested native drain channel before Windows host release.
      app.kill("SIGTERM");
      if (!(await exited(app, 40_000))) app.kill("SIGKILL");
      await exited(app, 5000);
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
  void (async () => {
    for await (const line of { [Symbol.asyncIterator]: () => lines }) {
      if (line === "stop") {
        stop();
        break;
      }
    }
    stop();
  })();
  try {
    await runHost(JSON.parse(first.value), stopping, () =>
      process.stdout.write('{"state":"running"}\n'),
    );
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
