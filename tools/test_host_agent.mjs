import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  claimState,
  validateConfig,
  hostEnvironment,
} from "../runtime/host-agent.mjs";

const config = (state) => ({
  state,
  runtime: "/signed/runtime",
  manifestSha256: "a".repeat(64),
  sourceRevision: "b".repeat(40),
  postgresMajor: "19",
  password: "synthetic-fixture-password-123456",
  databasePort: 54329,
  apiPort: 2283,
  entryPoints: {
    node: "node",
    server: "server/main.js",
    postgres: "pg/postgres",
    initdb: "pg/initdb",
    createdb: "pg/createdb",
    psql: "pg/psql",
    pgIsready: "pg/pg_isready",
    pgCtl: "pg/pg_ctl",
    hdr: "media/hdr",
    rawRenderer:
      "raw/bin/darktable-cli" + (process.platform === "win32" ? ".exe" : ""),
    rawDecoder:
      "raw/bin/dcraw_emu" + (process.platform === "win32" ? ".exe" : ""),
    ffmpeg: "media/ffmpeg" + (process.platform === "win32" ? ".exe" : ""),
    ffprobe: "media/ffprobe" + (process.platform === "win32" ? ".exe" : ""),
  },
});
test("host configuration rejects shared ports, unbounded secrets and relative paths", () => {
  const good = config("/private/state");
  assert.doesNotThrow(() => validateConfig(good));
  for (const change of [
    { entryPoints: { ...good.entryPoints, rawRenderer: undefined } },
    { entryPoints: { ...good.entryPoints, rawDecoder: undefined } },
    { entryPoints: { ...good.entryPoints, rawDecoder: "../dcraw_emu" } },
    { entryPoints: { ...good.entryPoints, rawRenderer: "raw/bin/unrelated" } },
    { entryPoints: { ...good.entryPoints, rawDecoder: "other/dcraw_emu" } },
    { apiPort: 54329 },
    { databasePort: 0 },
    { password: "" },
    { state: "relative" },
    { runtime: "relative" },
    { postgresMajor: "16" },
    { manifestSha256: "bad" },
    { entryPoints: { ...good.entryPoints, postgres: "../postgres" } },
    { entryPoints: { ...good.entryPoints, ffmpeg: "../ffmpeg" } },
    { entryPoints: { ...good.entryPoints, ffprobe: "/usr/bin/ffprobe" } },
    { entryPoints: { ...good.entryPoints, ffmpeg: undefined } },
    {
      entryPoints: {
        ...good.entryPoints,
        ffprobe: good.entryPoints.ffprobe.replace("media/", "other/"),
      },
    },
    { entryPoints: { ...good.entryPoints, ffmpeg: "media/unrelated" } },
  ]) {
    assert.throws(() => validateConfig({ ...good, ...change }));
  }
});
test("host media commands use private binaries without inheriting the caller environment", () => {
  const cfg = config("/private/state");
  const env = hostEnvironment(cfg);
  assert.equal(
    env.FRAMELEAF_RAW_DECODER_PATH,
    join(cfg.runtime, cfg.entryPoints.rawDecoder),
  );
  assert.equal(env.FFMPEG_PATH, join(cfg.runtime, cfg.entryPoints.ffmpeg));
  assert.equal(env.FFPROBE_PATH, join(cfg.runtime, cfg.entryPoints.ffprobe));
  assert.ok(
    env.PATH.split(process.platform === "win32" ? ";" : ":").includes(
      join(cfg.runtime, "raw/bin"),
    ),
  );
  assert.equal(env.HOME, join(cfg.state, "home"));
  for (const name of [
    "DB_PASSWORD",
    "PGPASSWORD",
    "DYLD_LIBRARY_PATH",
    "LD_LIBRARY_PATH",
  ])
    assert.equal(Object.hasOwn(env, name), false);
  const delimiter = process.platform === "win32" ? ";" : ":";
  assert.ok(env.PATH.split(delimiter).includes(join(cfg.runtime, "media")));
  assert.equal(env.PATH.split(delimiter)[0], join(cfg.runtime, "media"));
});
test("host state binds one runtime before initialization and refuses adoption or changed authority", async () => {
  const root = await mkdtemp(join(tmpdir(), "frameleaf-host-agent-"));
  try {
    const cfg = config(root);
    assert.equal(await claimState(cfg), true);
    assert.equal(await claimState(cfg), false);
    await assert.rejects(
      claimState({ ...cfg, manifestSha256: "c".repeat(64) }),
      /host_update_requires_manager/,
    );
    await assert.rejects(
      claimState({ ...cfg, sourceRevision: "d".repeat(40) }),
      /host_update_requires_manager/,
    );
    const state = JSON.parse(
      await readFile(join(root, "host-state.json"), "utf8"),
    );
    assert.equal(state.manifestSha256, cfg.manifestSha256);
    assert.ok(!JSON.stringify(state).includes(cfg.password));
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
test("host state never adopts existing unowned data or rewrites corrupt metadata", async () => {
  const root = await mkdtemp(join(tmpdir(), "frameleaf-host-agent-"));
  try {
    await writeFile(join(root, "user-file"), "keep");
    await assert.rejects(claimState(config(root)), /host_state_not_empty/);
    assert.equal(await readFile(join(root, "user-file"), "utf8"), "keep");
    await rm(join(root, "user-file"));
    await writeFile(join(root, "host-state.json"), "broken");
    await assert.rejects(claimState(config(root)), /host_state_invalid/);
    assert.equal(
      await readFile(join(root, "host-state.json"), "utf8"),
      "broken",
    );
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("a refused agent exits even while its owner still holds the input pipe", async () => {
  const { spawn } = await import("node:child_process");
  const { once } = await import("node:events");
  const { fileURLToPath } = await import("node:url");
  const child = spawn(
    process.execPath,
    [fileURLToPath(new URL("../runtime/host-agent.mjs", import.meta.url))],
    {
      env: { ...process.env, FRAMELEAF_HOST_AGENT: "1" },
      stdio: ["pipe", "ignore", "ignore"],
    },
  );
  try {
    child.stdin.write("{}\n");
    const [code] = await once(child, "exit", {
      signal: AbortSignal.timeout(3000),
    });
    assert.equal(code, 1);
  } finally {
    child.stdin.destroy();
    child.kill();
  }
});

test("port conflict refuses hosting before creating state", async () => {
  const { createServer } = await import("node:net");
  const { readdir } = await import("node:fs/promises");
  const { runHost } = await import("../runtime/host-agent.mjs");
  const root = await mkdtemp(join(tmpdir(), "frameleaf-host-conflict-"));
  const occupied = createServer();
  await new Promise((resolve) => occupied.listen(0, "127.0.0.1", resolve));
  try {
    const cfg = { ...config(root), apiPort: occupied.address().port };
    if (cfg.databasePort === cfg.apiPort) cfg.databasePort++;
    await assert.rejects(
      runHost(cfg, new Promise(() => {}), () => assert.fail()),
      /EADDRINUSE/,
    );
    assert.deepEqual(await readdir(root), []);
  } finally {
    await new Promise((resolve) => occupied.close(resolve));
    await rm(root, { recursive: true, force: true });
  }
});

test(
  "an owned state marker cannot authorize a substituted database directory",
  { skip: process.platform === "win32" },
  async () => {
    const { createServer } = await import("node:net");
    const { mkdir, symlink } = await import("node:fs/promises");
    const { runHost } = await import("../runtime/host-agent.mjs");
    const root = await mkdtemp(join(tmpdir(), "frameleaf-host-linked-"));
    const state = join(root, "state");
    const outside = join(root, "outside");
    await mkdir(state, { mode: 0o700 });
    await mkdir(outside, { mode: 0o700 });
    await writeFile(join(outside, "PG_VERSION"), "19");
    const probes = [createServer(), createServer()];
    for (const probe of probes)
      await new Promise((resolve) => probe.listen(0, "127.0.0.1", resolve));
    const ports = probes.map((probe) => probe.address().port);
    for (const probe of probes)
      await new Promise((resolve) => probe.close(resolve));
    const cfg = { ...config(state), apiPort: ports[0], databasePort: ports[1] };
    try {
      await claimState(cfg);
      await symlink(outside, join(state, "database"), "dir");
      await assert.rejects(
        runHost(cfg, new Promise(() => {}), () => assert.fail()),
        /host_database_directory_invalid/,
      );
      assert.equal(await readFile(join(outside, "PG_VERSION"), "utf8"), "19");
      await rm(join(state, "database"));
      await mkdir(join(state, "database"), { mode: 0o700 });
      await writeFile(join(state, "database/PG_VERSION"), "16");
      await writeFile(join(state, "database-password.tmp"), cfg.password, {
        mode: 0o600,
      });
      await assert.rejects(
        runHost(cfg, new Promise(() => {}), () => assert.fail()),
        /host_database_major_mismatch/,
      );
      await assert.rejects(readFile(join(state, "database-password.tmp")), {
        code: "ENOENT",
      });
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  },
);
