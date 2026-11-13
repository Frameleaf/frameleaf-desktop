import assert from "node:assert/strict";
import { spawn, execFile } from "node:child_process";
import { once } from "node:events";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { setTimeout as sleep } from "node:timers/promises";
import { fileURLToPath } from "node:url";
import { test } from "node:test";
import { promisify } from "node:util";

const guard = fileURLToPath(
  new URL("../runtime/studio-browser-guard.mjs", import.meta.url),
);
const env = () => ({
  ...process.env,
  FRAMELEAF_STUDIO_OWNER_PID: String(process.pid),
  FRAMELEAF_STUDIO_CHROMIUM: process.execPath,
  FRAMELEAF_STUDIO_GUARD_ACTIVE: "",
});
const bounded = (promise) =>
  Promise.race([
    promise,
    sleep(5000, undefined, { ref: false }).then(() => {
      throw new Error("guard test timed out");
    }),
  ]);
const exec = promisify(execFile);
const gone = async (pids) => {
  const deadline = Date.now() + 4500;
  do {
    const states = await Promise.all(
      pids.map(async (pid) => {
        try {
          return (
            await exec("/bin/ps", ["-p", String(pid), "-o", "stat="])
          ).stdout.trim();
        } catch (error) {
          if (error.code === 1) return "";
          throw error;
        }
      }),
    );
    // Linux may retain an adopted zombie until init reaps it; it cannot do work.
    if (states.every((state) => !state || state.startsWith("Z"))) return;
    await sleep(20);
  } while (Date.now() < deadline);
  assert.fail("browser group still running");
};
// Kills a detached group this test owns, after the test body or its failure. Once every member has
// exited, the group lingers until the system reaps them; macOS answers EPERM for such a group, where
// Linux answers ESRCH. Which one the test met depended on timing, so EPERM is accepted only when ps
// confirms that nothing in the group is still running.
const killGroup = async (group) => {
  try {
    process.kill(-group, "SIGKILL");
  } catch (error) {
    if (error.code === "ESRCH") return;
    if (error.code !== "EPERM") throw error;
    const { stdout } = await exec("/bin/ps", ["-axo", "pgid=,stat="]);
    const running = stdout
      .trim()
      .split("\n")
      .map((row) => row.trim().split(/\s+/))
      .filter(([pgid, state]) => Number(pgid) === group && !state.startsWith("Z"));
    assert.deepEqual(running, [], "browser group could not be stopped");
  }
};

test(
  "guard refuses shared groups, orphan startup and recursive launch",
  { skip: process.platform === "win32" },
  async () => {
    for (const options of [
      { detached: false, env: env() },
      { detached: true, env: { ...env(), FRAMELEAF_STUDIO_OWNER_PID: "1" } },
      { detached: true, env: { ...env(), FRAMELEAF_STUDIO_GUARD_ACTIVE: "1" } },
      {
        detached: true,
        env: { ...env(), FRAMELEAF_STUDIO_CHROMIUM: "relative" },
      },
    ]) {
      const child = spawn(process.execPath, [guard], {
        ...options,
        stdio: "ignore",
      });
      try {
        assert.deepEqual(await bounded(once(child, "exit")), [1, null]);
      } finally {
        child.kill("SIGKILL");
      }
    }
  },
);

test(
  "guardian forwards CDP pipes and watchdog kills the browser after guardian loss",
  { skip: process.platform === "win32" },
  async () => {
    const root = await mkdtemp(join(tmpdir(), "frameleaf-browser-guard-"));
    const record = join(root, "browser.json");
    const script = `
    const fs = require('node:fs');
    const { spawn } = require('node:child_process');
    const net = require('node:net');
    const child = spawn(process.execPath, ['-e', 'setInterval(() => {}, 1000)'], { stdio: 'ignore' });
    fs.writeFileSync(${JSON.stringify(record)}, JSON.stringify({ browser: process.pid, guardian: process.ppid, child: child.pid }));
    const input = new net.Socket({ fd: 3, readable: true, writable: false });
    input.on('data', data => fs.writeSync(4, data));
    setInterval(() => {}, 1000);
  `;
    const child = spawn(process.execPath, [guard, "-e", script], {
      detached: true,
      env: env(),
      stdio: ["ignore", "ignore", "ignore", "pipe", "pipe"],
    });
    const exited = once(child, "exit");
    let pids;
    try {
      await bounded(
        (async () => {
          const deadline = Date.now() + 4500;
          do {
            try {
              pids = JSON.parse(await readFile(record, "utf8"));
              break;
            } catch (error) {
              if (error.code !== "ENOENT" && !(error instanceof SyntaxError))
                throw error;
            }
            await sleep(20);
          } while (Date.now() < deadline);
          assert.ok(pids, "browser did not launch");
        })(),
      );
      assert.equal(pids.guardian, child.pid);
      const reply = once(child.stdio[4], "data");
      const ended = once(child.stdio[4], "end");
      child.stdio[3].write("cdp-test");
      assert.equal((await bounded(reply))[0].toString(), "cdp-test");
      child.kill("SIGKILL");
      await bounded(exited);
      // Pipe EOF proves the surviving watchdog closed the actual browser's inherited CDP fd.
      await bounded(ended);
      await gone([pids.browser, pids.child]);
    } finally {
      // The test always owns this detached group, including on assertion failure.
      await killGroup(child.pid);
      child.stdio[3].destroy();
      child.stdio[4].destroy();
      await bounded(exited);
      await rm(root, { recursive: true, force: true });
    }
  },
);

test(
  "guardian stops its browser when the worker parent is killed",
  { skip: process.platform === "win32" },
  async () => {
    const root = await mkdtemp(join(tmpdir(), "frameleaf-browser-owner-"));
    const record = join(root, "browser.json");
    const browserScript = `
    require('node:fs').writeFileSync(${JSON.stringify(record)}, JSON.stringify({ browser: process.pid, guardian: process.ppid }));
    setInterval(() => {}, 1000);
  `;
    const ownerScript = `
    const { spawn } = require('node:child_process');
    const child = spawn(process.execPath, [${JSON.stringify(guard)}, '-e', ${JSON.stringify(browserScript)}], {
      detached: true,
      env: { ...process.env, FRAMELEAF_STUDIO_OWNER_PID: String(process.pid) },
      stdio: ['ignore', 'ignore', 'ignore', 'pipe', 'pipe'],
    });
    child.on('error', () => process.exit(1));
    process.send({ guardian: child.pid });
    setInterval(() => {}, 1000);
  `;
    const owner = spawn(process.execPath, ["-e", ownerScript], {
      env: env(),
      stdio: ["ignore", "ignore", "ignore", "ipc"],
    });
    const exited = once(owner, "exit");
    let group, pids;
    try {
      [{ guardian: group }] = await bounded(once(owner, "message"));
      const deadline = Date.now() + 4500;
      do {
        try {
          pids = JSON.parse(await readFile(record, "utf8"));
          break;
        } catch (error) {
          if (error.code !== "ENOENT" && !(error instanceof SyntaxError))
            throw error;
        }
        await sleep(20);
      } while (Date.now() < deadline);
      assert.equal(pids?.guardian, group);
      assert.ok(pids?.browser);
      owner.kill("SIGKILL");
      await bounded(exited);
      await gone([pids.guardian, pids.browser]);
    } finally {
      owner.kill("SIGKILL");
      if (group) await killGroup(group);
      await bounded(exited);
      await rm(root, { recursive: true, force: true });
    }
  },
);

for (const disposition of ["normal browser exit", "watchdog death"]) {
  test(
    `guardian cleans the group after ${disposition}`,
    { skip: process.platform === "win32" },
    async () => {
      const root = await mkdtemp(join(tmpdir(), "frameleaf-browser-exit-"));
      const record = join(root, "browser.json");
      const script = `
      const { spawn } = require('node:child_process');
      const fs = require('node:fs');
      const child = spawn(process.execPath, ['-e', 'setInterval(() => {}, 1000)'], { stdio: 'ignore' });
      fs.writeFileSync(${JSON.stringify(record)}, JSON.stringify({ browser: process.pid, child: child.pid }));
      const input = new (require('node:net').Socket)({ fd: 3, readable: true, writable: false });
      input.once('data', () => process.exit(0));
      setInterval(() => {}, 1000);
    `;
      const child = spawn(process.execPath, [guard, "-e", script], {
        detached: true,
        env: env(),
        stdio: ["ignore", "ignore", "ignore", "pipe", "pipe"],
      });
      const exited = once(child, "exit");
      let pids;
      try {
        const deadline = Date.now() + 4500;
        do {
          try {
            pids = JSON.parse(await readFile(record, "utf8"));
            break;
          } catch (error) {
            if (error.code !== "ENOENT" && !(error instanceof SyntaxError))
              throw error;
          }
          await sleep(20);
        } while (Date.now() < deadline);
        assert.ok(
          pids?.browser && pids?.child,
          "browser fixture did not launch",
        );
        if (disposition === "normal browser exit") {
          child.stdio[3].write("close");
          assert.deepEqual(await bounded(exited), [0, null]);
        } else {
          // Only numeric process relationships are inspected; never collect command lines.
          const { stdout } = await exec("/bin/ps", ["-axo", "pid=,ppid="]);
          const watchdogs = stdout
            .trim()
            .split("\n")
            .map((row) => row.trim().split(/\s+/).map(Number))
            .filter(
              ([pid, parent]) => parent === child.pid && pid !== pids.browser,
            );
          assert.equal(watchdogs.length, 1);
          const watchdog = watchdogs[0][0];
          assert.ok(Number.isSafeInteger(watchdog) && watchdog > 1);
          process.kill(watchdog, "SIGKILL");
          assert.deepEqual(await bounded(exited), [null, "SIGKILL"]);
          await gone([watchdog]);
        }
        await gone([pids.browser, pids.child]);
      } finally {
        await killGroup(child.pid);
        child.stdio[3].destroy();
        child.stdio[4].destroy();
        await bounded(exited);
        await rm(root, { recursive: true, force: true });
      }
    },
  );
}
