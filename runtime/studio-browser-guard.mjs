// Playwright detaches its executable; keep a watchdog inside that private group.
import { spawn } from "node:child_process";
import { constants, lstatSync, accessSync } from "node:fs";
import { isAbsolute } from "node:path";
import { fileURLToPath } from "node:url";

const self = fileURLToPath(import.meta.url);
const stopGroup = (group) => {
  try {
    process.kill(-group, "SIGKILL");
  } finally {
    process.exit(1);
  }
};
const pid = (value) =>
  /^[1-9][0-9]*$/.test(value ?? "") &&
  Number.isSafeInteger(Number(value)) &&
  Number(value) > 1;
let ownedGroup;

try {
  if (process.platform === "win32") throw new Error();
  if (process.argv[2] === "--watch-group") {
    const group = Number(process.argv[3]);
    if (
      process.argv.length !== 4 ||
      !pid(process.argv[3]) ||
      process.ppid !== group ||
      !process.connected
    ) {
      throw new Error();
    }
    ownedGroup = group;
    process.once("disconnect", () => stopGroup(group));
    process.once("uncaughtException", () => stopGroup(group));
    process.once("unhandledRejection", () => stopGroup(group));
    process.channel.ref();
    process.send("ready", (error) => {
      if (error) stopGroup(group);
    });
  } else {
    const owner = Number(process.env.FRAMELEAF_STUDIO_OWNER_PID);
    const browser = process.env.FRAMELEAF_STUDIO_CHROMIUM;
    if (
      !pid(process.env.FRAMELEAF_STUDIO_OWNER_PID) ||
      process.ppid !== owner ||
      process.env.FRAMELEAF_STUDIO_GUARD_ACTIVE ||
      !isAbsolute(browser ?? "") ||
      !lstatSync(browser).isFile() ||
      browser === process.env.FRAMELEAF_STUDIO_BROWSER_GUARD
    ) {
      throw new Error();
    }
    accessSync(browser, constants.X_OK);
    // Refuse a non-detached invocation before installing any group-wide signal.
    process.kill(-process.pid, 0);
    ownedGroup = process.pid;
    const stop = () => stopGroup(process.pid);
    process.once("uncaughtException", stop);
    process.once("unhandledRejection", stop);
    process.once("SIGTERM", stop);
    process.once("SIGINT", stop);
    const checkOwner = () => {
      if (process.ppid !== owner) stop();
    };
    setInterval(checkOwner, 100);
    const watchdog = spawn(
      process.execPath,
      [self, "--watch-group", String(process.pid)],
      {
        detached: false,
        stdio: ["ignore", "ignore", "ignore", "ipc"],
      },
    );
    watchdog.once("exit", stop);
    watchdog.once("error", stop);
    const deadline = setTimeout(stop, 5000);
    watchdog.once("message", (message) => {
      if (message !== "ready") return stop();
      clearTimeout(deadline);
      checkOwner();
      const child = spawn(browser, process.argv.slice(2), {
        detached: false,
        env: { ...process.env, FRAMELEAF_STUDIO_GUARD_ACTIVE: "1" },
        // Forward Playwright's CDP pipes; the watchdog must never inherit them.
        stdio: ["ignore", "inherit", "inherit", 3, 4],
      });
      child.once("error", stop);
      // Closing our IPC on exit lets the watchdog kill any remaining group members.
      child.once("exit", (code) => process.exit(code ?? 1));
    });
  }
} catch {
  process.stderr.write("studio_browser_guard_refused\n");
  if (ownedGroup) stopGroup(ownedGroup);
  process.exitCode = 1;
}
