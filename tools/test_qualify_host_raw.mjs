import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";

test("RAW qualifier rejects failed components and server bindings before native execution", async () => {
  const root = await mkdtemp(join(tmpdir(), "frameleaf-raw-preflight-"));
  try {
    const runtime = join(root, "runtime"), component = join(root, "component");
    await mkdir(runtime);
    await mkdir(component);
    const script = new URL("./qualify_host_raw.mjs", import.meta.url);
    // Only reach the receipt guard here; genuine engine qualification uses pinned Node 26.
    const loader = `Object.defineProperty(process, "version", {value: "v26.11.1"}); process.argv.splice(1, 0, ${JSON.stringify(fileURLToPath(script))}); await import(${JSON.stringify(script.href)});`;
    for (const failed of ["runtime", "component"]) {
      for (const [name, folder] of [["component", component], ["runtime", runtime]]) {
        await writeFile(join(folder, "qualification.json"), JSON.stringify({
          qualification: name === failed ? "failed" : "passed",
          sourceRevision: "a".repeat(40), files: {},
        }));
      }
      const result = spawnSync(process.execPath, ["--input-type=module", "-e", loader, runtime, component], {
        encoding: "utf8", timeout: 10000,
      });
      assert.notEqual(result.status, 0);
      assert.match(result.stderr, failed === "component" ? /RAW component is not qualified/ : /Server binding is not qualified/);
    }
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
