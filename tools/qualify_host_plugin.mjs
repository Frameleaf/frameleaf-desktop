// Authoring fixture: execute the staged WASM through the packaged server's actual Extism runtime.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { isAbsolute, join } from "node:path";
import { pathToFileURL } from "node:url";

const [runtime, packageRoot] = process.argv.slice(2);
assert.equal(
  process.argv.length,
  4,
  "Usage: private-node tools/qualify_host_plugin.mjs /runtime /plugin-build-output",
);
assert.ok(isAbsolute(runtime) && isAbsolute(packageRoot));
assert.equal(process.version, "v26.11.1");
const receipt = JSON.parse(
  await readFile(join(packageRoot, "qualification.json"), "utf8"),
);
assert.equal(receipt.qualification, "passed");
const bytes = await readFile(join(packageRoot, "plugin/dist/plugin.wasm"));
const wasmSha256 = createHash("sha256").update(bytes).digest("hex");
assert.equal(wasmSha256, receipt.files["dist/plugin.wasm"].sha256);
const { newPlugin } = await import(
  pathToFileURL(
    join(runtime, "server/node_modules/@extism/extism/dist/esm/mod.js"),
  )
);
const modes = [];
for (const runInWorker of [false, true]) {
  const calls = [];
  const unexpected = (_context, _pointer) =>
    assert.fail("unexpected host callback");
  const plugin = await newPlugin(
    { wasm: [{ data: bytes }] },
    {
      useWasi: true,
      allowedPaths: {},
      runInWorker,
      functions: {
        "extism:host/user": {
          searchAlbums: unexpected,
          createAlbum: unexpected,
          addAssetsToAlbum: unexpected,
          addAssetsToAlbums: unexpected,
          httpRequest: unexpected,
          bulkTagAssets(context, pointer) {
            calls.push(context.read(pointer).json());
            return context.store(
              JSON.stringify({ success: true, response: [] }),
            );
          },
        },
      },
    },
  );
  try {
    const call = async (method, config, asset) => {
      const result = await plugin.call(
        method,
        JSON.stringify({
          workflow: { authToken: "synthetic-native-plugin-fixture" },
          config,
          data: { asset },
        }),
      );
      return result.json();
    };
    assert.deepEqual(
      await call(
        "assetFileFilter",
        { pattern: "leaf", matchType: "contains" },
        { originalFileName: "Frameleaf.jpg" },
      ),
      { workflow: { continue: true } },
    );
    assert.deepEqual(
      await call(
        "assetFileFilter",
        { pattern: "leaf", matchType: "exact" },
        { originalFileName: "Frameleaf.jpg" },
      ),
      { workflow: { continue: false } },
    );
    assert.deepEqual(await call("assetFavorite", {}, { isFavorite: false }), {
      changes: { asset: { isFavorite: true } },
    });
    assert.deepEqual(await call("assetFavorite", {}, { isFavorite: true }), {});
    assert.deepEqual(
      await call(
        "assetAddTags",
        { tags: ["synthetic-tag"] },
        { id: "synthetic-asset" },
      ),
      {},
    );
    assert.deepEqual(calls, [
      {
        authToken: "synthetic-native-plugin-fixture",
        args: [{ assetIds: ["synthetic-asset"], tagIds: ["synthetic-tag"] }],
      },
    ]);
    modes.push({ runInWorker, calls: 5, hostCallbackVerified: true });
  } finally {
    await plugin.close();
  }
}
console.log(
  JSON.stringify({
    qualification: "passed",
    sourceRevision: receipt.sourceRevision,
    wasmSha256,
    modes,
    scope: "synthetic core WASM calls and host callback only",
    redistributable: false,
  }),
);
