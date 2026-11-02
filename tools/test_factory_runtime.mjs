import { spawnSync } from "node:child_process";
import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash, generateKeyPairSync } from "node:crypto";
import {
  mkdtemp,
  mkdir,
  readFile,
  realpath,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  factorySourceRevision,
  signFactoryRuntime,
} from "./factory_runtime.mjs";

async function fixture(t, changes = {}) {
  const root = await mkdtemp(
    join(await realpath(tmpdir()), "frameleaf-factory-"),
  );
  t.after(() => rm(root, { recursive: true, force: true }));
  await mkdir(join(root, "payload"));
  const platform = { darwin: "macos", win32: "windows", linux: "linux" }[
    process.platform
  ];
  const architecture = { arm64: "aarch64", x64: "x86_64" }[process.arch];
  const manifest = {
    schemaVersion: 1,
    protocolVersion: 1,
    epoch: 2,
    platform,
    architecture,
    provider: "CPUExecutionProvider",
    python: "python",
    sourceRevision: factorySourceRevision,
    ...changes,
  };
  const files = {
    python: Buffer.from("fixture"),
    "provenance.json": Buffer.from(
      JSON.stringify({
        schemaVersion: 1,
        sourceRepository: "Frameleaf/frameleaf-app",
        sourceRevision: manifest.sourceRevision,
        profile: "cpu-ort",
        python: "3.12.13",
      }),
    ),
  };
  manifest.files = {};
  for (const [name, bytes] of Object.entries(files)) {
    await writeFile(join(root, "payload", name), bytes);
    manifest.files[name] = {
      bytes: bytes.length,
      sha256: createHash("sha256").update(bytes).digest("hex"),
    };
  }
  await writeFile(join(root, "manifest.json"), JSON.stringify(manifest));
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const policy = {
    schemaVersion: 1,
    minimumRuntimeEpoch: 2,
    keys: [
      {
        id: "fixture",
        publicKeyHex: publicKey
          .export({ format: "der", type: "spki" })
          .subarray(-32)
          .toString("hex"),
      },
    ],
  };
  return {
    root,
    target: `${platform}-${architecture}`,
    policy,
    privatePem: privateKey.export({ format: "pem", type: "pkcs8" }),
  };
}

test("factory archives use an approved source and a signature accepted by packaging", async (t) => {
  assert.match(factorySourceRevision, /^[a-f0-9]{40}$/);
  const f = await fixture(t);
  const receipt = await signFactoryRuntime(
    f.root,
    f.target,
    2,
    f.privatePem,
    f.policy,
  );
  assert.equal(receipt.sourceRevision, factorySourceRevision);
  assert.equal((await readFile(join(f.root, "manifest.sig"))).length, 64);
});

for (const [label, changes, target] of [
  ["unapproved source", { sourceRevision: "a".repeat(40) }],
  ["wrong epoch", { epoch: 3 }],
  ["wrong provider", { provider: "CoreMLExecutionProvider" }],
  ["wrong target", {}, "windows-aarch64"],
  ["candidate target mismatch", { architecture: "unsupported" }],
]) {
  test(`factory signing refuses ${label} before creating a signature`, async (t) => {
    const f = await fixture(t, changes);
    await assert.rejects(
      signFactoryRuntime(f.root, target ?? f.target, 2, f.privatePem, f.policy),
      /runtime_factory_candidate_unapproved/,
    );
    await assert.rejects(readFile(join(f.root, "manifest.sig")), {
      code: "ENOENT",
    });
  });
}

test("factory signing retains the existing payload-integrity refusal", async (t) => {
  const f = await fixture(t);
  await writeFile(join(f.root, "payload", "python"), "tampered");
  await assert.rejects(
    signFactoryRuntime(f.root, f.target, 2, f.privatePem, f.policy),
    /runtime_/,
  );
  await assert.rejects(readFile(join(f.root, "manifest.sig")), {
    code: "ENOENT",
  });
});

test("factory CLI never prints private-key parser input", async (t) => {
  const f = await fixture(t);
  const secret = "private-fixture-value-never-in-logs";
  const result = spawnSync(
    process.execPath,
    ["tools/factory_runtime.mjs", f.root, f.target, "2"],
    {
      input: `-----BEGIN PRIVATE KEY-----\n${secret}\n-----END PRIVATE KEY-----\n`,
      encoding: "utf8",
      timeout: 10000,
    },
  );
  assert.equal(result.status, 1);
  assert.equal(result.stdout, "");
  assert.equal(result.stderr.trim(), "runtime_factory_signing_failed");
  assert(!result.stderr.includes(secret));
  await assert.rejects(readFile(join(f.root, "manifest.sig")), {
    code: "ENOENT",
  });
});
