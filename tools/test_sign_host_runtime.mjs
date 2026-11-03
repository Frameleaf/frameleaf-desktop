import assert from "node:assert/strict";
import { test } from "node:test";
import { createHash, generateKeyPairSync } from "node:crypto";
import {
  mkdtemp,
  mkdir,
  writeFile,
  readFile,
  realpath,
  rm,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { signCandidate } from "./sign_runtime.mjs";
import {
  signHostCandidate,
  verifySignedHostCandidate,
  HOST_ROLES,
  HOST_REQUIRED,
} from "./sign_host_runtime.mjs";

async function fixture(t) {
  const root = await mkdtemp(join(await realpath(tmpdir()), "host-sign-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const keys = generateKeyPairSync("ed25519");
  const policy = {
    schemaVersion: 1,
    minimumRuntimeEpoch: 2,
    keys: [
      {
        id: "fixture",
        publicKeyHex: keys.publicKey
          .export({ format: "der", type: "spki" })
          .subarray(-32)
          .toString("hex"),
      },
    ],
  };
  const pem = keys.privateKey.export({ format: "pem", type: "pkcs8" });
  const ml = join(root, "payload/ml");
  await mkdir(join(ml, "payload"), { recursive: true });
  const artifact = (bytes) => ({
    bytes: bytes.length,
    sha256: createHash("sha256").update(bytes).digest("hex"),
  });
  const provenance = Buffer.from(
    JSON.stringify({
      schemaVersion: 1,
      sourceRepository: "Frameleaf/frameleaf-app",
      sourceRevision: "a".repeat(40),
      profile: "cpu-ort",
      python: "3.12.13",
    }),
  );
  await writeFile(join(ml, "payload/python"), "fixture");
  await writeFile(join(ml, "payload/provenance.json"), provenance);
  const target = {
    platform:
      process.platform === "darwin"
        ? "macos"
        : process.platform === "win32"
          ? "windows"
          : "linux",
    architecture: process.arch === "arm64" ? "aarch64" : "x86_64",
  };
  await writeFile(
    join(ml, "manifest.json"),
    JSON.stringify({
      schemaVersion: 1,
      protocolVersion: 1,
      epoch: 2,
      ...target,
      provider: "CPUExecutionProvider",
      python: "python",
      sourceRevision: "a".repeat(40),
      files: {
        python: artifact(Buffer.from("fixture")),
        "provenance.json": artifact(provenance),
      },
    }),
  );
  await signCandidate(ml, join(ml, "manifest.sig"), pem, policy);
  const entries = Object.fromEntries(
    HOST_ROLES.map((role) => [
      role,
      role === "mlManifest" ? "ml/manifest.json" : "components/" + role,
    ]),
  );
  const files = {};
  for (const name of new Set([...Object.values(entries), ...HOST_REQUIRED])) {
    if (name === "ml/manifest.json" || name === "ml/manifest.sig") continue;
    const path = join(root, "payload", name);
    await mkdir(join(path, ".."), { recursive: true });
    await writeFile(path, "fixture");
  }
  for (const name of [
    "ml/manifest.json",
    "ml/manifest.sig",
    "ml/payload/python",
    "ml/payload/provenance.json",
    ...Object.values(entries),
    ...HOST_REQUIRED,
  ]) {
    files[name] = artifact(await readFile(join(root, "payload", name)));
  }
  const manifest = {
    schemaVersion: 1,
    protocolVersion: 2,
    epoch: 2,
    ...target,
    sourceRevision: "b".repeat(40),
    nodeVersion: "26.11.1",
    postgresVersion: "19beta4",
    vectorVersion: "0.8.7",
    certified: false,
    entryPoints: entries,
    files,
  };
  const save = () =>
    writeFile(join(root, "manifest.json"), JSON.stringify(manifest));
  await save();
  return { root, pem, policy, manifest, save, artifact };
}

test("signs the complete host and verifies the nested ML authority without overwriting signatures", async (t) => {
  const f = await fixture(t);
  const signed = await signHostCandidate(f.root, f.pem, f.policy);
  assert.equal(signed.keyId, "fixture");
  assert.equal((await readFile(join(f.root, "manifest.sig"))).length, 64);
  const checked = await verifySignedHostCandidate(f.root, f.policy);
  assert.equal(checked.manifestSha256, signed.manifestSha256);
  assert.equal(
    checked.signatureSha256,
    createHash("sha256")
      .update(await readFile(join(f.root, "manifest.sig")))
      .digest("hex"),
  );
  await assert.rejects(
    signHostCandidate(f.root, f.pem, f.policy),
    /signature_exists/,
  );
});

test("refuses missing roles, unlisted files and altered nested ML even when parent hashes are updated", async (t) => {
  const f = await fixture(t);
  delete f.manifest.entryPoints.pgCtl;
  await f.save();
  await assert.rejects(
    signHostCandidate(f.root, f.pem, f.policy),
    /host_manifest_invalid/,
  );
  f.manifest.entryPoints.pgCtl = "components/pgCtl";
  await f.save();
  await writeFile(join(f.root, "payload/unlisted"), "fixture");
  await assert.rejects(
    signHostCandidate(f.root, f.pem, f.policy),
    /inventory_mismatch/,
  );
  await rm(join(f.root, "payload/unlisted"));
  const changed = Buffer.from("changed ML runtime");
  await writeFile(join(f.root, "payload/ml/payload/python"), changed);
  f.manifest.files["ml/payload/python"] = f.artifact(changed);
  await f.save();
  await assert.rejects(
    signHostCandidate(f.root, f.pem, f.policy),
    /artifact_changed/,
  );
});

test("refuses untrusted signing keys and epoch rollback", async (t) => {
  const f = await fixture(t);
  const other = generateKeyPairSync("ed25519").privateKey.export({
    format: "pem",
    type: "pkcs8",
  });
  await assert.rejects(
    signHostCandidate(f.root, other, f.policy),
    /release_key_untrusted/,
  );
  f.manifest.epoch = 1;
  await f.save();
  await assert.rejects(
    signHostCandidate(f.root, f.pem, f.policy),
    /host_manifest_incompatible/,
  );
});

test("host signature rejects later manifest edits and cannot wrap a foreign ML target", async (t) => {
  const f = await fixture(t);
  await signHostCandidate(f.root, f.pem, f.policy);
  f.manifest.sourceRevision = "c".repeat(40);
  await f.save();
  await assert.rejects(
    verifySignedHostCandidate(f.root, f.policy),
    /host_signature_invalid/,
  );
  await rm(join(f.root, "manifest.sig"));
  f.manifest.platform = f.manifest.platform === "windows" ? "linux" : "windows";
  await f.save();
  await assert.rejects(
    signHostCandidate(f.root, f.pem, f.policy),
    /host_ml_target_mismatch/,
  );
});

test("CLI never echoes malformed private-key input", async (t) => {
  const f = await fixture(t);
  const { spawnSync } = await import("node:child_process");
  const marker = "SECRET-MUST-NOT-APPEAR";
  const result = spawnSync(
    process.execPath,
    [
      fileURLToPath(new URL("./sign_host_runtime.mjs", import.meta.url)),
      "--candidate",
      f.root,
      "--private-key-stdin",
    ],
    { input: marker + "\n-----END PRIVATE KEY-----\n", encoding: "utf8" },
  );
  assert.equal(result.status, 1);
  assert.ok(!result.stdout.includes(marker) && !result.stderr.includes(marker));
  assert.match(result.stderr, /host_signing_failed/);
});

test("Manager code, recovery UI and backup engine are required signed host roles", async (t) => {
  const f = await fixture(t);
  assert.ok(HOST_ROLES.includes('manager'));
  assert.ok(HOST_ROLES.includes('managerWebIndex'));
  assert.ok(HOST_ROLES.includes('backupEngine'));
  assert.ok(HOST_REQUIRED.includes('backup/LICENSE'));
  assert.ok(HOST_REQUIRED.includes('backup/component.json'));
  for (const role of ['manager', 'managerWebIndex', 'backupEngine']) {
    const path = f.manifest.entryPoints[role];
    delete f.manifest.entryPoints[role];
    await f.save();
    await assert.rejects(signHostCandidate(f.root, f.pem, f.policy), /host_manifest_invalid/);
    f.manifest.entryPoints[role] = path;
  }
});

// Earlier desktop hosts do not retain package code leases.
test("host protocol one cannot be signed as a lease-aware host", async (t) => {
  const f = await fixture(t);
  f.manifest.protocolVersion = 1;
  await f.save();
  await assert.rejects(signHostCandidate(f.root, f.pem, f.policy), /host_manifest_incompatible/);
});
