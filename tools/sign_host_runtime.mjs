// Authoring only. A host signature binds every component and the independently signed ML pack.
import {
  createHash,
  createPrivateKey,
  createPublicKey,
  sign,
  verify,
} from "node:crypto";
import { lstat, open } from "node:fs/promises";
import { basename, dirname, isAbsolute, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  boundedFile,
  releasePolicy,
  readSigningKey,
  verifyPayload,
  verifySignedCandidate,
} from "./sign_runtime.mjs";

export const HOST_ROLES = [
  "node",
  "server",
  "postgres",
  "initdb",
  "pgDump",
  "pgRestore",
  "pgIsready",
  "pgChecksums",
  "pgCtl",
  "createdb",
  "psql",
  "vector",
  "hdr",
  "ffmpeg",
  "ffprobe",
  "exiftool",
  "rawRenderer",
  "rawDecoder",
  "webIndex",
  "studio",
  "studioBrowser",
  "studioBrowserGuard",
  "corePlugin",
  "mlManifest",
  "manager",
  "managerWebIndex",
];
export const HOST_REQUIRED = [
  "studio/engine-build.json",
  "studio/guard/studio-browser-guard.mjs",
  "studio/tools/bundled-worker-fonts.mjs",
  "studio/tools/render-worker-font-inputs.mjs",
  "studio/runtime/admission-font.json",
  "studio/runtime/admission-font.ttf",
  "build/geodata/geodata-date.txt",
  "build/geodata/cities500.txt",
  "build/geodata/admin1CodesASCII.txt",
  "build/geodata/admin2Codes.txt",
  "build/geodata/countryInfo.txt",
  "build/geodata/ne_10m_admin_0_countries.geojson",
  "build/geodata/landmarks.ndjson.gz",
  "ml/manifest.sig",
  "manager/app/release-worker.cjs",
  "manager/app/media-copy.cjs",
  "manager/.github/frameleaf-release.cjs",
  "manager/.github/verify-release-bundle.cjs",
  "manager/cosign.pub",
  "manager/component.json",
  "manager/package.json",
  "manager/LICENSE",
  "manager/node_modules/@nestjs/common/package.json",
  "manager/node_modules/@nestjs/core/package.json",
  "manager/node_modules/@nestjs/platform-express/package.json",
  "manager/node_modules/express/package.json",
  "manager/node_modules/js-yaml/package.json",
  "manager/node_modules/reflect-metadata/package.json",
  "manager/node_modules/rxjs/package.json",
  "manager/node_modules/zod/package.json",
];
const hash = (value) => createHash("sha256").update(value).digest("hex");
const fail = (code) => {
  throw new Error(code);
};
const publicKey = (hex) =>
  createPublicKey({
    key: Buffer.concat([
      Buffer.from("302a300506032b6570032100", "hex"),
      Buffer.from(hex, "hex"),
    ]),
    format: "der",
    type: "spki",
  });

async function checkedHost(candidate, trust, signature) {
  if (!isAbsolute(candidate)) fail("host_candidate_invalid");
  candidate = resolve(candidate);
  for (let path = candidate; ; path = dirname(path)) {
    const info = await lstat(path);
    if (!info.isDirectory() || info.isSymbolicLink())
      fail("host_candidate_invalid");
    if (dirname(path) === path) break;
  }
  const raw = await boundedFile(
    join(candidate, "manifest.json"),
    16 * 1024 * 1024,
  );
  let authority;
  if (signature) {
    authority = trust.keys.find(
      (key) =>
        /^[a-f0-9]{64}$/.test(key.publicKeyHex) &&
        verify(null, raw, publicKey(key.publicKeyHex), signature),
    );
    if (!authority) fail("host_signature_invalid");
  }
  const manifest = JSON.parse(raw);
  const fields = [
    "schemaVersion",
    "protocolVersion",
    "epoch",
    "platform",
    "architecture",
    "sourceRevision",
    "nodeVersion",
    "postgresVersion",
    "vectorVersion",
    "certified",
    "entryPoints",
    "files",
  ];
  if (
    Object.keys(manifest).sort().join(",") !== fields.sort().join(",") ||
    !manifest.entryPoints ||
    Array.isArray(manifest.entryPoints) ||
    Object.keys(manifest.entryPoints).sort().join(",") !==
      [...HOST_ROLES].sort().join(",") ||
    !manifest.files ||
    Array.isArray(manifest.files)
  )
    fail("host_manifest_invalid");
  const pins = JSON.parse(
    await boundedFile(
      fileURLToPath(new URL("../runtime/host-database.json", import.meta.url)),
      16384,
    ),
  );
  if (
    manifest.schemaVersion !== 1 ||
    manifest.protocolVersion !== 2 ||
    !Number.isSafeInteger(manifest.epoch) ||
    manifest.epoch < trust.minimumRuntimeEpoch ||
    !["macos", "linux", "windows"].includes(manifest.platform) ||
    !["aarch64", "x86_64"].includes(manifest.architecture) ||
    !/^[a-f0-9]{40}$/.test(manifest.sourceRevision ?? "") ||
    manifest.nodeVersion !== "26.11.1" ||
    manifest.postgresVersion !== pins.postgresVersion ||
    manifest.vectorVersion !== pins.pgvectorVersion ||
    manifest.certified !== pins.certified
  )
    fail("host_manifest_incompatible");
  for (const path of [...Object.values(manifest.entryPoints), ...HOST_REQUIRED])
    if (typeof path !== "string" || !Object.hasOwn(manifest.files, path))
      fail("host_component_missing");
  if (Object.hasOwn(manifest.files, "host-agent.mjs"))
    fail("host_fixture_agent_forbidden");
  await verifyPayload(join(candidate, "payload"), manifest.files, 100000);
  if (basename(manifest.entryPoints.mlManifest) !== "manifest.json")
    fail("host_ml_manifest_invalid");
  const ml = await verifySignedCandidate(
    join(candidate, "payload", dirname(manifest.entryPoints.mlManifest)),
    trust,
  );
  if (
    ml.manifest.platform !== manifest.platform ||
    ml.manifest.architecture !== manifest.architecture
  )
    fail("host_ml_target_mismatch");
  return { raw, manifest, keyId: authority?.id };
}

export async function signHostCandidate(candidate, privatePem, policy) {
  const trust = await releasePolicy(policy);
  const key = createPrivateKey(privatePem);
  if (key.asymmetricKeyType !== "ed25519") fail("release_key_untrusted");
  const publicHex = createPublicKey(key)
    .export({ format: "der", type: "spki" })
    .subarray(-32)
    .toString("hex");
  const authority = trust.keys.find((key) => key.publicKeyHex === publicHex);
  if (!authority) fail("release_key_untrusted");
  const { raw, manifest } = await checkedHost(candidate, trust);
  const signature = sign(null, raw, key);
  let output;
  try {
    output = await open(join(candidate, "manifest.sig"), "wx", 0o600);
  } catch (error) {
    if (error.code === "EEXIST") fail("host_signature_exists");
    throw error;
  }
  try {
    await output.writeFile(signature);
    await output.sync();
  } finally {
    await output.close();
  }
  return {
    keyId: authority.id,
    manifestSha256: hash(raw),
    signatureSha256: hash(signature),
    sourceRevision: manifest.sourceRevision,
    epoch: manifest.epoch,
    certified: manifest.certified,
  };
}

export async function verifySignedHostCandidate(candidate, policy) {
  const trust = await releasePolicy(policy);
  const signature = await boundedFile(join(candidate, "manifest.sig"), 64);
  if (signature.length !== 64) fail("host_signature_invalid");
  const checked = await checkedHost(candidate, trust, signature);
  return {
    keyId: checked.keyId,
    manifestSha256: hash(checked.raw),
    sourceRevision: checked.manifest.sourceRevision,
    epoch: checked.manifest.epoch,
    certified: checked.manifest.certified,
  };
}

if (
  process.argv[1] &&
  resolve(process.argv[1]) === fileURLToPath(import.meta.url)
) {
  try {
    const args = process.argv.slice(2);
    if (
      args.length !== 3 ||
      args[0] !== "--candidate" ||
      !isAbsolute(args[1]) ||
      args[2] !== "--private-key-stdin"
    )
      fail("usage: --candidate ABSOLUTE_PATH --private-key-stdin");
    const key = await readSigningKey();
    console.log(JSON.stringify(await signHostCandidate(args[1], key)));
  } catch (error) {
    const code =
      /^(host_|runtime_|release_|usage:)[a-zA-Z0-9_: ./-]{1,160}$/.test(
        error.message,
      )
        ? error.message
        : "host_signing_failed";
    console.error(code);
    process.exitCode = 1;
  }
}
