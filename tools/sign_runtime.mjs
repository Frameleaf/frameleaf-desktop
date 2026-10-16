/** Authoring only: verify immutable candidate bytes, then sign with the Infisical-owned release key. */
import {
  createHash,
  createPrivateKey,
  createPublicKey,
  sign,
  verify,
} from "node:crypto";
import { constants, createReadStream } from "node:fs";
import { lstat, open, readdir } from "node:fs/promises";
import { dirname, isAbsolute, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const trustPath = new URL("../runtime/release-trust.json", import.meta.url);
const profilesPath = new URL("../runtime/profiles.json", import.meta.url);
const digest = (value) => createHash("sha256").update(value).digest("hex");
const hashPattern = /^[a-f0-9]{64}$/;
const fail = (code) => {
  throw new Error(code);
};
function relative(value) {
  if (
    typeof value !== "string" ||
    !value ||
    value.length > 4096 ||
    /[\\:\x00-\x1f\x7f]/.test(value)
  )
    fail("runtime_path_invalid");
  for (const part of value.split("/")) {
    const stem = part.split(".")[0].toUpperCase();
    if (
      !part ||
      part === "." ||
      part === ".." ||
      /[. ]$/.test(part) ||
      /^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])$/.test(stem)
    )
      fail("runtime_path_invalid");
  }
  return value;
}
async function directory(path) {
  const stat = await lstat(path);
  if (!stat.isDirectory() || stat.isSymbolicLink())
    fail("runtime_directory_invalid");
}
async function boundedFile(path, max) {
  const stat = await lstat(path);
  if (!stat.isFile() || stat.isSymbolicLink() || stat.size > max)
    fail("runtime_file_invalid");
  const handle = await open(
    path,
    constants.O_RDONLY | (constants.O_NOFOLLOW || 0),
  );
  try {
    const info = await handle.stat();
    if (!info.isFile() || info.size > max) fail("runtime_file_invalid");
    const buffer = Buffer.alloc(max + 1);
    const { bytesRead } = await handle.read(buffer, 0, max + 1, 0);
    if (bytesRead > max || bytesRead !== info.size)
      fail("runtime_file_invalid");
    return buffer.subarray(0, bytesRead);
  } finally {
    await handle.close();
  }
}
async function verifyPayload(payload, files) {
  const names = Object.keys(files);
  if (!names.length || names.length > 50000) fail("runtime_manifest_invalid");
  const folded = new Set();
  let total = 0;
  for (const name of names) {
    relative(name);
    const artifact = files[name];
    if (
      !artifact ||
      Object.keys(artifact).sort().join(",") !== "bytes,sha256" ||
      !hashPattern.test(artifact.sha256) ||
      !Number.isSafeInteger(artifact.bytes) ||
      artifact.bytes < 0 ||
      artifact.bytes > 16 * 1024 ** 3
    )
      fail("runtime_manifest_invalid");
    total += artifact.bytes;
    if (total > 64 * 1024 ** 3 || folded.has(name.toLowerCase()))
      fail("runtime_manifest_invalid");
    folded.add(name.toLowerCase());
  }
  const actual = new Set();
  const pending = [""];
  let count = 0;
  while (pending.length) {
    const prefix = pending.pop();
    await directory(join(payload, prefix));
    for (const entry of await readdir(join(payload, prefix), {
      withFileTypes: true,
    })) {
      if (++count > 100000) fail("runtime_inventory_limit");
      const name = prefix ? `${prefix}/${entry.name}` : entry.name;
      relative(name);
      if (entry.isSymbolicLink()) fail("runtime_link_forbidden");
      if (entry.isDirectory()) pending.push(name);
      else if (entry.isFile()) actual.add(name);
      else fail("runtime_special_file_forbidden");
    }
  }
  if (actual.size !== names.length || names.some((name) => !actual.has(name)))
    fail("runtime_inventory_mismatch");
  for (const name of names) {
    const artifact = files[name];
    const path = join(payload, name);
    const stat = await lstat(path);
    if (!stat.isFile() || stat.isSymbolicLink() || stat.size !== artifact.bytes)
      fail("runtime_artifact_changed");
    const hash = createHash("sha256");
    let read = 0;
    const stream = createReadStream(path, {
      flags: constants.O_RDONLY | (constants.O_NOFOLLOW || 0),
      highWaterMark: 65536,
    });
    for await (const bytes of stream) {
      read += bytes.length;
      if (read > artifact.bytes) fail("runtime_artifact_changed");
      hash.update(bytes);
    }
    if (read !== artifact.bytes || hash.digest("hex") !== artifact.sha256)
      fail("runtime_artifact_changed");
  }
}
async function releasePolicy(policy) {
  const trust =
    policy ?? JSON.parse(await boundedFile(fileURLToPath(trustPath), 16384));
  if (
    trust.schemaVersion !== 1 ||
    !Number.isSafeInteger(trust.minimumRuntimeEpoch) ||
    trust.minimumRuntimeEpoch < 1 ||
    !Array.isArray(trust.keys) ||
    !trust.keys.length ||
    trust.keys.length > 16
  )
    fail("release_policy_invalid");
  return trust;
}
async function checkedCandidate(candidate, trust, signature) {
  candidate = resolve(candidate);
  for (let path = candidate; ; path = dirname(path)) {
    await directory(path);
    if (dirname(path) === path) break;
  }
  const raw = await boundedFile(
    join(candidate, "manifest.json"),
    8 * 1024 * 1024,
  );
  let authority;
  if (signature) {
    authority = trust.keys.find(
      ({ publicKeyHex }) =>
        /^[a-f0-9]{64}$/.test(publicKeyHex) &&
        verify(
          null,
          raw,
          createPublicKey({
            key: Buffer.concat([
              Buffer.from("302a300506032b6570032100", "hex"),
              Buffer.from(publicKeyHex, "hex"),
            ]),
            format: "der",
            type: "spki",
          }),
          signature,
        ),
    );
    if (!authority) fail("runtime_signature_invalid");
  }
  const manifest = JSON.parse(raw);
  const fields = [
    "schemaVersion",
    "protocolVersion",
    "epoch",
    "platform",
    "architecture",
    "provider",
    "python",
    "sourceRevision",
    "files",
  ]
    .sort()
    .join(",");
  if (
    Object.keys(manifest).sort().join(",") !== fields ||
    manifest.schemaVersion !== 1 ||
    manifest.protocolVersion !== 1 ||
    !Number.isSafeInteger(manifest.epoch) ||
    manifest.epoch < trust.minimumRuntimeEpoch ||
    !["macos", "linux", "windows"].includes(manifest.platform) ||
    !["aarch64", "x86_64"].includes(manifest.architecture) ||
    !/^[a-f0-9]{40}$/.test(manifest.sourceRevision) ||
    !manifest.files ||
    Array.isArray(manifest.files)
  )
    fail("runtime_manifest_invalid");
  const profiles = JSON.parse(
    await boundedFile(fileURLToPath(profilesPath), 16384),
  );
  const matches = Object.entries(profiles.profiles ?? {}).filter(
    ([, profile]) =>
      profile.provider === manifest.provider &&
      Array.isArray(profile.targets) &&
      profile.targets.includes(`${manifest.platform}-${manifest.architecture}`),
  );
  if (profiles.schemaVersion !== 1 || matches.length !== 1)
    fail("runtime_profile_unapproved");
  const [profileName, profile] = matches[0];
  relative(manifest.python);
  if (!Object.hasOwn(manifest.files, manifest.python))
    fail("runtime_manifest_invalid");
  await verifyPayload(join(candidate, "payload"), manifest.files);
  const provenance = JSON.parse(
    await boundedFile(join(candidate, "payload/provenance.json"), 65536),
  );
  if (
    provenance.schemaVersion !== 1 ||
    provenance.sourceRepository !== "Frameleaf/frameleaf-app" ||
    provenance.sourceRevision !== manifest.sourceRevision ||
    provenance.profile !== profileName ||
    provenance.python !== profile.python
  )
    fail("runtime_provenance_invalid");
  return { raw, manifest, keyId: authority?.id };
}
export async function verifySignedCandidate(candidate, policy) {
  const trust = await releasePolicy(policy);
  const signature = await boundedFile(join(candidate, "manifest.sig"), 64);
  if (signature.length !== 64) fail("runtime_signature_invalid");
  const checked = await checkedCandidate(candidate, trust, signature);
  return {
    manifest: checked.manifest,
    keyId: checked.keyId,
    manifestSha256: digest(checked.raw),
  };
}
export async function signCandidate(
  candidate,
  signaturePath,
  privatePem,
  policy,
) {
  const trust = await releasePolicy(policy);
  const key = createPrivateKey(privatePem);
  if (key.asymmetricKeyType !== "ed25519") fail("release_key_untrusted");
  const publicHex = createPublicKey(key)
    .export({ format: "der", type: "spki" })
    .subarray(-32)
    .toString("hex");
  const authority = trust.keys.find((key) => key.publicKeyHex === publicHex);
  if (!authority) fail("release_key_untrusted");
  signaturePath = resolve(signaturePath);
  const { raw, manifest } = await checkedCandidate(candidate, trust);
  await directory(dirname(signaturePath));
  const signature = sign(null, raw, key);
  let output;
  try {
    output = await open(signaturePath, "wx", 0o600);
  } catch (error) {
    if (error.code === "EEXIST") fail("runtime_signature_exists");
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
    manifestSha256: digest(raw),
    signatureSha256: digest(signature),
    sourceRevision: manifest.sourceRevision,
    epoch: manifest.epoch,
  };
}
async function readSigningKey() {
  process.stdin.setEncoding("utf8");
  let value = "";
  for await (const part of process.stdin) {
    value += part;
    if (Buffer.byteLength(value) > 4096) fail("release_key_invalid");
    if (value.includes("-----END PRIVATE KEY-----")) {
      process.stdin.pause();
      return value;
    }
  }
  fail("release_key_invalid");
}
if (
  process.argv[1] &&
  resolve(process.argv[1]) === fileURLToPath(import.meta.url)
) {
  try {
    const args = process.argv.slice(2);
    if (
      args.length !== 5 ||
      args[0] !== "--candidate" ||
      args[2] !== "--signature" ||
      args[4] !== "--private-key-stdin" ||
      !isAbsolute(args[1]) ||
      !isAbsolute(args[3])
    )
      fail(
        "usage: --candidate ABSOLUTE_PATH --signature ABSOLUTE_PATH --private-key-stdin",
      );
    const privateKey = await readSigningKey();
    console.log(
      JSON.stringify(await signCandidate(args[1], args[3], privateKey)),
    );
  } catch (error) {
    // OpenSSL and filesystem errors can contain key material or private authoring paths.
    const code = /^(runtime_|release_|usage:)[a-zA-Z0-9_: ./-]{1,160}$/.test(
      error.message,
    )
      ? error.message
      : "release_signing_failed";
    console.error(code);
    process.exitCode = 1;
  }
}
