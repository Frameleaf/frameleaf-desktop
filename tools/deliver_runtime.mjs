/** FD-60: turn a factory-signed accelerated pack into release parts and the signed delivery
 * manifest an installer carries.
 *
 * A pack is the concatenation of its accelerated runtime manifest, that manifest's 64-byte
 * signature and the payload files in the byte order of their names, cut into parts small enough
 * for a release. The delivery manifest names every part by size and SHA-256 and the runtime
 * manifest by SHA-256, lists the payload files that are executable where the pack was built
 * (the app makes exactly those executable, as a bundled pack keeps its files' modes), and is
 * signed with the runtime release key. The app
 * (src-tauri/src/accelerated_pack.rs) downloads the parts, checks each against the delivery
 * manifest and rebuilds the pack from what the two signed manifests say. */
import { createHash, createPrivateKey, createPublicKey, sign, verify } from "node:crypto";
import {
  closeSync,
  fsyncSync,
  mkdirSync,
  openSync,
  readSync,
  readdirSync,
  renameSync,
  writeSync,
} from "node:fs";
import { lstat, mkdir, readdir, writeFile } from "node:fs/promises";
import { dirname, isAbsolute, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  acceleratedManifest,
  acceleratedSignature,
  boundedFile,
  readSigningKey,
  releasePolicy,
  verifySignedAccelerated,
} from "./sign_runtime.mjs";

/** Where a signed pack (and so the installer) keeps delivery manifests, beside its payload. */
export const deliveryDirectory = "accelerated";
/** GitHub: "Each file included in a release must be under 2 GiB." */
export const partLimit = 2 * 1024 ** 3 - 1;
const defaultPartBytes = 1024 ** 3;
const cpuProvider = "CPUExecutionProvider";
const fields =
  "architecture,bytes,epoch,executable,manifestBytes,manifestSha256,parts,platform,profile,provider,schemaVersion";
/** The list of executable files makes a delivery manifest far larger than its parts alone. */
const deliveryLimit = 2 * 1024 * 1024;
const namePattern = /^[a-z0-9][a-z0-9._-]{0,127}$/;
const hashPattern = /^[a-f0-9]{64}$/;
const fail = (code) => {
  throw new Error(code);
};
const digest = (value) => createHash("sha256").update(value).digest("hex");
const profiles = async () =>
  JSON.parse(
    await boundedFile(
      fileURLToPath(new URL("../runtime/profiles.json", import.meta.url)),
      16384,
    ),
  );
/** The app reads names in byte order (a Rust BTreeMap of strings). */
const byteOrder = (names) =>
  [...names].sort((a, b) => Buffer.compare(Buffer.from(a), Buffer.from(b)));

function authority(raw, signature, trust) {
  return trust.keys.find(
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
}

/** The checks the app makes on a delivery manifest, apart from this computer's own target. */
function checkedDelivery(raw, signature, trust, approved) {
  if (signature.length !== 64 || !authority(raw, signature, trust))
    fail("accelerated_pack_signature_invalid");
  const delivery = JSON.parse(raw);
  const profile = Object.hasOwn(approved.profiles ?? {}, delivery.profile)
    ? approved.profiles[delivery.profile]
    : undefined;
  const names = new Set();
  let total = 0;
  if (
    Object.keys(delivery).sort().join(",") !== fields ||
    delivery.schemaVersion !== 1 ||
    approved.schemaVersion !== 1 ||
    !profile ||
    profile.provider === cpuProvider ||
    profile.provider !== delivery.provider ||
    !profile.targets.includes(`${delivery.platform}-${delivery.architecture}`) ||
    !Number.isSafeInteger(delivery.epoch) ||
    delivery.epoch < trust.minimumRuntimeEpoch ||
    !hashPattern.test(delivery.manifestSha256) ||
    !Number.isSafeInteger(delivery.manifestBytes) ||
    delivery.manifestBytes < 1 ||
    delivery.manifestBytes > 8 * 1024 * 1024 ||
    !Array.isArray(delivery.executable) ||
    delivery.executable.length > 100000 ||
    delivery.executable.some(
      (name, index) =>
        typeof name !== "string" ||
        !name ||
        /[\\:\x00-\x1f\x7f]/.test(name) ||
        name.split("/").some((part) => !part || part === "." || part === "..") ||
        (index > 0 &&
          Buffer.compare(Buffer.from(delivery.executable[index - 1]), Buffer.from(name)) >= 0),
    ) ||
    !Array.isArray(delivery.parts) ||
    !delivery.parts.length ||
    delivery.parts.length > 64
  )
    fail("accelerated_pack_manifest_invalid");
  for (const part of delivery.parts) {
    if (
      !part ||
      Object.keys(part).sort().join(",") !== "bytes,name,sha256" ||
      !namePattern.test(part.name) ||
      part.name.includes("..") ||
      names.has(part.name) ||
      !Number.isSafeInteger(part.bytes) ||
      part.bytes < 1 ||
      part.bytes > partLimit ||
      !hashPattern.test(part.sha256)
    )
      fail("accelerated_pack_manifest_invalid");
    names.add(part.name);
    total += part.bytes;
  }
  if (
    total !== delivery.bytes ||
    delivery.bytes > 16 * 1024 ** 3 ||
    delivery.bytes <= delivery.manifestBytes + 64
  )
    fail("accelerated_pack_manifest_invalid");
  return delivery;
}

async function plainDirectory(path) {
  try {
    const stat = await lstat(path);
    if (!stat.isDirectory() || stat.isSymbolicLink())
      fail("accelerated_pack_manifest_invalid");
    return true;
  } catch (error) {
    if (error.code === "ENOENT") return false;
    throw error;
  }
}

/** The delivery manifests beside a signed pack: every one signed, approved for the pack's own
 * target and built at the pack's epoch (the app admits no other). Returns their file names. */
export async function verifyDeliveries(candidate, manifest, policy) {
  const directory = join(resolve(candidate), deliveryDirectory);
  if (!(await plainDirectory(directory))) return [];
  const trust = await releasePolicy(policy);
  const approved = await profiles();
  const names = (await readdir(directory)).sort();
  const found = [];
  for (const name of names.filter((item) => item.endsWith(".json"))) {
    const profile = name.slice(0, -".json".length);
    const delivery = checkedDelivery(
      await boundedFile(join(directory, name), deliveryLimit),
      await boundedFile(join(directory, `${profile}.sig`), 64),
      trust,
      approved,
    );
    if (
      delivery.profile !== profile ||
      delivery.platform !== manifest.platform ||
      delivery.architecture !== manifest.architecture ||
      delivery.epoch !== manifest.epoch
    )
      fail("accelerated_pack_manifest_invalid");
    found.push(name, `${profile}.sig`);
  }
  if (!found.length || found.length !== names.length || found.sort().join() !== names.join())
    fail("accelerated_pack_manifest_invalid");
  return found;
}

function hashFile(path, bytes) {
  const hash = createHash("sha256");
  const buffer = Buffer.alloc(1024 * 1024);
  const file = openSync(path, "r");
  let read = 0;
  try {
    for (;;) {
      const count = readSync(file, buffer, 0, buffer.length, null);
      if (!count) break;
      read += count;
      if (read > bytes) fail("accelerated_pack_part_invalid");
      hash.update(buffer.subarray(0, count));
    }
  } finally {
    closeSync(file);
  }
  if (read !== bytes) fail("accelerated_pack_part_invalid");
  return hash.digest("hex");
}

/** A signed delivery manifest and the parts it names, exactly as a release would serve them. */
export async function verifyDelivery(manifestPath, signaturePath, partsDirectory, policy) {
  const delivery = checkedDelivery(
    await boundedFile(manifestPath, deliveryLimit),
    await boundedFile(signaturePath, 64),
    await releasePolicy(policy),
    await profiles(),
  );
  for (const part of delivery.parts) {
    const path = join(partsDirectory, part.name);
    const stat = await lstat(path).catch(() => fail("accelerated_pack_part_missing"));
    if (!stat.isFile() || stat.isSymbolicLink() || stat.size !== part.bytes)
      fail("accelerated_pack_part_invalid");
    if (hashFile(path, part.bytes) !== part.sha256) fail("accelerated_pack_part_invalid");
  }
  return delivery;
}

/** Writes a stream of buffers and files into numbered parts of `partBytes`. */
class PartWriter {
  constructor(directory, prefix, partBytes) {
    Object.assign(this, { directory, prefix, partBytes, parts: [], file: null });
  }
  open() {
    const name = `${this.prefix}.part${String(this.parts.length + 1).padStart(2, "0")}`;
    this.current = { name, bytes: 0, hash: createHash("sha256") };
    this.file = openSync(join(this.directory, name), "wx", 0o600);
  }
  close() {
    if (this.file === null) return;
    fsyncSync(this.file);
    closeSync(this.file);
    this.file = null;
    const { name, bytes, hash } = this.current;
    this.parts.push({ name, bytes, sha256: hash.digest("hex") });
  }
  write(buffer) {
    for (let offset = 0; offset < buffer.length; ) {
      if (this.file === null) this.open();
      const count = Math.min(buffer.length - offset, this.partBytes - this.current.bytes);
      const slice = buffer.subarray(offset, offset + count);
      writeSync(this.file, slice);
      this.current.hash.update(slice);
      this.current.bytes += count;
      offset += count;
      if (this.current.bytes === this.partBytes) this.close();
    }
  }
  file_(path, bytes) {
    const buffer = Buffer.alloc(1024 * 1024);
    const source = openSync(path, "r");
    let read = 0;
    try {
      for (;;) {
        const count = readSync(source, buffer, 0, buffer.length, null);
        if (!count) break;
        read += count;
        this.write(buffer.subarray(0, count));
      }
    } finally {
      closeSync(source);
    }
    if (read !== bytes) fail("runtime_artifact_changed");
  }
}

/** Split the signed accelerated pack in `candidate` into parts under `output/parts` and write
 * its signed delivery manifest to `output/<profile>.json` and `.sig`. */
export async function deliverRuntime(candidate, output, privatePem, policy, options = {}) {
  candidate = resolve(candidate);
  output = resolve(output);
  const partBytes = options.partBytes ?? defaultPartBytes;
  if (!Number.isSafeInteger(partBytes) || partBytes < 1 || partBytes > partLimit)
    fail("accelerated_pack_part_size_invalid");
  const trust = await releasePolicy(policy);
  const key = createPrivateKey(privatePem);
  if (key.asymmetricKeyType !== "ed25519") fail("release_key_untrusted");
  const publicHex = createPublicKey(key)
    .export({ format: "der", type: "spki" })
    .subarray(-32)
    .toString("hex");
  if (!trust.keys.some((item) => item.publicKeyHex === publicHex))
    fail("release_key_untrusted");
  // Every byte of the payload against the signed accelerated manifest, before any of it is cut.
  const accelerated = await verifySignedAccelerated(candidate, trust);
  if (!accelerated) fail("accelerated_pack_missing");
  const { manifest, manifestSha256 } = accelerated;
  const approved = await profiles();
  const target = `${manifest.platform}-${manifest.architecture}`;
  const matches = Object.entries(approved.profiles).filter(
    ([, profile]) => profile.provider === manifest.provider && profile.targets.includes(target),
  );
  if (matches.length !== 1) fail("runtime_profile_unapproved");
  const [profile] = matches[0];
  const raw = await boundedFile(join(candidate, acceleratedManifest), 8 * 1024 * 1024);
  const signature = await boundedFile(join(candidate, acceleratedSignature), 64);
  if (digest(raw) !== manifestSha256) fail("runtime_artifact_changed");
  await mkdir(join(output, "parts"), { recursive: true });
  if ((await readdir(output)).length !== 1 || (await readdir(join(output, "parts"))).length)
    fail("accelerated_pack_output_exists");
  const writer = new PartWriter(
    join(output, "parts"),
    `frameleaf-accelerated-${profile}-${target}-e${manifest.epoch}-${manifestSha256.slice(0, 12)}`,
    partBytes,
  );
  writer.write(raw);
  writer.write(signature);
  // A file is executable in the app exactly when it is where the pack was built. Windows has
  // no such bit, and its packs need none.
  const executable = [];
  for (const name of byteOrder(Object.keys(manifest.files))) {
    const path = join(candidate, "payload", name);
    if (process.platform !== "win32" && manifest.platform !== "windows" && (await lstat(path)).mode & 0o111)
      executable.push(name);
    writer.file_(path, manifest.files[name].bytes);
  }
  writer.close();
  if (process.platform !== "win32" && manifest.platform !== "windows" && !executable.includes(manifest.python))
    fail("accelerated_pack_interpreter_not_executable");
  const delivery = {
    schemaVersion: 1,
    profile,
    platform: manifest.platform,
    architecture: manifest.architecture,
    provider: manifest.provider,
    epoch: manifest.epoch,
    manifestSha256,
    manifestBytes: raw.length,
    bytes: writer.parts.reduce((total, part) => total + part.bytes, 0),
    executable,
    parts: writer.parts,
  };
  const body = Buffer.from(JSON.stringify(delivery));
  const signed = sign(null, body, key);
  checkedDelivery(body, signed, trust, approved);
  await writeFile(join(output, `${profile}.json`), body, { flag: "wx" });
  await writeFile(join(output, `${profile}.sig`), signed, { flag: "wx" });
  await verifyDelivery(
    join(output, `${profile}.json`),
    join(output, `${profile}.sig`),
    join(output, "parts"),
    trust,
  );
  return { profile, delivery, manifestSha256: digest(body) };
}

/** Rebuild a pack from verified parts, as the app does: `output` receives the accelerated
 * manifest, its signature and `payload/`. For checks and hardware qualification. */
export async function reassemble(manifestPath, signaturePath, partsDirectory, output, policy) {
  const trust = await releasePolicy(policy);
  const delivery = await verifyDelivery(manifestPath, signaturePath, partsDirectory, trust);
  output = resolve(output);
  await mkdir(output, { recursive: true });
  if ((await readdir(output)).length) fail("accelerated_pack_output_exists");
  let index = 0;
  let file = null;
  const read = (target, length) => {
    for (let offset = 0; offset < length; ) {
      if (file === null) {
        if (index >= delivery.parts.length) fail("accelerated_pack_archive_invalid");
        file = openSync(join(partsDirectory, delivery.parts[index++].name), "r");
      }
      const count = readSync(file, target, offset, length - offset, null);
      if (!count) {
        closeSync(file);
        file = null;
      }
      offset += count;
    }
  };
  try {
    const raw = Buffer.alloc(delivery.manifestBytes);
    const signature = Buffer.alloc(64);
    read(raw, raw.length);
    read(signature, 64);
    if (digest(raw) !== delivery.manifestSha256 || !authority(raw, signature, trust))
      fail("accelerated_pack_archive_invalid");
    const manifest = JSON.parse(raw);
    const names = byteOrder(Object.keys(manifest.files));
    const total = names.reduce((sum, name) => sum + manifest.files[name].bytes, raw.length + 64);
    if (
      total !== delivery.bytes ||
      manifest.platform !== delivery.platform ||
      manifest.architecture !== delivery.architecture ||
      manifest.provider !== delivery.provider ||
      manifest.epoch !== delivery.epoch ||
      delivery.executable.some((name) => !Object.hasOwn(manifest.files, name))
    )
      fail("accelerated_pack_archive_invalid");
    const buffer = Buffer.alloc(1024 * 1024);
    for (const name of names) {
      if (/[\\:\x00-\x1f\x7f]/.test(name) || name.split("/").some((part) => !part || part === "." || part === ".."))
        fail("accelerated_pack_archive_invalid");
      const path = join(output, "payload", ...name.split("/"));
      mkdirSync(dirname(path), { recursive: true });
      const target = openSync(path, "wx", delivery.executable.includes(name) ? 0o700 : 0o600);
      const hash = createHash("sha256");
      try {
        for (let left = manifest.files[name].bytes; left > 0; ) {
          const count = Math.min(left, buffer.length);
          read(buffer, count);
          writeSync(target, buffer, 0, count);
          hash.update(buffer.subarray(0, count));
          left -= count;
        }
      } finally {
        closeSync(target);
      }
      if (hash.digest("hex") !== manifest.files[name].sha256)
        fail("accelerated_pack_archive_invalid");
    }
    await writeFile(join(output, acceleratedManifest), raw, { flag: "wx" });
    await writeFile(join(output, acceleratedSignature), signature, { flag: "wx" });
    return { delivery, manifest };
  } finally {
    if (file !== null) closeSync(file);
  }
}

/** The release step: `downloads` holds one folder per factory artifact
 * (`factory-accelerated-manifest-<target>-<profile>` and `factory-accelerated-parts-<target>-<profile>`).
 * Every pack is verified against its signed delivery manifest, then its parts move to `assets`. */
export async function stageRelease(downloads, assets, policy) {
  downloads = resolve(downloads);
  assets = resolve(assets);
  const staged = [];
  if (!(await plainDirectory(downloads))) return staged;
  const names = readdirSync(downloads).sort();
  const prefix = "factory-accelerated-manifest-";
  for (const name of names.filter((item) => item.startsWith(prefix))) {
    const pack = name.slice(prefix.length);
    const files = readdirSync(join(downloads, name)).sort();
    const manifest = files.find((item) => item.endsWith(".json"));
    if (files.length !== 2 || !manifest || files.join() !== [manifest, manifest.replace(/\.json$/, ".sig")].sort().join())
      fail("accelerated_pack_manifest_invalid");
    const parts = join(downloads, `factory-accelerated-parts-${pack}`);
    const delivery = await verifyDelivery(
      join(downloads, name, manifest),
      join(downloads, name, manifest.replace(/\.json$/, ".sig")),
      parts,
      policy,
    );
    if (`${delivery.platform}-${delivery.architecture}-${delivery.profile}` !== pack)
      fail("accelerated_pack_manifest_invalid");
    if (readdirSync(parts).sort().join() !== delivery.parts.map((part) => part.name).sort().join())
      fail("accelerated_pack_part_invalid");
    for (const part of delivery.parts) renameSync(join(parts, part.name), join(assets, part.name));
    staged.push({ pack, parts: delivery.parts.length, bytes: delivery.bytes });
  }
  // Parts without the manifest that vouches for them are never published.
  if (names.some((item) => item.startsWith("factory-accelerated-parts-") && !staged.some(({ pack }) => item === `factory-accelerated-parts-${pack}`)))
    fail("accelerated_pack_manifest_invalid");
  return staged;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const args = process.argv.slice(2);
    if (args[0] === "--release" && args.length === 3) {
      console.log(JSON.stringify(await stageRelease(args[1], args[2])));
    } else if (args[0] === "--reassemble" && args.length === 5) {
      const { delivery } = await reassemble(args[1], args[2], args[3], args[4]);
      console.log(JSON.stringify({ profile: delivery.profile, bytes: delivery.bytes }));
    } else if (args.length === 2 && isAbsolute(args[0]) && isAbsolute(args[1])) {
      const { profile, delivery, manifestSha256 } = await deliverRuntime(
        args[0],
        args[1],
        await readSigningKey(),
      );
      console.log(
        JSON.stringify({ profile, manifestSha256, parts: delivery.parts.length, bytes: delivery.bytes }),
      );
    } else
      fail(
        "usage: ABSOLUTE_SIGNED_PACK ABSOLUTE_OUTPUT (key on stdin) | --reassemble MANIFEST SIGNATURE PARTS OUTPUT | --release DOWNLOADS ASSETS",
      );
  } catch (error) {
    // Key parser and filesystem errors must never enter workflow logs.
    console.error(
      /^(accelerated_pack_|runtime_|release_|usage:)[a-zA-Z0-9_: ./<>()|-]{1,200}$/.test(error.message)
        ? error.message
        : "accelerated_pack_delivery_failed",
    );
    process.exitCode = 1;
  }
}
