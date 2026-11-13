import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash, createPrivateKey, createPublicKey, sign } from "node:crypto";
import {
  cp,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  realpath,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  deliverRuntime,
  reassemble,
  stageRelease,
  verifyDeliveries,
  verifyDelivery,
} from "./deliver_runtime.mjs";
import { deliverFactoryRuntime, factoryPacksFor, factorySourceRevisionFor } from "./factory_runtime.mjs";

const sha256 = (value) => createHash("sha256").update(value).digest();
// A fixed key that exists only for this fixture: the Rust tests derive the same one, so the
// pack this tool cuts here is the pack src-tauri/src/accelerated_pack/tests.rs rebuilds.
const privateKey = createPrivateKey({
  key: Buffer.concat([
    Buffer.from("302e020100300506032b657004220420", "hex"),
    sha256("frameleaf accelerated pack fixture key"),
  ]),
  format: "der",
  type: "pkcs8",
});
const privatePem = privateKey.export({ format: "pem", type: "pkcs8" });
const policy = {
  schemaVersion: 1,
  minimumRuntimeEpoch: 2,
  keys: [
    {
      id: "fixture",
      publicKeyHex: createPublicKey(privateKey)
        .export({ format: "der", type: "spki" })
        .subarray(-32)
        .toString("hex"),
    },
  ],
};
const committed = fileURLToPath(
  new URL("../src-tauri/src/accelerated_pack/fixture/", import.meta.url),
);

/** Bytes that depend only on the name, so the fixture is the same on every computer. */
function bytes(name, length) {
  const parts = [];
  for (let block = sha256(name); Buffer.concat(parts).length < length; block = sha256(block))
    parts.push(block);
  return Buffer.concat(parts).subarray(0, length);
}

/** A small signed accelerated pack. The default is the committed one: CUDA for Windows. */
async function pack(t, { platform = "windows", architecture = "x86_64", profile = "cuda-ort", provider = "CUDAExecutionProvider", epoch = 7, sourceRevision = "c".repeat(40), signed = true } = {}) {
  const root = await mkdtemp(join(await realpath(tmpdir()), "frameleaf-deliver-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const candidate = join(root, "candidate");
  const files = {
    "python/python.exe": bytes("python", 100),
    "provenance.json": Buffer.from(
      JSON.stringify({
        schemaVersion: 1,
        sourceRepository: "Frameleaf/frameleaf-app",
        sourceRevision,
        profile,
        python: "3.12.13",
      }),
    ),
    // Names whose byte order differs from a case-insensitive or locale order.
    "Lib/site-packages/onnxruntime/capi/provider.dll": bytes("provider", 700),
    "Lib/Z.py": bytes("upper", 33),
    "Lib/a.py": bytes("lower", 65),
    "Lib/empty.py": Buffer.alloc(0),
    "lib-b/cudnn.dll": bytes("cudnn", 411),
  };
  const manifest = {
    schemaVersion: 1,
    protocolVersion: 1,
    epoch,
    platform,
    architecture,
    provider: "CPUExecutionProvider",
    python: "python/python.exe",
    sourceRevision,
    files: {},
  };
  for (const [name, content] of Object.entries(files)) {
    await mkdir(dirname(join(candidate, "payload", name)), { recursive: true });
    await writeFile(join(candidate, "payload", name), content);
    manifest.files[name] = { bytes: content.length, sha256: sha256(content).toString("hex") };
  }
  for (const [name, value] of [
    ["manifest", manifest],
    ["manifest-accelerated", { ...manifest, provider }],
  ]) {
    const raw = Buffer.from(JSON.stringify(value));
    await writeFile(join(candidate, `${name}.json`), raw);
    if (signed) await writeFile(join(candidate, `${name}.sig`), sign(null, raw, privateKey));
  }
  return { root, candidate, files, manifest, output: join(root, "delivery") };
}

async function tree(directory) {
  const found = {};
  for (const entry of await readdir(directory, { recursive: true, withFileTypes: true }))
    if (entry.isFile()) {
      const path = join(entry.parentPath, entry.name);
      found[path.slice(directory.length + 1).replaceAll("\\", "/")] = await readFile(path);
    }
  return found;
}

test("a signed pack is cut into parts and rebuilt byte for byte from the signed manifests", async (t) => {
  const f = await pack(t);
  const { profile, delivery } = await deliverRuntime(f.candidate, f.output, privatePem, policy, {
    partBytes: 512,
  });
  assert.equal(profile, "cuda-ort");
  assert.ok(delivery.parts.length > 2, "the fixture must span several parts");
  assert.equal(
    delivery.bytes,
    Object.values(f.files).reduce((total, content) => total + content.length, delivery.manifestBytes + 64),
  );
  assert.ok(delivery.parts.every((part) => /^frameleaf-accelerated-cuda-ort-windows-x86_64-e7-[a-f0-9]{12}\.part\d\d$/.test(part.name)));
  const rebuilt = join(f.root, "rebuilt");
  await reassemble(join(f.output, "cuda-ort.json"), join(f.output, "cuda-ort.sig"), join(f.output, "parts"), rebuilt, policy);
  assert.deepEqual(await tree(join(rebuilt, "payload")), await tree(join(f.candidate, "payload")));
  assert.deepEqual(
    await readFile(join(rebuilt, "manifest-accelerated.json")),
    await readFile(join(f.candidate, "manifest-accelerated.json")),
  );
  assert.deepEqual(
    await readFile(join(rebuilt, "manifest-accelerated.sig")),
    await readFile(join(f.candidate, "manifest-accelerated.sig")),
  );
  // The app's tests rebuild this same pack from the committed copy: both sides must agree on
  // the format. Ed25519 signatures are deterministic, so the copy is reproducible.
  if (process.env.FRAMELEAF_WRITE_FIXTURE) {
    await rm(committed, { recursive: true, force: true });
    await cp(f.output, committed, { recursive: true });
  }
  assert.deepEqual(
    await tree(f.output),
    await tree(committed.replace(/[\\/]$/, "")),
    "the pack format changed: update src-tauri/src/accelerated_pack.rs with it, then run FRAMELEAF_WRITE_FIXTURE=1 node --test tools/test_deliver_runtime.mjs",
  );
});

test("parts that do not match the signed delivery manifest are refused", async (t) => {
  const f = await pack(t);
  const { delivery } = await deliverRuntime(f.candidate, f.output, privatePem, policy, { partBytes: 512 });
  const paths = [join(f.output, "cuda-ort.json"), join(f.output, "cuda-ort.sig"), join(f.output, "parts")];
  await verifyDelivery(...paths, policy);
  const first = join(f.output, "parts", delivery.parts[0].name);
  const original = await readFile(first);
  const changed = Buffer.from(original);
  changed[10] ^= 1;
  await writeFile(first, changed);
  await assert.rejects(verifyDelivery(...paths, policy), /accelerated_pack_part_invalid/);
  await assert.rejects(reassemble(...paths, join(f.root, "out"), policy), /accelerated_pack_part_invalid/);
  await writeFile(first, original.subarray(0, original.length - 1));
  await assert.rejects(verifyDelivery(...paths, policy), /accelerated_pack_part_invalid/);
  await rm(first);
  await assert.rejects(verifyDelivery(...paths, policy), /accelerated_pack_part_missing/);
  await writeFile(first, original);
  await verifyDelivery(...paths, policy);
  // A delivery manifest that was altered, or signed by a key the app does not trust.
  const body = JSON.parse(await readFile(paths[0], "utf8"));
  body.parts[0].sha256 = "0".repeat(64);
  await writeFile(paths[0], JSON.stringify(body));
  await assert.rejects(verifyDelivery(...paths, policy), /accelerated_pack_signature_invalid/);
  const stranger = { ...policy, keys: [{ id: "other", publicKeyHex: "11".repeat(32) }] };
  await assert.rejects(verifyDelivery(...paths, stranger), /accelerated_pack_signature_invalid/);
});

test("only the release key cuts a pack, and only a fully verified signed accelerated pack", async (t) => {
  const f = await pack(t);
  const other = { ...policy, keys: [{ id: "other", publicKeyHex: "11".repeat(32) }] };
  await assert.rejects(deliverRuntime(f.candidate, f.output, privatePem, other), /release_key_untrusted/);
  await assert.rejects(
    deliverRuntime(f.candidate, f.output, privatePem, policy, { partBytes: 2 * 1024 ** 3 }),
    /accelerated_pack_part_size_invalid/,
  );
  await writeFile(join(f.candidate, "payload/Lib/a.py"), "changed");
  await assert.rejects(deliverRuntime(f.candidate, f.output, privatePem, policy), /runtime_artifact_changed/);
  const cpu = await pack(t);
  await rm(join(cpu.candidate, "manifest-accelerated.json"));
  await rm(join(cpu.candidate, "manifest-accelerated.sig"));
  await assert.rejects(deliverRuntime(cpu.candidate, cpu.output, privatePem, policy), /accelerated_pack_missing/);
});

test("an installer pack carries only delivery manifests signed for its own target and epoch", async (t) => {
  const f = await pack(t);
  await deliverRuntime(f.candidate, f.output, privatePem, policy, { partBytes: 512 });
  const installer = join(f.root, "installer");
  const place = async () => {
    await rm(installer, { recursive: true, force: true });
    await mkdir(join(installer, "accelerated"), { recursive: true });
    for (const name of ["cuda-ort.json", "cuda-ort.sig"])
      await cp(join(f.output, name), join(installer, "accelerated", name));
  };
  assert.deepEqual(await verifyDeliveries(join(f.root, "none"), f.manifest, policy), []);
  await place();
  assert.deepEqual(await verifyDeliveries(installer, f.manifest, policy), ["cuda-ort.json", "cuda-ort.sig"]);
  // The app admits a downloaded pack only at the processor runtime's own epoch.
  await assert.rejects(verifyDeliveries(installer, { ...f.manifest, epoch: 8 }, policy), /accelerated_pack_manifest_invalid/);
  await assert.rejects(verifyDeliveries(installer, { ...f.manifest, platform: "linux" }, policy), /accelerated_pack_manifest_invalid/);
  await writeFile(join(installer, "accelerated", "stray.txt"), "");
  await assert.rejects(verifyDeliveries(installer, f.manifest, policy), /accelerated_pack_manifest_invalid/);
  await place();
  await rm(join(installer, "accelerated", "cuda-ort.sig"));
  await assert.rejects(verifyDeliveries(installer, f.manifest, policy));
  await place();
  await cp(join(installer, "accelerated", "cuda-ort.json"), join(installer, "accelerated", "openvino-ort.json"));
  await cp(join(installer, "accelerated", "cuda-ort.sig"), join(installer, "accelerated", "openvino-ort.sig"));
  await assert.rejects(verifyDeliveries(installer, f.manifest, policy), /accelerated_pack_manifest_invalid/);
});

test("packaging maps the delivery manifests into the installer beside the processor runtime", async (t) => {
  const { packageConfiguration } = await import("./package_desktop.mjs");
  const platform = { darwin: "macos", win32: "windows", linux: "linux" }[process.platform];
  const architecture = { arm64: "aarch64", x64: "x86_64" }[process.arch];
  const profiles = JSON.parse(await readFile(new URL("../runtime/profiles.json", import.meta.url), "utf8")).profiles;
  // The processor pack an installer carries on this computer.
  const cpu = await pack(t, { platform, architecture });
  await rm(join(cpu.candidate, "manifest-accelerated.json"));
  await rm(join(cpu.candidate, "manifest-accelerated.sig"));
  const provenance = Buffer.from(
    JSON.stringify({
      schemaVersion: 1,
      sourceRepository: "Frameleaf/frameleaf-app",
      sourceRevision: profiles["cpu-ort"].sourceRevision,
      profile: "cpu-ort",
      python: "3.12.13",
    }),
  );
  await writeFile(join(cpu.candidate, "payload/provenance.json"), provenance);
  cpu.manifest.sourceRevision = profiles["cpu-ort"].sourceRevision;
  cpu.manifest.files["provenance.json"] = { bytes: provenance.length, sha256: sha256(provenance).toString("hex") };
  const raw = Buffer.from(JSON.stringify(cpu.manifest));
  await writeFile(join(cpu.candidate, "manifest.json"), raw);
  await writeFile(join(cpu.candidate, "manifest.sig"), sign(null, raw, privateKey));
  await packageConfiguration(cpu.candidate, policy);
  const carry = async (packs) => {
    await rm(join(cpu.candidate, "accelerated"), { recursive: true, force: true });
    await mkdir(join(cpu.candidate, "accelerated"));
    for (const [profile, provider, target] of packs) {
      const f = await pack(t, { platform: target, profile, provider });
      await deliverRuntime(f.candidate, f.output, privatePem, policy, { partBytes: 512 });
      for (const name of [`${profile}.json`, `${profile}.sig`])
        await cp(join(f.output, name), join(cpu.candidate, "accelerated", name));
    }
  };
  // A delivery manifest for another operating system never reaches this one's installer.
  await carry([["cuda-ort", "CUDAExecutionProvider", platform === "windows" ? "linux" : "windows"]]);
  await assert.rejects(packageConfiguration(cpu.candidate, policy), /accelerated_pack_manifest_invalid/);
  if (architecture !== "x86_64" || platform === "macos") return;
  await carry([
    ["cuda-ort", "CUDAExecutionProvider", platform],
    ["openvino-ort", "OpenVINOExecutionProvider", platform],
  ]);
  const { bundle } = await packageConfiguration(cpu.candidate, policy);
  const mapped = platform === "linux" ? bundle.linux.deb.files : Object.fromEntries(Object.entries(bundle.resources).map(([from, to]) => [to, from]));
  const prefix = platform === "linux" ? "/usr/share/Frameleaf/native-runtime" : "native-runtime";
  for (const name of ["cuda-ort.json", "cuda-ort.sig", "openvino-ort.json", "openvino-ort.sig"])
    assert.equal(mapped[`${prefix}/accelerated/${name}`], join(cpu.candidate, "accelerated", name));
  assert.equal(mapped[`${prefix}/manifest-accelerated.json`], undefined);
  // A delivery manifest whose signature does not hold never reaches an installer.
  await writeFile(join(cpu.candidate, "accelerated", "cuda-ort.sig"), Buffer.alloc(64));
  await assert.rejects(packageConfiguration(cpu.candidate, policy), /accelerated_pack_signature_invalid/);
});

test("the factory signs only the accelerated manifest of a downloadable pack and cuts it", async (t) => {
  for (const [profile, provider] of [["cuda-ort", "CUDAExecutionProvider"], ["openvino-ort", "OpenVINOExecutionProvider"]]) {
    const target = "windows-x86_64";
    const f = await pack(t, { profile, provider, sourceRevision: factorySourceRevisionFor(target, profile), signed: false });
    const receipt = await deliverFactoryRuntime(f.candidate, f.output, target, 7, privatePem, policy, { partBytes: 512 });
    assert.equal(receipt.profile, profile);
    assert.equal(receipt.epoch, 7);
    assert.ok(receipt.parts > 1);
    // The processor manifest of such a pack is never signed: it cannot become an installer's runtime.
    await assert.rejects(readFile(join(f.candidate, "manifest.sig")), { code: "ENOENT" });
    await verifyDelivery(join(f.output, `${profile}.json`), join(f.output, `${profile}.sig`), join(f.output, "parts"), policy);
  }
  // A processor pack, another target, another epoch or an unapproved source is not delivered.
  const cpu = await pack(t, { sourceRevision: factorySourceRevisionFor("windows-x86_64", "cuda-ort"), signed: false });
  await rm(join(cpu.candidate, "manifest-accelerated.json"));
  for (const [f, target, epoch] of [
    [cpu, "windows-x86_64", 7],
    [await pack(t, { sourceRevision: factorySourceRevisionFor("windows-x86_64", "cuda-ort"), signed: false }), "linux-x86_64", 7],
    [await pack(t, { sourceRevision: factorySourceRevisionFor("windows-x86_64", "cuda-ort"), signed: false }), "windows-x86_64", 8],
    [await pack(t, { signed: false }), "windows-x86_64", 7],
  ]) {
    await assert.rejects(deliverFactoryRuntime(f.candidate, f.output, target, epoch, privatePem, policy), /runtime_factory_candidate_unapproved/);
    await assert.rejects(readdir(join(f.output, "parts")), { code: "ENOENT" });
  }
});

test("the release step publishes only parts their signed delivery manifest vouches for", async (t) => {
  const f = await pack(t);
  const { delivery } = await deliverRuntime(f.candidate, f.output, privatePem, policy, { partBytes: 512 });
  const downloads = join(f.root, "downloads");
  const assets = join(f.root, "assets");
  const place = async () => {
    await rm(downloads, { recursive: true, force: true });
    await rm(assets, { recursive: true, force: true });
    await mkdir(assets);
    await mkdir(join(downloads, "factory-accelerated-manifest-windows-x86_64-cuda-ort"), { recursive: true });
    for (const name of ["cuda-ort.json", "cuda-ort.sig"])
      await cp(join(f.output, name), join(downloads, "factory-accelerated-manifest-windows-x86_64-cuda-ort", name));
    await cp(join(f.output, "parts"), join(downloads, "factory-accelerated-parts-windows-x86_64-cuda-ort"), { recursive: true });
  };
  assert.deepEqual(await stageRelease(join(f.root, "absent"), assets, policy), []);
  await place();
  assert.deepEqual(await stageRelease(downloads, assets, policy), [
    { pack: "windows-x86_64-cuda-ort", parts: delivery.parts.length, bytes: delivery.bytes },
  ]);
  assert.deepEqual((await readdir(assets)).sort(), delivery.parts.map((part) => part.name).sort());
  await place();
  await writeFile(join(downloads, "factory-accelerated-parts-windows-x86_64-cuda-ort", "extra.part99"), "x");
  await assert.rejects(stageRelease(downloads, assets, policy), /accelerated_pack_part_invalid/);
  await place();
  await rm(join(downloads, "factory-accelerated-manifest-windows-x86_64-cuda-ort"), { recursive: true });
  await assert.rejects(stageRelease(downloads, assets, policy), /accelerated_pack_manifest_invalid/);
  assert.deepEqual(await readdir(assets), []);
});

test("one factory run builds the installer pack and every downloadable pack of a target", () => {
  for (const target of ["windows-x86_64", "linux-x86_64"]) {
    assert.deepEqual(factoryPacksFor(target, "default"), [
      { profile: "cpu-ort", delivered: false },
      { profile: "cuda-ort", delivered: true },
      { profile: "openvino-ort", delivered: true },
    ]);
    assert.deepEqual(factoryPacksFor(target, "none"), [{ profile: "cpu-ort", delivered: false }]);
    // Naming one profile builds the installer's pack and only that downloadable pack.
    assert.deepEqual(factoryPacksFor(target, "cuda-ort"), [
      { profile: "cpu-ort", delivered: false },
      { profile: "cuda-ort", delivered: true },
    ]);
  }
  assert.deepEqual(factoryPacksFor("macos-aarch64", "cuda-ort"), [{ profile: "coreml-ort", delivered: false }]);
  assert.deepEqual(factoryPacksFor("macos-aarch64", "none"), [{ profile: "cpu-ort", delivered: false }]);
  // CoreML shares the processor pack and ships inside the installer; nothing is delivered.
  assert.deepEqual(factoryPacksFor("macos-aarch64", "default"), [{ profile: "coreml-ort", delivered: false }]);
  assert.deepEqual(factoryPacksFor("linux-aarch64", "default"), [{ profile: "cpu-ort", delivered: false }]);
  assert.throws(() => factoryPacksFor("windows-aarch64", "default"), /runtime_factory_source_invalid/);
});
