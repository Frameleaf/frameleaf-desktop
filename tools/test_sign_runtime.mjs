import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, verify } from "node:crypto";
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

test("signed Metal selection requires the fixed private package and rejects arbitrary entrypoints", async (t) => {
  const f = await fixture(t);
  const profile = JSON.parse(await readFile(new URL("../runtime/profiles.json", import.meta.url), "utf8")).profiles["coreml-ort"];
  const put = async (name, value) => {
    const bytes = Buffer.from(value);
    await mkdir(join(f.root, "payload", name, ".."), { recursive: true });
    await writeFile(join(f.root, "payload", name), bytes);
    f.manifest.files[name] = { bytes: bytes.length, sha256: createHash("sha256").update(bytes).digest("hex") };
  };
  await put("provenance.json", JSON.stringify({ schemaVersion: 1, sourceRevision: profile.sourceRevision, sourceRepository: "Frameleaf/frameleaf-app", profile: "coreml-ort", python: profile.python }));
  for (const name of ["__init__.py", "entry.py", "metal_observer.py", "metal_inference.py", "_frameleaf_coreml_observer.dylib"])
    await put(`private/frameleaf_desktop_ml/${name}`, "owned fixture");
  Object.assign(f.manifest, { provider: "CoreMLExecutionProvider", platform: "macos", architecture: "aarch64", moduleNamespace: "frameleaf_ml", sourceRevision: profile.sourceRevision, deviceObserver: { kind: "metal-v1" } });
  const authored = structuredClone(f.manifest);
  await writeFile(join(f.root, "manifest.json"), JSON.stringify(authored));
  await signCandidate(f.root, join(f.root, "valid.sig"), f.privatePem, f.policy);
  const malformed = [
    { ...authored, deviceObserver: { kind: "arbitrary-module" } },
    { ...authored, deviceObserver: { kind: "metal-v1", module: "os" } },
    { ...authored, moduleNamespace: "immich_ml" },
    { ...authored, architecture: "x86_64" },
    { ...authored, provider: "CPUExecutionProvider" },
    { ...authored, files: Object.fromEntries(Object.entries(authored.files).filter(([name]) => !name.endsWith("/entry.py"))) },
  ];
  for (let index = 0; index < malformed.length; index++) {
    await writeFile(join(f.root, "manifest.json"), JSON.stringify(malformed[index]));
    await assert.rejects(signCandidate(f.root, join(f.root, `invalid-${index}.sig`), f.privatePem, f.policy), /runtime_device_observer_invalid/);
  }
});

async function fixture(t) {
  const root = await mkdtemp(join(await realpath(tmpdir()), "frameleaf-sign-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  await mkdir(join(root, "payload"));
  const provenance = Buffer.from(
    JSON.stringify({
      schemaVersion: 1,
      sourceRevision: "a".repeat(40),
      sourceRepository: "Frameleaf/frameleaf-app",
      profile: "cpu-ort",
      python: "3.12.13",
    }),
  );
  await writeFile(join(root, "payload", "python"), "fixture");
  await writeFile(join(root, "payload", "provenance.json"), provenance);
  const artifact = (bytes) => ({
    bytes: bytes.length,
    sha256: createHash("sha256").update(bytes).digest("hex"),
  });
  const manifest = {
    schemaVersion: 1,
    protocolVersion: 1,
    epoch: 2,
    platform:
      process.platform === "darwin"
        ? "macos"
        : process.platform === "win32"
          ? "windows"
          : "linux",
    architecture: process.arch === "arm64" ? "aarch64" : "x86_64",
    provider: "CPUExecutionProvider",
    python: "python",
    sourceRevision: "a".repeat(40),
    files: {
      python: artifact(Buffer.from("fixture")),
      "provenance.json": artifact(provenance),
    },
  };
  await writeFile(join(root, "manifest.json"), JSON.stringify(manifest));
  const keys = generateKeyPairSync("ed25519");
  const policy = {
    schemaVersion: 1,
    minimumRuntimeEpoch: 2,
    minimumHostEpoch: 999,
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
  const privatePem = keys.privateKey.export({ format: "pem", type: "pkcs8" });
  return { root, manifest, keys, policy, privatePem };
}

test("signs exact verified manifest bytes with only the configured release authority", async (t) => {
  const f = await fixture(t);
  const receipt = await signCandidate(
    f.root,
    join(f.root, "manifest.sig"),
    f.privatePem,
    f.policy,
  );
  const signature = await readFile(join(f.root, "manifest.sig"));
  assert.equal(signature.length, 64);
  assert(
    verify(
      null,
      await readFile(join(f.root, "manifest.json")),
      f.keys.publicKey,
      signature,
    ),
  );
  assert.equal(receipt.keyId, "fixture");
  await assert.rejects(
    signCandidate(f.root, join(f.root, "manifest.sig"), f.privatePem, f.policy),
    /signature_exists/,
  );
});

test("signs only the declared CoreML Apple-silicon profile and binds its provenance", async (t) => {
  const f = await fixture(t);
  const provenance = JSON.parse(
    await readFile(join(f.root, "payload/provenance.json"), "utf8"),
  );
  provenance.profile = "coreml-ort";
  const authored = JSON.parse(
    await readFile(
      new URL("../runtime/profiles.json", import.meta.url),
      "utf8",
    ),
  ).profiles["coreml-ort"];
  provenance.sourceRevision = authored.sourceRevision;
  const bytes = Buffer.from(JSON.stringify(provenance));
  await writeFile(join(f.root, "payload/provenance.json"), bytes);
  f.manifest.files["provenance.json"] = {
    bytes: bytes.length,
    sha256: createHash("sha256").update(bytes).digest("hex"),
  };
  Object.assign(f.manifest, {
    provider: "CoreMLExecutionProvider",
    platform: "macos",
    architecture: "aarch64",
    sourceRevision: authored.sourceRevision,
  });
  await writeFile(join(f.root, "manifest.json"), JSON.stringify(f.manifest));
  await signCandidate(
    f.root,
    join(f.root, "manifest.sig"),
    f.privatePem,
    f.policy,
  );
  assert.equal((await readFile(join(f.root, "manifest.sig"))).length, 64);
  const { packageConfiguration } = await import("./package_desktop.mjs");
  if (process.platform === "darwin" && process.arch === "arm64") {
    const config = await packageConfiguration(f.root, f.policy);
    assert.equal(
      config.bundle.resources[join(f.root, "payload")],
      "native-runtime/payload",
    );
  } else {
    await assert.rejects(
      packageConfiguration(f.root, f.policy),
      /runtime_bundle_target_mismatch/,
    );
  }
});

test("rejects CoreML on other targets and mismatched CPU provenance", async (t) => {
  for (const [platform, architecture] of [
    ["windows", "x86_64"],
    ["linux", "aarch64"],
    ["macos", "x86_64"],
    ["macos", "aarch64"],
  ]) {
    const f = await fixture(t);
    Object.assign(f.manifest, {
      provider: "CoreMLExecutionProvider",
      platform,
      architecture,
    });
    await writeFile(join(f.root, "manifest.json"), JSON.stringify(f.manifest));
    await assert.rejects(
      signCandidate(
        f.root,
        join(f.root, "manifest.sig"),
        f.privatePem,
        f.policy,
      ),
      /runtime_(manifest|profile|provenance)_/,
    );
  }
});

test("changed payload, wrong key, extra files and rollback never receive a signature", async (t) => {
  const f = await fixture(t);
  const output = join(f.root, "manifest.sig");
  const other = generateKeyPairSync("ed25519").privateKey.export({
    format: "pem",
    type: "pkcs8",
  });
  await assert.rejects(
    signCandidate(f.root, output, other, f.policy),
    /release_key_untrusted/,
  );
  await writeFile(join(f.root, "payload", "python"), "changed");
  await assert.rejects(
    signCandidate(f.root, output, f.privatePem, f.policy),
    /artifact_changed/,
  );
  await writeFile(join(f.root, "payload", "python"), "fixture");
  await writeFile(join(f.root, "payload", "extra"), "unlisted");
  await assert.rejects(
    signCandidate(f.root, output, f.privatePem, f.policy),
    /inventory_mismatch/,
  );
  await rm(join(f.root, "payload", "extra"));
  f.manifest.epoch = 1;
  await writeFile(join(f.root, "manifest.json"), JSON.stringify(f.manifest));
  await assert.rejects(
    signCandidate(f.root, output, f.privatePem, f.policy),
    /manifest_invalid/,
  );
  await assert.rejects(readFile(output), /ENOENT/);
});

test("refuses traversal, ambiguous paths and source provenance mismatch", async (t) => {
  const f = await fixture(t);
  const output = join(f.root, "manifest.sig");
  f.manifest.python = "../python";
  await writeFile(join(f.root, "manifest.json"), JSON.stringify(f.manifest));
  await assert.rejects(
    signCandidate(f.root, output, f.privatePem, f.policy),
    /path_invalid/,
  );
  f.manifest.python = "python";
  f.manifest.sourceRevision = "b".repeat(40);
  await writeFile(join(f.root, "manifest.json"), JSON.stringify(f.manifest));
  await assert.rejects(
    signCandidate(f.root, output, f.privatePem, f.policy),
    /provenance_invalid/,
  );
});

test("does not sign an unsupported platform/profile combination", async (t) => {
  const f = await fixture(t);
  f.manifest.platform = "windows";
  f.manifest.architecture = "aarch64";
  await writeFile(join(f.root, "manifest.json"), JSON.stringify(f.manifest));
  await assert.rejects(
    signCandidate(f.root, join(f.root, "manifest.sig"), f.privatePem, f.policy),
    /profile_unapproved/,
  );
});

test("verifies a signed runtime without private key access and refuses altered or foreign signatures", async (t) => {
  const { verifySignedCandidate } = await import("./sign_runtime.mjs");
  const f = await fixture(t);
  await signCandidate(
    f.root,
    join(f.root, "manifest.sig"),
    f.privatePem,
    f.policy,
  );
  const checked = await verifySignedCandidate(f.root, f.policy);
  assert.equal(checked.manifest.sourceRevision, f.manifest.sourceRevision);
  assert.equal(checked.keyId, "fixture");
  await writeFile(join(f.root, "manifest.sig"), Buffer.alloc(64));
  await assert.rejects(
    verifySignedCandidate(f.root, f.policy),
    /runtime_signature_invalid/,
  );
});

test("packaging maps the approved runtime into the native resource location and refuses stale sources", async (t) => {
  const { packageConfiguration } = await import("./package_desktop.mjs");
  const profile = JSON.parse(
    await readFile(
      new URL("../runtime/profiles.json", import.meta.url),
      "utf8",
    ),
  ).profiles["cpu-ort"];
  const f = await fixture(t);
  await signCandidate(
    f.root,
    join(f.root, "manifest.sig"),
    f.privatePem,
    f.policy,
  );
  await assert.rejects(
    packageConfiguration(f.root, f.policy),
    /runtime_bundle_source_unapproved/,
  );
  const provenance = JSON.parse(
    await readFile(join(f.root, "payload/provenance.json"), "utf8"),
  );
  provenance.sourceRevision = profile.sourceRevision;
  const bytes = Buffer.from(JSON.stringify(provenance));
  f.manifest.sourceRevision = profile.sourceRevision;
  f.manifest.files["provenance.json"] = {
    bytes: bytes.length,
    sha256: createHash("sha256").update(bytes).digest("hex"),
  };
  await writeFile(join(f.root, "payload/provenance.json"), bytes);
  await writeFile(join(f.root, "manifest.json"), JSON.stringify(f.manifest));
  await rm(join(f.root, "manifest.sig"));
  await signCandidate(
    f.root,
    join(f.root, "manifest.sig"),
    f.privatePem,
    f.policy,
  );
  const config = await packageConfiguration(f.root, f.policy);
  assert.deepEqual(config.bundle.resources, {
    [join(f.root, "manifest.json")]: "native-runtime/manifest.json",
    [join(f.root, "manifest.sig")]: "native-runtime/manifest.sig",
    [join(f.root, "payload")]: "native-runtime/payload",
  });
  await writeFile(join(f.root, "payload/python"), "changed");
  await assert.rejects(
    packageConfiguration(f.root, f.policy),
    /artifact_changed/,
  );
});

test("desktop packaging refuses missing runtime input before invoking the app builder", async () => {
  const { spawnSync } = await import("node:child_process");
  const result = spawnSync(
    process.execPath,
    [fileURLToPath(new URL("./package_desktop.mjs", import.meta.url))],
    { encoding: "utf8" },
  );
  assert.equal(result.status, 1);
  assert.match(result.stderr, /usage: --runtime SIGNED_PACK/);
});

test("packaging refuses a correctly signed runtime for another operating system", async (t) => {
  const { packageConfiguration } = await import("./package_desktop.mjs");
  const f = await fixture(t);
  f.manifest.platform = f.manifest.platform === "linux" ? "macos" : "linux";
  await writeFile(join(f.root, "manifest.json"), JSON.stringify(f.manifest));
  await signCandidate(
    f.root,
    join(f.root, "manifest.sig"),
    f.privatePem,
    f.policy,
  );
  await assert.rejects(
    packageConfiguration(f.root, f.policy),
    /runtime_bundle_target_mismatch/,
  );
});

for (const namespace of ["immich_ml", "frameleaf_ml", "foreign", null]) {
  test(`runtime signing restricts module namespace ${namespace}`, async (t) => {
    const f = await fixture(t);
    f.manifest.moduleNamespace = namespace;
    await writeFile(join(f.root, "manifest.json"), JSON.stringify(f.manifest));
    const signing = signCandidate(
      f.root,
      join(f.root, "manifest.sig"),
      f.privatePem,
      f.policy,
    );
    if (["immich_ml", "frameleaf_ml"].includes(namespace)) await signing;
    else await assert.rejects(signing, /runtime_manifest_invalid/);
  });
}

test("PR274 CPU source is packageable only through its qualified macOS ARM64 approval", async (t) => {
  const { packageConfiguration } = await import("./package_desktop.mjs");
  const profiles = JSON.parse(
    await readFile(
      new URL("../runtime/profiles.json", import.meta.url),
      "utf8",
    ),
  ).profiles;
  const source = "1ca4d52e2b8158d89d8de8b17e1e6535e17691f4";
  assert.equal(
    profiles["cpu-ort"].sourceRevision,
    "25b22c16e47a27a2eb50017d838497abce850d11",
  );
  assert.deepEqual(profiles["cpu-ort"].additionalSources["macos-aarch64"], [source, "f93c34d196955da3e2760c095c08b27ccbf53315"]);
  assert.deepEqual(profiles["cpu-ort"].additionalSources["linux-aarch64"], ["f93c34d196955da3e2760c095c08b27ccbf53315"]);
  assert.equal(
    profiles["coreml-ort"].sourceRevision,
    "25b22c16e47a27a2eb50017d838497abce850d11",
  );
  const f = await fixture(t);
  const provenance = JSON.parse(
    await readFile(join(f.root, "payload/provenance.json"), "utf8"),
  );
  provenance.sourceRevision = source;
  const bytes = Buffer.from(JSON.stringify(provenance));
  f.manifest.sourceRevision = source;
  f.manifest.moduleNamespace = "frameleaf_ml";
  f.manifest.files["provenance.json"] = {
    bytes: bytes.length,
    sha256: createHash("sha256").update(bytes).digest("hex"),
  };
  await writeFile(join(f.root, "payload/provenance.json"), bytes);
  await writeFile(join(f.root, "manifest.json"), JSON.stringify(f.manifest));
  await signCandidate(
    f.root,
    join(f.root, "manifest.sig"),
    f.privatePem,
    f.policy,
  );
  if (process.platform !== "darwin" || process.arch !== "arm64") {
    await assert.rejects(
      packageConfiguration(f.root, f.policy),
      /runtime_bundle_source_unapproved/,
    );
    return;
  }
  const config = await packageConfiguration(f.root, f.policy);
  assert.equal(
    config.bundle.resources[join(f.root, "payload")],
    "native-runtime/payload",
  );
});

for (const [source, targets] of [
  ["f93c34d196955da3e2760c095c08b27ccbf53315", ["linux-aarch64", "macos-aarch64"]],
  ["0d9702c68f31ea3eea068ac59ca1cf36a2b520fc", ["linux-x86_64"]],
]) {
  test(`CPU source ${source} packages only on its qualified targets`, async (t) => {
    const { packageConfiguration } = await import("./package_desktop.mjs");
    const profiles = JSON.parse(
      await readFile(new URL("../runtime/profiles.json", import.meta.url), "utf8"),
    ).profiles;
    const approvedTargets = Object.entries(profiles["cpu-ort"].additionalSources)
      .filter(([, sources]) => sources.includes(source)).map(([target]) => target).sort();
    assert.deepEqual(approvedTargets, [...targets].sort());
    for (const [name, profile] of Object.entries(profiles)) {
      if (name !== "cpu-ort") {
        assert.notEqual(profile.sourceRevision, source);
        assert(!Object.values(profile.additionalSources ?? {}).flat().includes(source));
      }
    }
    const f = await fixture(t);
    const provenance = JSON.parse(
      await readFile(join(f.root, "payload/provenance.json"), "utf8"),
    );
    provenance.sourceRevision = source;
    const bytes = Buffer.from(JSON.stringify(provenance));
    f.manifest.sourceRevision = source;
    f.manifest.moduleNamespace = "frameleaf_ml";
    f.manifest.files["provenance.json"] = {
      bytes: bytes.length,
      sha256: createHash("sha256").update(bytes).digest("hex"),
    };
    await writeFile(join(f.root, "payload/provenance.json"), bytes);
    await writeFile(join(f.root, "manifest.json"), JSON.stringify(f.manifest));
    await signCandidate(
      f.root,
      join(f.root, "manifest.sig"),
      f.privatePem,
      f.policy,
    );
    const hostTarget = `${process.platform === "darwin" ? "macos" : process.platform}-${process.arch === "arm64" ? "aarch64" : "x86_64"}`;
    if (!targets.includes(hostTarget)) {
      await assert.rejects(
        packageConfiguration(f.root, f.policy),
        /runtime_bundle_source_unapproved/,
      );
      return;
    }
    const config = await packageConfiguration(f.root, f.policy);
    assert.equal(
      config.bundle.resources[join(f.root, "payload")],
      "native-runtime/payload",
    );
  });
}

test("CUDA authoring signs only its declared desktop targets and provenance", async (t) => {
  const { packageConfiguration } = await import("./package_desktop.mjs");
  const profiles = JSON.parse(
    await readFile(new URL("../runtime/profiles.json", import.meta.url), "utf8"),
  ).profiles;
  const authored = profiles["cuda-ort"];
  assert.equal(authored.extra, "cuda");
  assert.deepEqual(authored.targets, ["windows-x86_64", "linux-x86_64"]);
  for (const [platform, architecture, allowed] of [
    ["windows", "x86_64", true],
    ["linux", "x86_64", true],
    ["macos", "aarch64", false],
    ["windows", "aarch64", false],
    ["linux", "aarch64", false],
  ]) {
    const f = await fixture(t);
    const provenance = {
      schemaVersion: 1,
      sourceRevision: authored.sourceRevision,
      sourceRepository: "Frameleaf/frameleaf-app",
      profile: "cuda-ort",
      python: authored.python,
    };
    const bytes = Buffer.from(JSON.stringify(provenance));
    await writeFile(join(f.root, "payload/provenance.json"), bytes);
    Object.assign(f.manifest, {
      platform, architecture, provider: "CUDAExecutionProvider",
      sourceRevision: authored.sourceRevision,
    });
    f.manifest.files["provenance.json"] = {
      bytes: bytes.length,
      sha256: createHash("sha256").update(bytes).digest("hex"),
    };
    await writeFile(join(f.root, "manifest.json"), JSON.stringify(f.manifest));
    const sign = () => signCandidate(
      f.root, join(f.root, "manifest.sig"), f.privatePem, f.policy,
    );
    if (!allowed) {
      await assert.rejects(sign(), /runtime_profile_unapproved/);
      continue;
    }
    await sign();
    assert(verify(
      null, await readFile(join(f.root, "manifest.json")), f.keys.publicKey,
      await readFile(join(f.root, "manifest.sig")),
    ));
    const host = { win32: "windows", linux: "linux", darwin: "macos" }[process.platform];
    if (host === platform && process.arch === "x64") {
      const config = await packageConfiguration(f.root, f.policy);
      assert.equal(config.bundle.resources[join(f.root, "payload")], "native-runtime/payload");
    } else {
      await assert.rejects(packageConfiguration(f.root, f.policy), /runtime_bundle_target_mismatch/);
    }
  }
  const f = await fixture(t);
  Object.assign(f.manifest, {
    platform: "windows", architecture: "x86_64", provider: "CUDAExecutionProvider",
  });
  await writeFile(join(f.root, "manifest.json"), JSON.stringify(f.manifest));
  await assert.rejects(
    signCandidate(f.root, join(f.root, "manifest.sig"), f.privatePem, f.policy),
    /runtime_provenance_invalid/,
  );
});


test("current CoreML desktop source packages only on qualified macOS ARM64", async (t) => {
  const { packageConfiguration } = await import("./package_desktop.mjs");
  const profiles = JSON.parse(await readFile(new URL("../runtime/profiles.json", import.meta.url), "utf8")).profiles;
  const source = "b7b5756a3f9eaeec9e977460ab654cbbadee87e7";
  assert.deepEqual(profiles["coreml-ort"].additionalSources, { "macos-aarch64": [source] });
  for (const [revision, provider, allowed] of [
    [source, "CoreMLExecutionProvider", true],
    ["db72dcde18d3a4ff4ab5cfed3fb650a6b3629353", "CoreMLExecutionProvider", false],
    ["f".repeat(40), "CoreMLExecutionProvider", false],
    [source, "CPUExecutionProvider", false],
  ]) {
    const f = await fixture(t);
    const provenance = { schemaVersion: 1, sourceRepository: "Frameleaf/frameleaf-app", sourceRevision: revision,
      profile: provider === "CoreMLExecutionProvider" ? "coreml-ort" : "cpu-ort", python: "3.12.13" };
    const bytes = Buffer.from(JSON.stringify(provenance));
    await writeFile(join(f.root, "payload/provenance.json"), bytes);
    Object.assign(f.manifest, { platform: "macos", architecture: "aarch64", provider, sourceRevision: revision, moduleNamespace: "frameleaf_ml" });
    f.manifest.files["provenance.json"] = { bytes: bytes.length, sha256: createHash("sha256").update(bytes).digest("hex") };
    await writeFile(join(f.root, "manifest.json"), JSON.stringify(f.manifest));
    await signCandidate(f.root, join(f.root, "manifest.sig"), f.privatePem, f.policy);
    if (process.platform !== "darwin" || process.arch !== "arm64") {
      await assert.rejects(packageConfiguration(f.root, f.policy), /runtime_bundle_target_mismatch/);
    } else if (!allowed) {
      await assert.rejects(packageConfiguration(f.root, f.policy), /runtime_bundle_source_unapproved/);
    } else {
      const config = await packageConfiguration(f.root, f.policy);
      assert.equal(config.bundle.resources[join(f.root, "payload")], "native-runtime/payload");
    }
  }
});
