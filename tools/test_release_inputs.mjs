import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { releaseMatrix, validateReleaseTag, validateFactoryRun } from "./release_inputs.mjs";

test("release tags must match all application versions", () => {
  assert.equal(validateReleaseTag("v0.1.0", ["0.1.0", "0.1.0", "0.1.0"]), "v0.1.0");
  assert.equal(validateReleaseTag("v1.2.3-rc.1", ["1.2.3-rc.1"]), "v1.2.3-rc.1");
  for (const tag of ["main", "v0.1.0/other", "v0.1.0\n", "v01.1.0", "v0.1.0;echo", "v0.1.0-01"]) {
    assert.throws(() => validateReleaseTag(tag, [tag.slice(1)]), /release_version_invalid/);
  }
  assert.throws(() => validateReleaseTag("v0.1.0", ["0.1.0", "0.2.0"]), /release_version_mismatch/);
  assert.throws(() => validateReleaseTag("v0.1.0", []), /release_version_mismatch/);
});

test("release selections cover the supported architectures without adding Windows implicitly", () => {
  const linux = [
    { os: "ubuntu-24.04", target: "linux-x86_64" },
    { os: "ubuntu-24.04-arm", target: "linux-aarch64" },
  ];
  const macos = [
    { os: "macos-15", target: "macos-aarch64" },
    { os: "macos-15-intel", target: "macos-x86_64" },
  ];
  assert.deepEqual(releaseMatrix("macos-linux").include, [...macos, ...linux]);
  assert.deepEqual(releaseMatrix("all").include, [
    ...macos,
    { os: "windows-2022", target: "windows-x86_64" },
    ...linux,
  ]);
  assert.deepEqual(releaseMatrix("macos-aarch64").include, [macos[0]]);
  assert.deepEqual(releaseMatrix("linux").include, linux);
  assert.throws(() => releaseMatrix("anything"), /release_platforms_invalid/);
});

// Runtime consumers must reject artifacts from other workflows or untrusted refs.
test("private installer inputs require a successful main factory dispatch", () => {
  const run = { status: "completed", conclusion: "success", head_branch: "main",
    event: "workflow_dispatch", path: ".github/workflows/factory-runtime.yml@main",
    head_sha: "a".repeat(40), repository: { full_name: "Frameleaf/frameleaf-desktop" } };
  for (const path of [".github/workflows/factory-runtime.yml", ".github/workflows/factory-runtime.yml@main",
    ".github/workflows/factory-runtime.yml@refs/heads/main"]) {
    assert.equal(validateFactoryRun({ ...run, path }, "Frameleaf/frameleaf-desktop"), run.head_sha);
  }
  for (const changed of [null, {}, { ...run, status: "in_progress" },
    { ...run, conclusion: "failure" }, { ...run, head_branch: "other" },
    { ...run, event: "pull_request_target" }, { ...run, event: "pull_request" },
    { ...run, path: ".github/workflows/desktop.yml" },
    { ...run, path: ".github/workflows/desktop.yml@main" }, { ...run, path: null },
    { ...run, repository: { full_name: "attacker/fork" } },
    { ...run, repository: null }, { ...run, head_sha: "main" },
    { ...run, head_sha: "A".repeat(40) }, { ...run, head_sha: "a".repeat(40) + "\n" }]) {
    assert.throws(() => validateFactoryRun(changed, "Frameleaf/frameleaf-desktop"), /runtime_run_untrusted/);
  }
});

test("factory Windows selection builds one native target without changing the full matrix", () => {
  assert.deepEqual(releaseMatrix("windows"), { include: [
    { os: "windows-2022", target: "windows-x86_64" },
  ] });
});

test("update manifests match each installed package format to its signed asset", async () => {
  const { updateManifest } = await import("./release_inputs.mjs");
  const signature = "c2lnbmF0dXJl";
  const files = {
    "Frameleaf_1.2.3_aarch64.app.tar.gz": signature,
    "Frameleaf_1.2.3_amd64.AppImage": signature,
    "Frameleaf_1.2.3_amd64.deb": signature,
    "Frameleaf_1.2.3_x64-setup.exe": signature,
    "Frameleaf_1.2.3_x64_en-US.msi": signature,
  };
  const manifest = updateManifest("v1.2.3", "Frameleaf/frameleaf-desktop", files);
  assert.equal(manifest.version, "1.2.3");
  assert.deepEqual(Object.keys(manifest.platforms).sort(), [
    "darwin-aarch64-app", "linux-x86_64-appimage", "linux-x86_64-deb", "windows-x86_64-msi", "windows-x86_64-nsis",
  ]);
  assert.deepEqual(manifest.platforms["windows-x86_64-msi"], {
    url: "https://github.com/Frameleaf/frameleaf-desktop/releases/download/v1.2.3/Frameleaf_1.2.3_x64_en-US.msi",
    signature,
  });
  assert.throws(() => updateManifest("v1.2.3", "Frameleaf/frameleaf-desktop", {}), /update_assets_missing/);
  assert.throws(() => updateManifest("v1.2.3", "Frameleaf/frameleaf-desktop", {
    "Frameleaf_1.2.3_amd64.deb": "",
  }), /update_signature_invalid/);
});

test("updater verification requires the embedded key, exact bytes and release version", {
  skip: spawnSync("minisign", ["-v"]).error?.code === "ENOENT" && "minisign is unavailable",
}, async () => {
  const { verifyUpdaterAsset } = await import("./release_inputs.mjs");
  const dir = mkdtempSync(join(tmpdir(), "frameleaf-updater-test-"));
  try {
    const asset = join(dir, "desktop.deb");
    const pubkey = join(dir, "public");
    const secret = join(dir, "secret");
    const otherPubkey = join(dir, "other-public");
    const otherSecret = join(dir, "other-secret");
    execFileSync("minisign", ["-GW", "-p", pubkey, "-s", secret]);
    execFileSync("minisign", ["-GW", "-p", otherPubkey, "-s", otherSecret]);
    writeFileSync(asset, "signed package fixture");
    const signaturePath = join(dir, "signature");
    execFileSync("minisign", ["-S", "-s", secret, "-m", asset, "-x", signaturePath, "-t", "timestamp:0\tfile:desktop.deb\tversion:1.2.3"]);
    const signature = readFileSync(signaturePath).toString("base64");
    const trusted = readFileSync(pubkey).toString("base64");
    const other = readFileSync(otherPubkey).toString("base64");

    assert.doesNotThrow(() => verifyUpdaterAsset(asset, signature, trusted, "1.2.3"));
    assert.throws(() => verifyUpdaterAsset(asset, signature, trusted, "1.2.4"), /update_signature_version_mismatch/);
    assert.throws(() => verifyUpdaterAsset(asset, signature, other, "1.2.3"), /update_signature_verification_failed/);
    const editedComment = Buffer.from(readFileSync(signaturePath, "utf8").replace("version:1.2.3", "version:1.2.4")).toString("base64");
    assert.throws(() => verifyUpdaterAsset(asset, editedComment, trusted, "1.2.4"), /update_signature_verification_failed/);
    writeFileSync(asset, "changed package fixture");
    assert.throws(() => verifyUpdaterAsset(asset, signature, trusted, "1.2.3"), /update_signature_verification_failed/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
