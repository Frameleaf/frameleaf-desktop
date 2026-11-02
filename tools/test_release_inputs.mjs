import { test } from "node:test";
import assert from "node:assert/strict";
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
