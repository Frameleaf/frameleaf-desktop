import { test } from "node:test";
import assert from "node:assert/strict";
import { releaseMatrix, validateReleaseTag } from "./release_inputs.mjs";

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
