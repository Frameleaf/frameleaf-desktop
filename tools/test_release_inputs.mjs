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

test("release selection omits Windows until signing is configured", () => {
  assert.deepEqual(releaseMatrix("macos-linux").include.map((p) => p.target), ["macos-aarch64", "linux-x86_64"]);
  assert.equal(releaseMatrix("all").include.length, 3);
  assert.deepEqual(releaseMatrix("linux").include, [{ os: "ubuntu-24.04", target: "linux-x86_64" }]);
  assert.throws(() => releaseMatrix("anything"), /release_platforms_invalid/);
});
