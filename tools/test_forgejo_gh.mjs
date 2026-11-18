import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { GITHUB_REPOSITORY_ID, REPOSITORY, answer, apiCall, downloads, githubRun } from "./forgejo_gh.mjs";
import { validateDispatchRun } from "./release_inputs.mjs";

const SHA = "a5a9ebef42a1881e9b5646acc9cec35f97ccf146";
// Shapes as Forgejo 17 returns them (trimmed).
const run = {
  id: 507, index_in_repo: 7, workflow_id: "factory-runtime.yml", prettyref: "main", commit_sha: SHA,
  trigger_event: "workflow_dispatch", event: "", status: "success",
  repository: { id: 6, name: "frameleaf-desktop", full_name: REPOSITORY },
  started: "2026-11-18T06:19:41-07:00", created: "2026-11-18T06:19:41-07:00", updated: "2026-11-18T07:02:56-07:00",
  html_url: "https://code.heroapps.ca/Frameleaf/frameleaf-desktop/actions/runs/7",
};
const jobs = [{ id: 2405, run_id: 507, attempt: 1, name: "build", status: "success" }];
const bytes = Buffer.from("PK\u0003\u0004 an artifact archive");
const artifact = (id, name, extra = {}) => ({
  id, name, size_in_bytes: bytes.length, expired: false, run_id: 507,
  created_at: "2026-11-18T06:32:07-07:00", updated_at: "2026-11-18T06:32:12-07:00", ...extra,
});

function fake(overrides = {}, artifacts = [artifact(110, "factory-runtime-windows-x86_64")]) {
  const asked = [];
  const request = async (path, { raw = false } = {}) => {
    asked.push(path);
    if (raw) return new Response(bytes);
    if (path in overrides) return overrides[path];
    if (path === "actions/runs/507") return run;
    if (path === "actions/runs/507/jobs") return jobs;
    const page = /^actions\/runs\/507\/artifacts\?page=(\d+)&limit=50$/.exec(path);
    if (page) return artifacts.slice((page[1] - 1) * 50, page[1] * 50);
    const one = /^actions\/artifacts\/(\d+)$/.exec(path);
    if (one) return artifacts.find((a) => a.id === Number(one[1]));
    throw new Error(`unexpected ${path}`);
  };
  return { request, asked };
}

test("a Forgejo run reads as the GitHub run the release checks accept", async () => {
  const mapped = await answer("runs/507", fake().request);
  assert.equal(validateDispatchRun(mapped, REPOSITORY, ".github/workflows/factory-runtime.yml", "untrusted"), SHA);
  assert.deepEqual(mapped.repository, { id: GITHUB_REPOSITORY_ID, full_name: REPOSITORY });
  assert.equal(mapped.run_attempt, 1);
  assert.equal(mapped.run_number, 7);
});

test("only finished runs are completed, and only runs of this repository are answered", async () => {
  const running = await answer("runs/507", fake({ "actions/runs/507": { ...run, status: "running" } }).request);
  assert.deepEqual([running.status, running.conclusion], ["running", null]);
  assert.throws(() => validateDispatchRun(running, REPOSITORY, ".github/workflows/factory-runtime.yml", "untrusted"), /untrusted/);
  const foreign = { ...run, repository: { id: 9, full_name: "Someone/frameleaf-desktop" } };
  await assert.rejects(answer("runs/507", fake({ "actions/runs/507": foreign }).request), /foreign_repository/);
  assert.throws(() => githubRun(run, null), /jobs_invalid/);
});

test("an attempt is answered only when it is the run's latest", async () => {
  assert.equal((await answer("runs/507/attempts/1", fake().request)).id, 507);
  await assert.rejects(answer("runs/507/attempts/2", fake().request), /attempt_unavailable/);
  const rerun = fake({ "actions/runs/507/jobs": [{ ...jobs[0], attempt: 2 }] });
  assert.equal((await answer("runs/507/attempts/2", rerun.request)).run_attempt, 2);
});

test("every page of a run's artifacts is listed", async () => {
  const many = Array.from({ length: 51 }, (_, i) => artifact(200 + i, `part-${i}`));
  const { request, asked } = fake({}, many);
  const listed = await answer("runs/507/artifacts?per_page=100", request);
  assert.equal(listed.total_count, 51);
  assert.equal(listed.artifacts[50].name, "part-50");
  assert.ok(asked.includes("actions/runs/507/artifacts?page=2&limit=50"));
});

test("an artifact carries the digest of the archive Forgejo serves and passes the component producer check", async () => {
  const digest = createHash("sha256").update(bytes).digest("hex");
  const cache = mkdtempSync(join(tmpdir(), "forgejo-gh-test-"));
  const { request, asked } = fake();
  const mapped = await answer("artifacts/110", request, cache);
  assert.equal(mapped.digest, `sha256:${digest}`);
  // The archive crosses the network once: the download serves the measured bytes.
  const kept = await answer("artifacts/110/zip", request, cache);
  assert.deepEqual(Buffer.from(await kept.arrayBuffer()), bytes);
  assert.equal(asked.filter((path) => path === "actions/artifacts/110/zip").length, 1);
  rmSync(cache, { recursive: true, force: true });
  const producer = await answer("runs/507/attempts/1", fake().request);
  const approved = { artifactId: 110, runId: 507, runAttempt: 1, headSha: SHA, workflow: ".github/workflows/factory-runtime.yml", archiveSha256: digest };
  const check = spawnSync("python3", ["-I", "-c", [
    "import json, sys",
    `sys.path.insert(0, ${JSON.stringify(join(import.meta.dirname))})`,
    "from obtain_host_component import validate_producer",
    "approved, artifact, run = json.loads(sys.stdin.read())",
    "validate_producer(approved, artifact, run)",
  ].join("\n")], { input: JSON.stringify([approved, mapped, producer]), encoding: "utf8" });
  if (check.error?.code === "ENOENT") return; // no python3 (Windows): the Node checks above still ran
  assert.equal(check.status, 0, check.stderr);
});

test("the archive endpoint streams the bytes; other Actions endpoints are refused", async () => {
  const response = await answer("artifacts/110/zip", fake().request, join(tmpdir(), "forgejo-gh-none"));
  assert.deepEqual(Buffer.from(await response.arrayBuffer()), bytes);
  await assert.rejects(answer("workflows/release.yml/runs", fake().request), /unsupported/);
});

test("run download places one named artifact in the folder, several in folders of their names", () => {
  const all = [artifact(1, "factory-runtime-linux-x86_64"), artifact(2, "factory-accelerated-parts-a"),
    artifact(3, "factory-accelerated-manifest-a"), artifact(4, "factory-accelerated-old", { expired: true })];
  assert.deepEqual(downloads(all, ["factory-runtime-linux-x86_64"], [], "d").map(({ artifact, into }) => [artifact.id, into]), [[1, "d"]]);
  assert.deepEqual(downloads(all, [], ["factory-accelerated-*"], "d").map(({ into }) => into),
    [join("d", "factory-accelerated-parts-a"), join("d", "factory-accelerated-manifest-a")]);
  assert.throws(() => downloads(all, ["factory-accelerated-old"], [], "d"), /no_artifact/);
  assert.throws(() => downloads(all, [], ["nothing-*"], "d"), /no_artifact/);
});

test("gh api calls are parsed the way the workflows write them", () => {
  assert.deepEqual(apiCall(["--paginate", `repos/${REPOSITORY}/actions/runs/5/artifacts?per_page=100`, "--jq", ".artifacts[] | {name, expired}"]),
    { path: `repos/${REPOSITORY}/actions/runs/5/artifacts?per_page=100`, jq: ".artifacts[] | {name, expired}" });
  assert.deepEqual(apiCall([`repos/${REPOSITORY}/releases/assets/9`, "-H", "Accept: application/octet-stream"]),
    { path: `repos/${REPOSITORY}/releases/assets/9`, jq: undefined });
  assert.deepEqual(apiCall(["--method", "POST", "x"]), {});
});
