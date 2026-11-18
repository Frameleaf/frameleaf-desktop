#!/usr/bin/env node
// FL-1699: `gh` for jobs that run on Forgejo (code.heroapps.ca). There this repository's workflow
// runs and artifacts live on Forgejo, while git tags, releases and frameleaf-app stay on GitHub.
// The Actions calls the release workflows and tools make (`gh api repos/<this repo>/actions/...`
// and `gh run download`) are answered from Forgejo's API in GitHub's shape, so the run checks in
// release_inputs.mjs, release_prerequisites.mjs and obtain_host_component.py apply unchanged.
// Every other call goes to the real gh (GH_SHIM_REAL), and so to GitHub with GH_TOKEN.
// .github/actions/forgejo-gh puts this first on PATH; it is never used on GitHub.
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { createReadStream, createWriteStream, existsSync, mkdirSync, mkdtempSync, renameSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Readable } from "node:stream";
import { pipeline } from "node:stream/promises";
import { fileURLToPath } from "node:url";

export const REPOSITORY = "Frameleaf/frameleaf-desktop";
// The same repository's id on GitHub (obtain_host_component.REPOSITORY_ID): Forgejo is its mirror,
// and only runs of this exact repository are ever answered.
export const GITHUB_REPOSITORY_ID = 1421136454;
const ACTIONS = new RegExp(`^/?repos/${REPOSITORY}/actions/(.+)$`);
const DONE = new Set(["success", "failure", "cancelled", "skipped"]);
const PAGE = 50;

/** A Forgejo API request for this repository: JSON, or the raw response when `raw`. */
export async function forgejo(path, { raw = false } = {}, env = process.env) {
  const base = (env.GITHUB_API_URL || "").replace(/\/+$/, "");
  if (!/^https?:\/\//.test(base) || base === "https://api.github.com") throw new Error("forgejo_gh_not_on_forgejo");
  const response = await fetch(`${base}/repos/${REPOSITORY}/${path}`, {
    headers: { Accept: raw ? "application/octet-stream" : "application/json", ...(env.GH_SHIM_FORGEJO_TOKEN && { Authorization: `token ${env.GH_SHIM_FORGEJO_TOKEN}` }) },
    signal: AbortSignal.timeout(raw ? 3_600_000 : 60_000),
  });
  if (!response.ok) throw new Error(`forgejo_gh_http_${response.status}: ${path}`);
  return raw ? response : response.json();
}

function repository(owner) {
  if (owner?.full_name !== REPOSITORY) throw new Error("forgejo_gh_foreign_repository");
  return { id: GITHUB_REPOSITORY_ID, full_name: REPOSITORY };
}

/** A Forgejo run and its jobs as GitHub's run object. */
export function githubRun(run, jobs) {
  if (!Array.isArray(jobs)) throw new Error("forgejo_gh_jobs_invalid");
  const done = DONE.has(run.status);
  return {
    id: run.id,
    run_number: run.index_in_repo,
    run_attempt: Math.max(1, ...jobs.map((job) => job.attempt || 1)),
    head_sha: run.commit_sha,
    head_branch: run.prettyref,
    event: run.trigger_event || run.event,
    status: done ? "completed" : run.status,
    conclusion: done ? run.status : null,
    path: `.github/workflows/${run.workflow_id}`,
    repository: repository(run.repository),
    head_repository: repository(run.repository),
    run_started_at: run.started,
    created_at: run.created,
    updated_at: run.updated,
    html_url: run.html_url,
  };
}

/** A Forgejo artifact as GitHub's artifact object; `digest` only when it was measured. */
export function githubArtifact(artifact, run, digest) {
  return {
    id: artifact.id,
    name: artifact.name,
    size_in_bytes: artifact.size_in_bytes,
    expired: artifact.expired,
    created_at: artifact.created_at,
    updated_at: artifact.updated_at,
    ...(digest && { digest: `sha256:${digest}` }),
    workflow_run: {
      id: run.id,
      repository_id: GITHUB_REPOSITORY_ID,
      head_repository_id: GITHUB_REPOSITORY_ID,
      head_branch: run.head_branch,
      head_sha: run.head_sha,
    },
  };
}

async function runOf(id, request) {
  return githubRun(await request(`actions/runs/${id}`), await request(`actions/runs/${id}/jobs`));
}

async function artifactsOf(id, request) {
  const all = [];
  for (let page = 1; ; page++) {
    const rows = await request(`actions/runs/${id}/artifacts?page=${page}&limit=${PAGE}`);
    if (!Array.isArray(rows)) throw new Error("forgejo_gh_artifacts_invalid");
    all.push(...rows);
    if (rows.length < PAGE) return all;
  }
}

/** Where measured archives are kept for the job, so an archive crosses the network once. */
export function archives(env = process.env) {
  return join(env.RUNNER_TEMP || tmpdir(), "forgejo-gh-archives");
}

// Forgejo records no artifact digest; GitHub's is the SHA-256 of the archive it serves, so it is
// measured from the bytes Forgejo serves, and those bytes are kept: a later `.../zip` call returns
// exactly what was measured (the tools hash their download against the approval again).
async function measure(id, request, cache) {
  mkdirSync(cache, { recursive: true, mode: 0o700 });
  const kept = join(cache, `${id}.zip`), partial = `${kept}.partial`;
  const hash = createHash("sha256"), output = createWriteStream(partial, { flags: "wx", mode: 0o600 });
  try {
    for await (const chunk of (await request(`actions/artifacts/${id}/zip`, { raw: true })).body) {
      hash.update(chunk);
      if (!output.write(chunk)) await new Promise((resolve) => output.once("drain", resolve));
    }
    await new Promise((resolve, reject) => output.end((error) => (error ? reject(error) : resolve())));
    renameSync(partial, kept);
  } catch (error) {
    output.destroy();
    rmSync(partial, { force: true });
    throw error;
  }
  return hash.digest("hex");
}

/** The answer to `gh api repos/<this repo>/actions/<endpoint>`: JSON, or a response to stream. */
export async function answer(endpoint, request = forgejo, cache = archives()) {
  const [path] = endpoint.split("?");
  let match = /^runs\/(\d+)$/.exec(path);
  if (match) return runOf(match[1], request);
  match = /^runs\/(\d+)\/attempts\/(\d+)$/.exec(path);
  if (match) {
    const run = await runOf(match[1], request);
    if (run.run_attempt !== Number(match[2])) throw new Error("forgejo_gh_attempt_unavailable");
    return run;
  }
  match = /^runs\/(\d+)\/artifacts$/.exec(path);
  if (match) {
    const run = await runOf(match[1], request);
    const artifacts = (await artifactsOf(match[1], request)).map((artifact) => githubArtifact(artifact, run));
    return { total_count: artifacts.length, artifacts };
  }
  match = /^artifacts\/(\d+)$/.exec(path);
  if (match) {
    const artifact = await request(`actions/artifacts/${match[1]}`);
    return githubArtifact(artifact, await runOf(artifact.run_id, request), await measure(match[1], request, cache));
  }
  match = /^artifacts\/(\d+)\/zip$/.exec(path);
  if (match) {
    const kept = join(cache, `${match[1]}.zip`);
    return existsSync(kept) ? new Response(Readable.toWeb(createReadStream(kept))) : request(`actions/artifacts/${match[1]}/zip`, { raw: true });
  }
  throw new Error(`forgejo_gh_unsupported: actions/${endpoint}`);
}

function glob(pattern) {
  return new RegExp(`^${pattern.replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*").replace(/\?/g, ".")}$`);
}

/** The artifacts `gh run download` takes and where each goes: one `--name` alone into `dir`, else `dir/<name>`. */
export function downloads(artifacts, names, patterns, dir) {
  const live = artifacts.filter((artifact) => artifact.expired === false);
  const chosen = live.filter((a) => names.includes(a.name) || patterns.some((p) => glob(p).test(a.name)));
  for (const name of names) if (!chosen.some((a) => a.name === name)) throw new Error(`forgejo_gh_no_artifact: ${name}`);
  if (!chosen.length) throw new Error("forgejo_gh_no_artifact");
  const alone = names.length === 1 && !patterns.length;
  return chosen.map((artifact) => ({ artifact, into: alone ? dir : join(dir, artifact.name) }));
}

function extract(zip, into) {
  mkdirSync(into, { recursive: true });
  // zipfile drops absolute and parent components from member names, so nothing lands outside `into`.
  for (const python of ["python3", "python"]) {
    const result = spawnSync(python, ["-I", "-m", "zipfile", "-e", zip, into], { stdio: "inherit" });
    if (!result.error) {
      if (result.status !== 0) throw new Error("forgejo_gh_extract_failed");
      return;
    }
  }
  throw new Error("forgejo_gh_needs_python");
}

async function runDownload(args, request = forgejo) {
  const names = [], patterns = [];
  let run, dir = ".";
  for (let i = 0; i < args.length; i++) {
    const option = args[i];
    if (option === "--name" || option === "-n") names.push(args[++i]);
    else if (option === "--pattern" || option === "-p") patterns.push(args[++i]);
    else if (option === "--dir" || option === "-D") dir = args[++i];
    else if (option === "--repo" || option === "-R") { if (args[++i] !== REPOSITORY) throw new Error("forgejo_gh_foreign_repository"); }
    else if (/^\d+$/.test(option) && !run) run = option;
    else throw new Error(`forgejo_gh_unsupported_option: ${option}`);
  }
  if (!run) throw new Error("forgejo_gh_run_required");
  const scratch = mkdtempSync(join(process.env.RUNNER_TEMP || tmpdir(), "forgejo-gh-"));
  try {
    for (const { artifact, into } of downloads(await artifactsOf(run, request), names, patterns, dir)) {
      const zip = join(scratch, `${artifact.id}.zip`);
      const response = await request(`actions/artifacts/${artifact.id}/zip`, { raw: true });
      await pipeline(Readable.fromWeb(response.body), createWriteStream(zip));
      extract(zip, into);
    }
  } finally {
    rmSync(scratch, { recursive: true, force: true });
  }
}

/** The endpoint of a `gh api` call, and its --jq filter. */
export function apiCall(args) {
  let path, jq;
  for (let i = 0; i < args.length; i++) {
    if (args[i] === "--jq" || args[i] === "-q") jq = args[++i];
    else if (args[i] === "-H" || args[i] === "--header") i++; // one Forgejo representation per endpoint
    else if (args[i] === "--paginate") continue; // every page is read
    else if (!args[i].startsWith("-") && !path) path = args[i];
    else return {};
  }
  return { path, jq };
}

async function api(args) {
  const { path, jq } = apiCall(args.slice(1));
  const actions = ACTIONS.exec(path ?? "");
  if (!actions) return passthrough(args);
  const result = await answer(actions[1]);
  if (result instanceof Response) return pipeline(Readable.fromWeb(result.body), process.stdout);
  const json = JSON.stringify(result);
  if (!jq) return void process.stdout.write(json + "\n");
  // gh prints strings raw and everything else as one compact JSON line, as `jq -r -c` does.
  const filtered = spawnSync("jq", ["-r", "-c", jq], { input: json, stdio: ["pipe", "inherit", "inherit"] });
  if (filtered.error || filtered.status !== 0) throw new Error("forgejo_gh_jq_failed");
}

function passthrough(args) {
  const real = process.env.GH_SHIM_REAL;
  if (!real) throw new Error("forgejo_gh_real_gh_missing");
  const result = spawnSync(real, args, { stdio: "inherit", env: { ...process.env, GH_HOST: "github.com" } });
  if (result.error) throw result.error;
  process.exit(result.status ?? 1);
}

export async function main(args) {
  if (args[0] === "api") return api(args);
  if (args[0] === "run" && args[1] === "download") return runDownload(args.slice(2));
  return passthrough(args);
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  main(process.argv.slice(2)).catch((error) => {
    process.stderr.write(`${error.message}\n`);
    process.exit(1);
  });
}
