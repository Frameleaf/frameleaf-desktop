import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

export function validateFactoryRun(run, repository) {
  if (
    !run || run.status !== "completed" || run.conclusion !== "success" ||
    run.head_branch !== "main" || run.event !== "workflow_dispatch" ||
    typeof run.path !== "string" ||
    run.path.split("@")[0] !== ".github/workflows/factory-runtime.yml" ||
    run.repository?.full_name !== repository ||
    typeof run.head_sha !== "string" || run.head_sha.length !== 40 ||
    !/^[a-f0-9]{40}$/.test(run.head_sha)
  ) throw new Error("runtime_run_untrusted");
  return run.head_sha;
}

export function releaseMatrix(platforms) {
  if (!["macos-linux", "all", "linux"].includes(platforms))
    throw new Error("release_platforms_invalid");
  return { include: [
    ...(platforms !== "linux" ? [
      { os: "macos-15", target: "macos-aarch64" },
      { os: "macos-15-intel", target: "macos-x86_64" },
    ] : []),
    ...(platforms === "all" ? [{ os: "windows-2022", target: "windows-x86_64" }] : []),
    { os: "ubuntu-24.04", target: "linux-x86_64" },
    { os: "ubuntu-24.04-arm", target: "linux-aarch64" },
  ] };
}

export function validateReleaseTag(tag, versions) {
  const number = "(?:0|[1-9][0-9]*)";
  const identifier = `(?:${number}|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*)`;
  if (typeof tag !== "string" || !new RegExp(`^v${number}\\.${number}\\.${number}(?:-${identifier}(?:\\.${identifier})*)?$`).test(tag) || /\s/.test(tag))
    throw new Error("release_version_invalid");
  if (!versions.length || versions.some((version) => `v${version}` !== tag))
    throw new Error("release_version_mismatch");
  return tag;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const root = new URL("../", import.meta.url);
  const pkg = JSON.parse(await readFile(new URL("package.json", root), "utf8"));
  const config = JSON.parse(await readFile(new URL("src-tauri/tauri.conf.json", root), "utf8"));
  const cargo = await readFile(new URL("src-tauri/Cargo.toml", root), "utf8");
  const version = cargo.match(/^version\s*=\s*"([^"]+)"/m)?.[1];
  console.log(validateReleaseTag(process.argv[2], [pkg.version, config.version, version]));
}
