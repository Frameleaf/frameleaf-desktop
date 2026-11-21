import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

/** The commit of a finished manual run of `workflow` on main in this repository; anything else is refused with `code`. */
export function validateDispatchRun(run, repository, workflow, code) {
  if (
    !run || run.status !== "completed" || run.conclusion !== "success" ||
    run.head_branch !== "main" || run.event !== "workflow_dispatch" ||
    typeof run.path !== "string" ||
    run.path.split("@")[0] !== workflow ||
    run.repository?.full_name !== repository ||
    typeof run.head_sha !== "string" || run.head_sha.length !== 40 ||
    !/^[a-f0-9]{40}$/.test(run.head_sha)
  ) throw new Error(code);
  return run.head_sha;
}

export function validateFactoryRun(run, repository) {
  return validateDispatchRun(run, repository, ".github/workflows/factory-runtime.yml", "runtime_run_untrusted");
}

const targets = {
  "macos-aarch64": { os: "macos-15", target: "macos-aarch64" },
  "macos-x86_64": { os: "macos-15-intel", target: "macos-x86_64" },
  "windows-x86_64": { os: "windows-2022", target: "windows-x86_64" },
  // Ubuntu 22.04 has glibc 2.35: what is built there also loads on Debian 12.
  "linux-x86_64": { os: "ubuntu-22.04", target: "linux-x86_64" },
  "linux-aarch64": { os: "ubuntu-22.04-arm", target: "linux-aarch64" },
};
const macos = ["macos-aarch64", "macos-x86_64"];
const linux = ["linux-x86_64", "linux-aarch64"];
// Every choice the release and factory workflows offer. Each platform can be selected alone,
// so one platform that cannot build or be signed never holds back the others.
const selections = {
  "macos-linux": [...macos, ...linux],
  all: [...macos, "windows-x86_64", ...linux],
  macos,
  linux,
  windows: ["windows-x86_64"],
  "macos-aarch64": ["macos-aarch64"],
  "macos-x86_64": ["macos-x86_64"],
  "linux-x86_64": ["linux-x86_64"],
  "linux-aarch64": ["linux-aarch64"],
};
export const releasePlatformChoices = Object.keys(selections);

// The label of the owner's own Mac on Forgejo, used for Apple Silicon only when the owner opted in.
export const OWNER_MAC_LABEL = "macos-26";

/** `ownerMac`: on Forgejo, with the owner's opt-in, Apple Silicon builds on the owner's own Mac. */
export function releaseMatrix(platforms, { ownerMac = false } = {}) {
  if (typeof platforms !== "string" || !Object.hasOwn(selections, platforms))
    throw new Error("release_platforms_invalid");
  return {
    include: selections[platforms].map((target) => ({
      ...targets[target],
      ...(ownerMac && target === "macos-aarch64" ? { os: OWNER_MAC_LABEL } : {}),
    })),
  };
}

// FL-1699: on Forgejo (code.heroapps.ca) the labels above stay GitHub's, and a target is built only
// where Forgejo has a runner it can safely use. Anything else is refused before a job is allocated.
const noForgejoRunner = {
  "macos-aarch64": "Forgejo's only Mac runner is the owner's own Mac, not a disposable machine to sign, notarize and qualify a release on",
  "macos-x86_64": "Forgejo has no Intel Mac runner",
  // Linux builds in an Ubuntu 22.04 container (glibc 2.35), checked after the build: linux-x86_64
  // on the runners labelled ubuntu-22.04 (the DigitalOcean slots and Unraid), linux-aarch64 on the
  // owner's Mac slot labelled ubuntu-22.04-arm (owner, 2026-11-21: "Yes, both").
};
/**
 * Why each selected target cannot build on Forgejo: `stage` is "runtime" (factory packs) or "installer".
 * `ownerMac`: the owner allowed their own Mac for Apple Silicon (repository variable
 * `DESKTOP_RELEASE_MACOS_ON_OWNER_MAC`, docs/releases.md); without it that target stays refused.
 */
export function forgejoTargetProblems(platforms, stage, { ownerMac = false } = {}) {
  if (stage !== "runtime" && stage !== "installer") throw new Error("forgejo_stage_invalid");
  return releaseMatrix(platforms).include.flatMap(({ target }) => {
    const reason = ownerMac && target === "macos-aarch64" ? undefined : noForgejoRunner[target];
    return reason ? [`${target}: ${reason}`] : [];
  });
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

export function updateManifest(tag, repository, signatures) {
  const version = tag.slice(1);
  validateReleaseTag(tag, [version]);
  const formats = {
    "app.tar.gz": ["darwin", "app"],
    AppImage: ["linux", "appimage"],
    deb: ["linux", "deb"],
    exe: ["windows", "nsis"],
    msi: ["windows", "msi"],
  };
  const platforms = {};
  for (const [name, value] of Object.entries(signatures)) {
    const filename = name.startsWith(`Frameleaf_${version}_`) && name.slice(`Frameleaf_${version}_`.length);
    const match = filename && /^(aarch64|arm64|amd64|x64)(?:-setup|_en-US)?\.(app\.tar\.gz|AppImage|deb|exe|msi)$/.exec(filename);
    if (!match) throw new Error(`update_asset_invalid: ${name}`);
    const [, architecture, extension] = match;
    const [os, installer] = formats[extension];
    const arch = architecture === "aarch64" || architecture === "arm64" ? "aarch64" : "x86_64";
    const target = `${os}-${arch}-${installer}`;
    if (platforms[target]) throw new Error(`update_asset_duplicate: ${target}`);
    const signature = value.trim();
    if (!/^[A-Za-z0-9+/]+={0,2}$/.test(signature)) throw new Error(`update_signature_invalid: ${name}`);
    platforms[target] = {
      url: `https://github.com/${repository}/releases/download/${tag}/${name}`,
      signature,
    };
  }
  if (!Object.keys(platforms).length) throw new Error("update_assets_missing");
  return { version, platforms };
}

export function verifyUpdaterAsset(file, signature, publicKey, version) {
  const dir = mkdtempSync(join(tmpdir(), "frameleaf-updater-"));
  try {
    const signatureFile = join(dir, "signature");
    const keyFile = join(dir, "public-key");
    writeFileSync(signatureFile, Buffer.from(signature, "base64"));
    writeFileSync(keyFile, Buffer.from(publicKey, "base64"));
    let comment;
    try {
      comment = execFileSync("minisign", ["-VQ", "-m", file, "-x", signatureFile, "-p", keyFile], { encoding: "utf8" });
    } catch (cause) {
      throw new Error(`update_signature_verification_failed: ${file}`, { cause });
    }
    // Match Tauri's first version field after the artifact and trusted comment have both verified.
    if (comment.replace(/\r?\n$/, "").split("\t").find((field) => field.startsWith("version:")) !== `version:${version}`) {
      throw new Error(`update_signature_version_mismatch: ${file}`);
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

// Every target Desktop can update in place. A release that omits one leaves those installs on their current version.
export const updateFeedTargets = [
  "darwin-aarch64-app", "darwin-x86_64-app",
  "linux-aarch64-appimage", "linux-aarch64-deb", "linux-x86_64-appimage", "linux-x86_64-deb",
  "windows-x86_64-msi", "windows-x86_64-nsis",
];

/** Markdown for the workflow summary and draft notes, so an omitted platform is visible before publication. */
export function updateFeedSummary(manifest) {
  const offered = Object.keys(manifest.platforms).sort();
  const missing = updateFeedTargets.filter((target) => !manifest.platforms[target]);
  const windows = offered.some((target) => target.startsWith("windows-"));
  const lines = [`### Update feed for ${manifest.version}`, "", `\`latest.json\` offers ${manifest.version} to: ${offered.join(", ")}.`];
  if (!windows) {
    lines.push("", `**Windows was excluded from the update feed.** This release has no signed Windows installers, so Desktop on Windows will not be offered ${manifest.version} and stays on its installed version until a release includes them.`);
  }
  const others = windows ? missing : missing.filter((target) => !target.startsWith("windows-"));
  if (others.length) lines.push("", `Not in the update feed: ${others.join(", ")}.`);
  return lines.join("\n") + "\n";
}

/** The version each file records. The lock files are included: `cargo --locked` and `npm ci` fail on a stale one. */
export function applicationVersions(root = new URL("../", import.meta.url)) {
  const read = (path) => readFileSync(new URL(path, root), "utf8");
  const lock = JSON.parse(read("package-lock.json"));
  return {
    "package.json": JSON.parse(read("package.json")).version,
    "package-lock.json": lock.version,
    "package-lock.json (root package)": lock.packages?.[""]?.version,
    "src-tauri/tauri.conf.json": JSON.parse(read("src-tauri/tauri.conf.json")).version,
    "src-tauri/Cargo.toml": read("src-tauri/Cargo.toml").match(/^version\s*=\s*"([^"]+)"/m)?.[1],
    "src-tauri/Cargo.lock": read("src-tauri/Cargo.lock").match(/^name = "frameleaf-desktop"\r?\nversion = "([^"]+)"/m)?.[1],
  };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  console.log(validateReleaseTag(process.argv[2], Object.values(applicationVersions())));
}
