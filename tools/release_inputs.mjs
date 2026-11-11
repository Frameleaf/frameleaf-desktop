import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
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
  const appleSilicon = { os: "macos-15", target: "macos-aarch64" };
  if (platforms === "macos-aarch64") return { include: [appleSilicon] };
  if (!["macos-linux", "all", "linux", "windows"].includes(platforms))
    throw new Error("release_platforms_invalid");
  return { include: [
    ...(platforms !== "linux" && platforms !== "windows" ? [
      appleSilicon,
      { os: "macos-15-intel", target: "macos-x86_64" },
    ] : []),
    ...(platforms === "all" || platforms === "windows" ? [{ os: "windows-2022", target: "windows-x86_64" }] : []),
    ...(platforms !== "windows" ? [
      { os: "ubuntu-24.04", target: "linux-x86_64" },
      { os: "ubuntu-24.04-arm", target: "linux-aarch64" },
    ] : []),
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

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const root = new URL("../", import.meta.url);
  const pkg = JSON.parse(await readFile(new URL("package.json", root), "utf8"));
  const config = JSON.parse(await readFile(new URL("src-tauri/tauri.conf.json", root), "utf8"));
  const cargo = await readFile(new URL("src-tauri/Cargo.toml", root), "utf8");
  const version = cargo.match(/^version\s*=\s*"([^"]+)"/m)?.[1];
  console.log(validateReleaseTag(process.argv[2], [pkg.version, config.version, version]));
}
