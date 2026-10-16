/** Package a factory-signed runtime into the resource path consumed by worker setup. */
import { spawn } from "node:child_process";
import { readFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { verifySignedCandidate } from "./sign_runtime.mjs";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
export async function packageConfiguration(candidate, policy) {
  candidate = resolve(candidate);
  const { manifest } = await verifySignedCandidate(candidate, policy);
  const platform = { darwin: "macos", win32: "windows", linux: "linux" }[
    process.platform
  ];
  const architecture = { arm64: "aarch64", x64: "x86_64" }[process.arch];
  if (manifest.platform !== platform || manifest.architecture !== architecture)
    throw new Error("runtime_bundle_target_mismatch");
  const profiles = JSON.parse(
    await readFile(join(root, "runtime/profiles.json"), "utf8"),
  );
  const approved = Object.values(profiles.profiles ?? {}).filter(
    (profile) =>
      profile.provider === manifest.provider &&
      profile.sourceRevision === manifest.sourceRevision &&
      profile.targets?.includes(`${platform}-${architecture}`),
  );
  if (profiles.schemaVersion !== 1 || approved.length !== 1)
    throw new Error("runtime_bundle_source_unapproved");
  return {
    bundle: {
      resources: {
        [join(candidate, "manifest.json")]: "native-runtime/manifest.json",
        [join(candidate, "manifest.sig")]: "native-runtime/manifest.sig",
        [join(candidate, "payload")]: "native-runtime/payload",
      },
    },
  };
}

if (
  process.argv[1] &&
  resolve(process.argv[1]) === fileURLToPath(import.meta.url)
) {
  try {
    const args = process.argv.slice(2);
    if (
      args[0] !== "--runtime" ||
      !args[1] ||
      args.length > 3 ||
      (args[2] && args[2] !== "--debug")
    )
      throw new Error("usage: --runtime SIGNED_PACK [--debug]");
    const configuration = await packageConfiguration(args[1]);
    const cli = join(root, "node_modules/@tauri-apps/cli/tauri.js");
    const build = spawn(
      process.execPath,
      [
        cli,
        "build",
        "--config",
        JSON.stringify(configuration),
        ...args.slice(2),
      ],
      {
        cwd: root,
        stdio: "inherit",
        shell: false,
      },
    );
    process.exitCode = await new Promise((accept, reject) => {
      build.once("error", reject);
      build.once("exit", (code) => accept(code ?? 1));
    });
  } catch (error) {
    console.error(
      /^(runtime_|release_|usage:)/.test(error.message)
        ? error.message
        : "desktop_package_failed",
    );
    process.exitCode = 1;
  }
}
