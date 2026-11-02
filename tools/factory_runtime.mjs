import { readFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { packageConfiguration } from "./package_desktop.mjs";
import { boundedFile, readSigningKey, signCandidate } from "./sign_runtime.mjs";

const profiles = JSON.parse(
  await readFile(new URL("../runtime/profiles.json", import.meta.url)),
);
const profile = profiles.profiles["cpu-ort"];
export const factorySourceRevision = profile.sourceRevision;
if (
  profiles.schemaVersion !== 1 ||
  !/^[a-f0-9]{40}$/.test(factorySourceRevision)
)
  throw new Error("runtime_factory_source_invalid");

export async function signFactoryRuntime(
  candidate,
  target,
  epoch,
  privatePem,
  policy,
) {
  candidate = resolve(candidate);
  const manifest = JSON.parse(
    await boundedFile(join(candidate, "manifest.json"), 8 * 1024 * 1024),
  );
  if (
    !Number.isSafeInteger(epoch) ||
    epoch < 1 ||
    manifest.epoch !== epoch ||
    !profile.targets.includes(target) ||
    `${manifest.platform}-${manifest.architecture}` !== target ||
    manifest.sourceRevision !== factorySourceRevision ||
    manifest.provider !== profile.provider
  )
    throw new Error("runtime_factory_candidate_unapproved");
  const receipt = await signCandidate(
    candidate,
    join(candidate, "manifest.sig"),
    privatePem,
    policy,
  );
  await packageConfiguration(candidate, policy);
  return receipt;
}

if (
  process.argv[1] &&
  resolve(process.argv[1]) === fileURLToPath(import.meta.url)
) {
  try {
    if (process.argv.length !== 5)
      throw new Error("runtime_factory_arguments_invalid");
    console.log(
      JSON.stringify(
        await signFactoryRuntime(
          process.argv[2],
          process.argv[3],
          Number(process.argv[4]),
          await readSigningKey(),
        ),
      ),
    );
  } catch {
    // Key parser errors must never enter workflow logs.
    console.error("runtime_factory_signing_failed");
    process.exitCode = 1;
  }
}
