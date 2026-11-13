import { readFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { packageConfiguration } from "./package_desktop.mjs";
import {
  acceleratedSignature,
  boundedFile,
  readSigningKey,
  signCandidate,
  verifyUnsignedAccelerated,
} from "./sign_runtime.mjs";

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

export function factorySourceRevisionFor(target) {
  if (!profile.targets.includes(target))
    throw new Error("runtime_factory_source_invalid");
  // FD-40: every target builds the one source the model catalogue has profiles for.
  return factorySourceRevision;
}

/** The profile the factory builds for a target: its accelerated profile when the release
 * owner asks for one and exactly one is approved there, otherwise the processor profile. */
export function factoryProfileFor(target, accelerated) {
  factorySourceRevisionFor(target);
  const names = Object.entries(profiles.profiles)
    .filter(
      ([, value]) =>
        value.provider !== profile.provider && value.targets.includes(target),
    )
    .map(([name]) => name);
  return accelerated && names.length === 1 ? names[0] : "cpu-ort";
}

export async function checkFactoryInputs(candidate, target, epoch) {
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
    manifest.sourceRevision !== factorySourceRevisionFor(target) ||
    manifest.provider !== profile.provider
  )
    throw new Error("runtime_factory_candidate_unapproved");
  // An accelerated manifest is signed only for the profile approved for this target, from
  // that profile's own source.
  const accelerated = await verifyUnsignedAccelerated(candidate);
  const approved = profiles.profiles[factoryProfileFor(target, true)];
  if (
    accelerated &&
    (accelerated.manifest.provider !== approved.provider ||
      accelerated.manifest.sourceRevision !== approved.sourceRevision)
  )
    throw new Error("runtime_factory_candidate_unapproved");
  return Boolean(accelerated);
}

export async function signFactoryRuntime(candidate, target, epoch, privatePem, policy) {
  candidate = resolve(candidate);
  const accelerated = await checkFactoryInputs(candidate, target, epoch);
  const receipt = await signCandidate(
    candidate,
    join(candidate, "manifest.sig"),
    privatePem,
    policy,
  );
  if (accelerated)
    receipt.accelerated = await signCandidate(
      candidate,
      join(candidate, acceleratedSignature),
      privatePem,
      policy,
      true,
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
