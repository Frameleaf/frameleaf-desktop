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

/** The source a profile is built from on a target. FD-40: every target's processor runtime
 * builds the one source the model catalogue has profiles for. FD-56: an accelerated pack (both
 * of its manifests) builds its own profile's source. */
export function factorySourceRevisionFor(target, name = "cpu-ort") {
  const chosen = Object.hasOwn(profiles.profiles, name)
    ? profiles.profiles[name]
    : undefined;
  if (
    !profile.targets.includes(target) ||
    !chosen?.targets.includes(target) ||
    !/^[a-f0-9]{40}$/.test(chosen.sourceRevision)
  )
    throw new Error("runtime_factory_source_invalid");
  return chosen.sourceRevision;
}

const acceleratedProfiles = (target) =>
  Object.entries(profiles.profiles)
    .filter(
      ([, value]) =>
        value.provider !== profile.provider && value.targets.includes(target),
    )
    .map(([name]) => name);

/** The profile the factory builds for a target. `default` (or true): the accelerated profile
 * where exactly one is approved (CoreML on Apple Silicon), the processor profile elsewhere.
 * `none` (or false): the processor profile. A profile name (`cuda-ort`, `openvino-ort`): that
 * profile on the targets that approve it, and the default on the others. */
export function factoryProfileFor(target, accelerated) {
  factorySourceRevisionFor(target);
  const names = acceleratedProfiles(target);
  const usual = names.length === 1 ? names[0] : "cpu-ort";
  if (accelerated === false || accelerated === "none") return "cpu-ort";
  if (accelerated === true || accelerated === "default") return usual;
  if (
    typeof accelerated !== "string" ||
    !Object.hasOwn(profiles.profiles, accelerated) ||
    profiles.profiles[accelerated].provider === profile.provider
  )
    throw new Error("runtime_factory_profile_invalid");
  return names.includes(accelerated) ? accelerated : usual;
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
    manifest.provider !== profile.provider
  )
    throw new Error("runtime_factory_candidate_unapproved");
  // An accelerated manifest is signed only for a profile approved for this target, and the
  // whole pack (both manifests are one payload) must be built from that profile's source. A
  // pack without one is the processor runtime, from the processor profile's source.
  const accelerated = await verifyUnsignedAccelerated(candidate);
  const name = accelerated
    ? acceleratedProfiles(target).find(
        (item) =>
          profiles.profiles[item].provider === accelerated.manifest.provider,
      )
    : "cpu-ort";
  if (
    !name ||
    manifest.sourceRevision !== factorySourceRevisionFor(target, name) ||
    (accelerated &&
      accelerated.manifest.sourceRevision !== manifest.sourceRevision)
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
