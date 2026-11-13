import { readFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { deliverRuntime } from "./deliver_runtime.mjs";
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
 * that shares the processor profile's dependency set (CoreML on Apple Silicon), where exactly
 * one is approved; the processor profile elsewhere.
 * `none` (or false): the processor profile. A profile name (`cuda-ort`, `openvino-ort`): that
 * profile on the targets that approve it, and the default on the others. */
export function factoryProfileFor(target, accelerated) {
  factorySourceRevisionFor(target);
  const names = acceleratedProfiles(target);
  // Only a profile on the processor profile's own dependency set (CoreML) is a normal pack:
  // a CUDA or OpenVINO pack is another, far larger payload and is built only when named.
  const same = names.filter(
    (name) => profiles.profiles[name].extra === profile.extra,
  );
  const usual = same.length === 1 ? same[0] : "cpu-ort";
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

/** Every pack one factory run builds for a target (FD-60): the pack the installer carries and
 * the accelerated packs too large for an installer (a dependency set of their own: CUDA,
 * OpenVINO), which are delivered as release parts the app downloads on demand. `default` (or
 * true) delivers every such pack approved for the target, a profile name only that one, and
 * `none` (or false) none. The installer's pack is never one of them: the processor manifest of
 * such a pack is not signed. */
export function factoryPacksFor(target, accelerated) {
  const large = acceleratedProfiles(target).filter(
    (name) => profiles.profiles[name].extra !== profile.extra,
  );
  const named = large.includes(accelerated);
  const installer = factoryProfileFor(target, named ? "default" : accelerated);
  const delivered =
    accelerated === true || accelerated === "default"
      ? large
      : named
        ? [accelerated]
        : [];
  return [
    { profile: installer, delivered: false },
    ...delivered.map((name) => ({ profile: name, delivered: true })),
  ];
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

/** FD-60: sign the accelerated manifest of a pack the app downloads on demand, cut the pack
 * into release parts under `output/parts` and write its signed delivery manifest to `output`.
 * Only the accelerated manifest is signed: the pack never serves as a processor runtime. */
export async function deliverFactoryRuntime(
  candidate,
  output,
  target,
  epoch,
  privatePem,
  policy,
  options,
) {
  candidate = resolve(candidate);
  if (!(await checkFactoryInputs(candidate, target, epoch)))
    throw new Error("runtime_factory_candidate_unapproved");
  const receipt = await signCandidate(
    candidate,
    join(candidate, acceleratedSignature),
    privatePem,
    policy,
    true,
  );
  const { profile, delivery, manifestSha256 } = await deliverRuntime(
    candidate,
    output,
    privatePem,
    policy,
    options,
  );
  return {
    ...receipt,
    profile,
    deliveryManifestSha256: manifestSha256,
    parts: delivery.parts.length,
    bytes: delivery.bytes,
  };
}

if (
  process.argv[1] &&
  resolve(process.argv[1]) === fileURLToPath(import.meta.url)
) {
  try {
    if (process.argv.length !== 5 && process.argv.length !== 6)
      throw new Error("runtime_factory_arguments_invalid");
    const [candidate, target, epoch, delivery] = process.argv.slice(2);
    console.log(
      JSON.stringify(
        delivery
          ? await deliverFactoryRuntime(
              candidate,
              delivery,
              target,
              Number(epoch),
              await readSigningKey(),
            )
          : await signFactoryRuntime(
              candidate,
              target,
              Number(epoch),
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
