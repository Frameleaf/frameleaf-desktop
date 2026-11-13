/**
 * What a release needs before anything is built. Each check is a pure function over data the
 * workflow has already fetched, and its error says what is wrong and what to do about it.
 */
import { readFileSync, readdirSync } from "node:fs";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { sha256File } from "./release_draft.mjs";
import { releaseMatrix, validateDispatchRun } from "./release_inputs.mjs";
import { parseChecksums } from "./release_packaging.mjs";

const repositoryFile = (path) => JSON.parse(readFileSync(new URL(`../${path}`, import.meta.url), "utf8"));

// --- Windows signing -------------------------------------------------------------------------

export const windowsSigningVariables = [
  "AZURE_CLIENT_ID", "AZURE_TENANT_ID", "AZURE_SIGNING_ENDPOINT", "AZURE_SIGNING_ACCOUNT",
  "AZURE_SIGNING_PROFILE", "WINDOWS_SIGNING_SUBJECT",
];

/** Refuse a Windows release whose signing variables are unset, naming each one and where it is set. */
export function checkWindowsSigning(environment, repository) {
  const missing = windowsSigningVariables.filter((name) => {
    const value = environment[name];
    return typeof value !== "string" || !value.trim() || /[\r\n]/.test(value);
  });
  if (missing.length) {
    throw new Error(
      `windows_signing_unconfigured: ${missing.join(", ")} ${missing.length === 1 ? "is" : "are"} not set. ` +
      `Set ${missing.length === 1 ? "it" : "each"} as an environment variable (not a secret) of the desktop-release environment: ` +
      `https://github.com/${repository}/settings/environments. AZURE_SIGNING_PROFILE and WINDOWS_SIGNING_SUBJECT exist only ` +
      "after Microsoft's identity validation is approved and the Public Trust certificate profile is created " +
      "(docs/releases.md, Azure Artifact Signing setup). The other platforms can be released without them.",
    );
  }
}

// --- Runtime epoch ---------------------------------------------------------------------------

/** The epoch a new factory pack may use: above every epoch a pack has already been built with. */
export function checkFactoryEpoch(input, record = repositoryFile("runtime/factory-epochs.json"), trust = repositoryFile("runtime/release-trust.json")) {
  const highest = record?.highestUsedEpoch;
  if (record?.schemaVersion !== 1 || !Number.isSafeInteger(highest) || highest < 1)
    throw new Error("runtime_factory_epoch_record_invalid: runtime/factory-epochs.json must record highestUsedEpoch");
  const epoch = Number(input);
  if (typeof input !== "string" || !/^[1-9][0-9]*$/.test(input) || !Number.isSafeInteger(epoch) || epoch < trust.minimumRuntimeEpoch)
    throw new Error(`runtime_factory_epoch_invalid: epoch must be a whole number; the next one to use is ${highest + 1}`);
  if (epoch <= highest) {
    throw new Error(
      `runtime_factory_epoch_used: epoch ${epoch} is not above ${highest}, the highest epoch a pack was already built with ` +
      `(runtime/factory-epochs.json). An installed app refuses a lower epoch (runtime_epoch_rollback) and a different pack ` +
      `with the same one (runtime_epoch_reused). Use ${highest + 1}.`,
    );
  }
  return epoch;
}

// --- Factory run -----------------------------------------------------------------------------

/** Every selected target needs its own unexpired pack in the factory run. */
export function checkFactoryArtifacts(artifacts, platforms, run) {
  const available = new Set((artifacts ?? []).filter((item) => item && item.expired === false).map((item) => item.name));
  const missing = releaseMatrix(platforms).include.map(({ target }) => target)
    .filter((target) => !available.has(`factory-runtime-${target}`));
  if (missing.length) {
    throw new Error(
      `runtime_run_pack_missing: factory run ${run} has no unexpired factory-runtime-<target> artifact for ${missing.join(", ")}. ` +
      `Run factory-runtime.yml for ${missing.length === 1 ? "that platform" : "those platforms"} and pass that run, ` +
      "or select only the platforms this run built.",
    );
  }
}

/**
 * The same approval packaging applies after the build (tools/package_desktop.mjs), applied to the
 * manifests alone so a pack from another source or profile stops the release before it builds.
 */
export function checkFactoryPack(target, manifest, accelerated, options = {}) {
  const { profiles = repositoryFile("runtime/profiles.json"), record = repositoryFile("runtime/factory-epochs.json"), release = true } = options;
  const describe = (item) => `${item?.provider} from ${item?.sourceRevision}`;
  if (!manifest || `${manifest.platform}-${manifest.architecture}` !== target)
    throw new Error(`runtime_run_pack_target_mismatch: factory-runtime-${target} holds a pack for ${manifest?.platform}-${manifest?.architecture}`);
  const approvedFor = (item) => Object.values(profiles.profiles ?? {}).filter((profile) =>
    profile.provider === item.provider &&
    (profile.sourceRevision === item.sourceRevision ||
      (Array.isArray(profile.additionalSources?.[target]) && profile.additionalSources[target].includes(item.sourceRevision))) &&
    profile.targets?.includes(target));
  const approved = profiles.schemaVersion === 1 && (accelerated
    ? approvedFor(accelerated).length === 1 && manifest.sourceRevision === accelerated.sourceRevision
    : approvedFor(manifest).length === 1);
  if (!approved) {
    throw new Error(
      `runtime_run_pack_unapproved: the ${target} pack is ${describe(manifest)}` +
      (accelerated ? ` with an accelerated manifest ${describe(accelerated)}` : "") +
      `, which runtime/profiles.json on this commit does not approve for ${target}. ` +
      "Run factory-runtime.yml again from the commit being released and pass that run.",
    );
  }
  // Only a release reaches installed apps; an artifacts-only run may reuse an older pack.
  const highest = record?.highestUsedEpoch;
  for (const item of release ? (accelerated ? [manifest, accelerated] : [manifest]) : []) {
    if (!Number.isSafeInteger(item.epoch) || !Number.isSafeInteger(highest) || item.epoch <= highest) {
      throw new Error(
        `runtime_run_pack_epoch_used: the ${target} pack has runtime epoch ${item.epoch}, which is not above ${highest}, ` +
        `the highest epoch already used (runtime/factory-epochs.json). Build the pack again with epoch ${highest + 1}.`,
      );
    }
  }
  return `${target}: ${accelerated ? describe(accelerated) : describe(manifest)}, runtime epoch ${manifest.epoch}`;
}

// --- Model catalogue -------------------------------------------------------------------------

/** The newest published server release: `frameleaf-v<version>`, never a draft, prerelease or Manager release. */
export function latestServerRelease(releases) {
  const versions = (releases ?? [])
    .filter((release) => release && release.draft === false && release.prerelease === false)
    .map((release) => /^frameleaf-v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$/.exec(release.tag_name))
    .filter(Boolean)
    .map(([tag, ...parts]) => ({ tag, parts: parts.map(Number) }))
    .sort((a, b) => b.parts[0] - a.parts[0] || b.parts[1] - a.parts[1] || b.parts[2] - a.parts[2]);
  if (!versions.length) throw new Error("server_release_unknown: no published frameleaf-v<version> release was found in Frameleaf/frameleaf-app");
  return versions[0].tag;
}

/**
 * Desktop must not ship a model catalogue the released server does not have yet: its runtime
 * packs name sources that server does not know, so those installs have no AI processing.
 */
export function checkCatalogueAgainstServer(desktop, server, serverTag, allowNewer = false) {
  for (const [name, catalogue] of [["Desktop's runtime/model-catalogue.json", desktop], [`the catalogue in ${serverTag}`, server]]) {
    if (catalogue?.schemaVersion !== 1 || !Number.isSafeInteger(catalogue.epoch) || catalogue.epoch < 1)
      throw new Error(`catalogue_invalid: ${name} has no valid epoch`);
  }
  const state = `Desktop's model catalogue is epoch ${desktop.epoch}; the latest server release (${serverTag}) has epoch ${server.epoch}.`;
  if (desktop.epoch <= server.epoch) return state;
  if (allowNewer === true) return `${state} Released anyway because allow_unreleased_catalogue was set: AI processing on packs the server does not know stays off until the server is released.`;
  throw new Error(
    `catalogue_ahead_of_server: ${state} Release the server first: a pack built from a source ${serverTag} does not know ` +
    "has no AI processing against it. To release Desktop first anyway, set allow_unreleased_catalogue.",
  );
}

// --- Companion packages ----------------------------------------------------------------------

// The targets a Library companion package exists for.
export const companionTargets = ["macos-aarch64", "linux-x86_64", "windows-x86_64"];
// The workflows whose successful run retains a signed, installable companion package. Linux and
// Windows have none: their packages are not uploaded by any workflow in a signed, final form.
export const companionProducers = {
  ".github/workflows/macos-host-package.yml": {
    target: "macos-aarch64",
    artifact: "frameleaf-macos-arm64-companion-installed",
    asset: /^FrameleafCompanion_(?:0|[1-9][0-9]*)(?:\.(?:0|[1-9][0-9]*)){2}_arm64\.pkg$/,
  },
};

/** The run ids given: none for an empty value or `none`, otherwise up to one run per producing workflow. */
export function companionRunIds(input) {
  const value = typeof input === "string" ? input.trim() : "";
  if (value === "none" || !value) return [];
  const ids = value.split(",").map((id) => id.trim());
  if (ids.length > Object.keys(companionProducers).length || new Set(ids).size !== ids.length || ids.some((id) => !/^[1-9][0-9]{0,18}$/.test(id))) {
    throw new Error(
      "companion_runs_invalid: companion_run_ids must be the run id of a successful macos-host-package.yml run " +
      "(the notarized Apple Silicon companion package), or none to stage a draft without companion packages.",
    );
  }
  return ids;
}

/**
 * Which companion packages this run attaches and which are left to be added by hand.
 * `runs` maps each requested run id to its Actions run. A selected target that has a producing
 * workflow must be given a run, unless companion packages were declined with `none`.
 */
export function planCompanions(platforms, input, runs, repository) {
  const selected = releaseMatrix(platforms).include.map(({ target }) => target).filter((target) => companionTargets.includes(target));
  const attach = companionRunIds(input).map((id) => {
    const run = runs[id];
    const workflow = typeof run?.path === "string" ? run.path.split("@")[0] : "";
    if (!Object.hasOwn(companionProducers, workflow)) {
      throw new Error(`companion_run_untrusted: run ${id} is not a run of ${Object.keys(companionProducers).join(" or ")}`);
    }
    try {
      const { target, artifact } = companionProducers[workflow];
      return { run: id, target, artifact, workflow, revision: validateDispatchRun(run, repository, workflow, "companion_run_untrusted") };
    } catch {
      throw new Error(`companion_run_untrusted: run ${id} is not a successful manual run of ${workflow} on main in ${repository}`);
    }
  });
  for (const { run, target } of attach) {
    if (!selected.includes(target)) throw new Error(`companion_run_unselected: run ${run} holds the ${target} companion package, but ${target} is not being released by this run`);
    if (attach.filter((item) => item.target === target).length > 1) throw new Error(`companion_run_duplicate: more than one run was given for ${target}`);
  }
  const producible = Object.values(companionProducers).map(({ target }) => target);
  const declined = typeof input === "string" && input.trim() === "none";
  const missing = selected.filter((target) => producible.includes(target) && !attach.some((item) => item.target === target));
  if (missing.length && !declined) {
    throw new Error(
      `companion_run_missing: no companion package run was given for ${missing.join(", ")}. Pass the macos-host-package.yml run id ` +
      "in companion_run_ids, or none to stage the draft without it.",
    );
  }
  // Selected targets whose package no run supplies: declined ones, and those no workflow produces.
  const manual = selected.filter((target) => !attach.some((item) => item.target === target));
  return { attach, manual };
}

/** The one package in a producer's artifact, checked against the checksum that run recorded for it. */
export function checkCompanionArtifact(workflow, files, checksums) {
  const producer = companionProducers[workflow];
  const packages = files.filter(({ name }) => producer?.asset.test(name));
  if (packages.length !== 1) throw new Error(`companion_artifact_invalid: ${producer?.artifact} must hold exactly one companion package`);
  const [{ name, sha256 }] = packages;
  if (!/^[a-f0-9]{64}$/.test(sha256) || checksums.get(name) !== sha256)
    throw new Error(`companion_artifact_changed: ${name} does not match the checksum its run recorded`);
  return name;
}

/** Markdown for the run summary and the draft notes. */
export function companionSummary({ attach, manual }) {
  const lines = ["### Companion packages", ""];
  for (const item of attach) lines.push(`- ${item.target}: attached from run ${item.run} (${item.workflow.split("/").pop()}).`);
  for (const target of manual) lines.push(`- ${target}: **not attached by this run.** Add its signed companion package to the draft by hand before publishing.`);
  if (!attach.length && !manual.length) lines.push("- None of the selected platforms has a companion package.");
  return lines.join("\n") + "\n";
}

/** The same, as one sentence for the draft's notes, which keep one line per run. */
export function companionNote({ attach, manual }) {
  const parts = [
    ...attach.map((item) => `${item.target} attached from run ${item.run}`),
    ...manual.map((target) => `${target} not attached, add its signed package by hand before publishing`),
  ];
  return parts.length ? `Companion packages: ${parts.join("; ")}.` : "";
}

// --- Command line ----------------------------------------------------------------------------

const lines = (path) => readFileSync(path, "utf8").split("\n").filter(Boolean).map((line) => JSON.parse(line));
const commands = {
  "windows-signing": () => checkWindowsSigning(process.env, process.env.GITHUB_REPOSITORY),
  "factory-epoch": ([epoch]) => console.log(checkFactoryEpoch(epoch)),
  "factory-artifacts": ([file, platforms, run]) => checkFactoryArtifacts(lines(file), platforms, run),
  "factory-pack": ([target, directory, tagged]) => {
    const read = (name) => {
      try { return JSON.parse(readFileSync(join(directory, name), "utf8")); }
      catch (error) { if (error.code === "ENOENT") return undefined; throw error; }
    };
    console.log(`- ${checkFactoryPack(target, read("manifest.json"), read("manifest-accelerated.json"), { release: tagged === "release" })}`);
  },
  "server-release": ([file]) => console.log(latestServerRelease(lines(file))),
  catalogue: ([tag, file, allow]) => console.log(checkCatalogueAgainstServer(
    repositoryFile("runtime/model-catalogue.json"), JSON.parse(readFileSync(file, "utf8")), tag, allow === "true")),
  "companion-ids": ([input]) => { for (const id of companionRunIds(input)) console.log(id); },
  companions: ([platforms, input, directory]) => {
    const runs = Object.fromEntries(readdirSync(directory).filter((name) => name.endsWith(".json"))
      .map((name) => [name.slice(0, -5), JSON.parse(readFileSync(join(directory, name), "utf8"))]));
    console.log(JSON.stringify(planCompanions(platforms, input, runs, process.env.GITHUB_REPOSITORY)));
  },
  "companion-note": ([file]) => console.log(companionNote(JSON.parse(readFileSync(file, "utf8")))),
  "companion-artifact": async ([workflow, directory]) => {
    const files = [];
    for (const name of readdirSync(directory)) files.push({ name, sha256: await sha256File(join(directory, name)) });
    console.log(checkCompanionArtifact(workflow, files, parseChecksums(readFileSync(join(directory, "SHA256SUMS"), "utf8"))));
  },
  "companion-summary": ([file]) => process.stdout.write(companionSummary(JSON.parse(readFileSync(file, "utf8")))),
};

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const [command, ...args] = process.argv.slice(2);
  try {
    if (!Object.hasOwn(commands, command)) throw new Error(`usage: release_prerequisites.mjs ${Object.keys(commands).join("|")}`);
    await commands[command](args);
  } catch (error) {
    // One line, so GitHub shows the whole reason as the job's error annotation.
    console.error(`::error::${String(error.message).replace(/\r?\n/g, " ")}`);
    process.exitCode = 1;
  }
}
