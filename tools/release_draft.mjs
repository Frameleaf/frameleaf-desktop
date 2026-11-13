/**
 * Add one run's signed assets to the draft release for a tag. Platforms released by separate
 * runs end in one draft with one `latest.json` and one `SHA256SUMS` covering all of them.
 */
import { createHash } from "node:crypto";
import { createReadStream, mkdirSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { updateFeedSummary, updateFeedTargets, validateReleaseTag } from "./release_inputs.mjs";

// Rebuilt from everything on the draft each time, so they are the only assets a later run replaces.
export const generatedAssets = ["latest.json", "SHA256SUMS"];
const assetName = /^[A-Za-z0-9][A-Za-z0-9._-]*$/;
const digest = /^[a-f0-9]{64}$/;

/**
 * The draft a run adds to, or null when the tag has no release yet. A published release is never
 * changed, and two releases for one tag (which GitHub allows for drafts) are not guessed between.
 */
export function selectDraft(releases, tag) {
  const matches = (releases ?? []).filter((release) => release?.tag_name === tag);
  if (!matches.length) return null;
  if (matches.length > 1) {
    throw new Error(
      `release_tag_ambiguous: ${matches.length} releases exist for ${tag} (ids ${matches.map(({ id }) => id).join(", ")}). ` +
      "Delete all but the one to keep, then run again.",
    );
  }
  const [release] = matches;
  if (release.draft !== true) {
    throw new Error(`release_not_draft: the release for ${tag} is already published, so nothing is added to it. Release a new version instead.`);
  }
  const assets = (release.assets ?? []).map((asset) => {
    const sha256 = typeof asset.digest === "string" && asset.digest.startsWith("sha256:") ? asset.digest.slice(7) : "";
    if (asset.state !== "uploaded" || !digest.test(sha256))
      throw new Error(`release_asset_unverifiable: ${asset.name} on the draft for ${tag} is incomplete or has no recorded SHA-256. Delete it from the draft, then run again.`);
    return { id: asset.id, name: asset.name, sha256 };
  });
  return { id: release.id, body: typeof release.body === "string" ? release.body : "", assets };
}

function checkManifest(manifest, tag, repository) {
  const prefix = `https://github.com/${repository}/releases/download/${tag}/`;
  if (!manifest || manifest.version !== tag.slice(1) || !manifest.platforms || typeof manifest.platforms !== "object")
    throw new Error(`release_manifest_invalid: latest.json is not for ${tag}`);
  for (const [target, entry] of Object.entries(manifest.platforms)) {
    if (
      !updateFeedTargets.includes(target) || Object.keys(entry ?? {}).sort().join() !== "signature,url" ||
      typeof entry.url !== "string" || !entry.url.startsWith(prefix) || !assetName.test(entry.url.slice(prefix.length)) ||
      typeof entry.signature !== "string" || !/^[A-Za-z0-9+/]+={0,2}$/.test(entry.signature)
    ) throw new Error(`release_manifest_invalid: latest.json entry ${target}`);
  }
  return prefix;
}

/**
 * Pure merge of what a draft holds with what this run built.
 *
 * `existing` is null or `{ assets: [{ name, sha256 }], manifest }` from the draft; `incoming` is
 * the same shape for this run. Returns the asset names to upload, those already present with the
 * same bytes, and the regenerated `latest.json` and `SHA256SUMS` text. An asset is never replaced
 * by different bytes, and every updater signature is carried through exactly as it was written.
 */
export function mergeDraft({ tag, repository, existing, incoming }) {
  validateReleaseTag(tag, [tag.slice(1)]);
  const assets = new Map();
  const add = (list, where) => {
    const names = [];
    for (const { name, sha256 } of list) {
      if (generatedAssets.includes(name)) continue;
      if (typeof name !== "string" || !assetName.test(name) || !digest.test(sha256) || names.includes(name))
        throw new Error(`release_asset_invalid: ${name} ${where}`);
      names.push(name);
    }
    return names;
  };
  for (const name of add(existing?.assets ?? [], "on the draft")) assets.set(name, existing.assets.find((asset) => asset.name === name).sha256);
  const upload = [];
  const unchanged = [];
  for (const name of add(incoming.assets, "from this run")) {
    const sha256 = incoming.assets.find((asset) => asset.name === name).sha256;
    if (!assets.has(name)) upload.push(name);
    else if (assets.get(name) === sha256) unchanged.push(name);
    else {
      throw new Error(
        `release_asset_conflict: the draft for ${tag} already has ${name} with different bytes ` +
        `(${assets.get(name)}; this run built ${sha256}). Nothing was changed. To replace it, delete that asset ` +
        "and its .sig from the draft, then run again.",
      );
    }
    assets.set(name, sha256);
  }

  const platforms = {};
  for (const [manifest, where] of [[existing?.manifest, "on the draft"], [incoming.manifest, "from this run"]]) {
    if (!manifest) continue;
    const prefix = checkManifest(manifest, tag, repository);
    for (const [target, entry] of Object.entries(manifest.platforms)) {
      if (platforms[target] && (platforms[target].url !== entry.url || platforms[target].signature !== entry.signature))
        throw new Error(`release_manifest_conflict: ${target} ${where} differs from the entry already in latest.json for ${tag}`);
      if (!assets.has(entry.url.slice(prefix.length)))
        throw new Error(`release_manifest_asset_missing: latest.json ${where} offers ${entry.url.slice(prefix.length)}, which is not among the release assets`);
      platforms[target] = { url: entry.url, signature: entry.signature };
    }
  }
  // An updater package (one with a signature beside it) that the feed does not offer would never reach anyone.
  const offered = new Set(Object.values(platforms).map(({ url }) => url.slice(url.lastIndexOf("/") + 1)));
  for (const name of assets.keys()) {
    if (/\.(app\.tar\.gz|AppImage|deb|exe|msi)$/.test(name) && assets.has(`${name}.sig`) && !offered.has(name))
      throw new Error(`release_manifest_incomplete: ${name} has an updater signature but latest.json does not offer it. Delete that asset and its .sig from the draft, then run again.`);
  }
  if (!Object.keys(platforms).length) throw new Error("update_assets_missing");
  const manifest = { version: tag.slice(1), platforms: Object.fromEntries(Object.keys(platforms).sort().map((target) => [target, platforms[target]])) };
  const manifestText = JSON.stringify(manifest, null, 2) + "\n";
  assets.set("latest.json", createHash("sha256").update(manifestText).digest("hex"));
  const checksums = [...assets.keys()].sort().map((name) => `${assets.get(name)}  ${name}\n`).join("");
  return { upload: upload.sort(), unchanged: unchanged.sort(), manifest, manifestText, checksums };
}

/** The draft's notes: what earlier runs wrote, one line for this run, and the current update feed. */
export function mergeNotes(body, line, sections) {
  const marker = (body ?? "").search(/^### /m);
  const earlier = (marker < 0 ? body ?? "" : body.slice(0, marker)).trim();
  return [earlier, line.trim(), ...sections.map((section) => section.trim())].filter(Boolean).join("\n\n") + "\n";
}

export const sha256File = (path) => new Promise((accept, reject) => {
  const hash = createHash("sha256");
  createReadStream(path).on("error", reject).on("data", (chunk) => hash.update(chunk)).on("end", () => accept(hash.digest("hex")));
});

const commands = {
  // find TAG RELEASES.jsonl OUTPUT.json: prints the draft's id and its latest.json asset id (empty when there is none).
  find: ([tag, releases, output]) => {
    const draft = selectDraft(readFileSync(releases, "utf8").split("\n").filter(Boolean).map((line) => JSON.parse(line)), tag);
    writeFileSync(output, JSON.stringify(draft));
    console.log(`release_id=${draft?.id ?? ""}`);
    console.log(`manifest_asset=${draft?.assets.find(({ name }) => name === "latest.json")?.id ?? ""}`);
  },
  // merge TAG REPOSITORY ASSETS_DIR INCOMING_LATEST.json DRAFT.json EXISTING_LATEST.json|- OUTPUT_DIR NOTE
  merge: async ([tag, repository, directory, incomingManifest, draftFile, existingManifest, output, note]) => {
    const draft = JSON.parse(readFileSync(draftFile, "utf8"));
    const assets = [];
    for (const name of readdirSync(directory).sort()) assets.push({ name, sha256: await sha256File(join(directory, name)) });
    const existing = draft && {
      assets: draft.assets,
      manifest: existingManifest === "-" ? null : JSON.parse(readFileSync(existingManifest, "utf8")),
    };
    const recorded = draft?.assets.find(({ name }) => name === "latest.json")?.sha256;
    if (recorded !== (existingManifest === "-" ? undefined : await sha256File(existingManifest)))
      throw new Error("release_manifest_invalid: the latest.json read from the draft is not the one the draft holds");
    const merged = mergeDraft({ tag, repository, existing, incoming: { assets, manifest: JSON.parse(readFileSync(incomingManifest, "utf8")) } });
    mkdirSync(output, { recursive: true });
    writeFileSync(join(output, "latest.json"), merged.manifestText);
    writeFileSync(join(output, "SHA256SUMS"), merged.checksums);
    writeFileSync(join(output, "upload.txt"), merged.upload.map((name) => `${name}\n`).join(""));
    const feed = updateFeedSummary(merged.manifest);
    const plan = [
      `### Draft release ${tag}`, "",
      draft ? `Added to the existing draft (release ${draft.id}).` : "Created a new draft.",
      `Uploaded: ${merged.upload.join(", ") || "nothing new"}.`,
      ...(merged.unchanged.length ? [`Already on the draft with the same bytes: ${merged.unchanged.join(", ")}.`] : []),
      "",
    ].join("\n");
    writeFileSync(join(output, "summary.md"), `${plan}\n${feed}`);
    writeFileSync(join(output, "notes.md"), mergeNotes(draft?.body, note, [feed]));
  },
};

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const [command, ...args] = process.argv.slice(2);
  try {
    if (!Object.hasOwn(commands, command)) throw new Error("usage: release_draft.mjs find|merge");
    await commands[command](args);
  } catch (error) {
    console.error(`::error::${String(error.message).replace(/\r?\n/g, " ")}`);
    process.exitCode = 1;
  }
}
