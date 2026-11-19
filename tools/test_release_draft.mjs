import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { mergeDraft, mergeNotes, selectDraft } from "./release_draft.mjs";
import { updateManifest } from "./release_inputs.mjs";
import { parseChecksums } from "./release_packaging.mjs";

const tag = "v1.2.3";
const repository = "Frameleaf/frameleaf-desktop";
const sha = (text) => createHash("sha256").update(text).digest("hex");
const asset = (name, bytes = name) => ({ name, sha256: sha(bytes) });
// Real minisign signatures are long base64 with padding; these keep both properties.
const signatureOf = (name) => Buffer.from(`signature of ${name}`).toString("base64");
const run = (names) => ({
  assets: names.flatMap((name) => /\.dmg$/.test(name) ? [asset(name)] : [asset(name), asset(`${name}.sig`)]),
  manifest: updateManifest(tag, repository, Object.fromEntries(names.filter((name) => !/\.dmg$/.test(name)).map((name) => [name, signatureOf(name)]))),
});
const macos = () => run(["Frameleaf_1.2.3_aarch64.app.tar.gz", "Frameleaf_1.2.3_aarch64.dmg"]);
const linux = () => run(["Frameleaf_1.2.3_amd64.deb", "Frameleaf_1.2.3_amd64.AppImage", "Frameleaf_1.2.3_arm64.deb", "Frameleaf_1.2.3_aarch64.AppImage"]);
const windows = () => run(["Frameleaf_1.2.3_x64-setup.exe", "Frameleaf_1.2.3_x64_en-US.msi"]);
const merge = (existing, incoming) => mergeDraft({ tag, repository, existing, incoming });
// Stage runs one after another, as the workflow does: each adds its new assets and replaces the two generated files.
function stage(...runs) {
  let draft = null;
  let merged;
  for (const incoming of runs) {
    merged = merge(draft, incoming);
    draft = {
      assets: [
        ...(draft?.assets ?? []).filter(({ name }) => !["latest.json", "SHA256SUMS"].includes(name)),
        ...incoming.assets.filter(({ name }) => merged.upload.includes(name)),
        asset("latest.json", merged.manifestText), asset("SHA256SUMS", merged.checksums),
      ],
      manifest: merged.manifest,
    };
  }
  return { merged, draft };
}
const staged = (...runs) => stage(...runs).draft;

test("the first run for a tag uploads everything and lists every asset in SHA256SUMS", () => {
  const first = merge(null, macos());
  assert.deepEqual(first.upload, ["Frameleaf_1.2.3_aarch64.app.tar.gz", "Frameleaf_1.2.3_aarch64.app.tar.gz.sig", "Frameleaf_1.2.3_aarch64.dmg"]);
  assert.deepEqual(first.unchanged, []);
  assert.deepEqual(Object.keys(first.manifest.platforms), ["darwin-aarch64-app"]);
  const sums = parseChecksums(first.checksums);
  assert.deepEqual([...sums.keys()], [...first.upload, "latest.json"].sort());
  assert.equal(sums.get("latest.json"), sha(first.manifestText));
  assert.equal(first.manifestText, JSON.stringify(first.manifest, null, 2) + "\n");
});

test("a later run for the same tag adds its platforms to one latest.json and one SHA256SUMS", () => {
  const afterMac = staged(macos());
  const second = merge(afterMac, linux());
  assert.deepEqual(second.upload, linux().assets.map(({ name }) => name).sort());
  assert.deepEqual(Object.keys(second.manifest.platforms),
    ["darwin-aarch64-app", "linux-aarch64-appimage", "linux-aarch64-deb", "linux-x86_64-appimage", "linux-x86_64-deb"]);
  // Signatures are carried through byte for byte, from the draft and from this run.
  assert.equal(second.manifest.platforms["darwin-aarch64-app"].signature, signatureOf("Frameleaf_1.2.3_aarch64.app.tar.gz"));
  assert.deepEqual(second.manifest.platforms["darwin-aarch64-app"], afterMac.manifest.platforms["darwin-aarch64-app"]);
  assert.equal(second.manifest.platforms["linux-x86_64-deb"].signature, signatureOf("Frameleaf_1.2.3_amd64.deb"));
  const sums = parseChecksums(second.checksums);
  for (const { name, sha256 } of [...macos().assets, ...linux().assets]) assert.equal(sums.get(name), sha256, name);
  assert.equal(sums.get("latest.json"), sha(second.manifestText));
  assert.equal(sums.has("SHA256SUMS"), false);
  assert.equal(sums.size, macos().assets.length + linux().assets.length + 1);

  const third = stage(macos(), linux(), windows()).merged;
  assert.equal(Object.keys(third.manifest.platforms).length, 7);
  // The order the platforms were released in does not change the result.
  const other = stage(windows(), linux(), macos()).merged;
  assert.equal(other.manifestText, third.manifestText);
  assert.equal(other.checksums, third.checksums);
});

test("running the same platform again with the same bytes changes nothing", () => {
  const draft = staged(macos());
  const again = merge(draft, macos());
  assert.deepEqual(again.upload, []);
  assert.deepEqual(again.unchanged, macos().assets.map(({ name }) => name).sort());
  assert.equal(again.manifestText, JSON.stringify(draft.manifest, null, 2) + "\n");
});

test("an existing asset is never replaced by different bytes", () => {
  const draft = staged(macos());
  const rebuilt = macos();
  rebuilt.assets[0] = asset(rebuilt.assets[0].name, "rebuilt bytes");
  assert.throws(() => merge(draft, rebuilt), /release_asset_conflict: the draft for v1\.2\.3 already has Frameleaf_1\.2\.3_aarch64\.app\.tar\.gz with different bytes/);
  // The same package bytes with a new signature is also a different release, not an update of the feed.
  const resigned = macos();
  resigned.manifest.platforms["darwin-aarch64-app"].signature = signatureOf("another signing");
  assert.throws(() => merge(draft, resigned), /release_manifest_conflict: darwin-aarch64-app/);
});

test("only a single draft is ever added to", () => {
  const release = (changes = {}) => ({ id: 7, tag_name: tag, draft: true, body: "notes", assets: [
    { id: 70, name: "latest.json", state: "uploaded", digest: `sha256:${sha("manifest")}` }], ...changes });
  assert.equal(selectDraft([], tag), null);
  assert.equal(selectDraft([release({ tag_name: "v1.2.2" })], tag), null);
  assert.deepEqual(selectDraft([release({ tag_name: "v1.2.2", draft: false }), release()], tag),
    { id: 7, body: "notes", assets: [{ id: 70, name: "latest.json", sha256: sha("manifest") }] });
  assert.throws(() => selectDraft([release({ draft: false })], tag), /release_not_draft: the release for v1\.2\.3 is already published/);
  for (const draft of [false, undefined, null, "true"]) assert.throws(() => selectDraft([release({ draft })], tag), /release_not_draft/);
  // GitHub lets two drafts share a tag: both 0.1.5 runs staged their own. Never pick one.
  assert.throws(() => selectDraft([release(), release({ id: 8 })], tag), /release_tag_ambiguous: 2 releases exist for v1\.2\.3 \(ids 7, 8\)/);
  assert.throws(() => selectDraft([release(), release({ id: 8, draft: false })], tag), /release_tag_ambiguous/);
  for (const broken of [{ digest: null }, { digest: "md5:abc" }, { state: "starter" }]) {
    assert.throws(() => selectDraft([release({ assets: [{ id: 70, name: "Frameleaf.dmg", state: "uploaded", digest: `sha256:${sha("x")}`, ...broken }] })], tag),
      /release_asset_unverifiable: Frameleaf\.dmg/);
  }
});

test("a manifest that does not match the release it is merged into is refused", () => {
  const draft = staged(macos());
  const edit = (change) => { const incoming = linux(); change(incoming); return incoming; };
  assert.throws(() => merge(draft, edit((run) => { run.manifest.version = "1.2.4"; })), /release_manifest_invalid/);
  assert.throws(() => merge(draft, edit((run) => { run.manifest.platforms["linux-x86_64-deb"].url = "https://example.com/Frameleaf_1.2.3_amd64.deb"; })), /release_manifest_invalid/);
  assert.throws(() => merge(draft, edit((run) => { run.manifest.platforms["linux-x86_64-deb"].url = run.manifest.platforms["linux-x86_64-deb"].url.replace("v1.2.3", "v1.2.2"); })), /release_manifest_invalid/);
  assert.throws(() => merge(draft, edit((run) => { run.manifest.platforms["linux-x86_64-deb"].signature = ""; })), /release_manifest_invalid/);
  assert.throws(() => merge(draft, edit((run) => { run.manifest.platforms["freebsd-x86_64-pkg"] = run.manifest.platforms["linux-x86_64-deb"]; })), /release_manifest_invalid/);
  assert.throws(() => merge(draft, edit((run) => { run.assets = run.assets.filter(({ name }) => name !== "Frameleaf_1.2.3_amd64.deb"); })), /release_manifest_asset_missing/);
  // A signed updater package on the draft that its latest.json does not offer would reach nobody.
  assert.throws(() => merge({ ...draft, manifest: null }, linux()), /release_manifest_incomplete: Frameleaf_1\.2\.3_aarch64\.app\.tar\.gz/);
  assert.throws(() => merge(draft, edit((run) => { run.assets.push({ name: "../escape", sha256: sha("x") }); })), /release_asset_invalid/);
  assert.throws(() => merge(draft, edit((run) => { run.assets.push({ name: "Frameleaf.zip", sha256: "abc" }); })), /release_asset_invalid/);
  assert.throws(() => mergeDraft({ tag: "main", repository, existing: null, incoming: macos() }), /release_version_invalid/);
});

test("hand-attached assets on the draft are kept and listed in the checksums", () => {
  const companion = asset("FrameleafCompanion_1.2.4_arm64.pkg");
  const unsigned = asset("Frameleaf_1.2.3_x64-setup-unsigned.exe");
  const draft = staged(macos());
  draft.assets.push(companion, unsigned);
  const merged = merge(draft, linux());
  const sums = parseChecksums(merged.checksums);
  assert.equal(sums.get(companion.name), companion.sha256);
  assert.equal(sums.get(unsigned.name), unsigned.sha256);
  assert.equal(Object.keys(merged.manifest.platforms).some((target) => target.startsWith("windows-")), false);
});

test("the draft notes keep one line per run and the current update feed", () => {
  const first = mergeNotes("", "Run one. ", ["### Update feed for 1.2.3\n\nmacOS only.\n"]);
  assert.equal(first, "Run one.\n\n### Update feed for 1.2.3\n\nmacOS only.\n");
  assert.equal(mergeNotes(first, "Run two.", ["### Update feed for 1.2.3\n\nmacOS and Linux.\n"]),
    "Run one.\n\nRun two.\n\n### Update feed for 1.2.3\n\nmacOS and Linux.\n");
  assert.equal(mergeNotes(undefined, "Run one.", []), "Run one.\n");
});

test("the command the workflow runs stages two runs into one draft", () => {
  const tool = fileURLToPath(new URL("./release_draft.mjs", import.meta.url));
  const root = mkdtempSync(join(tmpdir(), "frameleaf-draft-test-"));
  const call = (...args) => spawnSync(process.execPath, [tool, ...args], { encoding: "utf8" });
  const write = (dir, files) => { mkdirSync(dir); for (const [name, text] of Object.entries(files)) writeFileSync(join(dir, name), text); return dir; };
  const files = (names) => Object.fromEntries(names.flatMap((name) => [[name, name], [`${name}.sig`, signatureOf(name)]]));
  const incoming = (name, names) => {
    const path = join(root, name);
    writeFileSync(path, JSON.stringify(updateManifest(tag, repository, Object.fromEntries(names.map((item) => [item, signatureOf(item)])))));
    return path;
  };
  try {
    const releases = join(root, "releases.jsonl");
    writeFileSync(releases, "");
    const draft = join(root, "draft.json");
    let found = call("find", tag, releases, draft);
    assert.equal(found.stdout, "release_id=\nmanifest_asset=\n", found.stderr);

    const mac = ["Frameleaf_1.2.3_aarch64.app.tar.gz"];
    const one = join(root, "one");
    let merged = call("merge", tag, repository, write(join(root, "mac"), files(mac)), incoming("mac.json", mac), draft, "-", one, "Run one.");
    assert.equal(merged.status, 0, merged.stderr);
    assert.equal(readFileSync(join(one, "upload.txt"), "utf8"), "Frameleaf_1.2.3_aarch64.app.tar.gz\nFrameleaf_1.2.3_aarch64.app.tar.gz.sig\n");
    assert.match(readFileSync(join(one, "notes.md"), "utf8"), /^Run one\.\n\n### Update feed for 1\.2\.3\n[^]*Windows was excluded from the update feed/);
    assert.match(readFileSync(join(one, "summary.md"), "utf8"), /^### Draft release v1\.2\.3\n\nCreated a new draft\./);

    // The draft as GitHub reports it after the first run.
    const uploaded = (name, text, id) => ({ id, name, state: "uploaded", digest: `sha256:${sha(text)}` });
    const manifestText = readFileSync(join(one, "latest.json"), "utf8");
    writeFileSync(releases, JSON.stringify({ id: 41, tag_name: tag, draft: true, body: readFileSync(join(one, "notes.md"), "utf8"), assets: [
      ...Object.entries(files(mac)).map(([name, text], index) => uploaded(name, text, index + 1)),
      uploaded("latest.json", manifestText, 9), uploaded("SHA256SUMS", readFileSync(join(one, "SHA256SUMS"), "utf8"), 10),
    ] }) + "\n");
    found = call("find", tag, releases, draft);
    assert.equal(found.stdout, "release_id=41\nmanifest_asset=9\n", found.stderr);

    const deb = ["Frameleaf_1.2.3_amd64.deb"];
    const existing = join(root, "existing-latest.json");
    writeFileSync(existing, manifestText);
    const two = join(root, "two");
    const linuxAssets = write(join(root, "linux"), files(deb));
    merged = call("merge", tag, repository, linuxAssets, incoming("linux.json", deb), draft, existing, two, "Run two.");
    assert.equal(merged.status, 0, merged.stderr);
    assert.equal(readFileSync(join(two, "upload.txt"), "utf8"), "Frameleaf_1.2.3_amd64.deb\nFrameleaf_1.2.3_amd64.deb.sig\n");
    const manifest = JSON.parse(readFileSync(join(two, "latest.json"), "utf8"));
    assert.deepEqual(Object.keys(manifest.platforms), ["darwin-aarch64-app", "linux-x86_64-deb"]);
    assert.equal(manifest.platforms["darwin-aarch64-app"].signature, signatureOf(mac[0]));
    assert.deepEqual([...parseChecksums(readFileSync(join(two, "SHA256SUMS"), "utf8")).keys()], [
      "Frameleaf_1.2.3_aarch64.app.tar.gz", "Frameleaf_1.2.3_aarch64.app.tar.gz.sig",
      "Frameleaf_1.2.3_amd64.deb", "Frameleaf_1.2.3_amd64.deb.sig", "latest.json"]);
    assert.match(readFileSync(join(two, "notes.md"), "utf8"), /^Run one\.\n\nRun two\.\n\n### Update feed for 1\.2\.3\n[^]*darwin-aarch64-app, linux-x86_64-deb\./);
    assert.match(readFileSync(join(two, "summary.md"), "utf8"), /Added to the existing draft \(release 41\)\./);

    // A latest.json that is not the one the draft holds, a changed asset and a published release each stop the run.
    writeFileSync(existing, manifestText + " ");
    merged = call("merge", tag, repository, linuxAssets, incoming("linux.json", deb), draft, existing, join(root, "three"), "Run two.");
    assert.equal(merged.status, 1);
    assert.match(merged.stderr, /^::error::release_manifest_invalid/);
    writeFileSync(existing, manifestText);
    writeFileSync(join(root, "mac", mac[0]), "rebuilt");
    merged = call("merge", tag, repository, join(root, "mac"), incoming("mac.json", mac), draft, existing, join(root, "four"), "Run again.");
    assert.equal(merged.status, 1);
    assert.match(merged.stderr, /^::error::release_asset_conflict/);
    writeFileSync(releases, JSON.stringify({ id: 41, tag_name: tag, draft: false, body: "", assets: [] }) + "\n");
    found = call("find", tag, releases, draft);
    assert.equal(found.status, 1);
    assert.match(found.stderr, /^::error::release_not_draft/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("the release workflow stages through the merge tool and never replaces a package", () => {
  const workflow = readFileSync(new URL("../.github/workflows/release.yml", import.meta.url), "utf8");
  assert.match(workflow, /node tools\/release_draft\.mjs find "\$RELEASE_TAG"/);
  assert.match(workflow, /node tools\/release_draft\.mjs merge "\$RELEASE_TAG" "\$GITHUB_REPOSITORY" release-assets/);
  // --clobber appears once, and only for the two files rebuilt from the whole draft.
  const clobber = workflow.split("\n").filter((line) => line.includes("--clobber") && !line.trim().startsWith("#"));
  assert.equal(clobber.length, 1);
  assert.match(clobber[0], /--clobber -- "\$draft\/latest\.json" "\$draft\/SHA256SUMS"$/);
  assert.match(workflow, /gh release create "\$RELEASE_TAG" [^\n]*--draft --prerelease/);
  assert.doesNotMatch(workflow, /gh release (?:delete|edit [^\n]*--draft=false)|--latest/);
});
