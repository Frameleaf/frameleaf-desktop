import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  checkCatalogueAgainstServer, checkCompanionArtifact, checkCompanionIdentity, checkCompanionWithoutIdentity, checkFactoryArtifacts,
  checkFactoryEpoch, checkFactoryPack, checkWindowsSigning, companionNote, companionProducers, companionRunIds, companionSummary,
  latestServerRelease, planCompanions, recordCompanion, windowsSigningVariables,
} from "./release_prerequisites.mjs";
import { HOST_REQUIRED, HOST_ROLES } from "./sign_host_runtime.mjs";
import { releaseMatrix, releasePlatformChoices } from "./release_inputs.mjs";

const repository = "Frameleaf/frameleaf-desktop";
const read = (path) => readFileSync(new URL(`../${path}`, import.meta.url), "utf8");
const tool = fileURLToPath(new URL("./release_prerequisites.mjs", import.meta.url));
const call = (args, env = {}) => spawnSync(process.execPath, [tool, ...args], { encoding: "utf8", env: { ...process.env, ...env } });

test("a Windows release names each missing signing variable and where to set it", () => {
  const configured = Object.fromEntries(windowsSigningVariables.map((name) => [name, "value"]));
  assert.doesNotThrow(() => checkWindowsSigning(configured, repository));
  // The state of the desktop-release environment when this was written: two variables are not set.
  const today = { ...configured, AZURE_SIGNING_PROFILE: "", WINDOWS_SIGNING_SUBJECT: undefined };
  assert.throws(() => checkWindowsSigning(today, repository), (error) => {
    assert.match(error.message, /^windows_signing_unconfigured: AZURE_SIGNING_PROFILE, WINDOWS_SIGNING_SUBJECT are not set\./);
    assert.match(error.message, /environment variable \(not a secret\) of the desktop-release environment: https:\/\/github\.com\/Frameleaf\/frameleaf-desktop\/settings\/environments/);
    assert.match(error.message, /Microsoft's identity validation/);
    return true;
  });
  assert.throws(() => checkWindowsSigning({ ...configured, AZURE_SIGNING_ACCOUNT: "  " }, repository), /^Error: windows_signing_unconfigured: AZURE_SIGNING_ACCOUNT is not set\. Set it as/);
  assert.throws(() => checkWindowsSigning({ ...configured, WINDOWS_SIGNING_SUBJECT: "CN=Frameleaf\nO=Other" }, repository), /WINDOWS_SIGNING_SUBJECT is not set/);
  for (const name of windowsSigningVariables) {
    const env = { ...configured };
    delete env[name];
    assert.throws(() => checkWindowsSigning(env, repository), new RegExp(`windows_signing_unconfigured: ${name} is not set`));
  }
});

test("the Windows signing check runs before any build and reads every variable the signing action needs", () => {
  const workflow = read(".github/workflows/release.yml");
  const action = read(".github/actions/windows-signing/action.yml");
  const preflight = /\n  signing-preflight:\n([^]*?)\n  build:\n/.exec(workflow)?.[1];
  assert.ok(preflight, "release.yml must have the signing preflight job before build");
  assert.match(preflight, /\n    if: needs\.prepare\.result == 'success' && contains\(needs\.prepare\.outputs\.matrix, '"windows-x86_64"'\)\n/);
  // The condition reads the matrix text, so it must find Windows exactly when the matrix has it.
  for (const choice of releasePlatformChoices) {
    const matrix = JSON.stringify(releaseMatrix(choice));
    assert.equal(matrix.includes('"windows-x86_64"'), ["all", "windows"].includes(choice), choice);
  }
  assert.match(preflight, /\n    environment: desktop-release\n/);
  assert.match(preflight, /node tools\/release_prerequisites\.mjs windows-signing/);
  for (const name of windowsSigningVariables) {
    assert.ok(preflight.includes(`${name}: \${{ vars.${name} }}`), name);
    assert.ok(action.includes(`'${name}'`), `the signing action no longer requires ${name}`);
  }
  // Every platform waits for it, and a failed preflight stops them all.
  assert.match(workflow, /\n  build:\n    needs: \[prepare, signing-preflight\]\n(?:    #.*\n)*    if: \$\{\{ !cancelled\(\) && needs\.prepare\.result == 'success' && \(needs\.signing-preflight\.result == 'success' \|\| needs\.signing-preflight\.result == 'skipped'\) \}\}\n/);
  assert.match(workflow, /\n  stage:\n(?:    #.*\n)*    if: \$\{\{ !cancelled\(\) && inputs\.tag != '' && needs\.build\.result == 'success' \}\}\n/);
  const missing = call(["windows-signing"], { GITHUB_REPOSITORY: repository, ...Object.fromEntries(windowsSigningVariables.map((name) => [name, name.startsWith("AZURE_SIGNING_P") ? "" : "set"])) });
  assert.equal(missing.status, 1);
  assert.match(missing.stderr, /^::error::windows_signing_unconfigured: AZURE_SIGNING_PROFILE is not set\./);
});

test("a factory epoch at or below one already used is refused, and the message says which to use", () => {
  const record = { schemaVersion: 1, highestUsedEpoch: 8 };
  const trust = { minimumRuntimeEpoch: 2 };
  assert.equal(checkFactoryEpoch("9", record, trust), 9);
  assert.equal(checkFactoryEpoch("12", record, trust), 12);
  // 7 was the workflow default after 8 had been used for the 0.1.6 draft.
  assert.throws(() => checkFactoryEpoch("7", record, trust), /runtime_factory_epoch_used: epoch 7 is not above 8[^]*runtime_epoch_rollback[^]*Use 9\.$/);
  assert.throws(() => checkFactoryEpoch("8", record, trust), /runtime_factory_epoch_used: epoch 8 is not above 8[^]*runtime_epoch_reused/);
  for (const value of ["", undefined, 9, "09", "9.0", " 9", "nine", "-1", "0", "99999999999999999999"]) {
    assert.throws(() => checkFactoryEpoch(value, record, trust), /runtime_factory_epoch_invalid: [^]*next one to use is 9/, String(value));
  }
  for (const broken of [null, {}, { schemaVersion: 2, highestUsedEpoch: 8 }, { schemaVersion: 1, highestUsedEpoch: "8" }, { schemaVersion: 1, highestUsedEpoch: 0 }]) {
    assert.throws(() => checkFactoryEpoch("9", broken, trust), /runtime_factory_epoch_record_invalid/);
  }
});

test("the factory workflow has no default epoch and the record is the highest epoch ever used", () => {
  const workflow = read(".github/workflows/factory-runtime.yml");
  const epoch = /\n      epoch:\n((?: {8}.*\n)+)/.exec(workflow)?.[1];
  assert.ok(epoch);
  assert.match(epoch, /\n? {8}required: true\n/);
  assert.doesNotMatch(epoch, /^ {8}default:/m);
  assert.match(workflow, /node tools\/release_prerequisites\.mjs factory-epoch "\$RUNTIME_EPOCH"/);
  const record = JSON.parse(read("runtime/factory-epochs.json"));
  // Epoch 8 was built for the 0.1.6 draft (factory run 42870045811); lowering the record reopens the trap.
  assert.ok(record.highestUsedEpoch >= 8);
  assert.equal(call(["factory-epoch", String(record.highestUsedEpoch + 1)]).stdout, `${record.highestUsedEpoch + 1}\n`);
  const used = call(["factory-epoch", String(record.highestUsedEpoch)]);
  assert.equal(used.status, 1);
  assert.match(used.stderr, /^::error::runtime_factory_epoch_used/);
  // The documented next epoch follows the record.
  assert.ok(read("docs/releases.md").includes(`the next epoch to use is **${record.highestUsedEpoch + 1}**`));
});

test("the factory run must hold an unexpired pack for every selected platform", () => {
  const artifacts = ["macos-aarch64", "linux-x86_64", "linux-aarch64"].map((target) => ({ name: `factory-runtime-${target}`, expired: false }));
  assert.doesNotThrow(() => checkFactoryArtifacts(artifacts, "linux", "42"));
  assert.doesNotThrow(() => checkFactoryArtifacts(artifacts, "macos-aarch64", "42"));
  assert.throws(() => checkFactoryArtifacts(artifacts, "macos-linux", "42"), /runtime_run_pack_missing: factory run 42 has no unexpired factory-runtime-<target> artifact for macos-x86_64\. Run factory-runtime\.yml for that platform/);
  assert.throws(() => checkFactoryArtifacts(artifacts, "all", "42"), /for macos-x86_64, windows-x86_64\. Run factory-runtime\.yml for those platforms/);
  assert.throws(() => checkFactoryArtifacts([{ name: "factory-runtime-windows-x86_64", expired: true }], "windows", "42"), /runtime_run_pack_missing/);
  // The unsigned intermediate of the same run is not a pack.
  assert.throws(() => checkFactoryArtifacts([{ name: "unsigned-runtime-windows-x86_64", expired: false }], "windows", "42"), /runtime_run_pack_missing/);
  assert.throws(() => checkFactoryArtifacts(undefined, "windows", "42"), /runtime_run_pack_missing/);
});

test("a pack from another source, profile, target or a used epoch stops the release before the build", () => {
  const cpu = "a".repeat(40), extra = "b".repeat(40), gpu = "c".repeat(40), other = "d".repeat(40);
  const profiles = { schemaVersion: 1, profiles: {
    "cpu-ort": { provider: "CPUExecutionProvider", targets: ["macos-aarch64", "linux-x86_64"], sourceRevision: cpu, additionalSources: { "macos-aarch64": [extra] } },
    "coreml-ort": { provider: "CoreMLExecutionProvider", targets: ["macos-aarch64"], sourceRevision: gpu },
  } };
  const options = { profiles, record: { schemaVersion: 1, highestUsedEpoch: 8 } };
  const pack = (changes = {}) => ({ platform: "linux", architecture: "x86_64", provider: "CPUExecutionProvider", sourceRevision: cpu, epoch: 9, ...changes });
  const mac = (changes = {}) => pack({ platform: "macos", architecture: "aarch64", ...changes });
  assert.equal(checkFactoryPack("linux-x86_64", pack(), undefined, options), `linux-x86_64: CPUExecutionProvider from ${cpu}, runtime epoch 9`);
  assert.doesNotThrow(() => checkFactoryPack("macos-aarch64", mac({ sourceRevision: extra }), undefined, options));
  // An accelerated pack: both manifests are one payload, built from the accelerated profile's source.
  const coreml = mac({ provider: "CoreMLExecutionProvider", sourceRevision: gpu });
  assert.match(checkFactoryPack("macos-aarch64", mac({ sourceRevision: gpu }), coreml, options), /CoreMLExecutionProvider from c{40}, runtime epoch 9$/);

  assert.throws(() => checkFactoryPack("linux-x86_64", pack({ sourceRevision: other }), undefined, options),
    /runtime_run_pack_unapproved: the linux-x86_64 pack is CPUExecutionProvider from d{40}, which runtime\/profiles\.json on this commit does not approve for linux-x86_64\. Run factory-runtime\.yml again/);
  // The additional source is approved for Apple Silicon only.
  assert.throws(() => checkFactoryPack("linux-x86_64", pack({ sourceRevision: extra }), undefined, options), /runtime_run_pack_unapproved/);
  assert.throws(() => checkFactoryPack("linux-x86_64", pack({ provider: "CUDAExecutionProvider" }), undefined, options), /runtime_run_pack_unapproved/);
  assert.throws(() => checkFactoryPack("macos-aarch64", mac(), coreml, options), /runtime_run_pack_unapproved[^]*with an accelerated manifest CoreMLExecutionProvider/);
  assert.throws(() => checkFactoryPack("macos-aarch64", mac({ sourceRevision: gpu }), { ...coreml, sourceRevision: other }, options), /runtime_run_pack_unapproved/);
  assert.throws(() => checkFactoryPack("linux-x86_64", pack(), pack({ provider: "CoreMLExecutionProvider", sourceRevision: gpu }), options), /runtime_run_pack_unapproved/);
  assert.throws(() => checkFactoryPack("linux-x86_64", pack(), undefined, { ...options, profiles: { ...profiles, schemaVersion: 2 } }), /runtime_run_pack_unapproved/);
  assert.throws(() => checkFactoryPack("linux-aarch64", pack(), undefined, options), /runtime_run_pack_target_mismatch: factory-runtime-linux-aarch64 holds a pack for linux-x86_64/);
  assert.throws(() => checkFactoryPack("linux-x86_64", undefined, undefined, options), /runtime_run_pack_target_mismatch/);

  // The 0.1.6 draft pack was epoch 8; the old workflow default was 7.
  for (const epoch of [7, 8, "9", undefined]) {
    assert.throws(() => checkFactoryPack("linux-x86_64", pack({ epoch }), undefined, options), /runtime_run_pack_epoch_used: [^]*Build the pack again with epoch 9\./, String(epoch));
  }
  assert.throws(() => checkFactoryPack("macos-aarch64", mac({ sourceRevision: gpu }), { ...coreml, epoch: 8 }, options), /runtime_run_pack_epoch_used/);
  // An artifacts-only run publishes nothing and may reuse an older pack, but never an unapproved one.
  assert.doesNotThrow(() => checkFactoryPack("linux-x86_64", pack({ epoch: 8 }), undefined, { ...options, release: false }));
  assert.throws(() => checkFactoryPack("linux-x86_64", pack({ epoch: 8, sourceRevision: other }), undefined, { ...options, release: false }), /runtime_run_pack_unapproved/);
});

test("the pack check agrees with this repository's approved profiles", () => {
  const profiles = JSON.parse(read("runtime/profiles.json"));
  const record = JSON.parse(read("runtime/factory-epochs.json"));
  const epoch = record.highestUsedEpoch + 1;
  for (const target of profiles.profiles["cpu-ort"].targets) {
    const [platform, architecture] = target.split("-");
    const manifest = { platform, architecture, provider: "CPUExecutionProvider", sourceRevision: profiles.profiles["cpu-ort"].sourceRevision, epoch };
    assert.doesNotThrow(() => checkFactoryPack(target, manifest), target);
    assert.throws(() => checkFactoryPack(target, { ...manifest, sourceRevision: "0".repeat(40) }), /runtime_run_pack_unapproved/, target);
  }
  const directory = mkdtempSync(join(tmpdir(), "frameleaf-pack-test-"));
  try {
    const manifest = { platform: "linux", architecture: "x86_64", provider: "CPUExecutionProvider", sourceRevision: profiles.profiles["cpu-ort"].sourceRevision, epoch: record.highestUsedEpoch };
    writeFileSync(join(directory, "manifest.json"), JSON.stringify(manifest));
    const release = call(["factory-pack", "linux-x86_64", directory, "release"]);
    assert.equal(release.status, 1);
    assert.match(release.stderr, /^::error::runtime_run_pack_epoch_used/);
    const artifacts = call(["factory-pack", "linux-x86_64", directory, ""]);
    assert.equal(artifacts.status, 0, artifacts.stderr);
    assert.match(artifacts.stdout, /^- linux-x86_64: CPUExecutionProvider from [a-f0-9]{40}, runtime epoch \d+\n$/);
    assert.equal(call(["factory-pack", "windows-x86_64", directory, ""]).status, 1);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("the newest published server release is chosen, never a draft, prerelease or Manager release", () => {
  const release = (tag_name, changes = {}) => ({ tag_name, draft: false, prerelease: false, ...changes });
  assert.equal(latestServerRelease([
    release("manager-v1.2.22"), release("frameleaf-v1.2.22", { draft: true }), release("frameleaf-v1.2.23", { prerelease: true }),
    release("frameleaf-v1.2.9"), release("frameleaf-v1.2.21"), release("frameleaf-v1.2.20"), release("frameleaf-v1.2.21-rc.1"),
    release("frameleaf-v1.10.0", { draft: undefined }),
  ]), "frameleaf-v1.2.21");
  assert.equal(latestServerRelease([release("frameleaf-v1.9.9"), release("frameleaf-v1.10.0"), release("frameleaf-v0.99.99")]), "frameleaf-v1.10.0");
  for (const none of [[], undefined, [release("manager-v1.2.21")], [release("frameleaf-v1.2.21", { draft: true })]]) {
    assert.throws(() => latestServerRelease(none), /server_release_unknown/);
  }
});

test("Desktop is not released with a model catalogue the released server does not have", () => {
  const catalogue = (epoch) => ({ schemaVersion: 1, epoch, profiles: [] });
  const tag = "frameleaf-v1.2.21";
  // What the review found: Desktop at 15, the latest server release at 14.
  assert.throws(() => checkCatalogueAgainstServer(catalogue(15), catalogue(14), tag),
    /^Error: catalogue_ahead_of_server: Desktop's model catalogue is epoch 15; the latest server release \(frameleaf-v1\.2\.21\) has epoch 14\. Release the server first[^]*allow_unreleased_catalogue\.$/);
  for (const allow of [undefined, false, "true", 1]) assert.throws(() => checkCatalogueAgainstServer(catalogue(15), catalogue(14), tag, allow), /catalogue_ahead_of_server/);
  assert.match(checkCatalogueAgainstServer(catalogue(15), catalogue(14), tag, true), /epoch 15;[^]*epoch 14\. Released anyway because allow_unreleased_catalogue was set/);
  assert.equal(checkCatalogueAgainstServer(catalogue(15), catalogue(15), tag), "Desktop's model catalogue is epoch 15; the latest server release (frameleaf-v1.2.21) has epoch 15.");
  assert.doesNotThrow(() => checkCatalogueAgainstServer(catalogue(14), catalogue(15), tag));
  for (const broken of [undefined, {}, { schemaVersion: 1 }, { schemaVersion: 2, epoch: 15 }, { schemaVersion: 1, epoch: "15" }, { schemaVersion: 1, epoch: 0 }]) {
    assert.throws(() => checkCatalogueAgainstServer(broken, catalogue(14), tag, true), /catalogue_invalid: Desktop's/);
    assert.throws(() => checkCatalogueAgainstServer(catalogue(15), broken, tag, true), /catalogue_invalid: the catalogue in frameleaf-v1\.2\.21/);
  }
});

test("the catalogue command compares this repository's catalogue and honours only the explicit override", () => {
  const directory = mkdtempSync(join(tmpdir(), "frameleaf-catalogue-test-"));
  try {
    const desktop = JSON.parse(read("runtime/model-catalogue.json")).epoch;
    const file = (epoch) => { const path = join(directory, `${epoch}.json`); writeFileSync(path, JSON.stringify({ schemaVersion: 1, epoch, profiles: [] })); return path; };
    assert.equal(call(["catalogue", "frameleaf-v9.9.9", file(desktop), "false"]).status, 0);
    const behind = call(["catalogue", "frameleaf-v9.9.9", file(desktop - 1), "false"]);
    assert.equal(behind.status, 1);
    assert.match(behind.stderr, /^::error::catalogue_ahead_of_server: [^]*Release the server first/);
    const allowed = call(["catalogue", "frameleaf-v9.9.9", file(desktop - 1), "true"]);
    assert.equal(allowed.status, 0, allowed.stderr);
    assert.match(allowed.stdout, /Released anyway/);
    const releases = join(directory, "releases.jsonl");
    writeFileSync(releases, ['{"tag_name":"manager-v1.2.21","draft":false,"prerelease":false}', '{"tag_name":"frameleaf-v1.2.21","draft":false,"prerelease":false}', ""].join("\n"));
    assert.equal(call(["server-release", releases]).stdout, "frameleaf-v1.2.21\n");
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
  const workflow = read(".github/workflows/release.yml");
  assert.match(workflow, /catalogue "\$server_tag" "\$RUNNER_TEMP\/server-catalogue\.json" "\$ALLOW_UNRELEASED_CATALOGUE"/);
  assert.match(workflow, /ALLOW_UNRELEASED_CATALOGUE: \$\{\{ inputs\.allow_unreleased_catalogue \}\}/);
  assert.match(workflow, /\n      allow_unreleased_catalogue:\n(?: {8}.*\n)*? {8}default: false\n/);
});

const companionWorkflow = ".github/workflows/macos-host-package.yml";
const linuxWorkflow = ".github/workflows/ubuntu-host-qualification.yml";
const windowsWorkflow = ".github/workflows/windows-compiled-host.yml";
const companionRun = (changes = {}) => ({ status: "completed", conclusion: "success", head_branch: "main", event: "workflow_dispatch",
  path: companionWorkflow, head_sha: "a".repeat(40), repository: { full_name: repository }, ...changes });
const sha = (bytes) => createHash("sha256").update(bytes).digest("hex");

test("companion run ids are a short list of run numbers or none", () => {
  assert.deepEqual(companionRunIds("42148037724"), ["42148037724"]);
  assert.deepEqual(companionRunIds(" 42148037724 "), ["42148037724"]);
  assert.deepEqual(companionRunIds("1, 2,3"), ["1", "2", "3"]);
  for (const empty of ["none", "", "  ", undefined]) assert.deepEqual(companionRunIds(empty), []);
  for (const value of ["abc", "1,2,3,4", "1,1", "01", "1;rm", "1 2", "-1", "None", "$(id)", "1,none"]) {
    assert.throws(() => companionRunIds(value), /companion_runs_invalid: .*ubuntu-host-qualification\.yml, windows-compiled-host\.yml/, value);
  }
});

test("every platform with a companion package needs its run, or an explicit none", () => {
  const runs = { 7: companionRun(), 8: companionRun({ path: linuxWorkflow }), 9: companionRun({ path: windowsWorkflow }) };
  const item = (run, target, artifact, workflow) => ({ run, target, artifact, workflow, revision: "a".repeat(40) });
  assert.deepEqual(planCompanions("all", "7,8,9", runs, repository), {
    attach: [
      item("7", "macos-aarch64", "frameleaf-macos-arm64-companion-installed", companionWorkflow),
      item("8", "linux-x86_64", "frameleaf-linux-x64-companion-installed", linuxWorkflow),
      item("9", "windows-x86_64", "frameleaf-windows-x64-companion-installed", windowsWorkflow),
    ],
    manual: [],
  });
  assert.throws(() => planCompanions("macos-linux", "7", runs, repository),
    /companion_run_missing: no companion package run was given for linux-x86_64\. Pass the run id of ubuntu-host-qualification\.yml/);
  assert.throws(() => planCompanions("all", "", runs, repository),
    /companion_run_missing: no companion package run was given for macos-aarch64, windows-x86_64, linux-x86_64\. Pass the run id of macos-host-package\.yml and windows-compiled-host\.yml and ubuntu-host-qualification\.yml/);
  for (const platforms of ["macos-aarch64", "linux", "linux-x86_64", "windows"]) {
    assert.throws(() => planCompanions(platforms, undefined, runs, repository), /companion_run_missing/, platforms);
  }
  assert.deepEqual(planCompanions("all", "none", runs, repository), { attach: [], manual: ["macos-aarch64", "windows-x86_64", "linux-x86_64"] });
  // Intel Macs and Linux ARM have no companion package.
  assert.deepEqual(planCompanions("macos-x86_64", "", {}, repository), { attach: [], manual: [] });
  assert.deepEqual(planCompanions("linux-aarch64", "", {}, repository), { attach: [], manual: [] });
  assert.throws(() => planCompanions("linux", "7", runs, repository), /companion_run_unselected: run 7 holds the macos-aarch64 companion package/);
  assert.throws(() => planCompanions("linux", "8,10", { ...runs, 10: companionRun({ path: linuxWorkflow }) }, repository), /companion_run_duplicate/);
});

test("a companion run is trusted only as a successful manual run of its workflow on main here", () => {
  for (const path of [companionWorkflow, `${companionWorkflow}@main`, `${companionWorkflow}@refs/heads/main`]) {
    assert.equal(planCompanions("macos-aarch64", "7", { 7: companionRun({ path }) }, repository).attach[0].revision, "a".repeat(40));
  }
  for (const changed of [undefined, null, {}, companionRun({ status: "in_progress" }), companionRun({ conclusion: "failure" }),
    companionRun({ head_branch: "other" }), companionRun({ event: "pull_request" }), companionRun({ path: null }),
    companionRun({ path: ".github/workflows/factory-runtime.yml" }), companionRun({ path: ".github/workflows/macos-host-signing.yml" }),
    // Workflows that sign or assemble but do not retain an installed, qualified package.
    companionRun({ path: ".github/workflows/linux-host-signing.yml" }), companionRun({ path: ".github/workflows/windows-host-signing.yml" }),
    companionRun({ repository: { full_name: "attacker/fork" } }), companionRun({ head_sha: "main" })]) {
    assert.throws(() => planCompanions("macos-aarch64", "7", { 7: changed }, repository), /companion_run_untrusted/);
  }
  // The run fetched for another id is never used.
  assert.throws(() => planCompanions("macos-aarch64", "8", { 7: companionRun() }, repository), /companion_run_untrusted/);
});

// A signed host manifest as a package carries it, with the keys that signed it.
function signedManifest(changes = {}) {
  const pins = JSON.parse(read("runtime/host-database.json"));
  const keys = generateKeyPairSync("ed25519");
  const trust = { schemaVersion: 1, minimumRuntimeEpoch: 2, keys: [{ id: "fixture",
    publicKeyHex: keys.publicKey.export({ format: "der", type: "spki" }).subarray(-32).toString("hex") }] };
  const files = Object.fromEntries([...HOST_ROLES.map((role) => `roles/${role}`), ...HOST_REQUIRED].map((path) => [path, { bytes: 1, sha256: "0".repeat(64) }]));
  const manifest = Buffer.from(JSON.stringify({
    schemaVersion: 1, protocolVersion: 2, epoch: 25, platform: "linux", architecture: "x86_64", sourceRevision: "9".repeat(40),
    nodeVersion: "26.11.1", postgresVersion: pins.postgresVersion, vectorVersion: pins.pgvectorVersion, certified: pins.certified,
    entryPoints: Object.fromEntries(HOST_ROLES.map((role) => [role, `roles/${role}`])), files, ...changes,
  }));
  return { manifest, signature: sign(null, manifest, keys.privateKey), trust };
}
const linuxNames = ["FrameleafCompanion_1.2.5_amd64_bootstrap.deb", "FrameleafCompanion_1.2.5_amd64_runtime.deb"];
const linuxIdentity = (manifest, changes = {}) => ({ schemaVersion: 1, target: "linux-x86_64", version: "1.2.5", manifestSha256: sha(manifest),
  controllerSha256: "c".repeat(64), files: { [linuxNames[0]]: sha("bootstrap"), [linuxNames[1]]: sha("runtime") }, ...changes });

test("a companion package this Desktop commit would refuse once installed stops the release", async () => {
  const { manifest, signature, trust } = signedManifest();
  const identity = linuxIdentity(manifest);
  assert.deepEqual(await checkCompanionIdentity(linuxWorkflow, identity, manifest, signature, trust), identity.files);

  // Signed by a key this commit does not trust, or not signed at all.
  await assert.rejects(checkCompanionIdentity(linuxWorkflow, identity, manifest, signature, signedManifest().trust),
    /^Error: companion_incompatible: the linux-x86_64 companion package \(Library 1\.2\.5, manifest [a-f0-9]{64}\) fails host_signature_invalid: .*runtime\/release-trust\.json/);
  await assert.rejects(checkCompanionIdentity(linuxWorkflow, identity, manifest, Buffer.alloc(64), trust), /companion_incompatible: .*host_signature_invalid/);
  await assert.rejects(checkCompanionIdentity(linuxWorkflow, identity, manifest, undefined, trust), /companion_incompatible: .*host_signature_invalid/);
  // The repository's own trust never accepts a fixture key.
  await assert.rejects(checkCompanionIdentity(linuxWorkflow, identity, manifest, signature), /companion_incompatible: .*host_signature_invalid/);

  // Stale: built for pins, a protocol or an epoch this commit no longer accepts.
  for (const stale of [{ postgresVersion: "18.0" }, { vectorVersion: "0.0.1" }, { protocolVersion: 1 }, { nodeVersion: "24.0.0" }, { epoch: 1 }]) {
    const old = signedManifest(stale);
    await assert.rejects(checkCompanionIdentity(linuxWorkflow, linuxIdentity(old.manifest), old.manifest, old.signature, old.trust),
      /companion_incompatible: .*fails host_manifest_incompatible: the Desktop built from this commit refuses it once installed/, JSON.stringify(stale));
  }
  const incomplete = signedManifest({ files: {} });
  await assert.rejects(checkCompanionIdentity(linuxWorkflow, linuxIdentity(incomplete.manifest), incomplete.manifest, incomplete.signature, incomplete.trust),
    /companion_incompatible: .*host_component_missing/);

  // A package for another platform under this workflow's name.
  const mac = signedManifest({ platform: "macos", architecture: "aarch64" });
  await assert.rejects(checkCompanionIdentity(linuxWorkflow, linuxIdentity(mac.manifest), mac.manifest, mac.signature, mac.trust),
    /companion_target_mismatch: the linux-x86_64 companion package holds a host for macos-aarch64/);
  assert.deepEqual(await checkCompanionIdentity(companionWorkflow,
    { ...linuxIdentity(mac.manifest, { target: "macos-aarch64" }), files: { "FrameleafCompanion_1.2.5_arm64.pkg": sha("pkg") } }, mac.manifest, mac.signature, mac.trust),
  { "FrameleafCompanion_1.2.5_arm64.pkg": sha("pkg") });

  // The record must be about this manifest and name exactly the workflow's package files.
  await assert.rejects(checkCompanionIdentity(linuxWorkflow, linuxIdentity(Buffer.from("other")), manifest, signature, trust), /companion_identity_invalid: .*does not match its manifest\.json/);
  for (const changed of [null, [], {}, linuxIdentity(manifest, { schemaVersion: 2 }), linuxIdentity(manifest, { version: "1.2" }), linuxIdentity(manifest, { version: "1.2.5-rc1" }),
    linuxIdentity(manifest, { controllerSha256: "C".repeat(64) }), linuxIdentity(manifest, { files: [] }), { ...identity, extra: true },
    linuxIdentity(manifest, { target: "windows-x86_64" }), linuxIdentity(manifest, { files: { [linuxNames[0]]: sha("bootstrap") } }),
    linuxIdentity(manifest, { files: { ...identity.files, "FrameleafCompanion_1.2.5_amd64_SOURCES.md": sha("x") } }),
    linuxIdentity(manifest, { files: { [linuxNames[0]]: sha("bootstrap"), "FrameleafCompanion_1.2.4_amd64_runtime.deb": sha("runtime") } }),
    linuxIdentity(manifest, { files: { [linuxNames[0]]: sha("bootstrap"), [linuxNames[1]]: "abc" } })]) {
    await assert.rejects(checkCompanionIdentity(linuxWorkflow, changed, manifest, signature, trust), /companion_identity_invalid/, JSON.stringify(changed));
  }
  await assert.rejects(checkCompanionIdentity("unknown.yml", identity, manifest, signature, trust), /companion_run_untrusted/);
});

test("an unsigned Windows installer is never a release companion package", async () => {
  const windows = signedManifest({ platform: "windows", architecture: "x86_64" });
  const identity = (files) => ({ ...linuxIdentity(windows.manifest, { target: "windows-x86_64" }), files });
  assert.deepEqual(companionProducers[windowsWorkflow].files("1.2.5"), ["FrameleafCompanion_1.2.5_x64-setup.exe"]);
  await checkCompanionIdentity(windowsWorkflow, identity({ "FrameleafCompanion_1.2.5_x64-setup.exe": sha("setup") }), windows.manifest, windows.signature, windows.trust);
  for (const name of ["FrameleafCompanion_1.2.5_x64-setup-unsigned.exe", "FrameleafNativeServer_0.1.0_x64-setup-unsigned.exe"]) {
    await assert.rejects(checkCompanionIdentity(windowsWorkflow, identity({ [name]: sha("setup") }), windows.manifest, windows.signature, windows.trust),
      /companion_identity_invalid: .*must name exactly FrameleafCompanion_1\.2\.5_x64-setup\.exe/);
  }
  // The workflow only writes that name after signing, and checks the configuration before it builds.
  const source = read(windowsWorkflow);
  const order = ["node tools/release_prerequisites.mjs windows-signing", "npm ci", "uses: ./.github/actions/windows-signing",
    "windows_sign.ps1 -Path $env:HOST_CONTROLLER", "ISCC.exe", "windows_sign.ps1 -Path $setup", "companion-record"].map((text) => source.indexOf(text));
  assert.ok(order.every((at, index) => at > 0 && (index === 0 || at > order[index - 1])), `windows-compiled-host.yml signing order ${order}`);
  // The release package and the private media move qualification are the two signed selections.
  assert.match(source, /environment: \$\{\{ \(inputs\.release_package \|\| inputs\.media_move\) && 'desktop-release' \|\| '' \}\}/);
});

test("only the one run from before identity records may be attached without one", () => {
  assert.equal(checkCompanionWithoutIdentity(companionWorkflow, "42148037724"), null);
  assert.throws(() => checkCompanionWithoutIdentity(companionWorkflow, "42148037725"),
    /companion_identity_missing: run 42148037725 has no frameleaf-macos-arm64-companion-installed-identity artifact .* Run macos-host-package\.yml again/);
  for (const workflow of [linuxWorkflow, windowsWorkflow, "unknown.yml"]) {
    assert.throws(() => checkCompanionWithoutIdentity(workflow, "42148037724"), /companion_identity_missing/, workflow);
  }
});

test("a producer's record passes the release's check, and the staged files must be the recorded ones", async () => {
  const { manifest, signature, trust } = signedManifest();
  const root = mkdtempSync(join(tmpdir(), "frameleaf-companion-record-test-"));
  try {
    const packages = join(root, "packages");
    mkdirSync(packages);
    writeFileSync(join(root, "manifest.json"), manifest);
    writeFileSync(join(root, "manifest.sig"), signature);
    writeFileSync(join(packages, linuxNames[0]), "bootstrap");
    await assert.rejects(recordCompanion(linuxWorkflow, "1.2.5", "c".repeat(64), join(root, "manifest.json"), join(root, "manifest.sig"), packages, join(root, "identity"), trust), /ENOENT/);
    writeFileSync(join(packages, linuxNames[1]), "runtime");
    const identity = await recordCompanion(linuxWorkflow, "1.2.5", "c".repeat(64), join(root, "manifest.json"), join(root, "manifest.sig"), packages, join(root, "identity"), trust);
    assert.deepEqual(identity, linuxIdentity(manifest));
    assert.deepEqual(JSON.parse(readFileSync(join(root, "identity/companion.json"), "utf8")), identity);
    assert.equal(readFileSync(join(packages, "SHA256SUMS"), "utf8"), linuxNames.map((name, index) => `${sha(["bootstrap", "runtime"][index])}  ${name}\n`).join(""));
    // What `prepare` reads back from the identity artifact is what `stage` holds the download to.
    const files = await checkCompanionIdentity(linuxWorkflow, JSON.parse(readFileSync(join(root, "identity/companion.json"), "utf8")),
      readFileSync(join(root, "identity/manifest.json")), readFileSync(join(root, "identity/manifest.sig")), trust);
    const staged = call(["companion-artifact", linuxWorkflow, packages, JSON.stringify(files)]);
    assert.equal(staged.stdout, linuxNames.join("\n") + "\n", staged.stderr);
    writeFileSync(join(packages, linuxNames[1]), "replaced");
    const changed = call(["companion-artifact", linuxWorkflow, packages, JSON.stringify(files)]);
    assert.equal(changed.status, 1);
    assert.match(changed.stderr, /^::error::companion_artifact_changed: FrameleafCompanion_1\.2\.5_amd64_runtime\.deb is missing or does not match/);
    rmSync(join(packages, linuxNames[0]));
    assert.throws(() => checkCompanionArtifact(linuxWorkflow, [{ name: linuxNames[1], sha256: sha("runtime") }], new Map(), files), /companion_artifact_changed: FrameleafCompanion_1\.2\.5_amd64_bootstrap\.deb/);

    // A record the release would refuse is never written: the producing run fails instead.
    await assert.rejects(recordCompanion(linuxWorkflow, "1.2.5", "c".repeat(64), join(root, "manifest.json"), join(root, "manifest.sig"), packages, join(root, "other"), trust), /ENOENT/);
    writeFileSync(join(packages, linuxNames[0]), "bootstrap");
    await assert.rejects(recordCompanion(linuxWorkflow, "1.2.5", "c".repeat(64), join(root, "manifest.json"), join(root, "manifest.sig"), packages, join(root, "other")), /companion_incompatible/);
    await assert.rejects(recordCompanion(linuxWorkflow, "1.2", "c".repeat(64), join(root, "manifest.json"), join(root, "manifest.sig"), packages, join(root, "other"), trust), /companion_identity_invalid/);
    assert.throws(() => readFileSync(join(root, "other/companion.json")), /ENOENT/);

    // The command the release runs: the repository's trust refuses the fixture key, and a run without a record is named.
    const refused = call(["companion-identity", linuxWorkflow, "8", join(root, "identity")]);
    assert.equal(refused.status, 1);
    assert.match(refused.stderr, /^::error::companion_incompatible: the linux-x86_64 companion package/);
    assert.equal(call(["companion-identity", companionWorkflow, "42148037724", "-"]).stdout, "null\n");
    assert.match(call(["companion-identity", linuxWorkflow, "8", "-"]).stderr, /^::error::companion_identity_missing: run 8/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("the run from before identity records is attached on the checksum it recorded", () => {
  const name = "FrameleafCompanion_1.2.4_arm64.pkg";
  const files = [{ name, sha256: sha("pkg") }, { name: "SHA256SUMS", sha256: sha("sums") }, { name: "installed-receipt.json", sha256: sha("receipt") }];
  assert.deepEqual(checkCompanionArtifact(companionWorkflow, files, new Map([[name, sha("pkg")]])), [name]);
  assert.throws(() => checkCompanionArtifact(companionWorkflow, files, new Map([[name, sha("other")]])), /companion_artifact_changed/);
  assert.throws(() => checkCompanionArtifact(companionWorkflow, files, new Map()), /companion_artifact_changed/);
  assert.throws(() => checkCompanionArtifact(companionWorkflow, files.slice(1), new Map()), /companion_artifact_invalid/);
  assert.throws(() => checkCompanionArtifact(companionWorkflow, [...files, { name: "FrameleafCompanion_1.2.5_arm64.pkg", sha256: sha("x") }], new Map([[name, sha("pkg")]])), /companion_artifact_invalid/);
  for (const other of ["FrameleafCompanion-1.2.4-macOS-arm64-unsigned-41.pkg", "FrameleafCompanion_1.2.4_x64-setup-unsigned.exe", "FrameleafCompanion_1.2.4_arm64.pkg.zip"]) {
    assert.throws(() => checkCompanionArtifact(companionWorkflow, [{ name: other, sha256: sha("x") }], new Map([[other, sha("x")]])), /companion_artifact_invalid/, other);
  }
  assert.throws(() => checkCompanionArtifact("unknown.yml", files, new Map([[name, sha("pkg")]])), /companion_artifact_invalid/);

  const directory = mkdtempSync(join(tmpdir(), "frameleaf-companion-test-"));
  try {
    writeFileSync(join(directory, name), "pkg");
    writeFileSync(join(directory, "SHA256SUMS"), `${sha("pkg")}  ${name}\n`);
    writeFileSync(join(directory, "installed-receipt.json"), "{}");
    for (const legacy of [[], ["null"]]) assert.equal(call(["companion-artifact", companionWorkflow, directory, ...legacy]).stdout, `${name}\n`);
    writeFileSync(join(directory, name), "changed");
    const changed = call(["companion-artifact", companionWorkflow, directory]);
    assert.equal(changed.status, 1);
    assert.match(changed.stderr, /^::error::companion_artifact_changed/);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("the summary and the draft notes say which companion packages still have to be added by hand", () => {
  const plan = planCompanions("all", "none", {}, repository);
  assert.equal(companionSummary({ attach: planCompanions("macos-aarch64", "7", { 7: companionRun() }, repository).attach, manual: plan.manual.slice(1) }), [
    "### Companion packages", "",
    "- macos-aarch64: attached from run 7 (macos-host-package.yml).",
    "- windows-x86_64: **not attached by this run.** Add its signed companion package to the draft by hand before publishing.",
    "- linux-x86_64: **not attached by this run.** Add its signed companion package to the draft by hand before publishing.", "",
  ].join("\n"));
  assert.equal(companionNote({ attach: [{ target: "macos-aarch64", run: "7" }], manual: ["linux-x86_64"] }),
    "Companion packages: macos-aarch64 attached from run 7; linux-x86_64 not attached, add its signed package by hand before publishing.");
  assert.equal(companionNote({ attach: [], manual: [] }), "");
  assert.match(companionSummary({ attach: [], manual: [] }), /None of the selected platforms has a companion package/);
});

test("each producing workflow retains its package and identity record, and the release reads both", () => {
  for (const [workflow, producer] of Object.entries(companionProducers)) {
    const source = read(workflow);
    assert.ok(source.includes(`name: ${producer.artifact}\n`), `${workflow} no longer uploads ${producer.artifact}`);
    assert.ok(source.includes(`name: ${producer.artifact}-identity\n`), `${workflow} does not upload ${producer.artifact}-identity`);
    assert.ok(source.includes(`node tools/release_prerequisites.mjs companion-record ${workflow} `), `${workflow} does not record its package`);
    // Kept for the default 90 days so an unchanged package's run can be reused by the next release.
    for (const upload of source.split("uses: actions/upload-artifact").slice(1).filter((step) => step.includes(`name: ${producer.artifact}`))) {
      assert.doesNotMatch(upload.split("\n      - ")[0], /retention-days/, workflow);
    }
  }
  // No draft release is named in a workflow: each takes the draft it reads as an input.
  for (const workflow of Object.keys(companionProducers)) assert.doesNotMatch(read(workflow), /releases\/[0-9]+/, workflow);
  assert.match(read(companionWorkflow), /keys == \["assetId","controllerSha256","manifestSha256","packageSha256","releaseId"\]/);

  const directory = mkdtempSync(join(tmpdir(), "frameleaf-companion-runs-test-"));
  try {
    mkdirSync(join(directory, "runs"));
    writeFileSync(join(directory, "runs", "7.json"), JSON.stringify(companionRun()));
    const planned = call(["companions", "macos-aarch64", "7", join(directory, "runs")], { GITHUB_REPOSITORY: repository });
    assert.equal(planned.status, 0, planned.stderr);
    assert.equal(JSON.parse(planned.stdout).attach[0].artifact, "frameleaf-macos-arm64-companion-installed");
    const missing = call(["companions", "macos-aarch64", "", join(directory, "runs")], { GITHUB_REPOSITORY: repository });
    assert.equal(missing.status, 1);
    assert.match(missing.stderr, /^::error::companion_run_missing/);
    assert.equal(call(["companion-ids", "7"]).stdout, "7\n");
    assert.equal(call(["companion-ids", "none"]).stdout, "");
    assert.equal(call(["unknown"]).status, 1);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
  const workflow = read(".github/workflows/release.yml");
  assert.match(workflow, /COMPANION_RUN_IDS: \$\{\{ inputs\.companion_run_ids \}\}/);
  // The identity is checked in `prepare`, before the build; `stage` holds the download to it.
  const prepare = workflow.slice(workflow.indexOf("\n  prepare:"), workflow.indexOf("\n  signing-preflight:"));
  assert.match(prepare, /node tools\/release_prerequisites\.mjs companion-identity "\$workflow" "\$run" "\$identity"/);
  const stage = workflow.slice(workflow.indexOf("\n  stage:"));
  assert.match(stage, /node tools\/release_prerequisites\.mjs companion-artifact "\$workflow" "\$download" "\$files"/);
});
