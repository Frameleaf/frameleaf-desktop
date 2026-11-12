import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { cpSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { consistentVersion, parseChecksums, pendingChecksum, stampPackaging } from "./release_packaging.mjs";

const repository = fileURLToPath(new URL("../", import.meta.url));
const packaging = [
  "packaging/aur/PKGBUILD",
  "packaging/aur/.SRCINFO",
  "packaging/chocolatey/frameleaf.nuspec",
  "packaging/chocolatey/tools/chocolateyinstall.ps1",
];

function withTree(run) {
  const root = mkdtempSync(join(tmpdir(), "frameleaf-packaging-test-"));
  try {
    mkdirSync(join(root, "src-tauri"));
    for (const file of ["package.json", "src-tauri/tauri.conf.json", "src-tauri/Cargo.toml", "packaging"]) {
      cpSync(join(repository, file), join(root, file), { recursive: true });
    }
    const read = (file) => readFileSync(join(root, file), "utf8");
    return run(root, read, (file, change) => writeFileSync(join(root, file), change(read(file))));
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
}

const digest = (text) => createHash("sha256").update(text).digest("hex");

test("the application and every packaging file state one version", () => {
  const version = consistentVersion();
  assert.equal(version, JSON.parse(readFileSync(join(repository, "package.json"), "utf8")).version);
  const changes = {
    "package.json": (text) => text.replace(`"version": "${version}"`, '"version": "9.9.9"'),
    "src-tauri/tauri.conf.json": (text) => text.replace(`"version": "${version}"`, '"version": "9.9.9"'),
    "src-tauri/Cargo.toml": (text) => text.replace(`version = "${version}"`, 'version = "9.9.9"'),
    "packaging/aur/PKGBUILD": (text) => text.replace(`pkgver=${version}`, "pkgver=9.9.9"),
    "packaging/aur/.SRCINFO": (text) => text.replace(`/download/v${version}/`, "/download/v9.9.9/"),
    "packaging/chocolatey/frameleaf.nuspec": (text) => text.replace(`<version>${version}</version>`, "<version>9.9.9</version>"),
    "packaging/chocolatey/tools/chocolateyinstall.ps1": (text) => text.replace(`Frameleaf_${version}_x64`, "Frameleaf_9.9.9_x64"),
  };
  for (const [file, change] of Object.entries(changes)) {
    withTree((root, read, edit) => {
      assert.equal(consistentVersion(root), version);
      const before = read(file);
      edit(file, change);
      assert.notEqual(read(file), before, file);
      assert.throws(() => consistentVersion(root), /release_version_mismatch/, file);
    });
  }
});

test("Chocolatey may only name the signed installer", () => {
  withTree((root, read, edit) => {
    edit("packaging/chocolatey/tools/chocolateyinstall.ps1", (text) => text.replace("_x64_en-US.msi", "_x64_en-US-unsigned.msi"));
    assert.throws(() => consistentVersion(root), /release_version_mismatch: .*chocolateyinstall\.ps1 \(none\)/);
  });
});

test("stamping takes checksums only from the release and leaves the rest pending", () => {
  withTree((root, read) => {
    const install = () => read("packaging/chocolatey/tools/chocolateyinstall.ps1");
    const pending = stampPackaging(root, "1.2.3");
    assert.equal(pending.aur, "not publishable: the release has no Frameleaf_1.2.3_amd64.deb or Frameleaf_1.2.3_arm64.deb");
    assert.equal(pending.chocolatey, "not publishable: the release has no signed Windows installer (Frameleaf_1.2.3_x64_en-US.msi)");
    assert.deepEqual(read("packaging/aur/PKGBUILD").match(/^(?:pkgver|sha256sums_\w+)=.*$/gm),
      ["pkgver=1.2.3", `sha256sums_x86_64=('${pendingChecksum}')`, `sha256sums_aarch64=('${pendingChecksum}')`]);
    assert.doesNotMatch(read("packaging/aur/PKGBUILD"), /SKIP/);
    assert.ok(install().startsWith("$ErrorActionPreference = 'Stop'\nthrow 'No signed Windows installer exists for Frameleaf 1.2.3, so this package must not be published.'\n"));
    assert.ok(install().includes(`checksum64     = '${pendingChecksum}'`));

    // A release that published only unsigned Windows installers still has nothing Chocolatey may install.
    const linux = parseChecksums([
      `${digest("amd64")}  Frameleaf_1.2.3_amd64.deb`,
      `${digest("arm64")} *Frameleaf_1.2.3_arm64.deb`,
      `${digest("unsigned")}  Frameleaf_1.2.3_x64_en-US-unsigned.msi`,
      `${digest("older")}  Frameleaf_1.2.2_x64_en-US.msi`,
      "",
    ].join("\n"));
    const withoutWindows = stampPackaging(root, "1.2.3", linux);
    assert.equal(withoutWindows.aur, "publishable");
    assert.match(withoutWindows.chocolatey, /^not publishable/);
    assert.ok(read("packaging/aur/PKGBUILD").includes(`sha256sums_x86_64=('${digest("amd64")}')\nsha256sums_aarch64=('${digest("arm64")}')\n`));
    assert.ok(read("packaging/aur/.SRCINFO").includes(
      "\tsource_aarch64 = frameleaf-desktop-1.2.3-arm64.deb::https://github.com/Frameleaf/frameleaf-desktop/releases/download/v1.2.3/Frameleaf_1.2.3_arm64.deb\n" +
      `\tsha256sums_aarch64 = ${digest("arm64")}\n`));
    assert.match(install(), /^throw 'No signed Windows installer/m);
    assert.doesNotMatch(install(), /unsigned\.msi|[a-f0-9]{64}/);

    const signed = stampPackaging(root, "1.2.3", new Map([...linux, ["Frameleaf_1.2.3_x64_en-US.msi", digest("signed")]]));
    assert.deepEqual(signed, { version: "1.2.3", aur: "publishable", chocolatey: "publishable" });
    assert.doesNotMatch(install(), /throw/);
    assert.ok(install().includes("url64bit       = 'https://github.com/Frameleaf/frameleaf-desktop/releases/download/v1.2.3/Frameleaf_1.2.3_x64_en-US.msi'"));
    assert.ok(install().includes(`checksum64     = '${digest("signed")}'`));
    assert.match(read("packaging/chocolatey/frameleaf.nuspec"), /<version>1\.2\.3<\/version>[^]*\/releases\/tag\/v1\.2\.3<\/releaseNotes>/);
    assert.throws(() => consistentVersion(root), /release_version_mismatch/, "the application files still state the repository version");

    // Moving to the next version must drop the previous release's checksums and block Chocolatey again.
    stampPackaging(root, "1.2.4");
    assert.doesNotMatch(packaging.map(read).join(""), /[a-f0-9]{64}/);
    assert.equal(install().match(/^throw /gm).length, 1);
  });
});

test("the committed packaging is exactly what the stamping script writes", () => {
  withTree((root, read) => {
    const committed = packaging.map(read);
    const checksums = new Map();
    for (const [, name, sum] of read("packaging/aur/.SRCINFO")
      .matchAll(/(Frameleaf_[\w.]+\.deb)\n\tsha256sums_\w+ = ([a-f0-9]{64})$/gm)) checksums.set(name, sum);
    const msi = /(Frameleaf_[\w.-]+\.msi)'\n\s*checksum64\s*= '([a-f0-9]{64})'/.exec(read("packaging/chocolatey/tools/chocolateyinstall.ps1"));
    if (msi) checksums.set(msi[1], msi[2]);
    stampPackaging(root, consistentVersion(root), checksums);
    assert.deepEqual(packaging.map(read), committed);
  });
});

test("release checksums are parsed strictly and unsupported versions are refused", () => {
  assert.deepEqual([...parseChecksums(`${digest("a")}  one.deb\n`)], [["one.deb", digest("a")]]);
  for (const text of ["abc  one.deb\n", `${digest("a").toUpperCase()}  one.deb\n`, `${digest("a")} one.deb\n`,
    `${digest("a")}  one.deb\n${digest("b")}  one.deb\n`, "SKIP  one.deb\n"]) {
    assert.throws(() => parseChecksums(text), /release_checksums_invalid/);
  }
  withTree((root) => {
    for (const version of ["1.2.3-rc.1", "1.2", "v1.2.3", "01.2.3"]) assert.throws(() => stampPackaging(root, version), /packaging_version_unsupported/);
    writeFileSync(join(root, "packaging/aur/PKGBUILD"), "pkgver=1\npkgver=2\n");
    assert.throws(() => stampPackaging(root, "1.2.3"), /packaging_template_changed: packaging\/aur\/PKGBUILD/);
  });
});
