/** Stamp the AUR and Chocolatey files with the application version and the release's own checksums. */
import { readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { applicationVersions } from "./release_inputs.mjs";

const repository = "https://github.com/Frameleaf/frameleaf-desktop";
// Not a checksum: makepkg and Chocolatey both reject the download until a release supplies the real value.
export const pendingChecksum = "checksum-pending-release";
const unpublishable = "throw 'No signed Windows installer exists for Frameleaf";

const files = {
  pkgbuild: "packaging/aur/PKGBUILD",
  srcinfo: "packaging/aur/.SRCINFO",
  nuspec: "packaging/chocolatey/frameleaf.nuspec",
  install: "packaging/chocolatey/tools/chocolateyinstall.ps1",
};

// The release workflow only produces these names from Authenticode-verified builds;
// installers published without a signature carry an `-unsigned` suffix and never match.
const assets = (version) => ({
  x86_64: `Frameleaf_${version}_amd64.deb`,
  aarch64: `Frameleaf_${version}_arm64.deb`,
  msi: `Frameleaf_${version}_x64_en-US.msi`,
});

const directory = (root) => root instanceof URL ? root : pathToFileURL(resolve(root) + "/");

/** Every version each packaging file states, including the ones embedded in download URLs. */
export function packagingVersions(root = new URL("../", import.meta.url)) {
  const read = (path) => readFileSync(new URL(path, directory(root)), "utf8");
  const all = (text, pattern) => [...text.matchAll(pattern)].flatMap((match) => match.slice(1));
  const pkgbuild = read(files.pkgbuild);
  const srcinfo = read(files.srcinfo);
  const nuspec = read(files.nuspec);
  const install = read(files.install);
  return {
    [files.pkgbuild]: all(pkgbuild, /^pkgver=(.*)$/gm),
    [files.srcinfo]: [
      ...all(srcinfo, /^\tpkgver = (.*)$/gm),
      ...all(srcinfo, /^\tsource_\w+ = frameleaf-desktop-(.+)-\w+\.deb::.*\/download\/v(.+)\/Frameleaf_(.+)_\w+\.deb$/gm),
    ],
    [files.nuspec]: [
      ...all(nuspec, /<version>(.*)<\/version>/g),
      ...all(nuspec, /<releaseNotes>.*\/tag\/v(.*)<\/releaseNotes>/g),
    ],
    [files.install]: all(install, /^\s*url64bit\s*=\s*'.*\/download\/v(.+)\/Frameleaf_(.+)_x64_en-US\.msi'$/gm),
  };
}

/** The single version shared by the application and its packaging, or an error naming each file that differs. */
export function consistentVersion(root = new URL("../", import.meta.url)) {
  const application = applicationVersions(directory(root));
  const version = application["package.json"];
  // Package managers only carry stable releases, so a prerelease leaves the packaging at the last stable version.
  const packaging = typeof version === "string" && version.includes("-") ? {} : packagingVersions(root);
  const stated = { ...Object.fromEntries(Object.entries(application).map(([file, version]) => [file, [version]])), ...packaging };
  const wrong = Object.entries(stated)
    .filter(([, versions]) => !versions.length || versions.some((found) => found !== version))
    .map(([file, versions]) => `${file} (${versions.join(", ") || "none"})`);
  if (typeof version !== "string" || wrong.length) throw new Error(`release_version_mismatch: package.json is ${version}; ${wrong.join("; ")}`);
  return version;
}

/** Parse `sha256sum` output strictly; a malformed or repeated line is an error, never a guess. */
export function parseChecksums(text) {
  const checksums = new Map();
  for (const line of text.split("\n")) {
    if (!line) continue;
    const match = /^([a-f0-9]{64}) [ *](.+)$/.exec(line);
    if (!match || checksums.has(match[2])) throw new Error("release_checksums_invalid");
    checksums.set(match[2], match[1]);
  }
  return checksums;
}

function replaceOnce(text, pattern, replacement, file) {
  if ((text.match(new RegExp(pattern.source, pattern.flags.replace("g", "") + "g")) ?? []).length !== 1)
    throw new Error(`packaging_template_changed: ${file}`);
  return text.replace(pattern, () => replacement);
}

/**
 * Rewrite the packaging files for `version`. `checksums` is the release's parsed SHA256SUMS; without the
 * matching asset a checksum stays pending and that package is reported as not publishable.
 */
export function stampPackaging(root, version, checksums = new Map()) {
  if (!/^(?:0|[1-9][0-9]*)(?:\.(?:0|[1-9][0-9]*)){2}$/.test(version)) throw new Error("packaging_version_unsupported");
  const names = assets(version);
  const sum = (name) => checksums.get(name) ?? pendingChecksum;
  const edit = (file, change) => {
    const path = new URL(file, directory(root));
    writeFileSync(path, change(readFileSync(path, "utf8")));
  };
  const source = (name) =>
    `frameleaf-desktop-${version}-${name.match(/_(\w+)\.deb$/)[1]}.deb::${repository}/releases/download/v${version}/${name}`;

  edit(files.pkgbuild, (text) => {
    text = replaceOnce(text, /^pkgver=.*$/m, `pkgver=${version}`, files.pkgbuild);
    text = replaceOnce(text, /^pkgrel=.*$/m, "pkgrel=1", files.pkgbuild);
    for (const arch of ["x86_64", "aarch64"])
      text = replaceOnce(text, new RegExp(`^sha256sums_${arch}=.*$`, "m"), `sha256sums_${arch}=('${sum(names[arch])}')`, files.pkgbuild);
    return text;
  });
  edit(files.srcinfo, (text) => {
    text = replaceOnce(text, /^\tpkgver = .*$/m, `\tpkgver = ${version}`, files.srcinfo);
    text = replaceOnce(text, /^\tpkgrel = .*$/m, "\tpkgrel = 1", files.srcinfo);
    for (const arch of ["x86_64", "aarch64"]) {
      text = replaceOnce(text, new RegExp(`^\\tsource_${arch} = .*$`, "m"), `\tsource_${arch} = ${source(names[arch])}`, files.srcinfo);
      text = replaceOnce(text, new RegExp(`^\\tsha256sums_${arch} = .*$`, "m"), `\tsha256sums_${arch} = ${sum(names[arch])}`, files.srcinfo);
    }
    return text;
  });
  edit(files.nuspec, (text) => {
    text = replaceOnce(text, /<version>.*<\/version>/, `<version>${version}</version>`, files.nuspec);
    return replaceOnce(text, /<releaseNotes>.*<\/releaseNotes>/, `<releaseNotes>${repository}/releases/tag/v${version}</releaseNotes>`, files.nuspec);
  });
  const signedWindows = checksums.has(names.msi);
  edit(files.install, (text) => {
    text = text.split("\n").filter((line) => !line.startsWith(unpublishable)).join("\n");
    text = replaceOnce(text, /^\s*url64bit\s*=\s*'.*'$/m, `  url64bit       = '${repository}/releases/download/v${version}/${names.msi}'`, files.install);
    text = replaceOnce(text, /^\s*checksum64\s*=\s*'.*'$/m, `  checksum64     = '${sum(names.msi)}'`, files.install);
    if (signedWindows) return text;
    // Fail the install itself, so a package packed from this tree by mistake cannot install anything.
    return replaceOnce(text, /^\$ErrorActionPreference = 'Stop'$/m,
      `$ErrorActionPreference = 'Stop'\n${unpublishable} ${version}, so this package must not be published.'`, files.install);
  });

  const missing = [names.x86_64, names.aarch64].filter((name) => !checksums.has(name));
  return {
    version,
    aur: missing.length ? `not publishable: the release has no ${missing.join(" or ")}` : "publishable",
    chocolatey: signedWindows ? "publishable" : `not publishable: the release has no signed Windows installer (${names.msi})`,
  };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const args = process.argv.slice(2);
  if (args.length > 1) throw new Error("usage: release_packaging.mjs [SHA256SUMS]");
  const root = new URL("../", import.meta.url);
  const version = Object.values(applicationVersions(root)).reduce((first, next) => {
    if (first !== next) throw new Error("release_version_mismatch");
    return first;
  });
  const result = stampPackaging(root, version, args[0] ? parseChecksums(readFileSync(args[0], "utf8")) : undefined);
  console.log(`### Package manager files for ${result.version}\n\n- AUR: ${result.aur}\n- Chocolatey: ${result.chocolatey}`);
}
