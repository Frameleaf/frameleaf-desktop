// Synthetic metadata acceptance through the packaged server; never reads user media.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtemp, readFile, rename, rm } from "node:fs/promises";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { isAbsolute, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const [runtime, mode] = process.argv.slice(2);
assert.ok(runtime && isAbsolute(runtime));
assert.equal(process.version, "v26.11.1");
const require = createRequire(join(runtime, "server/package.json"));
const { ExifTool } = require("exiftool-vendored");
if (mode === "--missing-perl") {
  const tool = new ExifTool();
  try {
    await assert.rejects(
      tool.version(),
      /Private ExifTool Perl runtime is missing/,
    );
  } finally {
    await tool.end();
  }
  console.log("private-perl-missing-refused");
} else {
  assert.equal(mode, undefined);
  const receipt = JSON.parse(
    await readFile(join(runtime, "qualification.json"), "utf8"),
  );
  assert.equal(receipt.qualification, "passed");
  const hash = async (path) =>
    createHash("sha256")
      .update(await readFile(path))
      .digest("hex");
  assert.equal(
    await hash(
      join(runtime, "server/node_modules/exiftool-vendored/dist/ExifTool.js"),
    ),
    receipt.adaptedModuleSha256,
  );
  const perl = join(runtime, "perl/bin/perl");
  assert.equal(await hash(perl), receipt.files.perl["bin/perl"].sha256);
  const { MetadataRepository } = await import(
    pathToFileURL(
      join(runtime, "server/dist/repositories/metadata.repository.js"),
    )
  );
  const repository = new MetadataRepository({
    setContext() {},
    warn() {},
    debug() {},
    error() {},
  });
  repository.setMaxConcurrency(1);
  const temporary = await mkdtemp(
    join(tmpdir(), "frameleaf-private-exiftool-"),
  );
  const source = join(temporary, "café-original.jpg");
  const copy = join(temporary, "location-free.jpg");
  const sharp = require("sharp");
  let before;
  let inspection;
  try {
    await sharp({
      create: { width: 96, height: 64, channels: 3, background: "#235847" },
    })
      .jpeg()
      .toFile(source);
    await repository.writeTags(source, {
      Make: "Frameleaf synthetic fixture",
      Model: "Private Perl",
      GPSLatitude: 51.05,
      GPSLongitude: -114.07,
      GPSLatitudeRef: "N",
      GPSLongitudeRef: "W",
      "XMP-dc:Description": "Café — synthetic metadata",
    });
    const tags = await repository.readTags(source);
    assert.equal(tags.Make, "Frameleaf synthetic fixture");
    assert.equal(tags.Model, "Private Perl");
    assert.equal(tags.ImageWidth, 96);
    assert.equal(tags.ImageHeight, 64);
    assert.equal(tags.Description, "Café — synthetic metadata");
    assert.ok(Math.abs(tags.GPSLatitude - 51.05) < 0.00001);
    assert.ok(Math.abs(tags.GPSLongitude + 114.07) < 0.00001);
    inspection = await repository.inspectLocation(source);
    assert.ok(inspection.locationTags.length > 0);
    assert.deepEqual(inspection.problems, []);
    before = await hash(source);
    await repository.writeLocationFreeCopy(source, copy);
    assert.deepEqual(await repository.inspectLocation(copy), {
      locationTags: [],
      problems: [],
      samsungTrailer: false,
    });
    assert.equal(await hash(source), before);
    const copied = await repository.readTags(copy);
    assert.equal(copied.Make, tags.Make);
    assert.equal(copied.Description, tags.Description);
    const pixels = async (path) =>
      createHash("sha256")
        .update(await sharp(path).raw().toBuffer())
        .digest("hex");
    assert.equal(await pixels(copy), await pixels(source));
  } finally {
    await repository.teardown();
    await rm(temporary, { recursive: true, force: true });
  }
  await rename(perl, perl + ".held");
  try {
    const child = spawnSync(
      process.execPath,
      [fileURLToPath(import.meta.url), runtime, "--missing-perl"],
      { encoding: "utf8", timeout: 15000, env: process.env },
    );
    assert.equal(child.status, 0, child.stderr || String(child.error));
    assert.match(child.stdout, /private-perl-missing-refused/);
  } finally {
    await rename(perl + ".held", perl);
  }
  console.log(
    JSON.stringify(
      {
        qualification: "passed",
        sourceRevision: receipt.sourceRevision,
        vendorVersion: receipt.vendorVersion,
        perlSource: receipt.perlSource,
        metadataReadWrite: true,
        unicodeMetadata: true,
        locationFreeCopy: true,
        originalUnchanged: true,
        decodedPixelsUnchanged: true,
        missingPrivatePerlRefused: true,
        fullMediaConformance: false,
        installedPlatformQualified: false,
      },
      null,
      2,
    ),
  );
}
