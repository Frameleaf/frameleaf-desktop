// Authoring acceptance against synthetic RAW only; no user media or installed-platform claim.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { isAbsolute, join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { hostEnvironment } from "../runtime/host-agent.mjs";

const [runtime, component] = process.argv.slice(2);
assert.equal(
  process.argv.length,
  4,
  "Usage: private-node tools/qualify_host_raw.mjs /runtime /raw-build-output",
);
assert.ok(isAbsolute(runtime) && isAbsolute(component));
assert.equal(process.version, "v26.11.1");
const extension = process.platform === "win32" ? ".exe" : "";
assert.ok(
  ["darwin", "linux", "win32"].includes(process.platform),
  "Unsupported native RAW fixture platform",
);
const receipt = JSON.parse(
  await readFile(join(component, "qualification.json"), "utf8"),
);
assert.equal(receipt.qualification, "passed");
const serverReceipt = JSON.parse(
  await readFile(join(runtime, "qualification.json"), "utf8"),
);
assert.equal(serverReceipt.qualification, "passed");
assert.ok(/^[a-f0-9]{40}$/.test(serverReceipt.sourceRevision));
if (serverReceipt.sourceRevision !== receipt.sourceRevision) {
  assert.deepEqual(serverReceipt.rawSource, receipt.source);
  assert.deepEqual(serverReceipt.librawSource, receipt.librawSource);
}
const engine = join(runtime, "raw");
const hash = (bytes) => createHash("sha256").update(bytes).digest("hex");
const renderer = "bin/darktable-cli" + extension;
const decoder = "bin/dcraw_emu" + extension;
const executable = join(engine, renderer);
assert.equal(
  hash(await readFile(executable)),
  receipt.files[renderer].sha256,
);
const root = await mkdtemp(join(tmpdir(), "frameleaf-private-raw-"));
assert.equal(
  hash(await readFile(join(engine, decoder))),
  receipt.files[decoder].sha256,
);
const environment = {
  ...hostEnvironment({
    runtime,
    state: root,
    entryPoints: {
      ffmpeg: "media-tools/ffmpeg" + extension,
      ffprobe: "media-tools/ffprobe" + extension,
      node: "node" + extension,
      // RAW component checks do not execute the browser role.
      studioBrowser: "browser/chrome" + extension,
      studioBrowserGuard: "studio/guard/studio-browser-guard" + extension,
      studio: "studio/tools/bundled-worker.mjs",
      postgres: "pg/bin/postgres" + extension,
      rawRenderer: "raw/" + renderer,
      rawDecoder: "raw/" + decoder,
    },
  }),
  TMPDIR: root,
  TMP: root,
  TEMP: root,
  OMP_THREAD_LIMIT: "1",
  FRAMELEAF_HDR_BINDING: join(runtime, "media/image-hdr.node"),
};
await mkdir(environment.HOME);

function syntheticDng() {
  const shorts = (...values) => {
    const bytes = Buffer.alloc(values.length * 2);
    values.forEach((value, i) => bytes.writeUInt16LE(value, i * 2));
    return bytes;
  };
  const longs = (...values) => {
    const bytes = Buffer.alloc(values.length * 4);
    values.forEach((value, i) => bytes.writeUInt32LE(value, i * 4));
    return bytes;
  };
  const rationals = (...values) =>
    Buffer.concat(values.map(([n, d]) => longs(n, d)));
  const width = 256,
    height = 192;
  const tags = new Map([
    [256, [4, 1, longs(width)]],
    [257, [4, 1, longs(height)]],
    [258, [3, 1, shorts(16)]],
    [259, [3, 1, shorts(1)]],
    [262, [3, 1, shorts(32803)]],
    [271, [2, 10, Buffer.from("Frameleaf\0")]],
    [272, [2, 16, Buffer.from("Synthetic Bayer\0")]],
    [273, [4, 1, longs(0)]],
    [274, [3, 1, shorts(1)]],
    [277, [3, 1, shorts(1)]],
    [278, [4, 1, longs(height)]],
    [279, [4, 1, longs(width * height * 2)]],
    [284, [3, 1, shorts(1)]],
    [33421, [3, 2, shorts(2, 2)]],
    [33422, [1, 4, Buffer.from([0, 1, 1, 2])]],
    [50706, [1, 4, Buffer.from([1, 4, 0, 0])]],
    [50707, [1, 4, Buffer.from([1, 1, 0, 0])]],
    [50708, [2, 26, Buffer.from("Frameleaf Synthetic Bayer\0")]],
    [50710, [1, 3, Buffer.from([0, 1, 2])]],
    [50711, [3, 1, shorts(1)]],
    [50714, [5, 1, rationals([64, 1])]],
    [50717, [4, 1, longs(4095)]],
    [50719, [4, 2, longs(0, 0)]],
    [50720, [4, 2, longs(width, height)]],
    [
      50721,
      [
        10,
        9,
        rationals(
          ...Array.from({ length: 9 }, (_, i) => [
            Math.floor(i / 3) === i % 3 ? 10000 : 0,
            10000,
          ]),
        ),
      ],
    ],
    [50728, [5, 3, rationals([1, 1], [1, 1], [1, 1])]],
    [50778, [3, 1, shorts(21)]],
    [50829, [4, 4, longs(0, 0, height, width)]],
  ]);
  const ifd = Buffer.alloc(2 + tags.size * 12 + 4);
  ifd.writeUInt16LE(tags.size);
  const extra = [];
  let offset = 8 + ifd.length,
    stripEntry;
  [...tags]
    .sort(([a], [b]) => a - b)
    .forEach(([tag, [type, count, bytes]], i) => {
      const entry = 2 + i * 12;
      ifd.writeUInt16LE(tag, entry);
      ifd.writeUInt16LE(type, entry + 2);
      ifd.writeUInt32LE(type === 2 ? bytes.length : count, entry + 4);
      if (bytes.length > 4) {
        ifd.writeUInt32LE(offset, entry + 8);
        extra.push(bytes);
        offset += bytes.length;
        if (offset % 2) {
          extra.push(Buffer.alloc(1));
          offset++;
        }
      } else bytes.copy(ifd, entry + 8);
      if (tag === 273) stripEntry = entry;
    });
  assert.ok(stripEntry);
  ifd.writeUInt32LE(offset, stripEntry + 8);
  const pixels = Buffer.alloc(width * height * 2);
  for (let y = 0; y < height; y++)
    for (let x = 0; x < width; x++)
      pixels.writeUInt16LE(
        128 + ((x * 7 + y * 5 + ((y % 2) * 2 + (x % 2)) * 400) % 3200),
        (y * width + x) * 2,
      );
  const output = Buffer.concat([
    Buffer.from("II"),
    shorts(42),
    longs(8),
    ifd,
    ...extra,
    pixels,
  ]);
  assert.equal(output.length, offset + pixels.length);
  return output;
}

try {
  for (const key of Object.keys(process.env)) delete process.env[key];
  Object.assign(process.env, environment);
  const require = createRequire(join(runtime, "server/package.json"));
  const sharp = require("sharp");
  const { renderDarktable, encodeNativeDevelopOutput } = await import(
    pathToFileURL(join(runtime, "server/dist/utils/darktable-renderer.js"))
  );
  const input = join(root, "café-写真-bayer.dng");
  const original = syntheticDng();
  await writeFile(input, original);
  const { renderRawWithLibRaw } = await import(
    pathToFileURL(join(runtime, "server/dist/utils/raw-renderer.js"))
  );
  const sensor = await renderRawWithLibRaw(input);
  const sensorMetadata = await sharp(sensor).metadata();
  assert.equal(sensorMetadata.bitsPerSample, 16);
  assert.ok(
    sensorMetadata.icc &&
      sensorMetadata.width > 32 &&
      sensorMetadata.height > 32,
  );
  const decoder = process.env.FRAMELEAF_RAW_DECODER_PATH;
  process.env.FRAMELEAF_RAW_DECODER_PATH = join(root, "missing-dcraw_emu");
  try {
    await assert.rejects(renderRawWithLibRaw(input), {
      reason: "dependency_missing",
    });
  } finally {
    process.env.FRAMELEAF_RAW_DECODER_PATH = decoder;
  }
  const recipe = { version: 2, renderer: "darktable/5.6.1", exposureEV: 0 };
  const baseline = await renderDarktable(input, recipe);
  const brighter = await renderDarktable(input, { ...recipe, exposureEV: 1 });
  const repeated = await renderDarktable(input, recipe);
  const metadata = await sharp(baseline).metadata();
  assert.equal(metadata.bitsPerSample, 16);
  assert.ok(metadata.icc && metadata.width > 32 && metadata.height > 32);
  const pixels = async (bytes) =>
    sharp(bytes).raw({ depth: "ushort" }).toBuffer();
  assert.deepEqual(await pixels(repeated), await pixels(baseline));
  const sum = async (bytes) =>
    (await sharp(bytes).stats()).channels
      .slice(0, 3)
      .reduce((n, channel) => n + channel.mean, 0);
  assert.ok(
    (await sum(brighter)) > (await sum(baseline)),
    "EV+1 must brighten the rendered pixels",
  );
  const preview = await encodeNativeDevelopOutput(brighter, {
    format: "jpeg",
    quality: 92,
    size: 64,
  });
  const previewMetadata = await sharp(preview).metadata();
  assert.equal(Math.max(previewMetadata.width, previewMetadata.height), 64);
  assert.ok(previewMetadata.icc);
  assert.equal(hash(await readFile(input)), hash(original));
  const loadedImages = [];
  if (process.platform === "darwin") {
    for (const name of ["audit-config", "audit-cache"])
      await mkdir(join(root, name));
    const child = spawnSync(
      executable,
      [
        input,
        join(root, "audit.png"),
        "--library",
        ":memory:",
        "--icc-type",
        "SRGB",
        "--core",
        "--configdir",
        join(root, "audit-config"),
        "--cachedir",
        join(root, "audit-cache"),
        "--disable-opencl",
        "--conf",
        "write_sidecar_files=never",
      ],
      {
        env: { ...environment, DYLD_PRINT_LIBRARIES: "1" },
        encoding: "utf8",
        timeout: 120000,
        maxBuffer: 4 * 1024 ** 2,
      },
    );
    assert.equal(child.status, 0, child.stderr || String(child.error));
    for (const line of child.stderr.split("\n")) {
      const match = /^dyld\[\d+\]:.*? (\/.*)$/.exec(line);
      if (!match) continue;
      const path = resolve(match[1]);
      assert.ok(
        path.startsWith(resolve(engine) + "/") ||
          path.startsWith("/usr/lib/") ||
          path.startsWith("/System/Library/"),
        "External native image: " + path,
      );
      loadedImages.push(path);
    }
    assert.ok(loadedImages.length > 0, "dyld must report actual loaded images");
    await sharp(join(root, "audit.png")).stats();
  }
  console.log(
    JSON.stringify(
      {
        qualification: "passed",
        sourceRevision: serverReceipt.sourceRevision,
        rawEngineSourceRevision: receipt.sourceRevision,
        syntheticRawOnly: true,
        hostEnvironmentUsed: true,
        engineRoot: engine,
        librawSensorRender: true,
        missingPrivateDecoderRefused: true,
        profiled16BitOutput: true,
        repeatedPixelsIdentical: true,
        exposureBrightens: true,
        jpegPreview: true,
        originalUnchanged: true,
        loadedImageCount: loadedImages.length,
        fullRawConformance: false,
        installedPlatformQualified: false,
      },
      null,
      2,
    ),
  );
} finally {
  await rm(root, { recursive: true, force: true });
}
