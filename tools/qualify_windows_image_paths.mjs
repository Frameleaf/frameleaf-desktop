import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { createRequire } from 'node:module';
import { join } from 'node:path';

assert.equal(process.platform, 'win32');
assert.equal(process.env.RUNNER_ENVIRONMENT, 'github-hosted');
const temporary = process.env.RUNNER_TEMP;
const physical = process.env.FRAMELEAF_TEST_PHYSICAL_TEMP;
const dependencies = process.env.FRAMELEAF_TEST_SHARP_ROOT;
assert.ok(temporary && dependencies);
assert.ok(physical?.startsWith('\\\\.\\GLOBALROOT\\Device\\HarddiskVolume'));
const lock = JSON.parse(await readFile(join(dependencies, 'package-lock.json'), 'utf8'));
// Match the server's c6403974 lockfile before executing either package.
for (const [name, integrity] of [
  ['sharp', 'sha512-Ywn4OnzGukp7CDMrp08RQ50YKmuwG47brZgIVPTvBaaAfQlRlygrRqSrxdCiL9M+LlzLBiJ68IR1QqvzHyjC7g=='],
  ['@img/sharp-win32-x64', 'sha512-x76eH0vEiHlcMQu8Y8IenntaACtddpT6W0wmXtWrnKcnKI7ME5DdgqhAD6SEWOEl1v2zDvkZDhFA9KnURwpfqg=='],
]) {
  assert.equal(lock.packages['node_modules/' + name].version, '0.35.5');
  assert.equal(lock.packages['node_modules/' + name].integrity, integrity);
}
const sharp = createRequire(join(dependencies, 'package.json'))('sharp');
const root = await mkdtemp(join(temporary, 'frameleaf-image-path-'));
const physicalRoot = physical + root.slice(temporary.length);
const original = Buffer.from('iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAIAAAD8GO2jAAAAKklEQVR4nGNQaEigKWIYtWDUglELRi0YtWDUglELRi0YtWDUglELhooFAHfgAD2FaRhWAAAAAElFTkSuQmCC', 'base64');
const results = [];
try {
  await writeFile(join(root, 'source.png'), original, { flag: 'wx' });
  assert.deepEqual(await readFile(join(physicalRoot, 'source.png')), original);
  for (const [inputName, inputRoot] of [['ordinary', root], ['physical', physicalRoot]]) {
    for (const [outputName, outputRoot] of [['ordinary', root], ['physical', physicalRoot]]) {
      const result = { input: inputName, output: outputName, passed: false };
      try {
        const output = join(outputRoot, inputName + '-' + outputName + '.jpg');
        await sharp(join(inputRoot, 'source.png')).resize(16, 16).jpeg().toFile(output);
        const info = await sharp(await readFile(output)).metadata();
        assert.equal(info.width, 16); assert.equal(info.height, 16);
        result.passed = true;
      } catch (error) {
        const message = String(error?.message ?? '');
        result.failure = message.includes('Input file is missing') ? 'sharp_input_missing'
          : message.includes('unable to open for write') ? 'image_output_open_failed' : 'unreported';
        result.code = ['ENOENT', 'EINVAL', 'EACCES', 'EPERM'].includes(error?.code) ? error.code : null;
      }
      results.push(result);
    }
  }
  console.log(JSON.stringify({ diagnosticOnly: true, node: process.version, sharp: sharp.versions.sharp, nodePhysicalRead: true, results }));
  assert.ok(results.every(result => result.passed), 'Image library physical-path contract failed');
} finally { await rm(root, { recursive: true, force: true }); }
