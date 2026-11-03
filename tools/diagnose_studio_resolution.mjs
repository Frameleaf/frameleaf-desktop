// Re-run a failed adapter build without writing output; retain bounded resolver evidence only.
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

const source = process.argv[2];
assert.equal(process.argv.length, 3);
assert.ok(path.isAbsolute(source));
const engine = path.join(source, 'studio/engine');
const require = createRequire(path.join(engine, 'node_modules/vite-plus/package.json'));
const { build } = await import(pathToFileURL(require.resolve('vite')).href);
const configuration = await import(pathToFileURL(path.join(source, 'studio/adapters/web/vite.config.mjs')).href);
const config = await configuration.default();
let remaining = 64;
let traced = false;
for (const plugin of config.plugins) {
  if (plugin?.name !== 'frameleaf-gate-timeline-persistence') continue;
  const resolve = plugin.resolveId;
  assert.equal(typeof resolve, 'function');
  plugin.resolveId = async function (source, importer, options) {
    const result = await resolve.call(this, source, importer, options);
    if (source.includes('timeline-persistence') && remaining-- > 0) {
      console.log('STUDIO_RESOLUTION', JSON.stringify({
        source: source.slice(0, 1024), importer: importer?.slice(0, 1024),
        result: (typeof result === 'string' ? result : result?.id)?.slice(0, 1024),
      }));
    }
    return result;
  };
  traced = true;
}
assert.ok(traced, 'Expected persistence resolver was not found');
await build({ ...config, configFile: false, logLevel: 'silent',
  build: { ...config.build, write: false } });
