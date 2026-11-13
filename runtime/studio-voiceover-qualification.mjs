// Executed only by the Apple Silicon signed-host qualification test.
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

const candidate = resolve('app/studio/tools/qualification/fd36-kokoro/candidate.mjs');
const { generateSpeechFile } = await import(pathToFileURL(candidate).href);
const parts = [];
let length = 0;
for await (const part of process.stdin) {
  length += part.length;
  if (length > 1600) throw new Error('Invalid qualification script.');
  parts.push(part);
}
const text = new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(parts));
const preview = await generateSpeechFile({
  runtimeRoot: resolve('js'),
  modelRoot: resolve('model'),
  espeakRoot: resolve('espeak'),
  text,
  voice: process.argv[1],
});
process.stdout.write(Buffer.from(await preview.blob.arrayBuffer()));
