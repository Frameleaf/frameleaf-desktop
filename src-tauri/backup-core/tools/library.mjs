// The library both engines back up in the cross-engine tests. tests/common/mod.rs builds the same one.
import { createHash } from 'node:crypto';

export const chunker = { min: 64, avg: 256, max: 1024 };
export const packTarget = 64 * 1024;
export const rootKey = Buffer.alloc(32, 0x42);

export function noise(length, seed) {
  const out = Buffer.alloc(length);
  let state = seed >>> 0;
  for (let index = 0; index < length; index++) {
    state ^= state << 13;
    state >>>= 0;
    state ^= state >>> 17;
    state ^= state << 5;
    state >>>= 0;
    out[index] = state & 0xff;
  }
  return out;
}

const dir = (path, mtime) => ({ path, type: 'dir', mode: 0o755, mtime });
const file = (path, content, mtime, mode = 0o644) => ({ path, type: 'file', mode, mtime, content });
const link = (path, target, mtime) => ({ path, type: 'symlink', mode: 0o777, mtime, target });

/** Two versions: the second edits one file and adds another, so the second snapshot reuses most of the first. */
export const versions = [
  {
    time: '2026-11-01T10:00:00.000Z',
    entries: [
      dir(['Documents'], 1_700_000_000_000),
      file(['Documents', 'notes.txt'], { text: 'remember the milk\n', repeat: 400 }, 1_700_000_001_000),
      dir(['Documents', 'Tax'], 1_700_000_002_000),
      file(['Documents', 'Tax', 'Return 2025.xlsx'], { noise: [50_000, 2] }, 1_700_000_003_000, 0o600),
      file(['big.bin'], { noise: [400_000, 3] }, 1_700_000_004_000),
      file(['nothing'], { text: '', repeat: 1 }, 1_700_000_005_000),
      link(['link'], 'Documents/notes.txt', 1_700_000_006_000),
      file(['old.txt'], { text: 'from before 1970\n', repeat: 3 }, -86_400_123),
      dir(['empty'], 1_700_000_007_000),
      file(['Ünïcode ✓.txt'], { noise: [3000, 5] }, 1_700_000_008_000),
      // UTF-8 byte order and UTF-16 code-unit order disagree on these two: trees use code units.
      file(['z\u{FFFD}.txt'], { text: 'replacement', repeat: 1 }, 1_700_000_009_000),
      file(['z\u{1F600}.txt'], { text: 'smile', repeat: 1 }, 1_700_000_010_000),
    ],
  },
];
versions.push({
  time: '2026-11-02T10:00:00.000Z',
  entries: [
    ...versions[0].entries.map((entry) =>
      entry.path.join('/') === 'Documents/notes.txt'
        ? { ...entry, content: { text: 'remember the milk and the bread\n', repeat: 400 }, mtime: 1_700_100_000_000 }
        : entry,
    ),
    file(['Documents', 'new.bin'], { noise: [20_000, 9] }, 1_700_100_001_000),
  ],
});

export const contentOf = (content) =>
  content.noise ? noise(...content.noise) : Buffer.from(content.text.repeat(content.repeat));

/** A source over one version, keyed by content hash as the photo server keys its files. */
export function source(version) {
  const below = (path) =>
    version.entries.filter(
      (entry) => entry.path.length === path.length + 1 && path.every((name, index) => entry.path[index] === name),
    );
  return {
    async list(path) {
      return below(path).map((entry) => {
        const body = entry.type === 'file' ? contentOf(entry.content) : null;
        return {
          name: entry.path.at(-1),
          type: entry.type,
          mode: entry.mode,
          uid: 0,
          gid: 0,
          mtime: entry.mtime,
          size: body ? body.length : 0,
          ...(entry.target === undefined ? {} : { target: entry.target }),
          ...(body ? { key: createHash('sha256').update(body).digest('hex') } : {}),
        };
      });
    },
    async *read(path) {
      const entry = version.entries.find((item) => item.path.join('/') === path.join('/'));
      yield contentOf(entry.content);
    },
  };
}

/** What a restore of a version must give: per path, its kind, content hash or link target, mode and time. */
export function expected(version) {
  return Object.fromEntries(
    version.entries.map((entry) => [
      entry.path.join('/'),
      entry.type === 'file'
        ? { type: 'file', sha256: createHash('sha256').update(contentOf(entry.content)).digest('hex'), mode: entry.mode, mtime: entry.mtime }
        : entry.type === 'dir'
          ? { type: 'dir', mode: entry.mode }
          : { type: 'symlink', target: entry.target },
    ]),
  );
}
