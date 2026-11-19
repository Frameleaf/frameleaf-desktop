# frameleaf-backup-core

The desktop app's backup engine: the `frameleaf-repository` version 1 format of
`packages/backup-core` in frameleaf-app, ported to Rust. The format is defined by that package's
`FORMAT.md`; this crate writes the same bytes, and a repository written by either engine restores,
verifies and prunes with the other. No UI here.

| Module            | What it holds                                                               |
| ----------------- | --------------------------------------------------------------------------- |
| `keys`            | HKDF keys, blob ids, AES-256-GCM sealing, zstd blobs                        |
| `chunker`         | keyed FastCDC with normalised chunking                                      |
| `repository`      | config, ~64 MiB packs with sealed trailers, index objects, snapshots        |
| `tree`, `backup`  | Merkle folder trees, sources, the backup run                                |
| `restore`         | find, browse, restore by path (moves aside, never deletes)                  |
| `maintenance`     | retention, prune (safe to stop at any step), verify                         |
| `store`, `s3`     | memory, folder and S3 stores; SigV4 signing, Range GET reads, multipart     |
| `snapshot_record` | the Ed25519-signed history record of a snapshot                             |
| `recovery`        | the FLRK recovery code; Manager's vault id                                  |
| `escrow`          | scrypt + AES-256-GCM key escrow                                             |

The engine is synchronous; run it on a blocking thread from async code.

## Tests against the TypeScript engine

`cargo test -p frameleaf-backup-core` checks the TypeScript engine's pinned vectors and the ones in
`tests/fixtures/vectors.json`, and restores, verifies, prunes and re-backs-up `tests/fixtures/ts-repo`,
a repository the TypeScript engine stored (the same library gives byte-identical trees).

Both fixture sets come from the TypeScript engine. With frameleaf-app's `packages/backup-core` built
(`tsc -p packages/backup-core/tsconfig.json --outDir <dist>`):

```bash
node tools/export_fixtures.mjs <dist>   # rewrites tests/fixtures
node tools/check_rust_repo.mjs <dist>   # this engine stores the library; the TypeScript engine reads it back
```
