# Carry-forward proof

An opt-in test that moves a library from one Postgres build to another with the code the app
ships (`runtime/host-agent.mjs`), using real databases. It is not part of `npm test` and nothing
here is packaged.

```sh
sh tools/carry_forward/run.sh
```

It needs Docker, the server image `ghcr.io/frameleaf/frameleaf-server:latest` (override with
`FRAMELEAF_CARRY_SERVER_IMAGE`), network access to fetch the Postgres and pgvector sources, and
about 4 GB of disk. The first build compiles Postgres twice (`FRAMELEAF_CARRY_JOBS` sets the
compile jobs, 4 by default).

## What stands in for what

There is only one signed companion package today, so two Postgres builds stand in for the two
packages:

| | Stand-in |
|---|---|
| Previous package | Postgres 18.7 with pgvector 0.8.7, built from source |
| New package | the pins in `runtime/host-database.json` (Postgres 19beta4, pgvector 0.8.7), built from the pinned sources with the switches `tools/build_host_database.py` uses |
| Photo server | the server image's own build, which also supplies Node |

The library schema is created by the product server's own migrations. The server refuses any
Postgres but 19, so the schema is created on the new build and moved to the previous build as
plain SQL; `library.sql` then loads a synthetic library into it (6,000 photos and videos with
EXIF, two renditions each, one CLIP embedding each, 4,000 faces with embeddings, 40 people,
60 albums, tags, memories and comments). No real photos or data are involved.

## What runs for real

The export run (previous Postgres, read-only, loopback), the dump and its verification, the
restore into a fresh directory with the new Postgres, the row-count comparison, the server's
migrations and schema validation, the vector index checks, `pg_checksums`, and a start of the
photo server on the restored directory. The failure cases: an export interrupted by its owner
going away and by being killed, three kinds of corrupted export, a restore that does not match the
export, and too little room for either step.

## What does not

The journal write that selects the new package and directory is Rust
(`src-tauri/src/host_state.rs`) and is covered by unit tests there. Here the agent is handed the
database reference that write would hold. No signed package, Manager or installed controller is
involved.
