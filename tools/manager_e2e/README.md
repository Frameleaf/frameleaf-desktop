# Local Manager, end to end

An opt-in run of Desktop's own local-Manager code against a real Manager, photo server and
database, in Docker. It exists because the capabilities a Manager declares (`runtime-status`,
`ports`, `tls-rotation`) are otherwise only tested in pieces on each side.

```
tools/manager_e2e/run.sh COMPANION_DIRECTORY CAPABLE_REVISION [PLAIN_REVISION]
```

- `COMPANION_DIRECTORY`: a directory holding the released Linux companion's two packages
  (`FrameleafCompanion_*_amd64_bootstrap.deb` and `..._runtime.deb` from a Desktop release).
- `CAPABLE_REVISION`: a `Frameleaf/frameleaf-app` commit whose Manager declares the capabilities.
- `PLAIN_REVISION` (optional): a commit whose Manager declares none, such as a released Manager.

It needs Docker with `linux/amd64` (on Apple silicon that is emulated and slow: allow an hour),
about 25 GB in Docker's disk, and network access to GitHub, nodejs.org, crates.io and npm.

## What runs

1. An Ubuntu 24.04 image with the released companion installed by `apt`, as on a person's computer.
2. In a container from it, this repository is copied, and its test binary and controller
   (`frameleaf-native-host`) are built. **One thing differs from what ships:** a signing key made
   for the run is added to that copy's `runtime/release-trust.json`. Nothing else is changed.
3. For each server revision, Manager is built with `tools/build_host_manager.py`, as a companion
   release builds it. `assemble.mjs` then installs a second companion: the released payload (Node,
   photo server, Postgres, everything else, byte for byte) with that Manager in place of its own,
   a manifest rewritten for those files and signed with the run's key, and the controller built
   in step 2 (without its debug information, to fit the size an installed controller may have),
   finalized by that controller's own `--finalize-install`.
4. The ignored tests in `src-tauri/src/host_setup_manager_e2e.rs` run one at a time, each as a new
   unprivileged account with its own library profile and its own Secret Service keyring. They call
   what the interface calls (`HostSetup::start`, `authorize`, `photos_url`, `stop`, and the paired
   Manager commands), so Desktop verifies the package, spawns Manager with a private bootstrap,
   Manager starts the controller, and the controller starts Postgres and the photo server.

## What it does not do

- The profile is prepared by running the controller's `--provision-profile` as root directly;
  the `pkexec` prompt that normally authorizes that is not shown.
- Time does not pass. A TLS identity near or past its expiry is made by saving one that was
  issued earlier, through the same keystore records a start writes; one that expires during
  the run is issued to last `FRAMELEAF_MANAGER_E2E_SHORT` seconds (default 150). Manager's
  30-day grace period ending cannot be reached this way and stays unit-tested in the server
  repository.
- A failed start whose first attempt presented a renewed identity is reached, for the grace
  period, by making the last attempt of that start directly (`start_without_renewing`).
- Only Linux x86_64 runs; macOS and Windows differ in how the controller is protected and owned.

Manager allows one address 120 paired requests in ten minutes, so the tests ask about a running
operation every five seconds. Every start verifies the whole package, which takes a minute or
more under emulation.

## Cleaning up

`run.sh` prints the three commands that remove the container, the cache volume and the image.
