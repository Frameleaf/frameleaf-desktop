# Fast AI startup design

Status: proposed, not implemented. Touches `frameleaf-desktop` and `frameleaf-app`.

## Problem

A person opens Frameleaf and waits many minutes before their computer does any AI work. The wait
repeats on every launch, although nothing on the computer has changed. Regular users will not
wait for this.

**Goal:** an app restart with nothing changed starts working in under 60 seconds on an SSD, with
no full model test. A real test still runs whenever something it proved may have changed.

## What happens today

Measured on one Windows PC (Ryzen 5 3600X, NVMe SSD, RTX 3060) on 2026-11-22. Hash times were taken
with files probably already in the OS cache, so they are lower bounds. The app has no phase timing,
so the split of a whole startup is not yet known.

| Cost | Evidence | Size here |
|---|---|---|
| Every model key is run on a test input in a new process | `worker_setup.rs`, `'qualification` loop | 15 to 60 s per key, 4 keys on CPU, 3 on GPU |
| The GPU is compared with the CPU on first use | `plan.unmeasured` | About 100 s, once per runtime |
| A full runtime hash on load, attestation, and before and after every test and serve | `check_files` in `native_runtime.rs` | About 11 passes of the CPU runtime (2.4 s each) and 9 of the GPU runtime (6.5 s each) |
| Model files are hashed once per model key, and CLIP's three keys share files | `prepare_cache` in the `profiles` loop | 4.5 GB in 6.7 s per pass |
| Results die with the worker session and last one hour | Server `desktop_worker_qualification` | Every launch, then hourly |

The repeated hashing alone is roughly 1.5 to 2 minutes on this fast SSD, and will be far worse on a
hard drive. The model tests are the larger cost.

## Design

Three phases, each useful alone and shippable in order.

### Phase 0: measure (desktop)

Log the duration of each startup phase: runtime verification, model verification, each test,
GPU comparison, and runtime start. No file paths or personal details. Later phases are judged by
these numbers.

### Phase 1: hash once per launch (desktop only)

- `VerifiedRuntime` does one full hash when loaded and records each file's size, modified time and
  file identity. Later `check_files` calls in that launch compare the inventory and that metadata,
  and fall back to a full hash on any difference.
- A verified model cache is remembered in memory by `cache_identity`, so CLIP's three keys hash its
  files once. A model test that reports changed or missing files clears that memory.
- Every launch still hashes every file once. Nothing about the trust model changes.

### Phase 2: results that survive restarts (server and desktop)

Keep the real test result and let a new session reuse it while everything it proved is unchanged.

#### Server

New capability: `features.workerQualificationReuse: true`.

New table `desktop_worker_standing_qualification`, written or replaced after a real report's grant
succeeds, so a report the server accepted but could not grant is never reusable:

| Column | Purpose |
|---|---|
| `id` | The original challenge id. The spec's binding is derived from it, so it must not change |
| `deviceId` | FK, cascade |
| `photoSessionId` | FK, cascade. **Signing out ends reuse** |
| `authorizationEpoch` | A re-authorized device tests again |
| `modelKey`, `profileSha256`, `configSha256`, `inputKind` | What was tested |
| `runtime`, `runtimeFingerprint`, `reportSha256` | What it ran on and what it reported |
| `verifiedAt`, `expiresAt` | Time of the real test, plus 30 days |

Unique on `(deviceId, modelKey, runtime provider)`: the CPU and GPU profiles of a model share a
model key.

New endpoint `POST /api/desktop/worker/qualifications/{id}/reuse`, signed with the scope
`qualification-reuse:{id}`, with the body `{modelKey, provider, runtimeSourceRevision, runtime, report}`.
The server, in order:

1. Authenticates the worker session.
2. Requires the profile to still be the configured one (`selected`).
3. Refuses a held model (`assertNotHeld`).
4. Verifies the factory-signed runtime attestation and the epoch floor.
5. Loads the standing row for this device, photo session and epoch, unexpired, and requires every
   stored field to match.
6. Runs `DesktopQualificationReceipt.validate` on the report, and requires its hash and fingerprint
   to equal the row's.
7. Writes the session's `desktop_worker_qualification` row with the **same id**, `createdAt` now and
   a one-hour expiry, replacing any row for that model.
8. Grants through the existing `activate` or `activateModel`, so account approval, profile and CLIP
   index checks all still apply.

Reuse **must not** call `clearWithdrawal`. A real test resets the server's failure count. If reuse
did too, a failing model could renew itself forever and never be withdrawn. `withdraw` deletes the
standing rows for all equivalent keys, so a withdrawn model must pass a real test.

Any refusal is `409 desktop_qualification_reuse_refused`, except the existing named refusals from
steps 1 to 4 and 8.

#### Desktop

After each accepted real test, save a private record in `worker/qualification-reuse/`: the spec,
the report, the runtime manifest hash, the device identity (`device_identity`), the model cache
identity, and a digest of the server, account and device ids. Delete the folder on sign-out and
library switch.

At startup, for each model key, reuse is attempted only when all of these hold:

- The server advertises the capability.
- The record's digest, profile, runtime manifest and model cache identity match.
- The GPU and driver identity matches.
- This launch's file verification passed.
- `validate_report` passes on the restored report.

Then the desktop calls `/reuse`, reads the accepted qualification through the existing
`GET /qualifications/{id}`, and binds it with the existing `AcceptedQualification::bind`.
**Any failure falls back to today's real test, once, for that model.** Reuse can never leave a
model unavailable.

While working, the desktop calls `/reuse` about 10 minutes before a qualification expires and
swaps in the new expiry **without stopping the runtime**. If that fails, the existing path runs.

`validate_task` requires a task's `qualificationExpiresAt` to equal the held qualification's expiry,
so a plain swap would reject tasks already in hand. New claims use the renewed qualification. Each
task in hand keeps validating against the one it was claimed under until it finishes, and the old
one is dropped once no task uses it.

#### When a real test still runs

First setup, a new app runtime, changed model files or profile, a changed GPU or driver, a new
sign-in or device authorization, a withdrawn model, a runtime failure that asks for requalifying,
**Retry Setup**, and a result older than 30 days.

#### Compatibility

| Desktop | Server | Result |
|---|---|---|
| new | new | Reuse |
| new | old | No capability, so real tests as today, with Phase 1's faster hashing |
| old | new | Unchanged. Its real reports also populate standing rows, which it never uses |

## Security

- The test proves that a signed runtime gave the known answer on this device. It is not hardware
  attestation, and its fixture and expected answer are known to the desktop, so rerunning it adds
  no protection against a modified client. Its value is catching a broken install, driver or
  model, and reuse keeps retesting when any of those change.
- The existing rule that a new sign-in never revives earlier qualifications is kept by the
  `photoSessionId` cascade.
- Reports hold hardware facts (GPU, driver, memory), not photos. Saving them locally changes the
  current rule that raw reports are not persisted, so this needs the owner's approval below.

## Testing

- Desktop: one full hash per launch; a changed file is detected and rehashed; each reuse condition
  blocks reuse; a refused reuse falls back to one real test; renewal keeps the runtime running and
does not reject a task claimed before it.
- Server: each step's refusal; sign-out, re-authorization, expiry and withdrawal all end reuse; reuse
  does not reset the failure count; hold is honoured; old desktops are unaffected.
- End to end on Windows with a GPU: restart with nothing changed starts in under 60 s, then change
  each input and confirm a real test runs.

## Decisions for the owner

1. **Maximum age of a reused result.** Proposed: 30 days.
2. **Saving raw test reports in the app's private folder.** Proposed: yes, deleted on sign-out.

## Delivery order

1. Phase 0 and Phase 1 in `frameleaf-desktop`.
2. Server table, endpoint and capability in `frameleaf-app`.
3. Desktop reuse, then update `docs/desktop-worker-setup-protocol.md`, which both repositories
   implement.
