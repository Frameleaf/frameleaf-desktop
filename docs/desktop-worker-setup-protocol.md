# Desktop AI worker setup protocol

How Frameleaf Desktop sets itself up as an AI worker. The desktop does nothing except run the
model the server has configured for each enabled AI task. It verifies that model, downloads it,
checks it gives the known answer, reports, then works. The server's own AI, its destinations and
its routing play no part in setup.

Both repositories implement this document: `frameleaf-desktop` (client) and `frameleaf-app`
(server). The endpoints are the existing `/api/desktop/worker/*` ones. This revision changes what
the server checks, not the wire format, so older desktops keep working.

## One catalogue: the server's

The server's model catalogue (`server/resources/desktop/model-catalogue.json` in frameleaf-app) is the
only one. The desktop runs exactly the profile the server sends for each model the server selected, and
keeps no catalogue of its own. Downloads come only from Frameleaf's model mirror and are hash-checked
against that profile. The model runs in the factory-signed runtime and must reproduce the profile's
`expectedOutput`. `runtime/model-catalogue.json` in this repository is a copy kept for tests and
release tools. The app never reads it, and the release check keeps it equal to the paired server tag.

When the desktop is the server (local-server mode), the packaged Frameleaf server reads its own
catalogue like any other server. That is still the one catalogue.

### The server's own AI is in the catalogue too

Owner decisions made during this work, which replace the original design:

- **No fallback to the plain model name.** The server's smart search used to fall back to the
  bare model name when it had no catalogue identity for its own AI. That fallback is removed.
  Once a desktop has been granted smart search, the server's own AI must serve a catalogue
  identity as well, so every vector made from then on is tied to one; vectors the server
  made before stay as they are.
- **The catalogue was recut for the server's current AI build** (epoch 17, 171 profiles). It
  appends nine smart-search profiles for the processor (the image encoder and both text encoders
  of `ViT-B-16-SigLIP-384__webli`, `ViT-B-32__openai` and `ViT-SO400M-16-SigLIP2-384__webli`)
  under runtime source `95593fc6887c74a705c85b0ab8c9685c79afb0e4`. Each is a twin of the newest
  processor profile for the same request: the same files, fixture and expected output, with a
  model key of its own. Nothing was removed or changed; the first 162 profiles are as before.
- **No desktop is offered those nine.** No desktop runtime is built or factory-signed from that
  source, and `/models` lists a profile only for the runtime source the desktop reports. The
  desktop parses them like any other profile and never runs them.
- **One embedding space across runtime revisions.** A runtime revision has model keys of its
  own, because a key covers the hash of the runtime's preprocessing sources. Profiles of one
  model whose model files, fixture and expected output are the same are one embedding space,
  whatever their keys.
  - The smart-search index is admitted under the keys of the first desktop granted smart
    search. Desktops on other runtime revisions of the same model are granted too and share
    the index. A task made for one revision's key is leased to a desktop holding the same
    encoder under its own revision's key, and the claim reply carries the key that desktop
    holds.
  - The server asks its own AI under each revision's key of the same encoder until the AI
    serves one (it serves only the key of its own build), and remembers which. Vectors are
    stored under the admitted key, so a library keeps one producer key.
  - A library that already has vectors the server made keeps them.
- **What happens when the server's AI has no catalogue identity.** It answers
  `409 model_identity_unavailable` to the server's request, and the server's own work fails with
  that error: embedding a photo on the server, and encoding the words of a search. It is logged
  at warn on the server and nothing is written. The refusal is not remembered, so an AI that is updated works on the
  next request. Desktops are not affected: they keep embedding photos.
- **Kept in step by the server's checks.** The server's CI fails when its AI build has no
  profile for some search request, and a recut only appends: no revision, provider or profile
  is removed, so this repository's copy stays a superset with the same beginning.

## Version signal

`GET /api/desktop/capabilities` → `features.workerAutoSetup: true` on servers that follow this
document. Older servers omit the key. The desktop reads a missing key as `false`.

`features.workerWithdrawalNotice: true` says the server understands `reportWithdrawn` on a claim
(see Leases). The desktop sends that field only to a server that advertises it, because a server
from before it refuses a claim carrying a field it does not know.

`features.workerConcurrentLeases: true` says a desktop may hold several leases at once (see
Several tasks at once). Only then does the desktop send `concurrentLeases` to `/models` and
`slots` on a claim; without it the desktop holds one lease, exactly as before.

## Setup sequence

Every signed `POST` has the body `{"payload": "<JSON string>"}`: the fields shown below are the
JSON inside that string, exactly the bytes the request proof (`x-frameleaf-desktop-proof`) signs.
`GET` and `DELETE` requests have no body and sign the empty string.

| Step | Desktop | Server |
|---|---|---|
| 1 | `POST /api/desktop/worker/models` `{runtimeSourceRevision, provider, protocolVersion: 2}` | For each enabled task, returns the model keys and the full catalogue profile of each. |
| 2 | Validates each served profile, then downloads its files from the model mirror and hash-checks them against that profile. | — |
| 3 | `POST /api/desktop/worker/challenges` `{requestId, modelKey, provider, runtimeSourceRevision, runtime}` | Checks the factory signature on the runtime attestation, then issues the catalogue profile's fixture bound to a nonce. |
| 4 | Runs the fixture in the signed runtime, which compares the result with the profile's `expectedOutput`. | — |
| 5 | `POST /api/desktop/worker/challenges/{id}/report` `{report}` | Validates the report against the profile and runtime, then grants the model to this worker. |
| 6 | Claims, heartbeats and returns leases as before (`claim`, `heartbeat`, …). | Leases that task's queued work to a ready desktop. |

The account still has to have **Desktop AI processing** turned on (`desktop_pool` policy). Lease and
session authentication (`x-frameleaf-desktop-proof`) is unchanged.

A challenge and an accepted qualification are bound to the worker session id and authorization
epoch, not to the session token: renewing the session (`POST /api/desktop/worker/session`) leaves
them valid.

### The desktop follows the server

The desktop never needs a restart or **Retry Setup** because the server changed something.

- **Models.** While it works, the desktop reads `/models` again every 5 minutes, and at once when a
  challenge or report is refused with `desktop_model_profile_unavailable` / `_changed`. It compares
  each task's `state` and `modelKeys`. On a difference it stops its runtime, downloads and
  hash-checks the new models, qualifies them, and carries on. A task turned on later starts; a task
  turned off stops; with no task left it shows "no work assigned" and asks again every 5 minutes.
  Model files the server no longer lists are removed after the new set has qualified.
- **Refused tasks.** A task refused for another reason (`desktop_clip_index_*`) stays off while the
  others work, and is tried again 2 minutes after the refusal (a model change still being
  applied) or 30 minutes after it (a library built with another model). Offering it again
  checks every task once more, so the tasks that are ready first get at least as long to work
  as the last round of checks took (and never less than 2 minutes).
- **Policy.** `desktop_pool_policy_required` is waited out on every endpoint, session issue and
  renewal included: the desktop asks again every 5 minutes and when its route to the server
  changes.
- **Home network.** `desktop_worker_lan_required` comes only from the signed worker and task
  endpoints (not session issue, renewal or revocation), and is waited out the same way.
- **Plain HTTP by name.** A server saved as `http://nas.fritz.box:2283` is accepted without a
  lookup, so it stays valid when DNS is down or the computer is away. Sign-in, Sign in with
  Frameleaf and Manager accept such a name as a home address once it has resolved home. The desktop connects to
  such a name only at home-network addresses (private, loopback, link-local, CGNAT/Tailscale),
  directly and never through a proxy; an answer with none of those is a network error. Both
  rules are applied to each request as it connects, so they hold for every client whenever it
  was built, and requests to anything else follow the system's proxy settings as before. A
  name typed with `http://` that can't be found right now (DNS down, another network) is
  answered as unreachable, not with a request to use HTTPS.
- **Clock.** Every response's `Date` header tells the desktop the server's time. After this
  computer's own clock is set, or it wakes from sleep, the desktop asks the server the time
  again (`GET /api/server/ping`, unsigned) before it judges any deadline. When the two clocks
  differ by 30 seconds or more, the desktop times its requests and reads the server's deadlines by
  the server's clock (the server refuses a request timed more than 2 minutes off). Enrolment that
  is still refused for its timestamp (`device_proof_expired`) is shown as `clock_invalid`.
- **New fields.** The desktop ignores fields it does not know in the `/models` reply and its task
  entries, in a challenge and in an accepted qualification. A catalogue profile is hashed into its
  model key and stays strict: an unknown field in a profile refuses the reply.

### Inventory (`/models`)

With `protocolVersion: 2` in the request, the reply is `protocolVersion: 2`, still with four workloads.
Each `eligible` entry also has `profiles`: the server's catalogue profile for each of `modelKeys`, in
the same order and exactly as the server ships it. The desktop refuses the whole reply if a profile
fails validation or does not carry the key, workload, provider and runtime source it is listed for.
Without `protocolVersion`, current desktops get the `protocolVersion: 1` reply, unchanged.

On a `workerAutoSetup` server, `state` is one of:

- `eligible`: the task is enabled and the catalogue has its model for this runtime. `modelKeys` holds 3 keys for `clip` (image + text encoders), 1 for `ocr` and `face`.
- `disabled`: AI, or this task, is turned off on the server.
- `unsupported`: the configured model has no catalogue profile for this runtime/provider, or the task is `enrichment`.

`pinned`, `legacy` and `unavailable` describe routing, and only older servers send them.

With `"concurrentLeases": true` in the request (sent only to a server that advertises
`workerConcurrentLeases`), each `eligible` entry also carries `"concurrency": <int ≥ 1>`: the
administrator's Jobs setting for that task's queue (smart search, faces, text). Without the
request field the reply is as above, so desktops already released never see the new field.

## What the server checks

To issue a challenge:
- AI and the task are enabled.
- The catalogue has the profile for this exact `modelKey` + provider + runtime source.
- The profile matches the configured model (CLIP model name; face/OCR settings).
- The runtime attestation is factory-signed (`verifyDesktopRuntimeAttestation`) and meets the epoch floor.

To accept a report:
- It is bound to the challenge, profile and signed runtime (`DesktopQualificationReceipt.validate`).
- The account approval is current.
- The profile is still the configured one (re-read inside the grant transaction).
- For CLIP, the desktop vector index is admitted for the profile's embedding space. A library
  the server already embedded is accepted and keeps its vectors; another runtime revision of the
  same model is accepted; only a library holding vectors tagged with another model's key is
  refused.

Removed: the server's own reference run (`DesktopNasProducerService`), default-route checks
(`assertDefaultRoute`), and destination availability checks.

### Leasing

A job whose admission lands on a home destination (Local or LAN) can go to a ready desktop of an
approved account, whatever the route's origin (default, pinned or legacy) and whether or not that
destination's AI is up. Work an administrator sends to Frameleaf Cloud stays on Frameleaf Cloud.

### Several tasks at once

Owner decision made during this work: a desktop follows the administrator's Jobs concurrency
setting instead of working one task at a time. This replaces "each desktop holds at most one
lease".

- **What the server allows.** `concurrency` in the `/models` reply, per task, from the Jobs
  setting. The server hands over a new lease only while the desktop holds fewer than that many
  for the task's workload.
- **What the desktop can take.** One number for the whole runtime: the least of the server's
  allowance for the tasks that are ready (their `concurrency` added up), what this computer can
  take, and what it managed since it last ran short of memory.
  - A graphics card or neural engine: up to eight at once. The processor: one, or two on a
    computer with eight cores or more (each task already gets four threads).
  - Memory: beside the loaded models, each task in hand is taken to need a quarter of the
    models' memory, at least 256 MB; what is free now, less the models, says how many fit.
  - A graphics card's own memory can't be read, so the number is a starting point, lowered
    when memory runs short while working, on the same device:
    - the model refuses two tasks in a row while several are in hand: half as many from then
      on;
    - the runtime process ends or stops answering with several tasks in hand: half as many,
      then one. The graphics card keeps the work. Only a runtime that fails with one task in
      hand is treated as failing (the work then moves to the processor, as before).
    It does not stop, and it does not go back up until AI processing is stopped and started
    again. Pauses for memory, power and network are unchanged.
  - Nothing to set on the desktop.
- **Claims.** `"slots": <1..64>` on every claim says how many more tasks the desktop can take
  right now. A claim still returns at most one task; with `slots` it is always a new lease,
  never one already held. With nothing in hand the desktop waits for work as before (`waitMs`
  20000). With tasks in hand it asks without waiting (`waitMs` 0), as soon as a task is done
  and there is room, and again a second later when the server had nothing. A slow task does
  not hold up the others' places.
- **Each task is reported as soon as it is done**, its result or its failure, without waiting
  for the others in hand.
- **A runtime that ends under several tasks is one failure.** One of the tasks in hand is
  reported `model-unavailable` and the others are handed back `cancelled`, so the server's
  count toward withdrawing the model goes up by one, not by the number of tasks.
- **The heartbeat starts at the claim**, and runs while the task's input is fetched as well as
  while the model works. Inputs of several tasks are downloaded side by side.
- **Each lease is its own.** Its own input, heartbeat, result and failure. A failure, a refused
  input, a lost lease, a hold or a withdrawal touches only its own task or model; the others
  finish and report. Stop, sign-out, library switch, quit and a pause for power or network
  hand back every lease held, each with `fail` `cancelled`; a stop waits three seconds for
  that, and a second more for each further task in hand.
- **One request at a time.** Signed requests still go one at a time in sequence order, which
  is why the claims for more room do not wait.
- The runtime process is started able to serve as many requests at once as this computer
  could take, so a higher Jobs setting takes effect with the next claim, without a restart. The signed runtime takes one input per inference call, so several tasks are several
  calls served side by side, not one batched call.
- **A lease whose claim reply was lost** is not returned again under `slots`. It runs out
  after 120 seconds; the server hands back at once a lease it made while the connection was
  closing.
- **Queue jobs.** The server remembers what the desktop holds plus its last `slots` as how
  many tasks it runs at once (one, for a desktop that never sent `slots`). For each task it
  holds for a queue, and each task it can still take, the server starts one job in that queue
  on top of the administrator's own concurrency, under the conditions in the next section, and
  only while the queue's Jobs setting is not reached for that desktop and one of the queue's
  next jobs is for a photo it may take. Free slots are counted for smart search first, then
  faces, then text.
- A `slots` outside 1 to 64 is refused with `400 desktop_worker_payload_invalid`.

### Several desktops at once

Any number of desktops can work the same queue. `claim` takes
the oldest task its qualified models can run, with `FOR UPDATE SKIP LOCKED`, so whichever desktop
asks first gets the next item. To keep them busy, the server starts one extra job (as many as
the desktop said it can run, where it holds several leases) in a queue
(`smartSearch`, `faceDetection`, `ocr`) for a desktop only when all of these hold: the desktop is
online (a request in the last 150 seconds: the lease plus 30 seconds), its account is still
approved, it holds an unexpired qualification for the model the settings ask for now, and that
queue's work would go to desktops first (the first place in the processing order that is available
now is the desktops). Each lease a desktop holds counts for the queue of the job it is for. Each task it can still
take counts for the first of smart search, faces and text that it can work, that has a job coming
up for a photo it may take (its own account's, or anyone's for a computer that works on everyone's
photos), and of whose work it holds fewer tasks than that queue's Jobs setting. Only the next 64
jobs of a queue are looked at. With the server itself first in the order and its AI answering, no extra jobs start.
That is on top of the administrator's own concurrency setting. The broker holds at most 256
open tasks (it was 32).

For a route pinned to the server, desktops come after the server (it is tried first); for the
default order, wherever "your computers" sits in the administrator's order.

`task.modelKey` in a claim is the key this desktop holds the model under. A task made for one
runtime revision's CLIP key is leased to a desktop holding the same encoder under its own
revision's key. `task.qualificationId` is the desktop's current qualification for that model.

### Leases

- A lease lasts 120 seconds from each heartbeat (the desktop sends one every 20 seconds for
  each lease it holds); the result or a failure ends it. Qualifying again while holding a lease does
  not end it.
- `POST /api/desktop/tasks/{id}/fail` `{code}` takes `inference-failed`, `input-invalid`,
  `model-unavailable` or `cancelled`, and the server logs the code. The desktop sends `cancelled`
  when it hands a lease back unfinished (Stop, sign-out, library switch, quitting the app, a pause
  for power or network, waking from sleep), `input-invalid` when the input does not match its hash
  or the model refuses that one input, `model-unavailable` when its runtime process stopped, and
  `inference-failed` otherwise. Pause (the person's own) lets the task in hand finish first.
- `cancelled` puts the task straight back in line and does not count toward the three failures
  after which the task itself fails. The other three codes each count.
- **Grant withdrawal.** After three `inference-failed` or `model-unavailable` in a row from one
  worker session for one model (a result in between resets the count; `cancelled` and
  `input-invalid` do not count), the server withdraws that model from the desktop: its
  qualification is deleted, `claim` returns nothing for it and
  `GET /worker/qualifications/{id}` answers `401 desktop_qualification_invalid`. The `fail` reply is
  still `{"accepted": true}`, and `/models` still lists the model, so a new challenge and report
  grant it again. The desktop keeps the same count the same way (for each model, the failures it
  reported as `inference-failed` or `model-unavailable` since that model's last result) and, at
  the third, qualifies again without being told. The server keeps its count per device and model
  (a new session does not reset it) and answers that qualification with
  `409 desktop_qualification_hold` for 5 minutes, which the desktop waits out for that model.
- **Withdrawal notice.** The server's count outlives a desktop's restart, so it can withdraw a
  model the desktop still believes it holds. When the server advertises
  `features.workerWithdrawalNotice`, the desktop adds `"reportWithdrawn": true` to its claim
  payload (beside `modelKeys` and `waitMs`). A claim that names a withdrawn model then answers at
  once `409 desktop_qualification_hold` instead of a task, for as long as the model is asked for
  and not granted again. The desktop (`worker_model_withdrawn`) stops claiming and qualifies
  again: the withdrawn model's challenge answers the same 409, that task is set aside for the
  hold, and the other models go back to work. Without the field a claim behaves as before.
- On a stop the desktop gives the task in hand up to 3 seconds to send `cancelled`, and a claim
  already sent up to 2 seconds to answer so a task leased in that moment is handed straight back.
- Signed requests are sent one at a time, in sequence order.

## Refusal codes

The server logs every refusal (`warn`, with device, model key and code). The desktop shows a
specific message for each.

**The `message` is the name.** The desktop matches a refusal by `message` alone, on every endpoint;
the HTTP status only matters for a refusal with no known name. Servers have sent the same refusal
under different statuses (policy-off was 401 at session issue and 409 on report before it became
403 everywhere), and both old and new servers are understood.

| HTTP | Server `message` | When | Desktop code | What the desktop does |
|---|---|---|---|---|
| 403 | `desktop_pool_policy_required` | Account has not turned on Desktop AI processing (every endpoint, session issue and report included) | `worker_policy_required` | Waits; asks again every 5 minutes and when the network changes |
| 403 | `desktop_worker_lan_required` | Not on the server's home network (`/worker/*` and `/tasks/*`; not session issue, renew or revoke) | `worker_lan_required` | Same |
| 409 | `desktop_pool_policy_changed` | The policy the lease or session ran under changed | `worker_policy_changed` | New session, qualify again, carry on |
| 401 | `desktop_worker_credential_invalid` (worker endpoints) | Worker session ended (household change) or proof refused | `worker_session_rejected` | New session, qualify again, carry on |
| 401 | `desktop_worker_credential_invalid` (session issue) | The device itself is refused | `worker_device_refused` | Stops and says so |
| 403 | `desktop_worker_photo_session_required` (session issue) | The caller is not a photo session (API key, shared link) | `worker_sign_in_required` | Stops; sign in again |
| 401 | none, or the server's ordinary sign-in message (session issue) | The photo sign-in expired; refused before the device is looked at | `worker_sign_in_required` | Stops; sign in again |
| 401 | `desktop_lease_invalid` | Lease no longer held, including a lease lost while its input is read | `worker_lease_refused` | Drops that task, reports nothing more about it, claims the next |
| 401 | `desktop_challenge_invalid` / `desktop_qualification_invalid` / `desktop_worker_activation_invalid` | Challenge or qualification expired, or not this session's | `worker_qualification_restart` | New challenge for that model, after a short wait. Shown as waiting, with the reason |
| 409 | `desktop_challenge_conflict` / `_capacity`, `desktop_qualification_capacity`, `desktop_clip_publication_isolation` | Challenge and grant bookkeeping | `worker_challenge_busy` | Same; never stops. Shown as waiting, with the reason |
| 409 | `desktop_challenge_too_large` / `_runtime_invalid` | The fixture is too large, or the runtime is not the one this device enrolled: the same answer every time | `worker_challenge_rejected` | Asked again twice, then: GPU runtime falls back to the processor; processor runtime leaves that task off with this reason (and stops with it when no task is left) |
| 401 | `desktop_proof_expired` (session issue and every signed endpoint) | The request's timestamp is more than 2 minutes from the server's clock; not a refused device | `clock_invalid` | Waits 5 minutes and tries again, reading the server's clock again each time |
| 409 | `desktop_model_profile_unavailable` | Task turned off, or model changed, since inventory | `workload_desktop_model_profile_unavailable` | Reads `/models` again and follows it |
| 409 | `desktop_model_profile_changed` | Profile changed between challenge and report | `workload_desktop_model_profile_changed` | Same |
| 409 | `desktop_pool_model_unavailable` (report only) | The qualification is for another key than the one being granted | `workload_<message>` | Same |
| 409 | `desktop_qualification_hold` (claim with `reportWithdrawn`) | A model named in the claim was withdrawn from this device and not granted again | `worker_model_withdrawn` | Qualifies again; the withdrawn model then meets the row below |
| 409 | `desktop_qualification_hold` (challenge, report) | The server withdrew this model after three failed tasks in a row and takes no new qualification for it from this device for 5 minutes | `workload_<message>` | That task waits, the others work; qualified again after 5½ minutes. A task on a GPU stays on the GPU |
| 409 | `desktop_clip_index_changed` / `_dimensions` | An administrator changed the search model and the server is still resetting the index (seconds to a minute) | `workload_<message>` | That task waits, the others work; tried again after 2 minutes |
| 409 | `desktop_clip_index_incompatible` / `_invalid`, `desktop_clip_space_unavailable` | The library holds vectors tagged with another model's key, or the stored index does not match the release | `workload_<message>` | That task stays off, the others work; tried again every 30 minutes |
| 400 | `desktop_result_invalid` / `desktop_result_too_large` (result) | The result is not what the task's model returns, or is over 4 MB. Nothing is staged and the lease stays | `server_http_400` | Fails that task with `inference-failed`, claims the next |
| 400 | `desktop_worker_payload_invalid` / `desktop_qualification_payload_invalid` | Payload not the schema | `server_http_400` | On a task: drops that task. Elsewhere: stops and shows it |
| 400 | `desktop_runtime_attestation_invalid` | Runtime not factory-signed, or epoch below the floor | `worker_runtime_unsigned` | GPU runtime: falls back to the processor runtime. Processor runtime: stops and says so |
| 400 | `desktop_qualification_report_invalid` | Report does not match profile or runtime | `worker_qualification_report_refused` | Same |
| 200 | `{"accepted": false}` on report | Report not accepted | `worker_qualification_refused` | GPU: falls back to the processor. Processor: that task is off |
| 200 | `{"accepted": false}` on heartbeat / result / fail | Lease gone | `worker_lease_lost` / `worker_result_refused` | Drops that task, claims the next |
| 5xx, 408, 429 | unknown or absent | Server failing or busy (500 is treated like 503) | `server_http_<status>` | Retries with backoff; never stops |
| other 4xx | unknown, on `tasks/{id}/input`, `/result`, `/fail`, `heartbeat` | — | `server_http_<status>` | Drops that task only (a bare 401 or 403 stops the worker) |
| other 4xx | unknown, elsewhere | — | `server_http_<status>` | GPU runtime while qualifying: falls back to the processor. Otherwise stops and shows it |

When the server refuses every task for a reason of its own (the `desktop_clip_index_*` rows with
smart search the only task), the desktop waits the same 2 or 30 minutes and offers again; it does
not stop. `desktop_identity_revoked_or_changed` comes only from enrolment
(`POST /api/desktop/devices/enroll`); if it ever arrives at session issue the desktop reads it as a
refused device. `desktop_clip_profile_unavailable` and `desktop_face_profile_unavailable` are understood
by the desktop (like `desktop_model_profile_unavailable`) but no current server sends them.

A run of dropped tasks or server errors slows the claims down (up to about a minute apart) and
shows the reason; it does not stop the worker.

These come from the desktop itself, before anything reaches the server:

| Desktop code | Cause |
|---|---|
| `runtime_output_mismatch` | Fixture result differs from `expectedOutput` (`native_output_*_mismatch`) |
| `runtime_out_of_memory` | Runtime ran out of memory (`native_memory_insufficient`, allocation failure). On a GPU this, like a check that timed out, moves the task to the processor for this run only; it is not remembered for the runtime epoch |
| `runtime_model_missing` | Model files missing or changed (`native_staged_model_unavailable`, `native_staged_hash_mismatch`) |
| `runtime_provider_unavailable` | GPU provider could not run; the desktop falls back to the processor |
| `runtime_crash_loop` | Three times in a row, with no task finished in between, the runtime process ended by itself or started and never answered its health check (`runtime_not_ready`). Its exit status and last error lines are logged and shown when the process did end |
| `clock_invalid` | The computer's clock can't be read, or enrolment was refused for its timestamp |
| `runtime_signature_invalid` | Bundled runtime fails its signature check |
| `model_disk_space_insufficient` | Not enough free disk for what is still to download (checked before the first request, with 64 MB to spare) |
| `server_update_required` | Server lacks `workerAutoSetup`, so it can't send its catalogue |

## Compatibility

| Desktop | Server | Result |
|---|---|---|
| old | new | Works. Same endpoints and payloads; the server no longer refuses on routing or its own AI. An old desktop matches some refusals by status and name together, so a status that changed (policy-off at session issue: 401 → 403; on report: 409 → 403) shows it a general message instead of a named one. |
| new | new | Works, with specific messages. |
| new | new, without `workerConcurrentLeases` | Works, one task at a time. |
| new | old | **Update your server** (`server_update_required`). The old server can't send its catalogue, and the desktop has none of its own. It checks again every few minutes. |
| old | old | Unchanged. |

Server-side NAS-producer codes (`desktop_nas_*`, `desktop_route_review_required`,
`desktop_pool_route_changed`) only come from older servers. A new desktop maps them to
`server_update_required` if it ever sees one.
