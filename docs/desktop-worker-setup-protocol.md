# Desktop AI worker setup protocol

How Frameleaf Desktop sets itself up as an AI worker. The desktop does nothing except run the
model the server has configured for each enabled AI task. It verifies that model, downloads it,
checks it gives the known answer, reports, then works. The server's own AI, its destinations and
its routing play no part in setup.

Both repositories implement this document: `frameleaf-desktop` (client) and `frameleaf-app`
(server). The endpoints are the existing `/api/desktop/worker/*` ones. This revision changes what
the server checks, not the wire format, so older desktops keep working.

## Version signal

`GET /api/desktop/capabilities` → `features.workerAutoSetup: true` on servers that follow this
document. Older servers omit the key. The desktop reads a missing key as `false`.

## Setup sequence

| Step | Desktop | Server |
|---|---|---|
| 1 | `POST /api/desktop/worker/models` `{runtimeSourceRevision, provider}` | For each enabled task, returns the catalogue profile(s) for the configured model on this runtime. |
| 2 | Downloads and hash-checks each profile's files against its own catalogue copy. | — |
| 3 | `POST /api/desktop/worker/challenges` `{requestId, modelKey, provider, runtimeSourceRevision, runtime}` | Checks the factory signature on the runtime attestation, then issues the catalogue profile's fixture bound to a nonce. |
| 4 | Runs the fixture in the signed runtime, which compares the result with the profile's `expectedOutput`. | — |
| 5 | `POST /api/desktop/worker/challenges/{id}/report` `{report}` | Validates the report against the profile and runtime, then grants the model to this worker. |
| 6 | Claims, heartbeats and returns leases as before (`claim`, `heartbeat`, …). | Leases that task's queued work to a ready desktop. |

The account still has to have **Desktop AI processing** turned on (`desktop_pool` policy). Lease and
session authentication (`x-frameleaf-desktop-proof`) is unchanged.

### Inventory (`/models`)

The response shape is unchanged (`protocolVersion: 1`, four workloads). On a `workerAutoSetup`
server, `state` is one of:

- `eligible`: the task is enabled and the catalogue has its model for this runtime. `modelKeys` holds 3 keys for `clip` (image + text encoders), 1 for `ocr` and `face`.
- `disabled`: AI, or this task, is turned off on the server.
- `unsupported`: the configured model has no catalogue profile for this runtime/provider, or the task is `enrichment`.

`pinned`, `legacy` and `unavailable` describe routing. Only older servers send them; the desktop
reads them as **update your server** (`server_update_required`).

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
- For CLIP, the desktop vector index is admitted for the profile's space. This refuses an existing index from a different model.

Removed: the server's own reference run (`DesktopNasProducerService`), default-route checks
(`assertDefaultRoute`), and destination availability checks.

### Leasing

A job whose admission lands on a home destination (Local or LAN) can go to a ready desktop of an
approved account, whatever the route's origin (default, pinned or legacy) and whether or not that
destination's AI is up. Work an administrator sends to Frameleaf Cloud stays on Frameleaf Cloud.

### Several desktops at once

Any number of desktops can work the same queue. Each desktop holds at most one lease. `claim` takes
the oldest task its qualified models can run, with `FOR UPDATE SKIP LOCKED`, so whichever desktop
asks first gets the next item. To keep them all busy, the server starts one extra job in that
queue (`smartSearch`, `faceDetection`, `ocr`) for each desktop that is online (seen in the last
90 seconds) and holds a model for it. That is on top of the administrator's own concurrency setting.
The broker still holds at most 32 open tasks.

## Refusal codes

The server logs every refusal (`warn`, with device, model key and code). The desktop shows a
specific message for each.

| HTTP | Server `message` | When | Desktop code |
|---|---|---|---|
| 403 | `desktop_pool_policy_required` | Account has not turned on Desktop AI processing | `worker_policy_required` |
| 400 | `desktop_runtime_attestation_invalid` | Runtime not factory-signed, or epoch below the floor | `worker_runtime_unsigned` |
| 409 | `desktop_model_profile_unavailable` | Task turned off, or model changed, since inventory | `workload_desktop_model_profile_unavailable` |
| 409 | `desktop_model_profile_changed` | Profile changed between challenge and report | `workload_desktop_model_profile_changed` |
| 400 | `desktop_qualification_report_invalid` | Report does not match profile or runtime | `worker_qualification_report_refused` |
| 409 | `desktop_clip_index_incompatible` / `_dimensions` / `_invalid` / `_changed` | Library already has smart-search vectors from another model | `workload_desktop_clip_index_*` |
| 409 | `desktop_challenge_conflict` / `_capacity` / `_too_large` / `_runtime_invalid` | Challenge bookkeeping | `server_http_409` (retry) |

These come from the desktop itself, before anything reaches the server:

| Desktop code | Cause |
|---|---|
| `runtime_output_mismatch` | Fixture result differs from `expectedOutput` (`native_output_*_mismatch`) |
| `runtime_out_of_memory` | Runtime ran out of memory (`native_memory_insufficient`, allocation failure) |
| `runtime_model_missing` | Model files missing or changed (`native_staged_model_unavailable`, `native_staged_hash_mismatch`) |
| `runtime_provider_unavailable` | GPU provider could not run; the desktop falls back to the processor |
| `runtime_signature_invalid` | Bundled runtime fails its signature check |
| `model_disk_space_insufficient` | Not enough free disk for the model download |
| `server_update_required` | Server lacks `workerAutoSetup` and refused on routing grounds |

## Compatibility

| Desktop | Server | Result |
|---|---|---|
| old | new | Works. Same endpoints and payloads; the server no longer refuses on routing or its own AI. |
| new | new | Works, with specific messages. |
| new | old | Works when the old server's routing allows it. Otherwise each refused task shows **update your server** (`server_update_required`), not a generic failure. |
| old | old | Unchanged. |

Server-side NAS-producer codes (`desktop_nas_*`, `desktop_route_review_required`,
`desktop_pool_route_changed`) only come from older servers. A new desktop maps them to
`server_update_required`.
