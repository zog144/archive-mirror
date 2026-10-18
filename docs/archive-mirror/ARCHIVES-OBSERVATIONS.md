# Administration → Archives, pass 1

Station-access 0.4.5 adds the administrator-only `/archives/` page and the
`archive_inventory` Django application. Archive-mirror 0.3.0 supplies read-only
observations from its actual ORM catalog and configured persistent object store.
Source archives and root filesystems are grouped by collection within the chosen
mirror. Publication is not deployment authorization.

## Administrator metadata API (version 1)

Both GET endpoints require a logged-in Django superuser. Anonymous requests return
401; ordinary users return 403. Responses use `Cache-Control: no-store`. They do
not contact hosts, probe arbitrary URLs, run jobs, or grant download authorization.

| Endpoint | Parameters | Response |
| --- | --- | --- |
| `/api/archives/mirrors/` | `limit` (1–100, default 25); optional `after` host UUID | `version`, `freshness_seconds`, `mirrors`, `next_cursor` (UUID or null) |
| `/api/archives/items/` | required `mirror` host UUID and `snapshot` UUID; optional `collection`, `after` position (0–9999), `limit` (1–100, default 25) | `version`, `mirror`, `snapshot`, `observed_at`, `items`, `next_cursor` (position or null) |

Omit `after` for the first item page. Pages use stable ascending positions within
an immutable completed snapshot. Collection filtering preserves those positions.
Mirror pages use ascending host UUIDs. Invalid, duplicate or unknown parameters
return 400. A superseded/deleted snapshot returns 409: refresh the mirror list and
restart item pagination. No totals are inferred from the length of a single page.
The UI loads 25 mirrors/items at a time; it does not eagerly fetch the entire fleet.

A mirror contains `host_id`, `name`, `selected`, `role_revision`, `state`, `reason`,
`observation_state`, `observed_at` (last complete successful catalog),
`last_attempt_at` (last completed report, including failure), `observation_revision`,
`role_observed_at`, `preparation` (`state`, `attempt_id`, `fresh`), `snapshot`,
`archive_count`, and `summary`. Counts and summaries are null without a successful
observation. Unselected/archived hosts with role records remain inspectable; archive
records and bytes are not deleted by this feature.

An item contains only:

- `collection`, `digest` (SHA-256, 64 lowercase hex), `kind` (`source` or `root-filesystem`).
- `name` (source name/latest pin when recorded), `version` (recorded commit/generation
  hex identifier), `size_bytes` (integer or null).
- `availability`: `present`, `missing`, `size-mismatch`, `unknown`.
- `filesystem_id` (host-local device identifier or null).
- `provenance`: `source-export`, `local-import`, `unknown`.
- `approval`: `approved`, `unapproved`, `unknown`, projecting an existing boolean
  `release_approved` only. This is recorded metadata, not a new approval authority.

Missing names/version/generation are unknown. Arbitrary provenance, repository
URLs, filesystem paths, exception messages, environment variables, credentials,
keys, request headers and download URLs are not included. The existing scoped
machine catalog also now allowlists provenance instead of echoing raw JSON.
`present` means a regular stored object with the recorded length was observed;
the observation scan does not rehash its contents or assert release fitness.

## Size and filesystem semantics

All API sizes are integer **bytes**, never formatted MB. UI **1 MB = 1,000,000 bytes**;
null displays **Unknown**, including capacity failures. Zero is shown only when
measured/known. Totals describe the whole mirror snapshot, not the current filter.

| Summary field | Meaning |
| --- | --- |
| `logical_bytes` | Sum of catalog record lengths; a digest in two collections contributes twice. Computed by the receiver from the full completed catalog. |
| `unique_content_bytes` | Sum once per digest on this mirror; null on unknown/conflicting sizes. Computed by the receiver. This is logical content, not disk use. |
| `allocated_object_bytes` | Object directory `st_blocks × 512`, once per `(device,inode)`, including unreferenced blobs. Null if the bounded scan is incomplete/unsafe or allocation is unavailable. |
| `accounting_complete` | Whether the object directory scan finished within limits without unsupported entries. |
| `filesystems` | At most 16 host-local devices, each with `id`, `stores`, `allocated_object_bytes`, `total_bytes`, `used_bytes`, `available_bytes`. |

Store and objects directories sharing a device produce one filesystem record.
Per-file bind mounts on other devices have unknown capacity unless actually
measured. Filesystem capacity uses `fstatvfs`: total = blocks × fragment size;
used = (blocks − free blocks) × fragment size; available = service-available blocks
× fragment size. Used includes other applications, staging, database and all other
filesystem users; it is **not archive-only usage**. Allocation counts inode blocks,
not a measurement of exclusive physical extents: reflinks, compression, snapshots,
remote storage and thin provisioning can differ. No fleet capacity total is shown;
devices are host-local and shared filesystems across mirrors cannot safely be added.

## Observation transport and bounded work

Remote mirrors **push signed observations**; browser GETs never crawl mirrors.
The reporting job uses the existing approved Ed25519 host identity and RFC 9421
request profile. No new shared secret, signing issuer key distribution, or changes
to host-discover 0.3.4 are introduced.

`POST /api/archives/reports/<host UUID>/` is a separate machine ingestion endpoint,
not a browser metadata query. Browser admin sessions and download JWTs do not
authorize it. Exact approved host-key binding, canonical registry HTTPS origin,
body digest, signature expiry and durable replay checks are required. Binding and
revocation are rechecked under the existing security lock. Archived or revoked
hosts cannot report. Report role revision must equal the current MirrorRole row,
including after deselection. A report cannot elect a host or change its role.

The body contains exactly:

```
version: 1
host_id: UUID
role_revision: positive integer
observation_id: UUID (one fresh identifier per complete scan)
observed_at: UTC/offset ISO datetime
status: ok | unavailable | limit-exceeded
serving: boolean
lease_expires_at: Unix seconds or null
preparation: {state, attempt_id}
summary: {collections, logical_bytes, unique_content_bytes,
          allocated_object_bytes, accounting_complete, filesystems}
total: 0..10000
offset: 0..9999 (0 for first/empty page)
items: [at most 100 allowlisted records]
```

The provider caps catalog rows and directory entries at 10,000. An oversized
catalog produces `limit-exceeded`, **not a truncated empty/successful catalog**.
An incomplete physical scan can still supply catalog metadata, but cannot supply
an allocated total. At most 100 collections, 16 devices and 256,000 request bytes
are accepted. All integers are bounded to safe JSON integer range. Item text is
bounded and constrained; nested arbitrary metadata is rejected. Unknown fields
are rejected, not persisted. Generic errors contain no submitted values.

Each page repeats identical snapshot metadata. Ordered pages are staged and
become visible only when all expected records arrive. Duplicate identities,
changed headers, gaps, stale timestamps, wrong revisions and replay are rejected.
Publication and previous-snapshot cleanup happen in one database transaction.
At most the last successful snapshot, last completed failure, and one in-progress
snapshot are retained per mirror. A new incomplete upload never hides the last
successful one. Fresh signatures do not allow old snapshots to replace newer ones.
Reports must be at most 300 seconds old (maximum future skew 5 seconds). The job
has a 240-second send-loop budget, connect/read timeouts, no redirects, verified
HTTPS, and disables environment proxy/credential discovery for its HTTP session.
It does not retry uncertain pages; the next invocation scans under a new ID.

## States and freshness

- **Assigned**: existing desired selection, without proof of preparation/serving.
- **Preparing**: a fresh signed observation of the public controller
  `application_preparation()` state `preparing`, with its attempt ID.
- **Starting**: existing fresh beacon role state `starting`; this alone does not
  prove dependency installation or preparation and is not relabeled as preparing.
- **Blocked**: unapproved host identity, fresh blocked/failed role evidence, or a
  fresh failed/uncertain preparation record. Recorded preparation `ready` does not
  independently prove compatibility with the currently selected image.
- **Serving**: selected and approved, current role revision, a successful provider
  readiness observation at most 45 seconds old, and an unexpired lease. The provider
  readiness check includes configured verifier keys, database/store, host/revision
  binding and a fresh scheduler heartbeat. A running process or election is insufficient.
- **Stale**: previously known evidence is too old or belongs to another role revision.
- **Not selected**: role withdrawn; catalog history/bytes retained.

Catalog freshness is 300 seconds. A fresh successful zero-record observation is
an empty catalog; missing reports are unavailable, never an empty store. A failed
fresh observation is unavailable and retains the previous successful catalog.
Silence after success (including an unreachable host) becomes stale. This push
protocol does not claim it can distinguish network failure from a stopped reporting
job; there is no invented "connection succeeded/failed" probe. UI shows timestamps,
old measurements and explicitly unknown current availability. Refresh reads new
cached observations; it does not start a scan or apply host configuration.

## Explicit deployment/configuration handoff (not performed)

Deploy both source versions through reviewed **host-deploy jobs**, run Django
migrations (new app `archive_inventory/0001_initial`), and install the rebuilt
frontend. Archive-mirror remains inside station-access. Preserve persistent data,
venv, database, identity and archive mounts. No whole-application BoxBridge may
stop the shared portal for archive-role withdrawal. Existing per-request role lease
and scoped download authorization remain authoritative; the observer changes none
of the serving/scheduler lifecycle calls or role election rules.

Configure a read-only reporting job on each mirror with access to its existing
provider catalog/configuration and object store, and its **existing approved host
identity**. Do not copy that private key into the web application or share it with
other beaconers. A dedicated observation process/account needs deliberately
provisioned read access; this source pass does not change account/group permissions.
The reporting configuration is a local owner-only (0600) JSON file:

```json
{
  "registry": "https://command-center.example",
  "identity_key": "/approved-host-identify/identity.pem",
  "ca_file": "/trusted-certificate/ca.pem",
  "controller_project": "/explicit/project",
  "application": "station-access"
}
```

`ca_file` is optional (system trust otherwise); certificate verification cannot be
disabled. `controller_project`/`application` are optional; missing/unreadable or
unsupported controller evidence remains unknown. Only `application_preparation()`
is called: never `refresh_application_preparation`, launch, mutation recovery,
stop, deletion or preparation. No arbitrary paths/URLs are accepted from the UI.

Run in the station-access environment with the correct Django settings and
`ARCHIVE_MIRROR_CONFIGURATION`:

```
python manage.py report_archive_inventory --configuration /private/reporting.json
```

A separately authorized host-deploy job can schedule this about every 30 seconds
to keep serving evidence current. Keep it independent of archive role scheduling
so deselection can still report retained data. Before that configuration is applied,
remote inventory remains unknown/stale rather than fabricated. This pass does not
install that job, restart hosts, distribute credentials, or deploy to the compiler.

## Verification boundary

See station-access `verification/archives/results.json` and its test output/layout
screenshots; provider-only results are in evidence/archives-observation-tests.json (retained historical verification; not distributed with the public manual). All new acceptance is **local fixtures**: real Django models/store,
real signature verification and JWT authorization; HTTPS transport is mocked in
the end-to-end reporting test. Chromium renders the built frontend at 320, 390 and
1440 pixels using mocked metadata. No live AWS, real network ingestion, source-built
rootfs or new persistent-service acceptance is claimed. Prior persistent-station
live evidence and host-discover 0.3.4 are preserved, not replaced by these fixtures.
