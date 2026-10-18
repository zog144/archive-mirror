# Production archive-mirror application composition

This is a **parseable** declarative application, not an automatically installed
production service. Pair it with the station-access production web application
in `zog144/station-access/integration/production/station-access/application.py`.
The historical shared-storage acceptance fixture is excluded from this source
export; it cannot provide two independent storage identities.

The separate applications must have **distinct controller-issued storage IDs and execution grants**. The archive application declares `execution_identity="application"`; host-deploy/root-control provisions its protected numeric grant. Preparation, server and scheduler are bound to that one archive grant. No archive program selects `regular`, UID/GID 993, or station-access's grant.
The archive `archive-data` mount is the root of `/var/lib/archive-mirror`;
the catalogue is `/var/lib/archive-mirror/catalogue.sqlite3` and stored bytes
are `/var/lib/archive-mirror/store/objects/<sha256>`. SQLite and archive objects
are imported by the explicit station-access offline two-storage migration tool.
No archive bytes are downloaded again when a matching checkpoint exists. After migration and trusted configuration are staged, run `python -m zog.archive_mirror.storage_ownership bind` as the controller-issued archive identity, supplying the exact protected grant ID/version, numeric UID/GID and archive storage ID from controller evidence. The command never provisions or chowns identities.

The operator must provision the **administrator-owned** host capability policy
at `/etc/zog/host-bindings.json`, with entries only for
`application=archive-mirror`, `program=refresh-scheduler` and
`program=server`, `capability=mirror-live`, with the dedicated
host-discover export source. Both programs require the lease: the server calls
`lease()` for readiness and each authenticated download; the scheduler calls
it each iteration. This is **not** a grant to station-access's web program.
Granting only the scheduler would cause the server to fail closed.
The programs receive only the controller-bound
`/run/zog-host/mirror-live` directory, never identity secrets or
the general credential tree. The operator-owned configuration file inside
archive-data must have `root=/var/lib/archive-mirror/store`,
`intent_file=/run/zog-host/mirror-live/mirror-intent.json`, exact host UUID,
endpoint, issuer, audience and a **public** authorized verification keyring.
Provision that configuration after migration; the verification keyring must be the application-owned `/var/lib/archive-mirror/public-keyring.json` containing public Ed25519 keys only. Never copy a host-discover enrollment/credential keyring, station deployment secrets, private key material or a live lease into archive storage.

The base image must provide Python 3.12+ with ssl/sqlite/lzma, necessary
dependencies, `/usr/bin/true`, and empty mount target directories. Published
immutable application-view digests must be selected and bound by the operator
before preparation: the template intentionally does not invent a software
identity. Call `prepare_application("archive-mirror")`, refresh until ready,
then launch with an explicit idempotent request. A stop/relaunch retains
the same storage ID and objects. Role withdrawal must stop archive serving
and scheduling but must not stop the separate station web application or
reclaim archive-data. React Archives visibility uses station's independent
host archive observations; the legacy same-Django-process optional provider
must be **disabled** in the station production web process.

This is declaration and migration-source acceptance, not a tested production
host cutover. Actual host capability policy, caller UID permissions, runtime
observations, journal and reboot acceptance, authenticated HTTP routing,
and original port-443 writer fence are host-deploy acceptance obligations.

## Execution identity and migration evidence

The archive execution grant must be distinct from station-access's grant, and the archive-data storage ID must be distinct from station-data. Existing archive files are never recursively chowned by archive-mirror. If migrated bytes are not already owned by the exact archive UID/GID, ownership verification blocks and the deployment owner must redo the reviewed migration rather than silently adopt them.

The ownership binder verifies the effective UID/GID, rejects supplementary groups, checks every archive-owned path for matching DAC ownership, validates the migrated catalogue/object/pin state, and writes `.zog-archive-ownership.json` with grant/storage identifiers plus catalogue/object evidence. Root-control's protected execution-identity registry remains authoritative; the marker is recovery evidence only. Run the same module with `verify` after relaunch/reboot.

Mirror-role withdrawal is intentionally outside the storage lifecycle. It may stop serving/scheduling, but it must not delete archive-data, the ownership marker, catalogue, pins or retained objects. Storage deletion/reassignment is a separate controller/host-deploy operation and must not be inferred from lease withdrawal.

## Runtime ownership guard

The production template sets `ARCHIVE_MIRROR_REQUIRE_OWNERSHIP=1` for both
`server` and `refresh-scheduler`. Startup therefore requires a valid
`.zog-archive-ownership.json` and verifies the current effective UID/GID,
absence of unrelated supplementary groups, archive-data top-level DAC, the
controller-scoped mirror intent path, application-owned public keyring and the
immutable migration origin. The server watchdog repeats this guard while
running.

The ownership marker deliberately does **not** record the live catalogue or
object-manifest hashes. Those are mutable archive state and are expected to
change as the mirror retains new objects. A legitimate publication must not
invalidate the durable grant/storage binding.

For a fresh read-only operational observation, run as the archive execution
identity:

```sh
archive-mirror cutover-evidence --root /var/lib/archive-mirror
```

The command takes a shared lock on the existing archive writer lock without
creating it, verifies current ownership plus the entire catalogue/object/pin
state, reports bounded retention counts and reports whether the mirror role is
currently selected. It never prunes, renews a role, changes the ownership
marker or authorizes cutover. Its JSON always contains
`safe_to_cut_over=false`; host-deploy remains the deployment decision owner.

Capture this report at least before role withdrawal, after withdrawal, after
runtime relaunch and after reboot. Archive catalogue/object hashes may differ
after legitimate mirror activity, but the ownership binding must remain
identical and withdrawal itself must not delete retained bytes or pin state.
