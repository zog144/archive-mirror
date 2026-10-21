# RETIRED — historical nonpersistent archive template

The accompanying `application.py` is intentionally non-deployable. Its old `regular` execution account predates controller-managed identities, while the current v1 identity contract is for persistent singleton applications. New archive services must use the separate production archive application with its own controller-issued grant. Do not provision a host `regular` user to revive this fixture.

# Box-control integration pass 2 (historical)

The shared station-access design and live persistent-mount acceptance supersede this
standalone proposal. Use the [production archive application](../production/archive-mirror/README.md).
The missing-controller-API findings below describe the pinned pass-2 baseline only.

## Service boundary

`application.py` defines one externally-controlled application runtime with two program
runtimes: `server` (archive-mirror's standalone Django/Waitress HTTP provider) and
`refresh-scheduler`. Both execute the Python installed in the selected immutable generation.
Station-access remains the administrative portal. The host's HTTPS proxy forwards only
archive collection and readiness routes to the loopback provider; TLS keys stay with the
proxy. Existing `integration/nginx.conf` gives those routes. Set
`ARCHIVE_MIRROR_ALLOWED_HOSTS` in both program environments to the actual endpoint hostname
when provisioning the application. Never replace this with a wildcard for convenience.

The declaration is a **template, not a deployable configuration on the current controller**.
Do not register/select it until the mount and API prerequisites below are satisfied. It
intentionally contains no invented mount fields or host-root fallback.

## Controller prerequisites and handoff

Inspected standalone box-control commit: `4947294a5a52affaa5ecb3317018d6665ae5068d`.
Inspected station-access baseline: `c4b3487fbf111eaaba8c7f2b394a185f6c9803a3`.

1. The standalone box-control lacks `cancel_application_launch`. The station-access
   dependency snapshot has a version of that API. Consolidate it into the authoritative
   box-control repository, preserving the latest operation/recovery and retention behavior.
   Cancellation must bind the exact launch request/application, safely cancel unstarted
   work, resolve an accepted runtime after a lost response, and preserve ambiguity instead
   of issuing a new launch. Recovery may need to complete already accepted work; do not
   promise cancellation skips authoritative recovery. Add crash/reboot/expired-evidence
   acceptance tests in that repository. The beacon now rejects a controller missing any
   required lifecycle API before issuing a launch request.
2. Current `mounts` become writable directories under
   `state/mounts/<application>/<runtime>/<program>/<name>`. They cannot represent the
   shared, retained store or live read-only role input required here. Add an explicit,
   operator-provisioned persistent volume facility to box-control/root-control. Bind sources
   and read-only flags into prepared operations and expected launched state; validate paths,
   ownership and observed bindings through the privileged boundary. Support the same
   persistent source for both members, across replacement and reboot. Do not use symlinks
   to escape existing mount validation or modify Zog-owned units outside box-control.

Required bindings (host sources are operator configuration, never heartbeat commands):

| Target in generation | Access | Purpose |
| --- | --- | --- |
| `/var/lib/archive-mirror` | shared read/write | catalogue.sqlite3, store/objects, scheduler state; retained across runtimes |
| `/etc/archive-mirror` | read-only | configuration and public verification keyring |
| `/var/lib/host-discover/credentials` | read-only | live role-intent directory; mount the directory so atomic replacement is visible |

Prefer a dedicated public intent export directory if the volume API can provision it;
the general credential directory also contains a consumer token and must never be
world-readable. Never expose the beacon's private identity directory, central issuer key,
station login export or host filesystem. Account/group mapping must permit only required
reads/writes. The server and scheduler must see the same catalogue and object store.

## Image-build handoff

Run `python3 -B -m zog.archive_mirror.preflight` **inside the candidate generation**, as its
runtime user, before admission. Running it with the host Python proves nothing about that
generation. It imports SSL, SQLite, XZ, Django, Waitress, PyJWT and the identity verifier,
and exercises SQLite, XZ and Ed25519. It does not modify the generation or provision keys.
It checks runtime dependencies, not volume permissions, lease validity or HTTP readiness.

Install archive-mirror and host-identify plus their package dependencies during image-build;
include working Python >=3.12 with `_ssl`, `_sqlite3`, `_lzma`, their native libraries,
trusted CA roots, and Ed25519-capable cryptography. Source refresh additionally needs Git
and its HTTPS dependencies. Install from the declared Python dependency constraints;
record the resolved versions in the generation manifest. Final self-hosted Glibc is not
required merely to test Python: its existing compatible dynamic loader/C library suffice.

Read-only probe on the compiler's previously accepted generation
`4c817d6e7e4e34bf06f9ad3a2c7eee0eafe728ae6126b98e77c50e36d3a63382`:
Python 3.14.7 started inside `RootDirectory` with `ProtectSystem=strict`, private networking,
no new privileges and the station-access user. ELF dependencies include libc.so.6,
libm.so.6, libpython3.14.so.1.0 and /lib64/ld-linux-x86-64.so.2, all within that generation.
The `_ssl` and `_sqlite3` extension modules were absent; Django, Waitress, cryptography,
PyJWT and archive-mirror were absent. This was a Python prerequisite probe, **not** a
box-control lifecycle test. It does not describe any newer image-build generation.

## Staged acceptance after prerequisites

1. Provision a separate test provider/store and migrate its standalone catalogue before
   selecting the role. Check rootfs preflight, exact volume permissions and public-key trust.
2. Configure the adapter only with a compatible controller and supported volume bindings.
   Verify first launch, repeated heartbeats and daemon restart retain one durable request
   and runtime identity. Incomplete observations must block replacement, never imply failure.
3. Validate HTTPS readiness against host UUID/revision, then discovery using `read_access`
   and a full scoped download/checksum. Anonymous/wrong-scope access must fail. Ensure the
   probe reaches the new provider, not the still-running station-access archive endpoint.
4. Withdraw/expire the lease, verify both members stop and archives remain. Exercise lost
   launch responses, uncertain operations, failed stops and reboot with the same bound IDs.
5. Only then cut over the production archive proxy. The current compiler deployment uses
   station-access's database; migrating to the standalone catalogue requires an explicit
   backup/import of archive records, provenance and pins, followed by checksum verification.
   Do not point the standalone provider at an empty database or silently split catalogues.

No active compiler services were replaced or restarted in this pass. The working direct
station-access deployment remains in place. Live lifecycle/discovery acceptance is blocked
on the controller API/volume facilities and generation dependencies above.
