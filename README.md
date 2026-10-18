# archive-mirror

**Public development source only.** No live archive objects, issuer secrets,
compiled rootfs releases or downloaded upstream source archives are included.
Third-party dependencies retain their own licenses.

**Documentation:** [Technical manual](docs/archive-mirror/README.md) · [Source traceability](docs/archive-mirror/TRACEABILITY.md). The manual organizes current concepts; linked detailed sources preserve exact contracts and historical evidence.

An immutable local archive store, monthly Git collector, and separate Django
application for station-access. It retains source snapshots and root filesystem
archives for Zog consumers; image-build produces rootfs bytes, the registry grants
access/leases, and host-discover reports provider readiness. This store does not
compile packages or certify a rootfs as release-ready.

Version 0.4.2. Python 3.12+, Linux, Git. Archives remain outside
GitHub and outside runtime generations. This release is a single-provider first
pass; provider discovery does not imply replicated contents.

## Install and integrate

Host-identify is a separately maintained public Zog component imported as `zog.host_identify`.
Use an exact tested companion revision; see [public companion review](docs/archive-mirror/PUBLIC-COMPANIONS.md).
For local source inspection and tests:

```sh
python3.12 -m venv .venv
. .venv/bin/activate
python -m pip install -e .
# Install a separately reviewed compatible host-identify source before integration tests.
```

This checkout is development source, not a deployment bundle or rootfs download.

Current station-access source already contains the optional installed-app and URL
integration. Install this package in its environment, set
`ARCHIVE_MIRROR_CONFIGURATION` to an administrator-owned configuration file, then
run its `python backend/manage.py migrate` from the station-access component
directory with the same persistent state settings as the portal. Legacy station-access integration patches are deliberately excluded from this
public source export. Integrate against current station-access contracts and
verify the exact selected public component revisions.

The catalogue at `/archives/` uses the existing administrator session and shows
100 recent records. It never reveals tokens or gives browser sessions machine
API rights. The existing frontend/navigation is unchanged; link directly to it.
A separate scheduler process uses the same Django settings/database as the portal.

For a standalone provider, set these environment variables:

```sh
export DJANGO_SETTINGS_MODULE=zog.archive_mirror.settings
export ARCHIVE_MIRROR_STATE=/var/lib/archive-mirror
export ARCHIVE_MIRROR_CONFIGURATION=/etc/archive-mirror/configuration.json
export ARCHIVE_MIRROR_ALLOWED_HOSTS=mirror.example.test
archive-mirror migrate
archive-mirror serve --host 127.0.0.1 --port 8080
# Separate supervised process:
archive-mirror scheduler
```

Precreate the state directory with the service account as owner. In integrated
mode use `DJANGO_SETTINGS_MODULE=station_access_project.settings` and the same
environment/database as station-access for the scheduler and all writer commands.
Do not point two databases at one object store. Migrate before launching workers.

Replace every example identity/origin/path in `integration/configuration.example.json`.
The public keyring is exactly the version-1 JSON produced by the registry's
`tools/archive-key.py`. Keep it and configuration administrator-owned. The issuer
private key and beacon private identity directory must never be mounted here.
Grant the service narrowly scoped read access to `mirror-intent.json`, e.g. the
existing archive-consumers group. Never make its directory generally writable.

The first pass uses one service account for collector and Django so published
mode-0600 objects can be read. Public ingress reaches only the HTTPS proxy;
Waitress binds loopback. `integration/nginx.conf.example` shows forwarding inside
an existing TLS server block. Provision certificates separately. No static alias,
CDN or unprotected storage URL may bypass Django authorization. Disable request/
response body and Authorization-header tracing.

## Publication and catalogue

```sh
archive-mirror import /input/root.tar.xz --collection root-filesystems --kind root-filesystem
archive-mirror pin root-filesystems SHA256 build-reference
archive-mirror unpin root-filesystems SHA256 build-reference
archive-mirror populate-sources /path/to/source-pins.json
archive-mirror release-source-pin-set PIN_SET_IDENTITY
# For a failed/incomplete population that should not be retried:
archive-mirror abandon-source-pin-set PIN_SET_IDENTITY
archive-mirror prune
```

Imports are trusted local administrative actions. They copy bytes without executing
or extracting them. The `.tar.xz` representation is a caller contract; arbitrary
input bytes are not certified as a valid, safe-to-extract or bootable filesystem.
Imported root filesystems are marked `release_approved: false`. A partial image-build
archive is useful for byte-transfer tests without requiring a complete rootfs.

Objects live at `ROOT/objects/SHA256`; metadata lives in the Django database.
Collection membership is independent of physical deduplication. Publication uses
a blocking single-host writer lock, staging, SHA-256, file fsync and directory fsync
before the database commit. Failure before commit may leave an unreferenced object, never a published
partial file. `prune` removes unreferenced objects/staging under the same lock.
A missing/corrupt previously stored object is an operational fault, not permission
to substitute newer bytes. Consumers must verify the expected SHA-256 after download.
Filesystem storage and the catalogue need consistent backups: stop writers, finish
publication/pruning, and back up the database and store together.

Do not modify object files in place. Stop all processes before restoring a backup.
Normal concurrent use is one host, one database, one persistent local filesystem;
NFS and multiple independent writers on different hosts are not supported.

## Reviewed source archives

Exact image-build release/source payloads can be populated from a bounded reviewed manifest without uploads from build hosts. See [reviewed source population](docs/archive-mirror/REVIEWED-SOURCES.md). The expected SHA-256 is authoritative; HTTPS upstream redirects, credentials, query strings and mismatched bytes are rejected. Active and incomplete source pin sets protect managed objects from pruning. Completed sets can be released explicitly; failed incomplete sets must either be retried or explicitly abandoned.

## Git collection and retention

Configure `sources` as records such as:

```json
{"name":"example", "url":"https://upstream.example/project.git", "branch":"main"}
```

`archive-mirror refresh` performs one collection pass under a valid provider lease.
The scheduler checks its lease every ten seconds, runs refresh immediately and then
hourly, collecting each configured source at most once in a UTC calendar month.
The first successful publication fixes that month's commit. Failed sources retry
on the next hourly pass. Missed months are not fabricated. Source names are stable
identities; changing a URL/branch does not replace an already successful month.

Each clone is shallow/single-branch/no-tags/no-checkout. Export reads tracked Git
blobs directly (ignores export-ignore/export-subst attributes), with sorted paths,
fixed zero ownership/time, preserved executable modes and symlinks, a stable source
name top directory, PAX tar and XZ preset 6. Recipe `tracked-tree-v1` is recorded. Byte reproducibility assumes the same Python/XZ
implementation; dependency versions used for acceptance are recorded in evidence.
No project scripts run. Submodules and LFS pointers are explicitly rejected.
Non-UTF-8 names fail this first pass. A command has a 300-second deadline; exports
are limited to 100,000 entries, 64 MiB per blob and 2 GiB tracked bytes. Cloning and
compression still need operator-provided disk/memory quotas and free workspace.
Symlinks are preserved as source data, not dereferenced; extraction policy belongs
to the consumer. Credentials embedded in upstream URLs are rejected.

Keep three successful monthly snapshot records per source. Identical trees reuse
an object. Pins retain archive metadata and bytes beyond that limit, but not old
monthly snapshot rows. Manual imports and root filesystems are never automatically
pruned in pass 1. Collection status exposes last attempt/success and sanitized error
class; errors do not replace successful snapshots. No remote pin API exists yet:
protect long-term build inputs administratively before relying on retention.

## HTTP and authorization

- `GET /collections/COLLECTION/`: requires `list`, pages of 100, `?page=N`.
- `GET /collections/COLLECTION/archives/SHA256.tar.xz`: requires `download` (compatibility route).
- `GET /collections/COLLECTION/objects/SHA256`: requires `download`, serves representation-neutral exact bytes.
- `GET /.well-known/zog/archive-mirror/ready`: public nonsecret readiness only.
- `GET /archives/`: station-access superuser catalogue; standalone has no login.

Bearer tokens are validated for every request by the existing host-identify
verifier, with explicit operation and collection, configured issuer/audience and
local Ed25519 public keys. No fallback to sessions/shared secrets or remote key
URLs. Downloads have size, checksum header and immutable digest identity. Headers
include no-store and nosniff. Full streaming downloads only: no Range resume,
remote uploads, release promotion or remote pruning. Each subsequent request must
re-authenticate; a stream admitted before token expiry is allowed to finish while
the provider lease remains active. Revocation remains bounded by token expiry
(900 seconds plus the verifier's five-second tolerance).

Consumers should use `zog.host_identify.mirror_access.read_access`, issue direct HTTPS
requests to its ready candidates, reject redirects and verify checksum/size against
a fixed manifest. Image-build can use the compatibility digest route before falling
back to canonical upstream; archive-mirror remains optional and no build re-resolves
"latest" in this implementation.

## Provider lifecycle

Configure box-control members `server` and `refresh-scheduler` to run the commands
above in a compatible image-build generation. Bind the persistent store and
catalogue read-write, public keyring/configuration read-only, and only the public
intent file read-only. Provision the HTTPS proxy/certificate for the selected
endpoint. This release cannot supply a complete runtime generation; host `/` is
not a supported substitute. Pin a compatible box-control release before deployment.

Lease identity/endpoint/revision are checked; the server watchdog checks every
five seconds, the scheduler every ten. Each protected HTTP request rechecks the
lease. Withdrawal/expiry shuts standalone processes down and kills an active
collection process group. Stored archives survive. In an existing shared
station-access process the archive routes fail closed while the surrounding portal
remains available; do not shut down the whole command center to withdraw a mirror.

Readiness requires valid lease, public keyring, readable catalogue/object directory
and fresh matching scheduler health (maximum 45 seconds). The beacon bridge also
checks required runtime processes. This is not a public Internet reachability test.

## Verification and scope

Run the source-local suites below; these are not live acceptance:

```sh
PYTHONPATH=src:. DJANGO_SETTINGS_MODULE=tests.settings python -m django test tests
PYTHONPATH=. python tests/runtime_acceptance.py
# Patched full registry source tree, with its original companion directories:
python tests/registry_acceptance.py /path/to/registry-source
```

Choose a compatible signed beacon/controller pair and follow host-deploy's
current migration instructions before deploying real beaconers. The historical
acceptance below does not establish compatibility with a newer bundle. AWS acceptance
uses generated local identities, no live command-center enrollment, and no rootfs
runtime. No production registry, DNS, provider election or host approval is changed.
Future passes: rootfs runtime acceptance, richer UI, broader image-build manifest automation,
submodule/LFS Git collection, range downloads, release signatures,
authenticated uploads, and provider replication.

## Box-control preparation

See [production application declaration](integration/production/archive-mirror/README.md).
Historical shared-station deployment scripts and private live acceptance evidence are
excluded from the public tree. Production identity, issuer policy and deployment
acceptance remain separate.

## Source map and interfaces

`src/zog/archive_mirror/store.py` handles immutable objects and pins; `collector.py`
exports tracked Git trees; `runtime.py` supervises server/scheduler lease behavior;
`views.py` enforces HTTP authorization; `models.py` and `migrations/` define catalogue
state. `integration/` holds configuration/proxy/application examples and `tests/`
holds Django and local runtime fixtures. Host-identity is installed from a separately reviewed public source revision; archive bytes and service state belong outside the repository.

The `archive-mirror` console script and `python -m zog.archive_mirror` use the same
CLI. Administrative writers and any direct `zog.archive_mirror.store` calls require
Django initialized with the same settings/database as the serving process.
`python -m zog.archive_mirror.preflight` checks Python/native-library prerequisites;
run it inside a candidate generation, not merely with the host interpreter.

## Administration catalog observations (0.3.0)

The station-access Archives page uses bounded, signed observations of the real catalog
and persistent store. See [the API and reporting contract](docs/archive-mirror/ARCHIVES-OBSERVATIONS.md).
Raw provenance is no longer echoed in the scoped machine catalog. This pass is
observational; no deployment, deletion, approval or lifecycle action is performed.

## Artifact license notices

See [NOTICE-CONTRACT.md](docs/archive-mirror/NOTICE-CONTRACT.md) for immutable source/rootfs evidence,
operator backfill, v1/v2 rollout, scoped APIs, bounds and retention. Local fixtures
only; no deployment or public image distribution is authorized by publication.


