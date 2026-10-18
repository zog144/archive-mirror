# Reviewed source population

Archive-mirror can preserve exact upstream source objects selected by image-build without
becoming authoritative for source identity. Image-build remains responsible for choosing
the canonical upstream URL and expected SHA-256. Archive-mirror only acquires, verifies,
retains and serves those declared bytes.

## Manifest contract

Use an immutable JSON manifest:

```json
{
  "schema": 1,
  "pin_set": "2026-10",
  "date": "2026-10-01",
  "sources": [
    {
      "package": "example",
      "source": "release",
      "url": "https://upstream.example/example-1.0.tar.gz",
      "sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    }
  ]
}
```

`package` and `source` are optional reporting labels. The URL and SHA-256 are the
reviewed source declaration. URLs must be credential-free HTTPS URLs without query or
fragment components. Archive-mirror does not resolve "latest" names or alter a digest
when upstream content changes.

Population is administrative:

```sh
archive-mirror populate-sources /path/to/image-build-source-pins.json
```

For each declaration, archive-mirror first checks the existing `sources` collection by
SHA-256. A verified hit uses no upstream network. A miss fetches the exact canonical URL,
rejects redirects, enforces the configured maximum object size, calculates SHA-256, and
publishes only when the result equals the declared digest. Publication then uses the
normal object-store staging, fsync, atomic rename and database transaction path.

Concurrent population of the same pin-set identity is serialized. Acquisition of the
same SHA-256 is also serialized across different pin sets, while unrelated source
downloads may proceed concurrently. The global object-store writer lock is held only for
short catalogue/object transitions, not while waiting on upstream network I/O. Store
mutations queue on that lock rather than failing because another local writer is active.

Temporary reviewed-source downloads live outside the published object directory. They
are never catalogue-visible, and retry cleans stale temporary files for the same digest
before fetching it again.

A pin-set identity is immutable with respect to its manifest bytes. Retrying the same
manifest is idempotent. Reusing the identity with different manifest bytes or a different
date fails. The pin set becomes active only after all declarations have matching
catalogue membership.

Population has three durable states:

- incomplete + inactive: retryable work in progress; any completed source memberships
  remain retention-protected across prune so a retry can reuse their verified objects;
- complete + active: the reviewed set is retained normally;
- complete + inactive: the set was explicitly released and no longer protects otherwise
  unreferenced managed objects.

An active incomplete state is forbidden by a database constraint. Re-running
`populate-sources` for a released manifest reactivates that exact manifest.

Release retention explicitly when a completed reviewed set is no longer active:

```sh
archive-mirror release-source-pin-set 2026-10
archive-mirror prune
```

A failed/incomplete population cannot be released, because doing so would silently make
recovery inputs reclaimable. Retry it with the same manifest, or explicitly abandon it:

```sh
archive-mirror abandon-source-pin-set 2026-10
archive-mirror prune
```

Abandonment is accepted only for incomplete sets. It removes their declaration
membership, after which managed objects may be reclaimed if no other snapshot, pin set,
or administrative pin references them.

Managed objects introduced by source population are eligible for pruning only after no
active or incomplete reviewed pin set, monthly snapshot, or administrative pin references
them. Pre-existing manual imports keep their existing retention class.

## Serving

The existing image-build-compatible route remains supported:

```
GET /collections/sources/archives/SHA256.tar.xz
```

A representation-neutral route serves the identical stored bytes:

```
GET /collections/sources/objects/SHA256
```

Both require the existing `download` authorization for collection `sources`, do not
redirect, and return `X-Archive-SHA256`, `Content-Length`, and a digest ETag. The
generic route uses `application/octet-stream`; the old route keeps its existing XZ
content type and filename for compatibility.

The authenticated collection catalogue includes bounded reviewed-source provenance:
pin-set identity, completion/active state, optional package/source labels and the
validated canonical URL. Arbitrary import metadata is still filtered and bearer credentials are never stored
or exposed.

## Redirect policy

Version 1 rejects every upstream redirect. This is deliberate: the reviewed canonical
URL is the only authorized acquisition target. A future redirect policy, if needed for a
specific upstream, should be separately reviewed rather than silently following arbitrary
3xx responses.

## Ownership boundary

- image-build owns reviewed source declarations, source identity and monthly pin exports;
- archive-mirror owns exact acquisition, durable content-addressed storage, pin-set
  retention and authenticated serving;
- build hosts do not need a remote upload API;
- image-build may still fall back to canonical upstream when no ready archive-mirror has
  the object.
