# Unified archive credential provisioning

Archive-mirror now has one narrow durable-secret adapter on top of the canonical
Zog HTTPS credential-delivery v1 protocol. It remains strictly separate from the
existing short-lived archive access grants.

## Two separate credential planes

**Archive consumer access grants** remain `zog-archive-jwt-v1` bearer tokens.
They are delivered through the existing authenticated Host response and checked
on each use for issuer, audience, archive operation, collection and expiry.
They are never converted to a long-lived provider password and never use the
provider credential purpose below.

**Archive upstream-provider credentials** use the common HTTPS credential
framework only when archive-mirror needs a durable secret for an approved
upstream provider. The archive-specific profile is:

- consumer: `archive-mirror`
- purpose: `archive-mirror-upstream-fetch`
- scope: `zog-archive-provider-credential-scope-v1`
- provider role: `archive-mirror-provider`
- operation: exactly `fetch`

The scope binds the exact Host ID and HostIdentity fingerprint, installation,
STATE volume, registry, upstream provider ID and credential-free HTTPS origin,
the current archive-mirror provider-role revision, exact sorted collections,
operation, underlying provider credential ID and credential revision.

Host-identify derives the common protocol `credential_id` from SHA-256 of the
nonsecret provider/origin/role/collection/operation/provider-credential scope.
Changing collection, provider origin, role revision, operation or provider
credential identity therefore requires a different common authorization.
Credential rotation advances `credential_revision` without weakening scope.

## Protected local installation

`zog.archive_mirror.provider_credentials.install_verified()` is the
archive-specific installation adapter. The protected common HTTPS receiver must
first verify the Credential Authority signature and pin, HostIdentity-signed
request, nonce/replay ledger, authorization state and signed delivery. The
archive adapter then:

1. revalidates the exact archive scope against the canonical request/delivery;
2. requires the current archive-mirror provider lease to match Host and exact
   role revision;
3. writes the opaque provider secret only to
   `ROOT/provider-credentials/` under a service-owned `0700` directory and a
   `0600`, single-link, non-symlink secret file;
4. persists only secret-free installation metadata and a crash-recovery pending
   marker;
5. supports idempotent replay of the exact same verified delivery and
   higher-revision rotation;
6. returns only secret-free installation evidence for the common receiver to
   correlate with its signed installation receipt.

The common receiver still owns HTTPS, authority signature verification,
anti-replay/revocation state and the canonical signed installation receipt.
Archive-mirror does not open a second network secret endpoint.

`open_for(scope, operation="fetch", collection=...)` returns a protected file
descriptor only when the installed scope, current provider-role lease,
collection and operation all still match. It never selects a path from caller
input.

## Withdrawal and persistence

Archive provider-role withdrawal or revision/Host identity change immediately
makes `open_for` fail closed. The credential file is not treated as permission
by itself.

Role withdrawal does **not** delete retained archive objects, pins, reviewed
source memberships or catalogue history. A separately authorized credential
revocation/removal workflow may delete or rotate the provider secret without
touching retained archive contents.

The private provider credential directory is persistent application state, so a
valid installed credential survives ordinary archive-mirror restart/reboot.
Its use still requires a current matching provider lease after restart.

## Secrets that never move here

- The archive token issuer's signing private key is never provisioned to a
  mirror; mirrors receive public verification keys only.
- TLS private keys remain owned by certificate/HTTPS termination.
- Provider secret bytes are never accepted in `configuration.json`, upstream
  URLs, argv, journals, browser/session responses or archive JWT records.
- Current Git/reviewed-source fetch code remains credential-free until a
  provider-specific acquisition adapter explicitly consumes `open_for`.

`archive-mirror credential-inventory` reports only the nonsecret policy and
enabled purpose; it never reports an installed provider secret or secret path.

## Source verification

`tests/test_provider_credentials.py` covers private installation, exact
collection/operation checks, role withdrawal with retained archive contents,
Host/role revision changes, expiry/revocation, idempotent replay, rotation and
secret-free inspection. Host-identify's `tests/test_archive_credentials.py`
covers the corresponding common-protocol scope and authorization binding.

This pass changes source only. No live credential, provider, archive role,
network endpoint or production archive state is mutated.

### Reconciliation: installation-record schema v2

Private provider installation evidence now records the **exact canonical destination**:
Host ID, HostIdentity fingerprint, installation ID, STATE volume ID and registry
ID, in addition to provider/collection/purpose/role and revision. The private
installation and pending schemas are v2. Changes in those identities block
`open_for`, inspection and attempted credential rotation even when the
provider's scope-derived credential ID remains unchanged. A legacy v1
installation record must be reprovisioned by the protected receiver under
reviewed authority; it is never silently upgraded or adopted. This does not
delete retained archive content or pin metadata.
