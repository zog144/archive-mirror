# Unified archive credential provisioning boundary

Archive-mirror uses the approved Zog credential-delivery framework only for
durable cross-host secrets that genuinely require provisioning. **No such
archive-owned secret exists in the current implementation**, so the archive
adapter intentionally enables zero HTTPS delivery purposes.

This is a security boundary, not missing transport code.

## Inventory

Current archive-related credential classes are:

- **Consumer access token** — the existing short-lived
  `zog-archive-jwt-v1` bearer grant. It is issued by the archive authority and
  delivered through the authenticated Host response path. Every use checks the
  configured issuer and audience plus explicit operation, collection and
  expiry. It is not converted to a password or persisted as a provider secret.
- **Token issuer signing private key** — durable authority secret. It must
  remain with the archive token authority and is never provisioned to a mirror.
  Archive-mirror receives only public Ed25519 verification keys.
- **Verification keyring** — public rotatable configuration, not a secret.
- **Upstream collection credential** — not supported today. Both monthly Git
  collection and reviewed exact-source acquisition require credential-free
  HTTPS origins and reject embedded credentials.
- **Provider/service credential** — none. Archive serving does not use a shared
  provider password.
- **TLS private key** — owned by certificate management / HTTPS termination, not
  by archive-mirror.

The same bounded metadata is available with:

```sh
archive-mirror credential-inventory
```

The command never returns token bytes, signing keys, filesystem secret paths or
vault material.

## Common HTTPS framework integration

`zog.host_identify.archive_credentials` is the archive-specific profile
registry. `enabled_https_purposes()` currently returns an empty tuple and
`https_delivery_profile(kind)` rejects every current class.

That means archive-mirror **does not**:

- reuse `issuer-cloudflare-dns01` or another component's purpose;
- add its own HTTP/SSH/socket secret transport;
- turn archive JWTs into long-lived shared passwords;
- install the token authority's signing key;
- accept arbitrary provider credentials in archive configuration.

If a future archive feature genuinely needs a durable cross-host secret, its
source change must add one explicit archive purpose and bind the common HTTPS
request to the exact approved Host/installation identity, provider or collection
role, credential revision, protected archive consumer/destination and allowed
operation. Replay/revocation handling, HTTP-signature verification and protected
local installation remain owned by the shared credential-delivery framework and
root/controller receiver; archive-mirror should supply only the narrow
archive-specific profile.

## Provider lifecycle and withdrawal

Mirror role selection remains independent of credential storage. A withdrawn or
expired role makes serving/discovery fail closed, but retained archive objects,
catalogue rows and pins remain on persistent archive storage.

Short-lived consumer grants remain independently bounded by their own expiry.
Changing the approved Host identity invalidates the current local
candidate/token binding; it does not migrate or refresh a credential implicitly.

## Configuration fail-closed behavior

Archive-mirror configuration is now a closed reviewed schema. Fields named as
passwords, tokens, credentials, signing/private keys or similar secrets are
rejected, including nested source definitions. Provider and issuer origins must
be credential-free HTTPS origins. Current source URLs with embedded
username/password credentials are rejected.

This prevents a future deployment from bypassing the unified credential
framework by putting a durable secret into `configuration.json`.

## Source verification

- archive-mirror: `tests/test_credentials.py` and existing authorization/
  provider-lifecycle tests;
- host-identify: `tests/test_archive_credentials.py`, including role
  withdrawal, expired access grants, incorrect collection scope and Host
  identity changes.

No live provider credential, vault secret, archive role, DNS, service or
production archive state is changed by this source integration.
