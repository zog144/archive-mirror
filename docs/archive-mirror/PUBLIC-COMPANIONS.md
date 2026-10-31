# Public host-identify companion review

Archive-mirror 0.4.2 imports `zog.host_identify`.

The exact companion selected for the purpose-scoped archive provider credential
adapter is:

`zog144/host-identify@c33c779acc3fd22f2e60324ecbd4d3baf7107afb`

This revision provides the canonical unified HTTPS credential protocol plus the
archive-specific `archive-mirror-upstream-fetch` profile. The existing
short-lived archive JWT verifier and mirror-access semantics remain separate.

Joint compatibility requirements:

1. install exactly the pinned public host-identify source;
2. run archive-mirror JWT/Ed25519 issuer/audience/operation/collection tests;
3. run provider credential installation, expiry/revocation, wrong collection,
   role withdrawal and Host/role-revision change tests;
4. verify the provider purpose binds exact archive scope while consumer JWTs do
   not use it;
5. verify role withdrawal leaves retained archive contents intact;
6. verify neither repository persists provider secret bytes in nonsecret
   metadata or exposes the archive token issuer signing key.

The archive-mirror GitHub workflow checks out and verifies this exact companion
SHA before running the full Django suite, then executes the companion tests as
well. Source CI does not authorize live credential delivery or provider
activation.

The 2026-10-31 reconciliation adds exact destination-identity checks to archive's private installation record and negative purpose/revision/rotation tests in both source trees. Prior private installation records lacking destination identity must be rejected and re-provisioned under the protected receiver rather than silently adopted.
