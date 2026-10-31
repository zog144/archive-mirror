# Public host-identify companion review

Archive-mirror 0.4.2 imports `zog.host_identify`.

The exact companion selected for the purpose-scoped archive provider credential
adapter is:

`zog144/host-identify@7881c116af45286d03f1da4ec70de8668acd52c2`

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
