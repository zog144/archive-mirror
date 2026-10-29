# Public host-identify companion review

Archive-mirror 0.4.2 imports `zog.host_identify`.

The exact companion selected for the unified archive credential-boundary pass is:

`zog144/host-identify@84f120888801d5c97100714fdb5562fb24e97254`

This revision retains the existing archive JWT verifier and mirror-access
semantics and adds the bounded `zog.host_identify.archive_credentials` policy
registry. It enables **no** durable archive HTTPS credential purpose today.

Joint compatibility requirements:

1. install exactly the pinned public host-identify source;
2. run archive-mirror JWT/Ed25519 issuer/audience/operation/collection tests;
3. run role withdrawal, expiry, wrong-collection and Host-identity-change tests;
4. verify the credential inventory exposes no token/private-key bytes and no
   enabled common-HTTPS purpose;
5. retain fail-closed mirror discovery and persistent archive preservation.

The archive-mirror GitHub workflow checks out and verifies this exact companion
SHA before running the full Django suite, then executes the companion's tests as
well. A successful source CI run does not authorize live credential delivery,
provider mutation, enrollment, DNS or production cutover.
