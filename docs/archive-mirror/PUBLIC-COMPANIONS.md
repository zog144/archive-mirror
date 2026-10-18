# Public host-identify companion review

Archive-mirror 0.4.2 imports `zog.host_identify`. The private historical
`version-share-handoff.json` selected `host-identify@4ea771766df606307769b5f56e22d06296440984`,
but this commit does **not** exist in the new public host-identify repository.
Do not carry that historical revision into the clean public source selector.

A reachable public *candidate*, not yet approved by joint compatibility tests:
`zog144/host-identify@1a5eac0b255c995022db6a3a4c0051efffa748cc`.

Before selecting it for installation:
1. Verify its exact public Git tree and Python namespace.
2. Run archive-mirror JWT, Ed25519, issuer/audience, lease, notice and negative
   authorization tests against the exact installed public component.
3. Prove unchanged fail-closed behavior for missing, expired and wrong-scope
   credentials. Use a disposable SQLite database, isolated state and no live DNS.
4. Record the tested version and source identity in the revised release selector,
   never replace a pinned revision with a moving `unstable` reference.

Source-only publication does not imply that live enrollment, actual archive
serving or host-controller compatibility has been independently accepted.
