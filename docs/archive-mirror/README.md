# archive-mirror documentation

Reviewed-source acquisition and retention for immutable, externally selected source objects. Image-build chooses the canonical source identity; archive-mirror acquires, verifies, retains and serves the declared bytes.

## Manual chapters

- [Overview and reviewed-source model](guide/reviewed-sources.md) — Ownership, declared source identity, immutable manifests and boundaries of trust.
- [Acquisition, mirroring and retention](guide/acquisition.md) — The acquisition lifecycle, storage and observability used by image-build.
- [Notice and export contracts](guide/notices.md) — Machine-readable notices, export requirements, and failures.
- [Observations, tests and operations](guide/verification.md) — Review, observation, acceptance and troubleshooting references.

- [Credential provisioning boundary](CREDENTIAL-PROVISIONING.md) — Archive secret inventory, short-lived access grants and the zero-enabled-purpose unified HTTPS integration.

## Reference and coverage

The [traceability map](TRACEABILITY.md) accounts for every existing source document. Root `README.md` remains the repository entry point; schema files, acceptance evidence and versioned contracts remain independently addressable. These guide pages organize the material and do not replace the authoritative detailed contracts.
