# Artifact-bound notices and export

## Notices bind artifacts rather than filenames

An immutable notice bundle is keyed to collection, artifact SHA-256 and artifact kind. The underlying archive retains its own content identity while canonical notice JSON and the rendered UTF-8 notice text have separate digests. An upstream package with a new archive digest requires independent evidence; notices are never regenerated from today's mutable catalogue to rewrite an older publication.

## Validation and publication

The shared `zog.archive_mirror.notice_contract` validator defines schema-1 canonical encoding and rejects malformed or unsafe records. Import/export and backfill check receipt identity, hashes and bound origin; publication uses atomic content-bound operations that prevent a successful but mismatched replacement from being mistaken for idempotent reuse.

## Trust limits

A notice list demonstrates recorded and validated declarations, not exhaustive license, patch or component review. Archive distribution and generation publication require their own independent approvals. Historical notice fixture acceptance remains evidence for its dated source revision.

## Detailed retained contracts

- [NOTICE-CONTRACT.md](../NOTICE-CONTRACT.md)
- [NOTICE-TEST-RESULTS.md](../NOTICE-TEST-RESULTS.md)

This chapter synthesizes reader-facing behavior; versioned wire contracts, historical fixture results and source revision limitations remain in the referenced documents. It does not independently certify a deployed service.
