# Verification, operations and recovery

## What was exercised

The preserved notice acceptance report records local Django fixtures, source-receipt cross-checks, checksum/size failure handling, atomic publication interruptions, path rejection and bounded metadata pages. Those tests are valuable evidence of contract behavior at a recorded revision—not proof that a production mirror, network route or full rootfs compiler was exercised.

## An operator checks exact identities

For missing catalogue objects, inspect the recorded collection, snapshot ID, artifact digest, notice receipt and original source pin before retrying acquisition or export. A failed request must not relabel a foreign object as accepted. Preserve failed result records and stop if bytes, receipt, original publisher identity or selected authorization no longer agree.

## Recovery and external ownership

Archive-mirror may retain immutable artifacts while station-access only exposes authorized read-only views; a separate host-discover live export can carry non-secret role intent without granting the station web container credential or arbitrary host-directory access. Production deployment and lease rotation have independent acceptance.

## Detailed retained contracts

- [NOTICE-TEST-RESULTS.md](../NOTICE-TEST-RESULTS.md)
- [NOTICE-CONTRACT.md](../NOTICE-CONTRACT.md)
- [ARCHIVES-OBSERVATIONS.md](../ARCHIVES-OBSERVATIONS.md)

This chapter synthesizes reader-facing behavior; versioned wire contracts, historical fixture results and source revision limitations remain in the referenced documents. It does not independently certify a deployed service.
