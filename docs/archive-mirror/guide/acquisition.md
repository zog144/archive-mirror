# Acquisition, observations and inventory

## Bounded mirror inventory

Archive-mirror's retained objects and catalogue are inspected through read-only, snapshot-bound observations. Station-access's administrator archive listing takes an explicit mirror and snapshot, rather than continuously re-querying or inventing a stable list from a moving directory. Archive object classifications such as source archive and rootfs generation must not be interchanged.

## Evidence and freshness

The metadata API distinguishes complete observations, stale or missing providers, and filtered/paginated results. A page of items is not evidence that the mirror is reachable *now* or that an EC2 host is healthy. Pagination that references an obsolete immutable snapshot must fail/refresh, not silently select a new snapshot mid-list.

## Security boundary

Browser metadata reads require administrator authorization, are bounded and no-store, and do not retrieve arbitrary URLs or grant raw archive-download credentials. The transport and provider integration remain separately authenticated.

## Detailed retained contracts

- [ARCHIVES-OBSERVATIONS.md](../ARCHIVES-OBSERVATIONS.md)
- [REVIEWED-SOURCES.md](../REVIEWED-SOURCES.md)

This chapter synthesizes reader-facing behavior; versioned wire contracts, historical fixture results and source revision limitations remain in the referenced documents. It does not independently certify a deployed service.
