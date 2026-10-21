# Overview and reviewed-source model

## Source identity stays with image-build

Archive-mirror is a preservation and transfer service for source bytes **already selected by image-build**. An immutable source-manifest entry binds canonical HTTPS URL and SHA-256; optional package/source labels aid reporting but cannot override those two fields. A mirror must not resolve an upstream `latest` URL, select a replacement commit, or accept changed bytes simply because an archive URL still responds.

## Validated population and retention

The source-population contract requires credential-free HTTPS origins without query strings or fragment components. Download, checksum validation, cache retention and serving are distinct stages. A local object with the wrong bytes is a fault; a successful mirror fetch changes transport evidence, not the reviewed monthly source identity. Preserve immutable manifest identity and independent retained object hashes.

## Authority and limits

The service cannot promote an archive into a reviewed Zog package, assign a source license or declare a build accepted. Those decisions require the pinned recipe and provenance producer. The documented manifest and authorization rules, not a convenient mirror response, are the source of truth.

## Detailed retained contracts

- [REVIEWED-SOURCES.md](../REVIEWED-SOURCES.md)
- [NOTICE-CONTRACT.md](../NOTICE-CONTRACT.md)

This chapter synthesizes reader-facing behavior; versioned wire contracts, historical fixture results and source revision limitations remain in the referenced documents. It does not independently certify a deployed service.
