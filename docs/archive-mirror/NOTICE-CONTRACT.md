# Artifact-bound notices — pass 1 (2026-09-30)

Archive-mirror 0.4.0 and station-access 0.4.16 implement local source/archive notices.
This pass neither distributes images publicly nor starts monthly catalogue builds.
It does not deploy, restart services, change DNS, or authorize a release.

## Identities and trust

An immutable notice bundle describes `(collection, archive_digest, artifact_kind)`.
The archive digest continues to identify the **unchanged archive bytes**. A separate
SHA256 identifies canonical notice JSON; another identifies the rendered UTF-8
notice document. Publication never rewrites an older artifact's claims from a live
catalogue. Same-name/new-version archives receive independent bindings.

The pure-stdlib `zog.archive_mirror.notice_contract` module is the authoritative shared
producer/receiver validator. Canonical JSON uses sorted keys, compact separators,
ASCII escapes, UTF-8 encoding. Schema 1 has exactly these top-level fields:

| Field | Meaning |
| --- | --- |
| schema | Integer 1 |
| collection / archive_digest | Configured collection identifier / SHA256 of stored archive |
| artifact_kind | `source` or `root-filesystem` |
| source_identity | Exactly `kind`, `digest`, `revision`. Kind is `release-archive`, `repository-export`, or `root-filesystem`; digest equals the archive digest. Only repository exports have a 40/64-hex revision. |
| generation | Recorded generation label or null; this is operator-supplied metadata, not a release approval or independently verified generation manifest. |
| records | Bounded package attributions, described below |
| texts | SHA256 → exact UTF-8 text; identical texts occur once, all attributions remain |
| coverage | `unknown`, `unresolved`, or `recorded`; recorded describes evidence coverage, not release eligibility |
| source_material | `unknown`, `missing`, or `verified`, independently from notice availability |

Each record has exactly `package`, `version`, `revision`, `stage`, `source_digest`,
`origin`, `expression`, `review`, `scope`, `exceptions`, `issues`, `texts`, and
`receipt_digest`. Version or exact revision is required. Stage distinguishes tools,
sysroot and final installations of the same package/version. Source digest identifies
that package's build input, not the rootfs digest. Null fields mean unknown; no
upstream license is inferred. Review is `unknown`, `declared`, `reviewed`, or
`unresolved`. A reviewed record must include expression, notice references, and a
source digest. Exceptions each contain `scope`, `expression`, `review`, `notes`.
Issues and exceptions preserve scoped upstream/patch concerns. Texts are digest
references. Receipt digest identifies the exact retained image-build record.json,
or the explicitly selected source metadata file; it is null for a standalone
producer-supplied bundle without an external record. Rootfs receipts remain in
the immutable rootfs archive; source metadata is projected into the immutable
bundle rather than copied as executable Python.

Limits: 512 KiB canonical bundle/request, 128 records, 256 distinct texts, 64 KiB
UTF-8 per text, 32 exceptions/issues/text references per record, 1 MiB rendered
notice document. Records include bounded individual strings (validator is normative).
Unknown fields and duplicate JSON keys are rejected. Larger evidence is **blocked**,
not truncated; a future reviewed schema/limit change is needed for larger images.

Only explicitly reviewed public metadata belongs in `origin`/record annotations.
Origins must be credential-free HTTPS public-style DNS URLs without query or fragment;
local/private origins are dropped by the receipt adapter with an explicit issue.
No URL is fetched. Arbitrary archive provenance, image-build recipes, host paths,
keys and download credentials are never copied. License text is inert plain text.
Do not put private data in producer-supplied public annotations or legal texts.

Zog's selected BSD-3-Clause OR GPL-3.0-only policy applies to its original material.
Missing third-party metadata never falls back to those terms.

## Import, export and backfill

Local operator commands, using the existing mirror configuration and database:

```
archive-mirror import SOURCE.tar.xz --collection sources --kind source --source-record exact-version-license.py
archive-mirror import SOURCE.tar.xz --collection sources --kind source --license-sidecar reviewed-bundle.json
archive-mirror import ROOTFS.tar.xz --collection root-filesystems --kind root-filesystem --rootfs-receipts --generation GENERATION
archive-mirror notices sources ARCHIVE_SHA256 --sidecar reviewed-bundle.json
archive-mirror notices root-filesystems ARCHIVE_SHA256 --rootfs-receipts --generation GENERATION --retained-inputs /operator/selected/release-inputs
```

For upstream release tarballs, `--source-record` consumes an explicitly selected
image-build literal license.py (or equivalent JSON). It never executes Python. The
record source hash must match the actual archive, and each retained evidence path
and digest is checked inside that tar without extraction. This is the preferred
path when version-bound package metadata is available. It is not valid for a
monthly repository export with a different byte identity.

Source sidecars are explicitly supplied, producer-reviewed records containing the
exact archive SHA256 and verified text hashes. The importing operator is the trust
boundary for these assertions; hashing alone does not independently validate the
legal interpretation or authenticate a third-party publisher. Remote upload is
subsequently authenticated with the approved host key. No sidecar is discovered at
an arbitrary URL and no current catalogue metadata is silently substituted.

Monthly repository source definitions can optionally specify a local
`license_sidecar` path. The collector applies it to the exported archive (including
an existing same-month export). Its identity must be `repository-export` with the
exact recorded commit **and** exported tar digest. A release tarball uses
`release-archive`; a commit is never equated to that tarball's digest. The explicit
`notices` command supports backfill after the export digest is known. Without
reviewed evidence, the export remains usable and has missing license evidence.

The image-build adapter reads only actual `record.json` receipts in the selected
stored tar and retained texts under `[sysroot/|tools/]usr/share/licenses/zog-packages/`.
It verifies the archive, record identity, source membership, evidence paths and
text hashes. It does not extract tar entries into the filesystem or follow links.
Tar limits are 200,000 members and 64 GiB declared expanded size; duplicate/unsafe
member paths fail closed. Receipts rooted under an extra wrapper directory must
first be exported in the documented root-relative format. LF and CRLF notice line endings are preserved byte-for-byte. Non-UTF-8 notices are
blocked rather than silently transcoded or dropping original bytes.

The aggregate deterministically sorts package index entries and text hashes,
includes full text once per hash, and keeps every attribution, scoped exception and
issue. The adapter **always** reports inherited/seed coverage unresolved: it is not
image-build's offline release checker. With no retained-input directory, source
availability is unknown; an explicit local directory verifies every receipt source
hash, reporting missing/corrupt inputs separately. Historical images without
receipts stay missing/unavailable, never retroactively declared reviewed.

Archive publication precedes optional evidence ingestion. If evidence fails, the
archive may already be present; the command returns failure and backfill can resume
using its digest. There is no misleading empty successful notice binding.

## Durability, collisions and retention

A complete canonical bundle is one immutable file in `root/notices/`, named by
collection plus archive digest. All publication takes the existing writer lock,
rehashes the stored archive, fsyncs a staging file, links it without replacement,
and fsyncs the notice directory. There is no split database/blob commit. Reads use
no-follow directory/file opens and check identity and hashes.

Before publication, interruption leaves only harmless staging data. After atomic
publication, a retry validates the identical file and synchronizes the directory.
Different evidence for an existing binding is blocked; corrupt/symlink evidence is
reported broken, never overwritten. Conflict/corruption resolution is a separate
explicit workflow, not a force flag. Missing files can be backfilled idempotently.

Existing archive/snapshot retention and pins are unchanged. Notices are not pruned
in this pass, including when an archive record is removed and later reimported.
Pinned artifacts retain both content and their notice sidecars. Orphan notice
cleanup and central cache eviction require a separate explicit retention policy.
No image-build source inputs are deleted. Object allocation metrics remain **object
blocks only**; filesystem usage naturally also includes notice storage.

## Mirror API

Existing list/download URLs and lease/collection authorization are preserved.
`GET /collections/C/` defaults to catalogue version 1. `?version=2` adds the compact
`licenses` summary. Observation `observe(version=1)` also defaults to v1;
`observe(version=2)` adds exactly the same per-item summary. No full text appears
in list observations. Summary fields are exactly `state`, `review`, `bundle_digest`,
`notice_digest`, `notice_bytes`, `package_count`, `issue_count`, `coverage`,
`source_material`. States: available, missing (observed absence), broken (verification
failure), unavailable (unknown/legacy). Unknown counts/digests are null, not zero.

`GET /collections/C/archives/SHA256/notices/` requires the existing download grant
for C and a current serving lease. Default metadata uses `offset=0&limit=25`
(maximum 25, offset ≤128), with `records`, `summary`, and nullable `next_offset`.
`?format=text` returns the bounded UTF-8 aggregate as a `.txt` attachment. Responses
are no-store/nosniff; text has sandbox/default-src-none CSP. Extra parameters,
including URL/path parameters, are rejected. Missing evidence is 404; invalid
stored evidence/service state fails closed. Browser admin status alone does not
satisfy this mirror download authorization.

See the station-access notice handoff for the compatible receiver rollout and
administrator-only portal cache, which never stores mirror bearer tokens.
