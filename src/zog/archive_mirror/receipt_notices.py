"""Read exact image-build receipts from a stored tar without filesystem extraction.

This is evidence ingestion, not a release checker. Coverage remains unresolved:
receipt attribution alone cannot prove ownership of inherited/seed image content.
"""
import hashlib
import json
import re
import tarfile
from pathlib import Path, PurePosixPath
from . import notice_contract as c
from .store import open_object

RECEIPT = re.compile(r'(?:sysroot/|tools/)?usr/share/licenses/zog-packages/[A-Za-z0-9._+-]+/record.json')
MAX_MEMBERS = 200000


def safe(name):
    if name.startswith('./'):
        name = name[2:]
    if not name or name.startswith('/') or '\\' in name or any(x in ('', '.', '..') for x in name.split('/')):
        raise ValueError('Unsafe archive member')
    return name


def build(archive, generation, retained_inputs=None):
    if archive.kind != 'root-filesystem':
        raise ValueError('Root filesystem required')
    with open_object(archive.digest) as stream:
        if hashlib.file_digest(stream, 'sha256').hexdigest() != archive.digest:
            raise ValueError('Archive digest mismatch')
        stream.seek(0)
        with tarfile.open(fileobj=stream, mode='r:*') as tar:
            members = {}
            expanded_size = 0
            for index, member in enumerate(tar):
                if index >= MAX_MEMBERS:
                    raise ValueError('Too many archive members')
                expanded_size += max(0, member.size)
                if expanded_size > 64*1024**3:
                    raise ValueError('Expanded archive too large')
                name = member.name.rstrip('/') if member.isdir() else member.name
                if name in ('.', './') and member.isdir():
                    continue
                name = safe(name)
                if name in members:
                    raise ValueError('Duplicate archive member')
                members[name] = member
            def content(name, maximum):
                item = members[safe(name)]
                if not item.isfile() or item.size > maximum:
                    raise ValueError('Invalid retained evidence')
                return tar.extractfile(item).read(maximum+1)
            receipts = sorted(n for n in members if RECEIPT.fullmatch(n))
            if not receipts:
                raise ValueError('License receipts unavailable')
            if len(receipts) > c.MAX_RECORDS:
                raise ValueError('Too many receipts')
            records, texts, sources = [], {}, set()
            for path in receipts:
                raw = content(path, c.MAX_BUNDLE)
                receipt = json.loads(raw)
                record = receipt['record']
                # image-build identity uses ASCII canonical JSON.
                if receipt['schema'] != 1 or receipt['record_identity'] != c.digest(c.canonical(record)):
                    raise ValueError('Receipt identity mismatch')
                c.exact(record, 'schema package version source status expression scope evidence components patches notes')
                if record['schema'] != 1:
                    raise ValueError('Unsupported receipt')
                declared_sources = {source['sha256'] for source in receipt['sources']}
                if not declared_sources or record['source']['sha256'] not in declared_sources:
                    raise ValueError('Source receipt mismatch')
                evidence = receipt['evidence']
                c.array(evidence, 32)
                if len(evidence) != len(record['evidence']):
                    raise ValueError('Receipt evidence mismatch')
                references = []
                base = path.rsplit('/', 1)[0]
                for original, retained in zip(record['evidence'], evidence):
                    c.exact(original, 'path sha256 source_sha256')
                    if any(retained.get(k) != v for k, v in original.items()):
                        raise ValueError('Receipt evidence changed')
                    if original['source_sha256'] not in declared_sources:
                        raise ValueError('Unretained evidence source')
                    c.pattern(original['sha256'], c.HEX); c.pattern(original['source_sha256'], c.HEX)
                    expected = base + '/texts/' + original['source_sha256'] + '/' + safe(original['path'])
                    if retained['installed_path'] != expected:
                        raise ValueError('Evidence path mismatch')
                    data = content(expected, c.MAX_TEXT)
                    if c.digest(data) != original['sha256']:
                        raise ValueError('Retained text changed')
                    texts[original['sha256']] = data.decode('utf-8')
                    references.append(original['sha256'])
                # Project only the reviewed public fields, never recipe/host paths.
                origin = record['source']['url']
                issues = list(record['notes'])
                try:
                    c.public_origin(origin)
                except ValueError:
                    origin = None
                    issues.append('Public upstream origin unavailable')
                issues.append('Inherited/seed file coverage has not been verified by this notice importer')
                if receipt.get('unreviewed_sources'):
                    issues.append('Additional source inputs have unresolved license review')
                if not references:
                    issues.append('Retained notice text unavailable')
                exceptions = []
                for part in record['components'] + record['patches']:
                    c.exact(part, 'scope expression status notes')
                    exceptions.append(dict(scope=part['scope'], expression=part['expression'], review=part['status'], notes=part['notes'] or None))
                for source in receipt['sources']:
                    c.pattern(source['sha256'], c.HEX)
                    sources.add(source['sha256'])
                stage = ('sysroot:' if path.startswith('sysroot/') else ('tools:' if path.startswith('tools/') else '')) + base.rsplit('/',1)[1]
                records.append(dict(package=record['package'], version=record['version'], revision=None, stage=stage, source_digest=record['source']['sha256'], origin=origin,
                    expression=record['expression'], review=record['status'], scope=record['scope'], exceptions=exceptions,
                    issues=issues, texts=sorted(set(references)), receipt_digest=c.digest(raw)))
    material = 'unknown'
    if retained_inputs is not None:
        material = 'verified'
        for sha in sorted(sources):
            path = Path(retained_inputs)/sha
            # Only local operator-specified retention root, never an uploaded path.
            if path.is_symlink() or not path.is_file():
                material = 'missing'; continue
            with path.open('rb') as stream:
                if hashlib.file_digest(stream, 'sha256').hexdigest() != sha:
                    material = 'missing'
    return c.validate(dict(schema=1, collection=archive.collection, archive_digest=archive.digest,
        artifact_kind='root-filesystem', source_identity=dict(kind='root-filesystem', digest=archive.digest, revision=None),
        generation=generation, records=records, texts=texts, coverage='unresolved', source_material=material))
