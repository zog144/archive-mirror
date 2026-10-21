"""Verify an explicitly selected version-bound image-build license record against
an exact upstream release tarball. Never import/execute license.py or use HEAD.
Repository exports use the distinct verified producer-sidecar path instead.
"""
import ast
import hashlib
import json
import tarfile
from . import notice_contract as c
from .receipt_notices import safe, MAX_MEMBERS
from .store import open_object


def build(archive, record_path):
    if archive.kind != 'source' or archive.provenance.get('commit'):
        raise ValueError('Release source archive required')
    with open(record_path, 'rb') as stream:
        raw = stream.read(c.MAX_BUNDLE+1)
    if len(raw) > c.MAX_BUNDLE:
        raise ValueError('Record too large')
    try:
        record = json.loads(raw)
    except ValueError:
        record = ast.literal_eval(raw.decode('utf-8'))
    c.exact(record, 'schema package version source status expression scope evidence components patches notes')
    c.exact(record['source'], 'url sha256')
    if type(record['schema']) is not int or record['schema'] != 1 or record['source']['sha256'] != archive.digest:
        raise ValueError('Source version/digest mismatch')
    c.array(record['evidence'], 32)
    expected = {}
    for item in record['evidence']:
        c.exact(item, 'path sha256 source_sha256')
        if item['source_sha256'] != archive.digest or safe(item['path']) in expected:
            raise ValueError('Source evidence mismatch')
        c.pattern(item['sha256'], c.HEX)
        expected[safe(item['path'])] = item['sha256']
    texts, seen, total = {}, set(), 0
    with open_object(archive.digest) as stream:
        if hashlib.file_digest(stream, 'sha256').hexdigest() != archive.digest:
            raise ValueError('Archive corrupt')
        stream.seek(0)
        with tarfile.open(fileobj=stream, mode='r:*') as tar:
            for index, item in enumerate(tar):
                total += max(0, item.size)
                if index >= MAX_MEMBERS or total > 64*1024**3:
                    raise ValueError('Expanded archive too large')
                name = item.name.rstrip('/') if item.isdir() else item.name
                if name in ('.', './') and item.isdir():
                    continue
                name = safe(name)
                if name in seen:
                    raise ValueError('Duplicate member')
                seen.add(name)
                if name in expected:
                    if not item.isfile() or item.size > c.MAX_TEXT:
                        raise ValueError('Unsafe notice text')
                    data = tar.extractfile(item).read(c.MAX_TEXT+1)
                    if c.digest(data) != expected[name]:
                        raise ValueError('Notice text changed')
                    texts[expected[name]] = data.decode('utf-8')
    if not set(expected) <= seen:
        raise ValueError('Missing notice evidence')
    origin = record['source']['url']; issues = list(record['notes'])
    try:
        c.public_origin(origin)
    except ValueError:
        origin=None;issues.append('Public upstream origin unavailable')
    if not texts:
        issues.append('Notice text unavailable')
    exceptions=[]
    for part in record['components'] + record['patches']:
        c.exact(part, 'scope expression status notes')
        exceptions.append(dict(scope=part['scope'],expression=part['expression'],review=part['status'],notes=part['notes'] or None))
    row=dict(package=record['package'],version=record['version'],revision=None,stage=None,source_digest=archive.digest,
        origin=origin,expression=record['expression'],review=record['status'],scope=record['scope'],exceptions=exceptions,
        issues=issues,texts=sorted(texts),receipt_digest=c.digest(raw))
    return c.validate(dict(schema=1,collection=archive.collection,archive_digest=archive.digest,artifact_kind='source',
        source_identity=dict(kind='release-archive',digest=archive.digest,revision=None),generation=None,
        records=[row],texts=texts,coverage='recorded',source_material='unknown' if record['patches'] else 'verified'))
