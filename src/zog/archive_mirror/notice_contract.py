"""Version 1 artifact-bound notices. Pure stdlib, shared by producer and receiver.

A verified digest binds evidence, not legal approval. Never infer a package license.
"""
import hashlib
import json
import re
from urllib.parse import urlsplit

MAX_BUNDLE = 524288
MAX_TEXT = 65536
MAX_RECORDS = 128
MAX_DOCUMENT = 1048576
HEX = r'[0-9a-f]{64}'


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()


def digest(data):
    return hashlib.sha256(data).hexdigest()


def exact(value, fields):
    if not isinstance(value, dict) or set(value) != set(fields.split()):
        raise ValueError('Invalid notice fields')


def string(value, maximum=512, nullable=False):
    if nullable and value is None:
        return
    if not isinstance(value, str) or not value or len(value.encode('utf-8')) > maximum or any(ord(c) < 32 and c not in '\r\n\t' for c in value):
        raise ValueError('Invalid notice string')


def pattern(value, regex):
    if not isinstance(value, str) or not re.fullmatch(regex, value):
        raise ValueError('Invalid notice identity')


def array(value, maximum):
    if not isinstance(value, list) or len(value) > maximum:
        raise ValueError('Notice limit exceeded')


def public_origin(value):
    if value is None:
        return
    string(value, 512)
    url = urlsplit(value)
    # Explicitly reviewed public metadata only; reject opaque paths and credentials.
    if url.scheme != 'https' or not url.hostname or url.username or url.password or url.query or url.fragment or url.port not in (None, 443) or '\\' in value or any(c.isspace() for c in value):
        raise ValueError('Invalid public origin')
    if not re.fullmatch(r'[A-Za-z0-9.-]+', url.hostname) or '.' not in url.hostname or url.hostname.endswith(('.local', '.internal')) or re.fullmatch(r'[0-9.]+', url.hostname):
        raise ValueError('Invalid public origin')


def validate(value):
    if len(canonical(value)) > MAX_BUNDLE:
        raise ValueError('Notice bundle too large')
    exact(value, 'schema collection archive_digest artifact_kind source_identity generation records texts coverage source_material')
    if type(value['schema']) is not int or value['schema'] != 1:
        raise ValueError('Unsupported notice schema')
    pattern(value['collection'], r'[a-z0-9][a-z0-9_-]{0,63}')
    pattern(value['archive_digest'], HEX)
    if value['artifact_kind'] not in ('source', 'root-filesystem'):
        raise ValueError('Invalid artifact kind')
    identity = value['source_identity']
    exact(identity, 'kind digest revision')
    if identity['kind'] not in ('release-archive', 'repository-export', 'root-filesystem') or identity['digest'] != value['archive_digest']:
        raise ValueError('Source identity mismatch')
    if identity['kind'] == 'repository-export':
        pattern(identity['revision'], r'[0-9a-f]{40}|[0-9a-f]{64}')
    elif identity['revision'] is not None:
        raise ValueError('Unexpected source revision')
    if (value['artifact_kind'] == 'root-filesystem') != (identity['kind'] == 'root-filesystem'):
        raise ValueError('Artifact identity mismatch')
    if value['generation'] is not None:
        pattern(value['generation'], r'[A-Za-z0-9][A-Za-z0-9._+-]{0,127}')
    if value['coverage'] not in ('unknown', 'unresolved', 'recorded') or value['source_material'] not in ('unknown', 'missing', 'verified'):
        raise ValueError('Invalid coverage')
    if not isinstance(value['texts'], dict) or len(value['texts']) > 256:
        raise ValueError('Invalid texts')
    for sha, content in value['texts'].items():
        pattern(sha, HEX); string(content, MAX_TEXT)
        if digest(content.encode()) != sha:
            raise ValueError('Notice text digest mismatch')
    array(value['records'], MAX_RECORDS)
    if not value['records']:
        raise ValueError('Missing records')
    used = set()
    identities = set()
    for record in value['records']:
        exact(record, 'package version revision stage source_digest origin expression review scope exceptions issues texts receipt_digest')
        pattern(record['package'], r'[A-Za-z0-9][A-Za-z0-9._+-]{0,127}')
        string(record['version'], 128, nullable=True)
        if record['revision'] is not None:
            pattern(record['revision'], r'[0-9a-f]{40}|[0-9a-f]{64}')
        if record['version'] is None and record['revision'] is None:
            raise ValueError('Missing package version or revision')
        if record['stage'] is not None:
            pattern(record['stage'], r'[A-Za-z0-9][A-Za-z0-9._+:-]{0,159}')
        if record['source_digest'] is not None:
            pattern(record['source_digest'], HEX)
        public_origin(record['origin']); string(record['expression'], 256, nullable=True)
        if record['review'] not in ('unknown', 'declared', 'reviewed', 'unresolved'):
            raise ValueError('Invalid review')
        string(record['scope'], 512)
        array(record['exceptions'], 32); array(record['issues'], 32); array(record['texts'], 32)
        for item in record['exceptions']:
            exact(item, 'scope expression review notes')
            string(item['scope']); string(item['expression'], 256, nullable=True); string(item['notes'], 2048, nullable=True)
            if item['review'] not in ('unknown', 'declared', 'reviewed', 'unresolved'):
                raise ValueError('Invalid exception review')
        for issue in record['issues']:
            string(issue, 2048)
        for sha in record['texts']:
            pattern(sha, HEX)
            if sha not in value['texts']:
                raise ValueError('Missing notice text')
            used.add(sha)
        if len(set(record['texts'])) != len(record['texts']):
            raise ValueError('Duplicate text reference')
        if record['receipt_digest'] is not None:
            pattern(record['receipt_digest'], HEX)
        if record['review'] == 'reviewed' and (not record['expression'] or not record['texts'] or not record['source_digest']):
            raise ValueError('Reviewed record lacks evidence')
        key = (record['package'], record['version'], record['revision'], record['stage'], record['scope'])
        if key in identities:
            raise ValueError('Duplicate attribution')
        identities.add(key)
    if used != set(value['texts']):
        raise ValueError('Unattributed text')
    if len(document(value)) > MAX_DOCUMENT:
        raise ValueError('Aggregate too large')
    return value


def document(value):
    lines = ['License / notice evidence — not release approval',
             'Collection: ' + value['collection'], 'Archive SHA256: ' + value['archive_digest'],
             'Artifact: ' + value['artifact_kind'], 'Generation: ' + (value['generation'] or 'unknown'),
             'Coverage: ' + value['coverage'], 'Retained source material: ' + value['source_material'], '', 'PACKAGE INDEX']
    for row in sorted(value['records'], key=lambda r: (r['package'], r['version'] or '', r['revision'] or '', r['stage'] or '', r['scope'])):
        lines += ['', row['package'] + ' ' + (row['version'] or row['revision']),
                  'Stage: ' + (row['stage'] or 'unknown'), 'Source SHA256: ' + (row['source_digest'] or 'unknown'),
                  'Origin: ' + (row['origin'] or 'unknown'), 'Scope: ' + row['scope'],
                  'License: ' + (row['expression'] or 'unknown'), 'Review: ' + row['review']]
        for part in row['exceptions']:
            lines += ['Exception/component: ' + part['scope'] + ' | ' + (part['expression'] or 'unknown') + ' | ' + part['review'], part['notes'] or '']
        lines += ['Issue: ' + issue for issue in row['issues']]
        lines += ['Notice SHA256: ' + sha for sha in row['texts']]
        if not row['texts']:
            lines += ['Notice text unavailable']
    for sha, content in sorted(value['texts'].items()):
        lines += ['', 'FULL NOTICE SHA256: ' + sha, content]
    return ('\n'.join(lines) + '\n').encode('utf-8')


def summary(value):
    validate(value)
    reviews = {r['review'] for r in value['records']} | {p['review'] for r in value['records'] for p in r['exceptions']}
    issues = sum(len(r['issues']) for r in value['records'])
    review = 'unresolved' if value['coverage'] != 'recorded' or issues or 'unresolved' in reviews else ('unknown' if 'unknown' in reviews else ('declared' if 'declared' in reviews else 'reviewed'))
    return dict(state='available', review=review, bundle_digest=digest(canonical(value)), notice_digest=digest(document(value)), notice_bytes=len(document(value)), package_count=len(value['records']), issue_count=issues, coverage=value['coverage'], source_material=value['source_material'])


def unavailable(state='unavailable'):
    return dict(state=state, review='unknown', bundle_digest=None, notice_digest=None, notice_bytes=None, package_count=None, issue_count=None, coverage='unknown', source_material='unknown')


def validate_summary(value):
    exact(value, 'state review bundle_digest notice_digest notice_bytes package_count issue_count coverage source_material')
    if value['state'] not in ('available', 'unavailable', 'missing', 'broken'):
        raise ValueError('Invalid notice availability')
    if value['state'] != 'available':
        if value != unavailable(value['state']):
            raise ValueError('Invalid unavailable evidence')
        return
    for field in ('bundle_digest', 'notice_digest'):
        pattern(value[field], HEX)
    for field, maximum in [('notice_bytes', MAX_DOCUMENT), ('package_count', MAX_RECORDS), ('issue_count', MAX_RECORDS*32)]:
        if type(value[field]) is not int or not 0 <= value[field] <= maximum:
            raise ValueError('Invalid notice count')
    if value['review'] not in ('unknown', 'declared', 'reviewed', 'unresolved') or value['coverage'] not in ('unknown', 'unresolved', 'recorded') or value['source_material'] not in ('unknown', 'missing', 'verified'):
        raise ValueError('Invalid notice summary')


def decode(data):
    if len(data) > MAX_BUNDLE:
        raise ValueError('Notice bundle too large')
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError('Duplicate JSON key')
            result[key] = value
        return result
    return validate(json.loads(data, object_pairs_hook=unique))
