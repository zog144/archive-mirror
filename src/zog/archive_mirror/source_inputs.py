"""Populate exact reviewed image-build source bytes into the sources collection."""
import datetime
import hashlib
import json
import os
import re
import tempfile
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import urlsplit
from django.db import transaction
from .config import configuration
from .models import Archive, ReviewedSource, SourcePinSet
from .store import locked, named_lock, open_object, publish, sync_directory

IDENTITY = re.compile(r'[A-Za-z0-9][A-Za-z0-9._-]{0,179}')
LABEL = re.compile(r'[A-Za-z0-9][A-Za-z0-9._+:-]{0,199}')
DIGEST = re.compile(r'[0-9a-f]{64}')

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None

def _text(value, name, optional=False):
    if optional and value in (None, ''):
        return ''
    if not isinstance(value, str) or not LABEL.fullmatch(value):
        raise ValueError('Invalid reviewed source ' + name)
    return value

def _url(value):
    if not isinstance(value, str):
        raise ValueError('Canonical URL required')
    parts = urlsplit(value)
    if parts.scheme != 'https' or not parts.hostname or parts.username or parts.password:
        raise ValueError('Credential-free HTTPS canonical URL required')
    if parts.fragment or parts.query:
        raise ValueError('Canonical URL query/fragment unsupported')
    return value

def decode_manifest(data):
    if not isinstance(data, (bytes, bytearray)) or len(data) > 8 * 1024 * 1024:
        raise ValueError('Invalid reviewed source manifest')
    try:
        value = json.loads(bytes(data))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise ValueError('Invalid reviewed source manifest')
    if not isinstance(value, dict) or set(value) != {'schema','pin_set','date','sources'} or value['schema'] != 1:
        raise ValueError('Unsupported reviewed source manifest')
    identity = value['pin_set']
    if not isinstance(identity, str) or not IDENTITY.fullmatch(identity):
        raise ValueError('Invalid pin-set identity')
    try:
        pin_date = datetime.date.fromisoformat(value['date'])
    except (TypeError, ValueError):
        raise ValueError('Invalid pin-set date')
    if not isinstance(value['sources'], list) or not value['sources'] or len(value['sources']) > 10000:
        raise ValueError('Reviewed sources required')
    sources = []
    declarations = set()
    for item in value['sources']:
        if not isinstance(item, dict) or not {'url','sha256'} <= set(item) or set(item) - {'url','sha256','package','source'}:
            raise ValueError('Invalid reviewed source declaration')
        digest = item['sha256']
        if not isinstance(digest, str) or not DIGEST.fullmatch(digest):
            raise ValueError('Invalid reviewed source digest')
        record = {
            'url': _url(item['url']),
            'sha256': digest,
            'package': _text(item.get('package'), 'package', True),
            'source': _text(item.get('source'), 'source', True),
        }
        key = tuple(record[k] for k in ('url','sha256','package','source'))
        if key in declarations:
            raise ValueError('Duplicate reviewed source declaration')
        declarations.add(key); sources.append(record)
    return identity, pin_date, sources

def _expected(sources):
    return {(x['sha256'],x['url'],x['package'],x['source']) for x in sources}

def _membership(pin_set):
    return set(pin_set.sources.values_list('archive__digest','canonical_url','package','source'))

def _existing(digest):
    archive = Archive.objects.filter(collection='sources', digest=digest).first()
    if not archive:
        return None
    with open_object(digest) as stream:
        if stream.seek(0, 2) != archive.size:
            raise ValueError('Stored reviewed source size mismatch')
        stream.seek(0)
        if hashlib.file_digest(stream, 'sha256').hexdigest() != digest:
            raise ValueError('Stored reviewed source corrupt')
    return archive

def _download_directory():
    root=Path(configuration()['root'])
    root.mkdir(parents=True,exist_ok=True)
    directory=root/'source-downloads'
    if directory.is_symlink():
        raise ValueError('Unsafe source download directory')
    directory.mkdir(exist_ok=True)
    sync_directory(root)
    return directory

def _download(record, opener=None):
    opener = opener or urllib.request.build_opener(NoRedirect())
    maximum = configuration().get('maximum_archive_bytes', 16 * 1024**3)
    directory=_download_directory()
    prefix=record['sha256']+'.'
    for stale in directory.iterdir():
        if stale.name.startswith(prefix) and (stale.is_file() or stale.is_symlink()):
            stale.unlink()
    temporary = tempfile.NamedTemporaryFile(prefix=prefix, dir=directory, delete=False)
    path = Path(temporary.name)
    checksum = hashlib.sha256(); size = 0
    try:
        with temporary:
            request = urllib.request.Request(record['url'], headers={'User-Agent':'zog-archive-mirror/1'})
            try:
                response = opener.open(request, timeout=60)
            except urllib.error.HTTPError as error:
                if 300 <= error.code < 400:
                    raise ValueError('Upstream redirect rejected')
                raise
            with response:
                final = response.geturl()
                if final != record['url']:
                    raise ValueError('Upstream redirect rejected')
                length = response.headers.get('Content-Length')
                if length is not None:
                    try: declared = int(length)
                    except ValueError: raise ValueError('Invalid upstream Content-Length')
                    if declared < 0 or declared > maximum: raise ValueError('Reviewed source too large')
                while True:
                    block = response.read(1024 * 1024)
                    if not block: break
                    size += len(block)
                    if size > maximum: raise ValueError('Reviewed source too large')
                    checksum.update(block); temporary.write(block)
                if length is not None and size != declared:
                    raise ValueError('Upstream size mismatch')
            temporary.flush();os.fsync(temporary.fileno())
        if checksum.hexdigest() != record['sha256']:
            raise ValueError('Reviewed source checksum mismatch')
        return path
    except Exception:
        path.unlink(missing_ok=True)
        raise

def _attach_locked(pin_set, archive, record):
    with transaction.atomic():
        current=SourcePinSet.objects.select_for_update().get(identity=pin_set.identity)
        if current.manifest_sha256 != pin_set.manifest_sha256 or current.pin_date != pin_set.pin_date:
            raise ValueError('Pin-set identity changed during population')
        # Objects first introduced by reviewed-source population are managed.
        # Administrative imports retain their original retention class.
        if archive.provenance.get('reviewed_source') is True and not archive.managed:
            archive.managed=True
            archive.save(update_fields=['managed'])
        ReviewedSource.objects.get_or_create(
            pin_set=current,archive=archive,package=record['package'],
            source=record['source'],canonical_url=record['url'])
    return archive

def _claim_existing(pin_set, record):
    with locked():
        archive=_existing(record['sha256'])
        if archive is None:
            return None
        return _attach_locked(pin_set,archive,record)

def _prepare_pin_set(identity,pin_date,manifest_digest,expected):
    with locked():
        with transaction.atomic():
            pin_set=SourcePinSet.objects.select_for_update().filter(identity=identity).first()
            if pin_set:
                if pin_set.manifest_sha256 != manifest_digest or pin_set.pin_date != pin_date:
                    raise ValueError('Pin-set identity already names different manifest')
            else:
                pin_set=SourcePinSet.objects.create(
                    identity=identity,pin_date=pin_date,manifest_sha256=manifest_digest)
            actual=_membership(pin_set)
            if not actual <= expected:
                raise ValueError('Pin-set membership differs from manifest')
            return pin_set

def populate(path, opener=None):
    data = Path(path).read_bytes()
    identity, pin_date, sources = decode_manifest(data)
    manifest_digest = hashlib.sha256(data).hexdigest()
    expected=_expected(sources)
    with named_lock('source-pin-set',identity):
        pin_set=_prepare_pin_set(identity,pin_date,manifest_digest,expected)
        completed=[]
        for record in sources:
            with named_lock('source-object',record['sha256']):
                archive=_claim_existing(pin_set,record)
                if archive is None:
                    temporary=_download(record,opener)
                    try:
                        archive=publish(temporary,'sources','source',
                            {'reviewed_source':True,'canonical_url':record['url']})
                    finally:
                        temporary.unlink(missing_ok=True)
                    if archive.digest != record['sha256']:
                        raise ValueError('Published reviewed source digest mismatch')
                    with locked():
                        archive=_attach_locked(pin_set,archive,record)
                completed.append(archive)
        with locked():
            with transaction.atomic():
                pin_set=SourcePinSet.objects.select_for_update().get(identity=identity)
                actual=_membership(pin_set)
                if actual != expected:
                    raise ValueError('Pin-set membership differs from manifest')
                pin_set.complete=True
                pin_set.active=True
                pin_set.save(update_fields=['complete','active'])
        return pin_set,completed

def deactivate(identity):
    with named_lock('source-pin-set',identity):
        with locked():
            with transaction.atomic():
                pin_set=SourcePinSet.objects.select_for_update().get(identity=identity)
                if not pin_set.complete:
                    raise ValueError('Incomplete source pin set cannot be released; retry or abandon it')
                pin_set.active=False
                pin_set.save(update_fields=['active'])
                return pin_set

def abandon(identity):
    """Explicitly discard a failed/incomplete population so its objects may be pruned."""
    with named_lock('source-pin-set',identity):
        with locked():
            with transaction.atomic():
                pin_set=SourcePinSet.objects.select_for_update().get(identity=identity)
                if pin_set.complete:
                    raise ValueError('Complete source pin set must be released, not abandoned')
                pin_set.delete()
    return identity
