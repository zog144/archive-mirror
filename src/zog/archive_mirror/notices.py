"""Immutable sidecars, published under the archive writer lock.

One atomic file is the entire binding; no split DB/blob commit to recover. Orphan
staging files are harmless. Existing claims are never replaced, including after
archive pruning/reimport. Notice retention is deliberately independent of prune.
"""
import hashlib
import os
import stat
import tempfile
from pathlib import Path
from . import notice_contract as contract
from .config import configuration
from .store import locked, open_object, sync_directory


def filename(archive):
    contract.pattern(archive.collection, r'[a-z0-9][a-z0-9_-]{0,63}')
    contract.pattern(archive.digest, contract.HEX)
    return archive.collection + '-' + archive.digest + '.json'


def read(archive):
    directory = os.open(Path(configuration()['root'])/'notices', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        fd = os.open(filename(archive), os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory)
    finally:
        os.close(directory)
    with os.fdopen(fd, 'rb') as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise ValueError('Unsafe notice object')
        value = contract.decode(stream.read(contract.MAX_BUNDLE+1))
    matches(archive, value)
    return value


def matches(archive, value):
    if (value['collection'], value['archive_digest'], value['artifact_kind']) != (archive.collection, archive.digest, archive.kind):
        raise ValueError('Notice binding mismatch')
    commit = archive.provenance.get('commit')
    if commit and (value['source_identity']['kind'] != 'repository-export' or value['source_identity']['revision'] != commit):
        raise ValueError('Repository revision mismatch')
    if value['source_identity']['kind'] == 'repository-export' and not commit:
        raise ValueError('Missing export revision evidence')


def publish(archive, value):
    contract.validate(value); matches(archive, value)
    data = contract.canonical(value)
    with locked() as root:
        # Backfill checks the actual stored bytes, not just a database name.
        with open_object(archive.digest) as source:
            if hashlib.file_digest(source, 'sha256').hexdigest() != archive.digest:
                raise ValueError('Archive corrupt')
        directory = root/'notices'
        if directory.is_symlink():
            raise ValueError('Unsafe notice directory')
        directory.mkdir(exist_ok=True, mode=0o700)
        sync_directory(root)
        target = directory/filename(archive)
        if target.exists() or target.is_symlink():
            if contract.canonical(read(archive)) != data:
                raise ValueError('Conflicting immutable notice evidence')
            sync_directory(directory)
            return contract.summary(value)
        fd, temporary = tempfile.mkstemp(dir=root/'staging')
        try:
            with os.fdopen(fd, 'wb') as stream:
                stream.write(data); stream.flush(); os.fsync(stream.fileno())
            # link, rather than replace: even an unexpected writer cannot overwrite.
            os.link(temporary, target)
            sync_directory(directory)
        finally:
            Path(temporary).unlink(missing_ok=True)
    return contract.summary(value)


def summary(archive):
    try:
        return contract.summary(read(archive))
    except FileNotFoundError:
        return contract.unavailable('missing')
    except (OSError, ValueError, KeyError, TypeError):
        return contract.unavailable('broken')
