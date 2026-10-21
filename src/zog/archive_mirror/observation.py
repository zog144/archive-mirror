"""Bounded read-only observations of the configured store. No credential serialization."""
import json
import os
import re
import stat
import time
import uuid
from pathlib import Path
from django.utils import timezone
from .config import configuration
from .models import Archive, Snapshot, Pin

MAX_ITEMS = 10000
DIGEST = re.compile(r'[0-9a-f]{64}\Z')
LABEL = re.compile(r'[A-Za-z0-9][A-Za-z0-9._+ -]{0,199}\Z')


def label(value):
    # Never echo URLs, paths, arbitrary provenance, exception text or credential fields.
    return value if isinstance(value, str) and LABEL.fullmatch(value) else None


def identity(config):
    fd = os.open(config['intent_file'], os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > 32768 or info.st_mode & 0o022:
            raise ValueError('Unsafe intent')
        intent = json.load(stream)
    host = str(uuid.UUID(config['host_id']))
    if intent['host_id'] != host or intent['version'] != 1:
        raise ValueError('Identity mismatch')
    revision = intent['desired']['revision']
    if type(revision) is not int or not 1 <= revision <= 2**53-1:
        raise ValueError('Invalid revision')
    return host, revision


def observe(version=1):
    if type(version) is not int or version not in (1, 2):
        raise ValueError("Unsupported observation version")
    config = configuration()
    host, revision = identity(config)
    result = dict(version=version, host_id=host, role_revision=revision,
                  observation_id=str(uuid.uuid4()), observed_at=timezone.now().isoformat(),
                  status='ok', serving=False, lease_expires_at=None, items=[],
                  preparation=dict(state='unknown', attempt_id=None),
                  summary=dict(collections=[], logical_bytes=None, unique_content_bytes=None,
                               allocated_object_bytes=None, accounting_complete=False, filesystems=[]))
    # Readiness is the existing provider check: current lease, keyring, database,
    # objects directory and fresh scheduler evidence; never election alone.
    from .views import ready
    from .lease import lease
    from types import SimpleNamespace
    try:
        if ready(SimpleNamespace(method="GET")).status_code == 200:
            intent = lease()
            result.update(serving=True, lease_expires_at=intent['desired']['lease_expires_at'])
    except (OSError, ValueError, KeyError, TypeError):
        pass
    try:
        rows = list(Archive.objects.order_by('id')[:MAX_ITEMS + 1])
        if len(rows) > MAX_ITEMS:
            result['status'] = 'limit-exceeded'
            result['serving'] = False
            return result  # No truncated catalogue masquerading as a complete one.
        root = Path(config['root'])
        directory = os.open(root/'objects', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            objects = {}
            complete = True
            # One directory, no recursion or user-supplied paths. Include orphan blobs.
            with os.scandir(directory) as entries:
                for index, entry in enumerate(entries):
                    if index >= MAX_ITEMS:
                        complete = False
                        break
                    if not DIGEST.fullmatch(entry.name):
                        complete = False
                        continue
                    info = entry.stat(follow_symlinks=False)
                    if not stat.S_ISREG(info.st_mode):
                        complete = False
                        continue
                    objects[entry.name] = info
            filesystems = {}
            for mount, fd in [('store', os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)), ('objects', os.dup(directory))]:
                try:
                    device = str(os.fstat(fd).st_dev)
                    if device in filesystems:
                        filesystems[device]['stores'].append(mount)
                        continue
                    capacity = dict(total_bytes=None, used_bytes=None, available_bytes=None)
                    try:
                        fs = os.fstatvfs(fd)
                        capacity = dict(total_bytes=fs.f_blocks*fs.f_frsize,
                                        used_bytes=(fs.f_blocks-fs.f_bfree)*fs.f_frsize,
                                        available_bytes=fs.f_bavail*fs.f_frsize)
                    except OSError:
                        pass
                    filesystems[device] = dict(id=device, stores=[mount], **capacity)
                finally:
                    os.close(fd)
            # A nested file mount can live on another filesystem. Capacity is unknown
            # there: do not invent a store-root capacity for it.
            for info in objects.values():
                filesystems.setdefault(str(info.st_dev), dict(id=str(info.st_dev), stores=['object'], total_bytes=None, used_bytes=None, available_bytes=None))
            if len(filesystems) > 16:
                result['status'] = 'limit-exceeded'
                result['serving'] = False
                return result
            per_device = {device: 0 for device in filesystems}
            seen_inodes = set()
            allocated = 0
            allocated_known = complete
            for info in objects.values():
                inode = (info.st_dev, info.st_ino)
                if inode in seen_inodes:
                    continue
                seen_inodes.add(inode)
                if hasattr(info, 'st_blocks'):
                    allocated += info.st_blocks * 512
                    per_device[str(info.st_dev)] += info.st_blocks * 512
                else:
                    allocated_known = False
            for device, fs in filesystems.items():
                fs["allocated_object_bytes"] = per_device[device] if allocated_known else None
            # Bounded subqueries avoid unbounded pin/snapshot prefetches.
            from django.db.models import OuterRef, Subquery
            metadata = Archive.objects.filter(id__in=[r.id for r in rows]).annotate(
                source_name=Subquery(Snapshot.objects.filter(archive_id=OuterRef('pk')).order_by('-month').values('source')[:1]),
                source_commit=Subquery(Snapshot.objects.filter(archive_id=OuterRef('pk')).order_by('-month').values('commit')[:1]),
                pin_name=Subquery(Pin.objects.filter(archive_id=OuterRef('pk')).order_by('id').values('name')[:1])).order_by('id')
            for row in metadata:
                provenance = row.provenance if isinstance(row.provenance, dict) else {}
                info = objects.get(row.digest)
                availability = 'present' if info and info.st_size == row.size else ('missing' if complete and not info else 'unknown')
                if info and info.st_size != row.size:
                    availability = 'size-mismatch'
                generation = provenance.get('generation') or provenance.get('commit') or row.source_commit
                generation = generation if isinstance(generation, str) and re.fullmatch(r'[0-9a-f]{7,64}', generation) else None
                result['items'].append(dict(collection=row.collection, digest=row.digest, kind=row.kind,
                    name=label(row.source_name) or label(row.pin_name), version=generation, size_bytes=row.size,
                    availability=availability, filesystem_id=str(info.st_dev) if info else None,
                    provenance='source-export' if row.source_name else ('local-import' if provenance.get('import') == 'local' else 'unknown'),
                    approval=('approved' if provenance['release_approved'] else 'unapproved') if type(provenance.get('release_approved')) is bool else 'unknown'))
                if version == 2:
                    from .notices import summary
                    result["items"][-1]["licenses"] = summary(row)
            distinct = {}
            consistent = True
            for row in rows:
                if row.digest in distinct and distinct[row.digest] != row.size:
                    consistent = False
                distinct[row.digest] = row.size
            result['summary'] = dict(collections=sorted(set(config['collections']) | {r.collection for r in rows}),
                logical_bytes=sum(r.size for r in rows), unique_content_bytes=sum(distinct.values()) if consistent else None,
                allocated_object_bytes=allocated if allocated_known else None, accounting_complete=complete,
                filesystems=list(filesystems.values()))
        finally:
            os.close(directory)
    except (OSError, ValueError):
        result['status'] = 'unavailable'
        result['serving'] = False
        result['items'] = []
    return result
