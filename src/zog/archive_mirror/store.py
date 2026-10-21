"""Single-host durable object publication; every writer uses the same file lock."""
import contextlib
import fcntl
import hashlib
import os
import re
import tempfile
from pathlib import Path
from django.db import transaction
from .config import configuration, collection
from .models import Archive, Snapshot, Pin

def sync_directory(path):
    fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY)
    try: os.fsync(fd)
    finally: os.close(fd)

def _root():
    root=Path(configuration()['root'])
    root.mkdir(parents=True,exist_ok=True)
    sync_directory(root.parent)
    return root

def _safe_directory(root,name):
    path=root/name
    if path.is_symlink():
        raise ValueError('Unsafe store directory')
    path.mkdir(exist_ok=True)
    return path

@contextlib.contextmanager
def named_lock(namespace,key):
    """Serialize one bounded logical operation without blocking unrelated network I/O."""
    if not re.fullmatch(r'[a-z][a-z0-9-]{0,31}',namespace) or not isinstance(key,str):
        raise ValueError('Invalid lock identity')
    root=_root()
    locks=_safe_directory(root,'locks')
    sync_directory(root)
    name=namespace+'-'+hashlib.sha256(key.encode('utf-8')).hexdigest()+'.lock'
    directory=os.open(locks,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:
        fd=os.open(name,os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600,dir_fd=directory)
    finally:
        os.close(directory)
    try:
        fcntl.flock(fd,fcntl.LOCK_EX)
        yield
    finally:
        os.close(fd)

@contextlib.contextmanager
def locked():
    root=_root()
    fd=os.open(root/'writer.lock',os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
    try:
        # Benign concurrent mutations queue instead of surfacing BlockingIOError.
        fcntl.flock(fd,fcntl.LOCK_EX)
        for name in ('objects','staging'):
            _safe_directory(root,name)
        sync_directory(root)
        yield root
    finally: os.close(fd)

def object_path(root,digest):
    if not re.fullmatch('[0-9a-f]{64}',digest): raise ValueError('Invalid digest')
    return root/'objects'/digest

def open_object(digest):
    root=Path(configuration()['root'])
    directory=os.open(root/'objects',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try: fd=os.open(object_path(root,digest).name,os.O_RDONLY|os.O_NOFOLLOW,dir_fd=directory)
    finally: os.close(directory)
    import stat
    if not stat.S_ISREG(os.fstat(fd).st_mode):
        os.close(fd);raise ValueError('Not a regular object')
    return os.fdopen(fd,'rb')

def publish(path, target, kind, provenance, source=None, month=None, commit=''):
    collection(target)
    if kind not in ('source','root-filesystem'): raise ValueError('Invalid archive type')
    if source and (not re.fullmatch('[a-z0-9][a-z0-9_-]{0,127}',source) or not re.fullmatch(r'\d{4}-(0[1-9]|1[0-2])',month or '')):
        raise ValueError('Invalid snapshot identity')
    with locked() as root:
        if source:
            existing=Snapshot.objects.filter(source=source,month=month).select_related('archive').first()
            if existing: return existing.archive
        descriptor,temporary=tempfile.mkstemp(dir=root/'staging')
        try:
            checksum=hashlib.sha256();size=0
            with os.fdopen(descriptor,'wb') as output, open(path,'rb') as incoming:
                while block:=incoming.read(1024*1024):
                    size+=len(block)
                    if size>configuration().get('maximum_archive_bytes',16*1024**3):raise ValueError('Archive too large')
                    checksum.update(block);output.write(block)
                output.flush();os.fsync(output.fileno())
            digest=checksum.hexdigest();destination=object_path(root,digest)
            if destination.exists() or destination.is_symlink():
                with open_object(digest) as old:
                    if hashlib.file_digest(old,'sha256').hexdigest()!=digest:raise ValueError('Stored object corrupt')
            else:
                os.replace(temporary,destination);sync_directory(root/'objects')
            with transaction.atomic():
                archive,created=Archive.objects.get_or_create(collection=target,digest=digest,defaults={'size':size,'kind':kind,'provenance':provenance,'managed':bool(source)})
                if archive.size!=size or archive.kind!=kind:raise ValueError('Conflicting archive metadata')
                if source:Snapshot.objects.create(source=source,month=month,archive=archive,commit=commit)
            return archive
        finally:
            Path(temporary).unlink(missing_ok=True)

def pin(target,digest,name,remove=False):
    if not name or len(name)>200:raise ValueError('Pin name required')
    with locked():
        archive=Archive.objects.get(collection=target,digest=digest)
        if remove:Pin.objects.filter(archive=archive,name=name).delete()
        else:Pin.objects.get_or_create(archive=archive,name=name)

def prune():
    """Keep snapshots, pins, active sets and recoverable incomplete source pin sets."""
    with locked() as root:
        with transaction.atomic():
            for source in Snapshot.objects.values_list('source',flat=True).distinct():
                old=list(Snapshot.objects.filter(source=source).order_by('-month').values_list('id',flat=True)[3:])
                Snapshot.objects.filter(id__in=old).delete()
            (Archive.objects.filter(kind='source',managed=True,snapshot__isnull=True,pin__isnull=True)
                .exclude(reviewed_sources__pin_set__active=True)
                .exclude(reviewed_sources__pin_set__complete=False)
                .delete())
        referenced=set(Archive.objects.values_list('digest',flat=True))
        for path in (root/'objects').iterdir():
            if re.fullmatch('[0-9a-f]{64}',path.name) and path.name not in referenced:path.unlink()
        for path in (root/'staging').iterdir():
            if path.is_file() or path.is_symlink():path.unlink()
        sync_directory(root/'objects');sync_directory(root/'staging')
