import datetime
import lzma
import os
import subprocess
import tarfile
import tempfile
from pathlib import Path
from .models import Snapshot
from .store import publish

def run(arguments, **kwargs):
    environment={**os.environ,'GIT_TERMINAL_PROMPT':'0','GIT_CONFIG_NOSYSTEM':'1','GIT_CONFIG_GLOBAL':'/dev/null','GIT_ALLOW_PROTOCOL':'https:file'}
    return subprocess.run(arguments,check=True,timeout=300,env=environment,stdout=subprocess.PIPE,stderr=subprocess.PIPE,**kwargs).stdout

def collect(definition,month=None,allow_local=False,require_lease=False):
    name=definition['name'];url=definition['url'];branch=definition['branch']
    import re
    if not isinstance(name,str) or not re.fullmatch('[a-z0-9][a-z0-9_-]{0,127}',name):raise ValueError('Invalid source name')
    month=month or datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m')
    previous=Snapshot.objects.filter(source=name,month=month).select_related('archive').first()
    if previous:return with_notices(previous.archive, definition)
    if not url.startswith('https://') and not (allow_local and Path(url).is_absolute()):raise ValueError('HTTPS upstream required')
    from urllib.parse import urlsplit
    parts=urlsplit(url)
    if parts.username or parts.password or parts.query or parts.fragment:raise ValueError('Credential-free upstream URL required')
    run(['git','check-ref-format','--branch',branch])
    with tempfile.TemporaryDirectory(prefix='archive-collect-') as work:
        root=Path(work);repo=root/'repository'
        run(['git','clone','--depth','1','--single-branch','--no-tags','--no-checkout','--branch',branch,'--',url,str(repo)])
        commit=run(['git','-C',str(repo),'rev-parse','HEAD']).decode().strip()
        listing=run(['git','-C',str(repo),'ls-tree','-r','-z','HEAD']).split(b'\0')
        files=[]
        if len(listing)>100001:raise ValueError('Too many tracked paths')
        for item in filter(None,listing):
            metadata,path=item.split(b'\t',1);mode,kind,oid=metadata.split()
            if mode==b'160000':raise ValueError('Submodules unsupported in pass 1')
            if path==b'.gitmodules':raise ValueError('Submodules unsupported in pass 1')
            files.append((path,mode,oid))
        archive=root/'source.tar.xz'
        with lzma.open(archive,'wb',preset=6) as compressed,tarfile.open(fileobj=compressed,mode='w|',format=tarfile.PAX_FORMAT) as output:
            import io
            total=0
            for path,mode,oid in sorted(files):
                size=int(run(['git','-C',str(repo),'cat-file','-s',oid.decode()]))
                total+=size
                if size>64*1024**2 or total>2*1024**3:raise ValueError('Source export limit exceeded')
                data=run(['git','-C',str(repo),'cat-file','blob',oid.decode()])
                if data.startswith(b'version https://git-lfs.github.com/spec/v1\n'):raise ValueError('Git LFS unsupported in pass 1')
                text=path.decode('utf-8')
                if text.startswith('/') or '..' in Path(text).parts:raise ValueError('Unsafe tracked path')
                entry=tarfile.TarInfo(name+'/'+text);entry.uid=entry.gid=entry.mtime=0;entry.uname=entry.gname=''
                if mode==b'120000':entry.type=tarfile.SYMTYPE;entry.linkname=data.decode();entry.mode=0o777
                else:entry.mode=0o755 if mode==b'100755' else 0o644;entry.size=len(data)
                output.addfile(entry,io.BytesIO(data) if entry.isfile() else None)
        if require_lease:
            from .lease import lease
            lease()
        result = publish(archive,'sources','source',{'url':url,'branch':branch,'commit':commit,'export_recipe':'tracked-tree-v1','attributes':'ignored'},name,month,commit)

        return with_notices(result, definition)


def with_notices(archive, definition):
    """Operator-supplied, exact export sidecar; no repository HEAD inference."""
    if definition.get('license_sidecar'):
        from . import notice_contract, notices
        with open(definition['license_sidecar'], 'rb') as stream:
            value = notice_contract.decode(stream.read(notice_contract.MAX_BUNDLE+1))
        notices.publish(archive, value)
    return archive
