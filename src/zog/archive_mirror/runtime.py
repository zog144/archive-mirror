import fcntl
import json
import logging
import os
import signal
import threading
import time
from pathlib import Path
from .config import configuration
from .lease import lease
from .store import sync_directory


def atomic(path,value):
    temporary=path.with_suffix('.new')
    with open(temporary,'w') as output:
        json.dump(value,output);output.flush();os.fsync(output.fileno())
    os.replace(temporary,path);sync_directory(path.parent)


def _guard():
    if os.environ.get("ARCHIVE_MIRROR_REQUIRE_OWNERSHIP") != "1":
        return None
    from django.conf import settings
    from .storage_ownership import runtime_guard
    return runtime_guard(Path(settings.BASE_DIR))


def scheduler():
    _guard()
    from .store import locked
    with locked() as root:pass
    fd=os.open(root/'scheduler.lock',os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
    fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
    stop=threading.Event()
    for number in (signal.SIGINT,signal.SIGTERM):signal.signal(number,lambda *_:stop.set())
    # Collection runs separately so lease/identity monitoring is never blocked by Git/compression.
    import subprocess,sys
    child=None;next_run=0
    try:
        while not stop.is_set():
            _guard()
            intent=lease()
            atomic(root/'scheduler.json',{'time':time.time(),'host_id':intent['host_id'],'revision':intent['desired']['revision']})
            if child and child.poll() is not None:
                logging.info('Collection pass finished: %s',child.returncode);child=None;next_run=time.monotonic()+3600
            if child is None and time.monotonic()>=next_run:
                child=subprocess.Popen([sys.executable,'-m','zog.archive_mirror','refresh'],start_new_session=True)
            stop.wait(10)
    finally:
        if child and child.poll() is None:
            os.killpg(child.pid,signal.SIGTERM)
            try:child.wait(timeout=5)
            except subprocess.TimeoutExpired:os.killpg(child.pid,signal.SIGKILL);child.wait()
        (root/'scheduler.json').unlink(missing_ok=True);os.close(fd)


def server(host='127.0.0.1',port=8080):
    from django.core.wsgi import get_wsgi_application
    from waitress import create_server
    _guard();lease()
    http=create_server(get_wsgi_application(),host=host,port=port)
    stop=threading.Event()
    for number in (signal.SIGINT,signal.SIGTERM):signal.signal(number,lambda *_:stop.set())
    def watchdog():
        while not stop.wait(5):
            try:
                _guard();lease()
            except (ValueError,OSError,KeyError,TypeError):
                stop.set()
        http.close()
    threading.Thread(target=watchdog,daemon=True).start()
    http.run()
