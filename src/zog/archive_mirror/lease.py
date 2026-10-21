import json
import os
import stat
import time
import uuid
from pathlib import Path
from .config import configuration

def lease():
    config=configuration();expected=str(uuid.UUID(config['host_id']))
    path=Path(config['intent_file'])
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
    with os.fdopen(fd,'rb') as source:
        info=os.fstat(source.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size>32768 or info.st_mode & 0o022:raise ValueError('Unsafe role intent')
        value=json.load(source)
    desired=value['desired'];expires=desired['lease_expires_at']
    if value['version']!=1 or value['host_id']!=expected or desired['version']!=1 or desired['selected'] is not True:
        raise ValueError('Role not selected')
    if type(expires) is not int or not time.time()<expires<=time.time()+905:raise ValueError('Role lease expired')
    if type(desired['revision']) is not int or desired['revision']<1 or desired['endpoint']!=config['endpoint']:raise ValueError('Role binding mismatch')
    return value
