import json
import os
import re
from pathlib import Path
from django.conf import settings

def configuration():
    value = json.loads(Path(settings.ARCHIVE_MIRROR_CONFIGURATION).read_text())
    root = Path(value['root'])
    if not root.is_absolute() or root == Path('/') or root.is_symlink():
        raise ValueError('Explicit persistent archive root required')
    if not isinstance(value['collections'], list) or not value['collections']:
        raise ValueError('Collections required')
    for name in value['collections']:
        if not isinstance(name,str) or not re.fullmatch(r'[a-z0-9][a-z0-9_-]{0,63}', name):
            raise ValueError('Invalid collection')
    return value

def collection(name):
    if name not in configuration()['collections']:
        raise ValueError('Unknown collection')
    return name
