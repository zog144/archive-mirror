"""Standalone provider settings; station-access can instead include this Django app."""
import os
from pathlib import Path
BASE_DIR=Path(os.environ.get('ARCHIVE_MIRROR_STATE','/var/lib/archive-mirror'))
SECRET_KEY='archive-provider-no-browser-sessions'
DEBUG=False
ALLOWED_HOSTS=os.environ.get('ARCHIVE_MIRROR_ALLOWED_HOSTS','localhost,127.0.0.1').split(',')
INSTALLED_APPS=['zog.archive_mirror']
DATABASES={'default':{'ENGINE':'django.db.backends.sqlite3','NAME':str(BASE_DIR/'catalogue.sqlite3'),'OPTIONS':{'timeout':30}}}
ROOT_URLCONF='zog.archive_mirror.urls'
MIDDLEWARE=[]
USE_TZ=True
ARCHIVE_MIRROR_CONFIGURATION=os.environ.get('ARCHIVE_MIRROR_CONFIGURATION','/etc/archive-mirror/configuration.json')
DEFAULT_AUTO_FIELD='django.db.models.BigAutoField'
