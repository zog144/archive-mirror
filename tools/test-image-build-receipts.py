"""Local compatibility fixture against a supplied exact image-build checkout.
No compilation, download, deployment or release eligibility claim.
"""
import io
import json
import os
from pathlib import Path
import shutil
import sys
import tarfile
import tempfile

sys.path[:0] = [str(Path(__file__).resolve().parents[1]), str(Path(sys.argv[1]).resolve())]
os.environ['DJANGO_SETTINGS_MODULE'] = 'tests.settings'
import django
django.setup()
from django.core.management import call_command
from django.test import override_settings
from image_build.licensing import preserve
from image_build.metadata import Package
from zog.archive_mirror import store, notices, receipt_notices, notice_contract as c

with tempfile.TemporaryDirectory() as directory:
    root=Path(directory);state=root/'state';cache=state/'image-build/sources';cache.mkdir(parents=True)
    archive=root/'source.tar';text=b'Actual producer fixture notice. Copyright Example.\n'
    with tarfile.open(archive,'w') as tar:
        item=tarfile.TarInfo('demo/LICENSE');item.size=len(text);tar.addfile(item,io.BytesIO(text))
    sha=c.digest(archive.read_bytes());shutil.copyfile(archive,cache/sha)
    source=root/'source';(source/'src/demo').mkdir(parents=True);(source/'src/demo/LICENSE').write_bytes(text)
    output=root/'output';(output/'usr/bin').mkdir(parents=True);(output/'usr/bin/demo').write_text('fixture')
    record=dict(schema=1,package='demo',version='1',source=dict(url=archive.as_uri(),sha256=sha),status='declared',expression='MIT',scope='All files',
        evidence=[dict(path='demo/LICENSE',sha256=c.digest(text),source_sha256=sha)],components=[],patches=[],notes=[])
    package=Package('demo-final',(dict(url=archive.as_uri(),sha256=sha,destination='src',archive=True),),(),(),{},{},('usr/bin/demo',),{},licensing=record)
    preserve(package,source,output,state)
    (output/'inherited-seed').write_text('fixture seed gap')
    image=root/'rootfs.tar.xz'
    with tarfile.open(image,'w:xz') as tar:
        tar.add(output,arcname='.')
    config=root/'mirror.json';config.write_text(json.dumps(dict(root=str(root/'store'),collections=['root-filesystems'])))
    with override_settings(ARCHIVE_MIRROR_CONFIGURATION=str(config)):
        call_command('migrate',verbosity=0)
        stored=store.publish(image,'root-filesystems','root-filesystem',{})
        value=receipt_notices.build(stored,'fixture-generation',state/'image-build/release-inputs')
        notices.publish(stored,value)
        assert value['source_material']=='verified'
        assert value['coverage']=='unresolved'
        assert value['records'][0]['stage']=='demo-final'
        assert value['records'][0]['origin'] is None  # local producer URL never exported
        assert text in c.document(value)
        assert str(root) not in c.document(value).decode()
        assert notices.read(stored)==value
print('PASS: actual image-build preserve() receipts, retained inputs, tar import, stage, full text, seed gap and private origin redaction; local fixture only.')
