import base64
import hashlib
import io
import json
import os
import subprocess
import tarfile
import tempfile
import time
import uuid
from pathlib import Path
from unittest.mock import patch
from django.test import TestCase,Client,override_settings
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from zog.host_identify.archive import issue
from zog.archive_mirror import store
from zog.archive_mirror.models import Archive,Snapshot
from zog.archive_mirror.collector import collect

class MirrorTests(TestCase):
    def setUp(self):
        self.temporary=tempfile.TemporaryDirectory();self.addCleanup(self.temporary.cleanup)
        self.root=Path(self.temporary.name);self.host=str(uuid.uuid4());self.key=Ed25519PrivateKey.generate()
        self.intent=self.root/'intent.json';self.set_intent()
        keyring=self.root/'public.json';keyring.write_text(json.dumps({'version':1,'keys':{'test':base64.b64encode(self.key.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)).decode()}}))
        self.config={'root':str(self.root/'store'),'collections':['sources','root-filesystems'],'host_id':self.host,'intent_file':str(self.intent),'endpoint':'https://mirror.test','keyring':str(keyring),'issuer':'https://registry.test','audience':'mirror-test'}
        self.configpath=self.root/'config.json';self.configpath.write_text(json.dumps(self.config))
        self.override=override_settings(ARCHIVE_MIRROR_CONFIGURATION=str(self.configpath));self.override.enable();self.addCleanup(self.override.disable)
        self.input=self.root/'input.tar.xz'
        with tarfile.open(self.input,'w:xz') as output:
            record=tarfile.TarInfo('root/etc/example');record.size=4;output.addfile(record,io.BytesIO(b'test'))
        self.client=Client()
    def set_intent(self,selected=True,expiry=None):
        self.intent.write_text(json.dumps({'version':1,'host_id':self.host,'desired':{'version':1,'selected':selected,'revision':1,'endpoint':'https://mirror.test','lease_expires_at':int(time.time())+900 if expiry is None else expiry}}));self.intent.chmod(0o640)
    def token(self,operations=None,collections=None,**kw):
        return issue(self.key,'test',kw.pop('issuer','https://registry.test'),kw.pop('audience','mirror-test'),self.host,operations or ['list','download'],collections or ['sources'],**kw)[0]
    def get(self,url,token=None):return self.client.get(url,HTTP_AUTHORIZATION='Bearer '+(token or self.token()))
    def publish(self,**kw):return store.publish(self.input,kw.pop('target','sources'),kw.pop('kind','source'),{},**kw)
    def test_download_exact_bytes_and_headers(self):
        archive=self.publish();r=self.get(f'/collections/sources/archives/{archive.digest}.tar.xz')
        self.assertEqual(r.status_code,200);self.assertEqual(b''.join(r.streaming_content),self.input.read_bytes());self.assertEqual(r['X-Archive-SHA256'],archive.digest)
    def test_list_is_separate_permission(self):
        self.publish();self.assertEqual(self.get('/collections/sources/',self.token(['download'])).status_code,403)
        self.assertEqual(self.get('/collections/sources/').json()['archives'][0]['bytes'],self.input.stat().st_size)
    def test_collection_boundary_even_for_same_digest(self):
        a=self.publish(target='root-filesystems',kind='root-filesystem')
        self.assertEqual(self.get(f'/collections/root-filesystems/archives/{a.digest}.tar.xz').status_code,403)
        self.assertEqual(self.get(f'/collections/sources/archives/{a.digest}.tar.xz').status_code,404)
    def test_bad_tokens(self):
        for token in ('bad',self.token(now=int(time.time())-1000),self.token(audience='other'),self.token(issuer='other')):
            self.assertEqual(self.get('/collections/sources/',token).status_code,403)
        self.assertEqual(self.client.get('/collections/sources/').status_code,403)
    def test_withdrawal_preserves_bytes(self):
        a=self.publish();self.set_intent(False)
        self.assertEqual(self.get('/collections/sources/').status_code,503)
        self.assertTrue((self.root/'store/objects'/a.digest).exists())
    def test_expired_lease(self):
        self.set_intent(expiry=int(time.time())-1);self.assertEqual(self.get('/collections/sources/').status_code,503)
    def test_symlink_rejected(self):
        a=self.publish();path=self.root/'store/objects'/a.digest;path.unlink();path.symlink_to(self.input)
        self.assertEqual(self.get(f'/collections/sources/archives/{a.digest}.tar.xz').status_code,503)
    def test_traversal(self):
        self.assertEqual(self.get('/collections/sources/archives/../../input.tar.xz').status_code,404)
    def test_partial_write_not_visible(self):
        with patch('zog.archive_mirror.store.os.replace',side_effect=OSError('failure')):
            with self.assertRaises(OSError):self.publish()
        self.assertEqual(Archive.objects.count(),0)
    def test_database_failure_leaves_recoverable_orphan(self):
        with patch.object(Archive.objects,'get_or_create',side_effect=RuntimeError('failure')):
            with self.assertRaises(RuntimeError):self.publish()
        self.assertEqual(Archive.objects.count(),0);store.prune()
        self.assertEqual(list((self.root/'store/objects').iterdir()),[])
    def test_three_months_and_pin(self):
        first=None
        for number in range(1,6):
            self.input.write_bytes(str(number).encode());a=self.publish(source='example',month=f'2026-0{number}',commit=str(number))
            if number==1:first=a;store.pin('sources',a.digest,'build-1')
        store.prune();self.assertEqual(Snapshot.objects.count(),3);self.assertEqual(Archive.objects.count(),4)
        store.pin('sources',first.digest,'build-1',True);store.prune();self.assertEqual(Archive.objects.count(),3)
    def test_imports_retained(self):
        self.publish();self.publish(target='root-filesystems',kind='root-filesystem');store.prune();self.assertEqual(Archive.objects.count(),2)
    def test_month_retry_is_idempotent(self):
        a=self.publish(source='example',month='2026-01',commit='one');self.input.write_bytes(b'other')
        b=self.publish(source='example',month='2026-01',commit='two');self.assertEqual(a.pk,b.pk);self.assertEqual(Snapshot.objects.count(),1)
    def test_unchanged_months_share_object(self):
        for n in range(1,5):self.publish(source='example',month=f'2026-0{n}',commit='one')
        store.prune();self.assertEqual(Archive.objects.count(),1);self.assertEqual(Snapshot.objects.count(),3)
    def test_readiness_requires_scheduler(self):
        self.publish();url='/.well-known/zog/archive-mirror/ready';self.assertEqual(self.client.get(url).status_code,503)
        path=self.root/'store/scheduler.json';path.write_text(json.dumps({'host_id':self.host,'revision':1,'time':time.time()}))
        self.assertEqual(self.client.get(url).status_code,200)
        path.write_text(json.dumps({'host_id':self.host,'revision':1,'time':time.time()-100}));self.assertEqual(self.client.get(url).status_code,503)
    def repository(self):
        repo=self.root/'upstream';repo.mkdir()
        def git(*args):return subprocess.run(['git','-C',str(repo),*args],check=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        git('init','-b','main');git('config','user.email','test@example.test');git('config','user.name','Test')
        (repo/'source.txt').write_text('source');(repo/'execute').write_text('exit 0\n');(repo/'execute').chmod(0o755);(repo/'link').symlink_to('source.txt')
        git('add','.');git('commit','-m','source')
        return repo,git
    def test_git_determinism_modes_and_provenance(self):
        repo,git=self.repository();definition={'name':'example','url':str(repo),'branch':'main'}
        a=collect(definition,'2026-01',True);b=collect(definition,'2026-02',True)
        self.assertEqual(a.digest,b.digest)
        with tarfile.open(self.root/'store/objects'/a.digest) as archive:
            self.assertEqual(archive.getmember('example/execute').mode,0o755);self.assertTrue(archive.getmember('example/link').issym())
        self.assertEqual(a.provenance['export_recipe'],'tracked-tree-v1')
    def test_git_lfs_rejected_without_snapshot(self):
        repo,git=self.repository();(repo/'large').write_text('version https://git-lfs.github.com/spec/v1\n');git('add','.');git('commit','-m','lfs')
        with self.assertRaises(ValueError):collect({'name':'example','url':str(repo),'branch':'main'},'2026-01',True)
        self.assertFalse(Snapshot.objects.exists())
    def test_submodule_rejected(self):
        repo,git=self.repository();(repo/'.gitmodules').write_text('');git('add','.');git('commit','-m','submodule')
        with self.assertRaises(ValueError):collect({'name':'example','url':str(repo),'branch':'main'},'2026-01',True)

    def test_generic_object_download_exact_bytes_and_headers(self):
        archive=self.publish();r=self.get(f'/collections/sources/objects/{archive.digest}')
        self.assertEqual(r.status_code,200);self.assertEqual(b''.join(r.streaming_content),self.input.read_bytes())
        self.assertEqual(r['Content-Type'],'application/octet-stream');self.assertEqual(r['X-Archive-SHA256'],archive.digest)

    def test_generic_object_download_requires_download_permission(self):
        archive=self.publish()
        self.assertEqual(self.get(f'/collections/sources/objects/{archive.digest}',self.token(['list'])).status_code,403)
