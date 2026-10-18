import copy
import io
import json
import tarfile
from unittest.mock import patch
from . import test_mirror as fixture
from django.test import TestCase
from zog.archive_mirror import notices, notice_contract as c, store
from zog.archive_mirror.receipt_notices import build


def bundle(archive, name='example', version='1.0', expression='MIT', text='Exact upstream license\nCopyright example\n'):
    sha = c.digest(text.encode())
    return dict(schema=1, collection=archive.collection, archive_digest=archive.digest, artifact_kind=archive.kind,
        source_identity=dict(kind='release-archive', digest=archive.digest, revision=None), generation=None,
        records=[dict(package=name, version=version, revision=None, stage=None, source_digest=archive.digest, origin='https://example.org/releases', expression=expression,
            review='declared', scope='package', exceptions=[], issues=[], texts=[sha], receipt_digest=None)],
        texts={sha:text}, coverage='recorded', source_material='unknown')


class NoticeTests(TestCase):
    setUp = fixture.MirrorTests.setUp
    set_intent = fixture.MirrorTests.set_intent
    token = fixture.MirrorTests.token
    get = fixture.MirrorTests.get
    publish = fixture.MirrorTests.publish
    def test_binding_versions_terms_idempotency_and_conflict(self):
        old=self.publish(); first=bundle(old)
        notices.publish(old,first);self.assertEqual(notices.publish(old,first),c.summary(first))
        self.input.write_bytes(b'new version'); new=self.publish(); second=bundle(new,version='2.0',expression='BSD-2-Clause',text='Other upstream terms')
        notices.publish(new,second)
        self.assertEqual(notices.read(old)['records'][0]['version'],'1.0')
        self.assertNotEqual(c.summary(first)['notice_digest'],c.summary(second)['notice_digest'])
        changed=copy.deepcopy(first);changed['records'][0]['version']='2.0'
        with self.assertRaises(ValueError):notices.publish(old,changed)
        with self.assertRaises(ValueError):notices.publish(old,second)
        self.assertEqual(notices.read(old),first)
        self.input.write_bytes(b'another package');other=self.publish()
        notices.publish(other,bundle(other,name='other',expression='Apache-2.0',text='Another complete notice'))
        self.assertEqual(notices.read(other)['records'][0]['expression'],'Apache-2.0')

    def test_missing_corrupt_hash_and_oversize(self):
        row=self.publish();self.assertEqual(notices.summary(row)['state'],'missing')
        value=bundle(row);next(iter(value['texts']))
        value['texts'][next(iter(value['texts']))]='changed'
        with self.assertRaises(ValueError):notices.publish(row,value)
        value=bundle(row,text='a'*(c.MAX_TEXT+1))
        with self.assertRaises(ValueError):c.validate(value)
        value=bundle(row);value['secret']='DO NOT DISCLOSE'
        with self.assertRaises(ValueError):c.validate(value)
        notices.publish(row,bundle(row))
        path=self.root/'store/notices'/notices.filename(row);path.write_text('{}')
        self.assertEqual(notices.summary(row)['state'],'broken')

    def test_interruption_before_and_after_atomic_commit(self):
        row=self.publish();value=bundle(row)
        with patch('zog.archive_mirror.notices.os.link',side_effect=OSError('fixture')):
            with self.assertRaises(OSError):notices.publish(row,value)
        self.assertEqual(notices.summary(row)['state'],'missing')
        original=notices.sync_directory
        def fail(path):
            if path.name=='notices':raise OSError('after commit')
            original(path)
        with patch('zog.archive_mirror.notices.sync_directory',side_effect=fail):
            with self.assertRaises(OSError):notices.publish(row,value)
        self.assertEqual(notices.publish(row,value),c.summary(value))
        store.prune();self.assertEqual(notices.read(row),value)

    def test_scope_lease_plain_text_and_pagination(self):
        row=self.publish();value=bundle(row,text='<script>window.secret="evil"</script>\nSecond line')
        value['records'] += [dict(value['records'][0],package='other')]
        notices.publish(row,value)
        self.assertNotIn('licenses',self.get('/collections/sources/').json()['archives'][0])
        self.assertEqual(self.get('/collections/sources/?version=2').json()['archives'][0]['licenses'],c.summary(value))
        path=f'/collections/sources/archives/{row.digest}/notices/'
        self.assertEqual(self.client.get(path).status_code,403)
        self.assertEqual(self.get(path,self.token(['list'])).status_code,403)
        self.assertEqual(self.get(path,self.token(collections=['root-filesystems'])).status_code,403)
        page=self.get(path+'?limit=1').json();self.assertEqual(len(page['records']),1);self.assertEqual(page['next_offset'],1)
        self.assertIsNone(self.get(path+'?limit=1&offset=1').json()['next_offset'])
        reply=self.get(path+'?format=text');self.assertEqual(reply.status_code,200)
        self.assertEqual(reply['Content-Type'],'text/plain; charset=utf-8');self.assertIn('sandbox',reply['Content-Security-Policy'])
        self.assertEqual(self.get(path+'?url=https://evil.test').status_code,400)
        self.set_intent(False);self.assertEqual(self.get(path).status_code,503)
        self.assertEqual(notices.read(row),value)

    def rootfs(self, changed=False, unsafe=False):
        members={};text=b'Common notice\nCopyright upstream\n';sha=c.digest(text)
        for name,expr in [('one','MIT'),('two','BSD-2-Clause')]:
            base='usr/share/licenses/zog-packages/'+name
            source='1'*64;location=base+'/texts/'+source+'/COPYING'
            evidence=dict(path='COPYING',sha256=sha,source_sha256=source)
            record=dict(schema=1,package=name,version='1.0',source=dict(url='https://example.org/source.tar.xz',sha256=source),
                status='declared',expression=expr,scope='package',evidence=[evidence],
                components=[dict(scope='font',expression=None,status='unresolved',notes='Needs review')],patches=[],notes=[])
            receipt=dict(schema=1,record=record,record_identity=c.digest(c.canonical(record)),sources=[dict(sha256=source)],
                evidence=[dict(evidence,installed_path=location if not unsafe else '../../etc/passwd')],unreviewed_sources=['2'*64],
                recipe={'private':'NEVER COPY'},owned_outputs=[],source_retention='release-inputs; no automatic expiry')
            members[base+'/record.json']=c.canonical(receipt);members[location]=b'changed' if changed else text
        members['seed/unknown-file']=b'inherited'
        with tarfile.open(self.input,'w:xz') as output:
            for path,data in members.items():
                info=tarfile.TarInfo(path);info.size=len(data);output.addfile(info,io.BytesIO(data))
        return self.publish(target='root-filesystems',kind='root-filesystem')

    def test_rootfs_actual_receipts_aggregate_dedup_exceptions_and_seed_gap(self):
        row=self.rootfs();value=build(row,'generation-1');notices.publish(row,value)
        self.assertEqual(len(value['records']),2);self.assertEqual(len(value['texts']),1)
        self.assertEqual(value['coverage'],'unresolved');self.assertEqual(value['source_material'],'unknown')
        doc=c.document(value).decode();self.assertEqual(doc.count('Common notice'),1)
        for expected in ['one 1.0','two 1.0','font','Inherited/seed','not release approval']:
            self.assertIn(expected,doc)
        self.assertNotIn('NEVER COPY',json.dumps(value))
        self.assertEqual(build(row,'generation-1',self.root/'absent')['source_material'],'missing')

    def test_rootfs_changed_text_and_forged_path_blocked(self):
        for kwargs in [dict(changed=True),dict(unsafe=True)]:
            with self.assertRaises(ValueError):build(self.rootfs(**kwargs),'generation-1')
        with tarfile.open(self.input,'w:xz'):
            pass
        with self.assertRaisesRegex(ValueError,'receipts unavailable'):
            build(self.publish(target='root-filesystems',kind='root-filesystem'),'old')

    def test_exact_repository_identity_and_reject_private_origin(self):
        row=self.publish();row.provenance={'commit':'a'*40};row.save()
        value=bundle(row)
        with self.assertRaises(ValueError):notices.publish(row,value)
        value['source_identity'].update(kind='repository-export',revision='a'*40)
        notices.publish(row,value)
        for origin in ['https://user:token@example.org/path','https://example.org/?token=secret','file:///home/secret','https://localhost/a']:
            value['records'][0]['origin']=origin
            with self.assertRaises(ValueError):c.validate(value)


    def test_release_package_metadata_is_verified_against_actual_tar(self):
        from zog.archive_mirror.source_notices import build as source_bundle
        text=b'Exact upstream release terms\r\n';sha=c.digest(text)
        with tarfile.open(self.input,'w:xz') as output:
            item=tarfile.TarInfo('example-1/COPYING');item.size=len(text);output.addfile(item,io.BytesIO(text))
        archive=self.publish()
        record=dict(schema=1,package='example',version='1',source=dict(url='https://example.org/source.tar.xz',sha256=archive.digest),
            status='declared',expression='MIT',scope='package',evidence=[dict(path='example-1/COPYING',sha256=sha,source_sha256=archive.digest)],
            components=[],patches=[],notes=[])
        path=self.root/'license.py';path.write_text(repr(record))
        value=source_bundle(archive,path);notices.publish(archive,value)
        self.assertEqual(c.document(value).count(text),1)
        record['source']['sha256']='0'*64;path.write_text(repr(record))
        with self.assertRaises(ValueError):source_bundle(archive,path)
        path.write_text("__import__('os').system('false')")
        with self.assertRaises(ValueError):source_bundle(archive,path)
