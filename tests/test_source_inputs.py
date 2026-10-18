import hashlib
import json
import tempfile
import threading
import uuid
from pathlib import Path
from unittest.mock import patch
from django.db import IntegrityError, transaction
from django.test import TestCase, override_settings
from zog.archive_mirror import store
from zog.archive_mirror.models import Archive, ReviewedSource, SourcePinSet
from zog.archive_mirror.source_inputs import populate, deactivate, abandon, decode_manifest

class Response:
    def __init__(self, data, url, final=None, length=True, fail_after=False):
        self.data=data;self.url=url;self.final=final or url;self.offset=0;self.fail_after=fail_after
        self.headers={'Content-Length':str(len(data))} if length else {}
    def __enter__(self):return self
    def __exit__(self,*args):pass
    def geturl(self):return self.final
    def read(self,size):
        if self.fail_after and self.offset:
            raise OSError('interrupted')
        if self.offset>=len(self.data):return b''
        value=self.data[self.offset:self.offset+size];self.offset+=len(value);return value

class Opener:
    def __init__(self, factory):self.factory=factory;self.calls=[]
    def open(self, request, timeout=0):
        self.calls.append((request.full_url,timeout))
        return self.factory(request.full_url)

class ReviewedSourceTests(TestCase):
    def setUp(self):
        self.temporary=tempfile.TemporaryDirectory();self.addCleanup(self.temporary.cleanup)
        self.root=Path(self.temporary.name)
        self.config={'root':str(self.root/'store'),'collections':['sources','root-filesystems'],
                     'maximum_archive_bytes':1024*1024}
        self.configpath=self.root/'config.json';self.configpath.write_text(json.dumps(self.config))
        self.override=override_settings(ARCHIVE_MIRROR_CONFIGURATION=str(self.configpath));self.override.enable();self.addCleanup(self.override.disable)

    def manifest(self, records, identity='2026-10'):
        path=self.root/(identity.replace('/','-')+'.json')
        path.write_text(json.dumps({'schema':1,'pin_set':identity,'date':'2026-10-01','sources':records},
                                   sort_keys=True,separators=(',',':')))
        return path

    def record(self,data=b'exact source',package='example',source='release',
               url='https://upstream.example/example.tar.gz'):
        return {'package':package,'source':source,'url':url,'sha256':hashlib.sha256(data).hexdigest()}

    def test_canonical_download_publishes_exact_digest(self):
        data=b'exact source';record=self.record(data);opener=Opener(lambda url:Response(data,url))
        pin_set,archives=populate(self.manifest([record]),opener)
        self.assertTrue(pin_set.active);self.assertTrue(pin_set.complete);self.assertEqual(len(opener.calls),1)
        self.assertEqual(archives[0].digest,record['sha256'])
        self.assertEqual((self.root/'store/objects'/record['sha256']).read_bytes(),data)

    def test_already_present_digest_avoids_upstream(self):
        data=b'exact source';record=self.record(data)
        local=self.root/'source';local.write_bytes(data)
        archive=store.publish(local,'sources','source',{'import':'local'})
        opener=Opener(lambda url:(_ for _ in ()).throw(AssertionError('network used')))
        pin_set,archives=populate(self.manifest([record]),opener)
        self.assertEqual(opener.calls,[]);self.assertEqual(archives[0].pk,archive.pk);self.assertTrue(pin_set.active)

    def test_wrong_bytes_rejected_without_publication(self):
        record=self.record(b'expected');opener=Opener(lambda url:Response(b'wrong',url))
        with self.assertRaisesRegex(ValueError,'checksum'):
            populate(self.manifest([record]),opener)
        self.assertFalse(Archive.objects.exists())
        self.assertFalse(SourcePinSet.objects.get().complete)

    def test_redirect_rejected(self):
        data=b'exact';record=self.record(data)
        opener=Opener(lambda url:Response(data,url,'https://cdn.example/exact'))
        with self.assertRaisesRegex(ValueError,'redirect'):
            populate(self.manifest([record]),opener)
        self.assertFalse(Archive.objects.exists())

    def test_interrupted_download_has_no_published_partial(self):
        data=b'x'*10;record=self.record(data)
        opener=Opener(lambda url:Response(data,url,fail_after=True))
        with self.assertRaises(OSError):populate(self.manifest([record]),opener)
        self.assertFalse(Archive.objects.exists())
        objects=self.root/'store/objects'
        self.assertFalse(objects.exists() and any(objects.iterdir()))

    def test_duplicate_bytes_deduplicate_and_keep_multiple_declarations(self):
        data=b'same';digest=hashlib.sha256(data).hexdigest()
        records=[
            {'package':'one','source':'release','url':'https://upstream.example/one.tar.gz','sha256':digest},
            {'package':'two','source':'vendor','url':'https://upstream.example/two.tar.gz','sha256':digest},
        ]
        opener=Opener(lambda url:Response(data,url))
        pin_set,archives=populate(self.manifest(records),opener)
        self.assertEqual(len(opener.calls),1);self.assertEqual(Archive.objects.count(),1)
        self.assertEqual(ReviewedSource.objects.filter(pin_set=pin_set).count(),2)
        self.assertEqual(archives[0].pk,archives[1].pk)

    def test_credentials_and_unsupported_schemes_rejected(self):
        good=self.record()
        for url in ('https://user:secret@upstream.example/a.tar.gz','http://upstream.example/a.tar.gz',
                    'file:///tmp/a','https://upstream.example/a.tar.gz?token=secret'):
            bad=dict(good,url=url)
            with self.assertRaises(ValueError):decode_manifest(self.manifest([bad],str(uuid.uuid4())).read_bytes())
        self.assertFalse(Archive.objects.exists())

    def test_catalogue_exposes_bounded_safe_reviewed_provenance(self):
        data=b'exact';record=self.record(data)
        pin_set,archives=populate(self.manifest([record]),Opener(lambda url:Response(data,url)))
        from zog.archive_mirror.views import item
        value=item(archives[0])
        self.assertEqual(value['reviewed_sources'][0]['canonical_url'],record['url'])
        self.assertEqual(value['reviewed_sources'][0]['pin_set'],pin_set.identity)
        self.assertTrue(value['reviewed_sources'][0]['complete'])
        self.assertTrue(value['reviewed_sources'][0]['active'])
        from django.http import JsonResponse
        self.assertNotIn('secret',JsonResponse(value).content.decode('utf-8'))

    def test_active_pin_set_protects_pruning(self):
        data=b'exact';record=self.record(data)
        pin_set,archives=populate(self.manifest([record]),Opener(lambda url:Response(data,url)))
        archive=archives[0];store.prune()
        self.assertTrue(Archive.objects.filter(pk=archive.pk).exists())
        deactivate(pin_set.identity);store.prune()
        self.assertFalse(Archive.objects.filter(pk=archive.pk).exists())
        self.assertFalse((self.root/'store/objects'/record['sha256']).exists())

    def test_failed_multi_source_population_survives_prune_and_resumes(self):
        first=b'first exact';second=b'second exact'
        one=self.record(first,package='one',url='https://upstream.example/one.tar.gz')
        two=self.record(second,package='two',url='https://upstream.example/two.tar.gz')
        manifest=self.manifest([one,two],'recovery-set')
        def initial(url):
            if url==one['url']:return Response(first,url)
            raise OSError('second source unavailable')
        with self.assertRaises(OSError):
            populate(manifest,Opener(initial))
        pin_set=SourcePinSet.objects.get(identity='recovery-set')
        self.assertFalse(pin_set.complete);self.assertFalse(pin_set.active)
        self.assertEqual(ReviewedSource.objects.filter(pin_set=pin_set).count(),1)
        first_archive=Archive.objects.get(digest=one['sha256'])
        self.assertTrue(first_archive.managed)
        store.prune()
        self.assertTrue(Archive.objects.filter(pk=first_archive.pk).exists())
        resumed=Opener(lambda url: Response(second,url) if url==two['url']
                       else (_ for _ in ()).throw(AssertionError('completed source downloaded again')))
        pin_set,archives=populate(manifest,resumed)
        self.assertTrue(pin_set.complete);self.assertTrue(pin_set.active)
        self.assertEqual([call[0] for call in resumed.calls],[two['url']])
        self.assertEqual({archive.digest for archive in archives},{one['sha256'],two['sha256']})

    def test_crash_after_publication_before_membership_reuses_object(self):
        data=b'published before catalogue membership';record=self.record(data)
        manifest=self.manifest([record],'publication-recovery')
        with patch.object(ReviewedSource.objects,'get_or_create',side_effect=RuntimeError('catalogue failure')):
            with self.assertRaises(RuntimeError):
                populate(manifest,Opener(lambda url:Response(data,url)))
        archive=Archive.objects.get(digest=record['sha256'])
        self.assertFalse(archive.managed)
        self.assertFalse(ReviewedSource.objects.exists())
        self.assertFalse(SourcePinSet.objects.get(identity='publication-recovery').complete)
        store.prune()
        self.assertTrue(Archive.objects.filter(pk=archive.pk).exists())
        no_network=Opener(lambda url:(_ for _ in ()).throw(AssertionError('published object downloaded again')))
        pin_set,archives=populate(manifest,no_network)
        self.assertEqual(no_network.calls,[])
        self.assertTrue(pin_set.complete);self.assertTrue(pin_set.active)
        archive.refresh_from_db();self.assertTrue(archive.managed)
        self.assertEqual(ReviewedSource.objects.filter(pin_set=pin_set).count(),1)

    def test_incomplete_pin_set_requires_abandon_not_release(self):
        first=b'first exact';second=b'second exact'
        one=self.record(first,package='one',url='https://upstream.example/one.tar.gz')
        two=self.record(second,package='two',url='https://upstream.example/two.tar.gz')
        manifest=self.manifest([one,two],'abandon-set')
        with self.assertRaises(OSError):
            populate(manifest,Opener(lambda url:Response(first,url) if url==one['url']
                                    else (_ for _ in ()).throw(OSError('unavailable'))))
        with self.assertRaisesRegex(ValueError,'Incomplete'):
            deactivate('abandon-set')
        self.assertEqual(abandon('abandon-set'),'abandon-set')
        self.assertFalse(SourcePinSet.objects.filter(identity='abandon-set').exists())
        self.assertFalse(ReviewedSource.objects.exists())
        store.prune()
        self.assertFalse(Archive.objects.filter(digest=one['sha256']).exists())

    def test_same_digest_across_pin_sets_reuses_one_object(self):
        data=b'shared reviewed source';record=self.record(data)
        first,_=populate(self.manifest([record],'pin-one'),Opener(lambda url:Response(data,url)))
        no_network=Opener(lambda url:(_ for _ in ()).throw(AssertionError('shared digest downloaded again')))
        second,_=populate(self.manifest([record],'pin-two'),no_network)
        self.assertEqual(no_network.calls,[]);self.assertEqual(Archive.objects.count(),1)
        deactivate(first.identity);store.prune()
        self.assertEqual(Archive.objects.count(),1)
        deactivate(second.identity);store.prune()
        self.assertEqual(Archive.objects.count(),0)

    def test_retry_cleans_stale_download_for_digest(self):
        data=b'exact source';record=self.record(data)
        directory=self.root/'store'/'source-downloads';directory.mkdir(parents=True)
        stale=directory/(record['sha256']+'.stale');stale.write_bytes(b'partial')
        populate(self.manifest([record],'stale-download'),Opener(lambda url:Response(data,url)))
        self.assertFalse(stale.exists())
        self.assertEqual(list(directory.iterdir()),[])

    def test_keyed_source_lock_serializes_same_identity(self):
        entered=threading.Event();release=threading.Event();second=threading.Event()
        errors=[]
        def first():
            try:
                with store.named_lock('source-object','same-digest'):
                    entered.set();release.wait(2)
            except Exception as error:errors.append(error)
        def later():
            try:
                entered.wait(2)
                with store.named_lock('source-object','same-digest'):
                    second.set()
            except Exception as error:errors.append(error)
        one=threading.Thread(target=first);two=threading.Thread(target=later)
        one.start();self.assertTrue(entered.wait(2));two.start()
        self.assertFalse(second.wait(0.1))
        release.set();self.assertTrue(second.wait(2))
        one.join(2);two.join(2)
        self.assertEqual(errors,[])

    def test_database_rejects_active_incomplete_pin_set(self):
        with self.assertRaises(IntegrityError):
            with transaction.atomic():
                SourcePinSet.objects.create(
                    identity='invalid-active',pin_date='2026-10-01',
                    manifest_sha256='0'*64,complete=False,active=True)
