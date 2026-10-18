import json
import os
from unittest.mock import patch
from django.test import TestCase
from . import test_mirror
from zog.archive_mirror.observation import observe
from zog.archive_mirror.models import Archive, Snapshot
from zog.archive_mirror import store


class ObservationTests(TestCase):
    setUp = test_mirror.MirrorTests.setUp
    set_intent = test_mirror.MirrorTests.set_intent
    publish = test_mirror.MirrorTests.publish

    def test_sources_rootfs_and_physical_dedup(self):
        a=self.publish()
        Snapshot.objects.create(archive=a,source='example',month='2026-09',commit='a'*40)
        b=self.publish(target='root-filesystems',kind='root-filesystem')
        b.provenance={'import':'local','release_approved':False,'password':'private-fixture','url':'https://secret@private.test'};b.save()
        result=observe();summary=result['summary']
        self.assertEqual(len(result['items']),2)
        self.assertEqual(summary['logical_bytes'],a.size*2)
        self.assertEqual(summary['unique_content_bytes'],a.size)
        info=(self.root/'store/objects'/a.digest).stat()
        self.assertEqual(summary['allocated_object_bytes'],info.st_blocks*512)
        self.assertEqual(len(summary['filesystems']),1)
        self.assertEqual(result['items'][0]['name'],'example')
        self.assertEqual(result['items'][1]['approval'],'unapproved')
        for secret in ['private-fixture','secret@','password','url']:self.assertNotIn(secret,json.dumps(result))

    def test_unavailable_is_not_empty_and_retained_after_withdrawal(self):
        self.assertEqual(observe()['status'],'unavailable')
        a=self.publish();self.set_intent(selected=False)
        result=observe();self.assertFalse(result['serving']);self.assertEqual(result['status'],'ok');self.assertEqual(len(result['items']),1)
        self.assertTrue((self.root/'store/objects'/a.digest).exists())
        Archive.objects.all().delete();self.assertEqual(observe()['items'],[])
        self.assertGreater(observe()['summary']['allocated_object_bytes'],0) # orphan counted

    def test_missing_corrupt_and_symlink_objects(self):
        a=self.publish();path=self.root/'store/objects'/a.digest
        path.unlink();self.assertEqual(observe()['items'][0]['availability'],'missing')
        path.write_bytes(b'bad');self.assertEqual(observe()['items'][0]['availability'],'size-mismatch')
        path.unlink();path.symlink_to(self.input)
        result=observe();self.assertEqual(result['items'][0]['availability'],'unknown');self.assertIsNone(result['summary']['allocated_object_bytes'])

    def test_scan_bound_and_measurement_failure(self):
        self.publish()
        with patch('zog.archive_mirror.observation.MAX_ITEMS',0):self.assertEqual(observe()['status'],'limit-exceeded')
        with patch('zog.archive_mirror.observation.os.fstatvfs',side_effect=OSError('private-path')):
            result=observe();self.assertIsNone(result['summary']['filesystems'][0]['available_bytes']);self.assertNotIn('private-path',json.dumps(result))

    def test_hardlinks_count_allocation_once(self):
        a=self.publish();os.link(self.root/'store/objects'/a.digest,self.root/'store/objects'/('f'*64))
        result=observe();self.assertEqual(result['summary']['allocated_object_bytes'],(self.root/'store/objects'/a.digest).stat().st_blocks*512)

    def test_download_catalogue_redacts_arbitrary_provenance(self):
        from zog.archive_mirror.views import item
        a=self.publish();a.provenance={'password':'private-fixture','url':'https://secret@host.test','commit':'c'*40,'release_approved':False}
        result=item(a)
        self.assertEqual(result['provenance'],{'commit':'c'*40,'release_approved':False})
        self.assertNotIn('private-fixture',str(result))
