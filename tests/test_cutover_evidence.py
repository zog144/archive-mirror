import base64
import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from zog.archive_mirror.cutover_evidence import collect
from zog.archive_mirror.storage_ownership import bind
from zog.archive_mirror.store_verification import export_catalogue
from tests.test_store_verification import fixture


@unittest.skipIf(os.geteuid() == 0, "cutover evidence tests require an unprivileged runner")
class CutoverEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.base=Path(self.tmp.name)
        source=self.base/'source';source.mkdir()
        database,store,self.digest=fixture(source)
        self.root=self.base/'archive-data';self.root.mkdir(mode=0o700)
        shutil.copytree(store,self.root/'store')
        export_catalogue(database,self.root/'catalogue.sqlite3')
        (self.root/'store'/'writer.lock').write_bytes(b'')
        (self.root/'public-keyring.json').write_text(json.dumps({
            'version':1,'keys':{'archive-test':base64.b64encode(b'k'*32).decode()}
        }))
        (self.root/'configuration.json').write_text(json.dumps({
            'root':'/var/lib/archive-mirror/store',
            'collections':['sources','root-filesystems'],
            'host_id':'00000000-0000-4000-8000-000000000001',
            'intent_file':'/run/zog-host/mirror-live/mirror-intent.json',
            'endpoint':'https://mirror.example.test',
            'issuer':'https://issuer.example.test',
            'audience':'zog-archive-mirror',
            'keyring':'/var/lib/archive-mirror/public-keyring.json',
            'maximum_archive_bytes':17179869184,
            'sources':[],
        }))
        self.uid=os.geteuid();self.gid=os.getegid()
        self.values=dict(storage_id='b'*32,grant_id='a'*32,grant_version=1,
                         uid=self.uid,gid=self.gid)
        with patch('zog.archive_mirror.storage_ownership.os.getgroups',
                   return_value=[self.gid]):
            bind(self.root,**self.values)

    def groups(self):
        return patch('zog.archive_mirror.storage_ownership.os.getgroups',
                     return_value=[self.gid])

    def test_selected_role_report_is_bounded_and_never_authorizes_cutover(self):
        role=lambda:{
            'desired':{'revision':7,'lease_expires_at':1893456000}
        }
        with self.groups():
            report=collect(self.root,role_reader=role,observed_at=123)
        self.assertTrue(report['valid'])
        self.assertFalse(report['safe_to_cut_over'])
        self.assertEqual(report['observed_at'],123)
        self.assertEqual(report['role'],{
            'available':True,'status':'selected','revision':7,
            'lease_expires_at':1893456000,
        })
        self.assertEqual(report['store']['retention']['pins'],1)
        self.assertEqual(report['store']['retention']['incomplete_source_pin_sets'],1)
        self.assertEqual(report['runtime_identity']['supplementary_groups'],[])
        serialized=json.dumps(report)
        self.assertNotIn('mirror.example.test',serialized)
        self.assertNotIn('public-keyring.json',serialized)
        self.assertNotIn(str(self.root),serialized)

    def test_role_withdrawal_still_reports_retained_archive_state(self):
        with self.groups():
            before=collect(self.root,role_reader=lambda:{
                'desired':{'revision':8,'lease_expires_at':1893456000}
            },observed_at=1)
            after=collect(self.root,role_reader=lambda:(_ for _ in ()).throw(
                ValueError('withdrawn')),observed_at=2)
        self.assertTrue(after['valid'])
        self.assertEqual(after['role'],{'available':False,'status':'unavailable'})
        self.assertEqual(after['store']['catalogue_sha256'],
                         before['store']['catalogue_sha256'])
        self.assertEqual(after['store']['object_manifest_sha256'],
                         before['store']['object_manifest_sha256'])
        self.assertEqual((self.root/'store/objects'/self.digest).read_bytes(),
                         b'the original archive bytes; never re-download')

    def test_writer_lock_is_required_for_consistent_observation(self):
        (self.root/'store'/'writer.lock').unlink()
        with self.groups(),self.assertRaises(FileNotFoundError):
            collect(self.root,role_reader=lambda:{
                'desired':{'revision':1,'lease_expires_at':1893456000}
            })

    def test_identity_drift_blocks_evidence(self):
        with patch('zog.archive_mirror.storage_ownership.os.geteuid',
                   return_value=self.uid+1),self.groups(),self.assertRaises(ValueError):
            collect(self.root,role_reader=lambda:{
                'desired':{'revision':1,'lease_expires_at':1893456000}
            })
