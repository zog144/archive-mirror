import base64
import hashlib
import json
import os
import shutil
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from zog.archive_mirror.storage_ownership import (
    StorageOwnershipError, bind, inspect, observe, runtime_guard, MARKER,
)
from zog.archive_mirror.store_verification import export_catalogue
from tests.test_store_verification import fixture


@unittest.skipIf(os.geteuid() == 0, "ownership contract tests require an unprivileged runner")
class StorageOwnershipTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.base=Path(self.tmp.name)
        source=self.base/'source';source.mkdir()
        database,store,self.digest=fixture(source)
        self.root=self.base/'archive-data';self.root.mkdir(mode=0o700)
        shutil.copytree(store,self.root/'store')
        export_catalogue(database,self.root/'catalogue.sqlite3')
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

    def groups(self):
        return patch('zog.archive_mirror.storage_ownership.os.getgroups',
                     return_value=[self.gid])

    def call_bind(self):
        with self.groups():
            return bind(self.root,**self.values)

    def call_guard(self):
        with self.groups():
            return runtime_guard(self.root)

    def call_observe(self):
        with self.groups():
            return observe(self.root)

    def test_binding_is_immutable_identity_not_mutable_store_snapshot(self):
        binding=self.call_bind()
        before=self.call_observe()
        self.assertEqual(binding['schema'],'zog-archive-storage-ownership-v2')
        self.assertNotIn('catalogue_sha256',binding)
        self.assertNotIn('object_manifest_sha256',binding)
        self.assertEqual(binding['binding']['storage_id'],'b'*32)
        self.assertEqual(binding['binding']['grant_id'],'a'*32)
        self.assertTrue(binding['mirror_role_data_persistent'])
        marker_bytes=(self.root/MARKER).read_bytes()

        data=b'legitimate archive added after ownership binding'
        digest=hashlib.sha256(data).hexdigest()
        (self.root/'store/objects'/digest).write_bytes(data)
        with sqlite3.connect(self.root/'catalogue.sqlite3') as db:
            db.execute(
                "INSERT INTO archive_mirror_archive "
                "(id,collection,digest,size,kind,managed,provenance,created) "
                "VALUES (2,?,?,?,?,?,?,?)",
                ('root-filesystems',digest,len(data),'root-filesystem',0,'{}','2026-10-12'),
            )

        self.assertEqual(self.call_guard(),binding)
        after=self.call_observe()
        self.assertNotEqual(after['catalogue_sha256'],before['catalogue_sha256'])
        self.assertNotEqual(after['object_manifest_sha256'],before['object_manifest_sha256'])
        self.assertEqual(after['counts']['archives'],before['counts']['archives']+1)
        self.assertEqual((self.root/MARKER).read_bytes(),marker_bytes)
        self.assertEqual(self.call_bind(),binding)

    def test_full_verify_can_compare_expected_controller_binding(self):
        binding=self.call_bind()
        with self.groups():
            result=inspect(self.root,**self.values)
        self.assertEqual(result['ownership'],binding)
        self.assertEqual(result['observation']['counts']['pins'],1)
        with self.groups(),self.assertRaisesRegex(StorageOwnershipError,'expected grant'):
            inspect(self.root,**{**self.values,'storage_id':'c'*32})

    def test_wrong_grant_or_supplementary_station_group_blocks_runtime(self):
        self.call_bind()
        with patch('zog.archive_mirror.storage_ownership.os.geteuid',return_value=self.uid+100),self.groups():
            with self.assertRaisesRegex(StorageOwnershipError,'bound archive grant'):
                runtime_guard(self.root)
        with patch('zog.archive_mirror.storage_ownership.os.getgroups',
                   return_value=[self.gid,self.gid+101]):
            with self.assertRaisesRegex(StorageOwnershipError,'supplementary'):
                runtime_guard(self.root)

    def test_station_credentials_or_unreviewed_state_cannot_enter_archive_data(self):
        self.call_bind()
        secret=self.root/'deployment-secrets.json'
        secret.write_text('station secret')
        with self.groups(),self.assertRaisesRegex(StorageOwnershipError,'station or unreviewed'):
            runtime_guard(self.root)

    def test_host_discover_credential_tree_and_external_keyring_are_rejected(self):
        self.call_bind()
        config=json.loads((self.root/'configuration.json').read_text())
        for key,value in (
            ('intent_file','/var/lib/host-discover/credentials/mirror-intent.json'),
            ('keyring','/var/lib/host-discover/credentials/keyring.json'),
        ):
            changed=dict(config);changed[key]=value
            (self.root/'configuration.json').write_text(json.dumps(changed))
            with self.subTest(key=key),self.groups(),self.assertRaises(StorageOwnershipError):
                runtime_guard(self.root)
        (self.root/'configuration.json').write_text(json.dumps(config))

    def test_role_withdrawal_is_not_storage_deletion(self):
        before=(self.root/'store/objects'/self.digest).read_bytes()
        binding=self.call_bind()
        self.assertEqual(self.call_guard(),binding)
        self.assertEqual((self.root/'store/objects'/self.digest).read_bytes(),before)

    def test_matching_complete_migration_origin_is_immutable(self):
        marker=self.root/'.zog-state-migration.json'
        marker.write_text(json.dumps({
            'schema':'zog-station-state-migration-v1','state':'complete',
            'binding':{'storage_ids':['c'*32,'b'*32]},
        }))
        binding=self.call_bind()
        self.assertIsNotNone(binding['migration_evidence_sha256'])
        marker.write_text(json.dumps({
            'schema':'zog-station-state-migration-v1','state':'complete',
            'binding':{'storage_ids':['d'*32,'b'*32]},
        }))
        with self.groups(),self.assertRaisesRegex(StorageOwnershipError,'origin changed'):
            runtime_guard(self.root)

    def test_marker_mode_and_top_level_dac_are_enforced(self):
        self.call_bind()
        self.assertEqual((self.root/MARKER).stat().st_mode & 0o777,0o600)
        (self.root/'configuration.json').chmod(0o666)
        with self.groups(),self.assertRaisesRegex(StorageOwnershipError,'world-writable'):
            runtime_guard(self.root)
