import base64
import json
import os
import stat
import tempfile
import time
import uuid
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from django.test import TestCase,override_settings

from zog.host_identify import archive_credentials,credential_delivery,signatures
from zog.archive_mirror import provider_credentials,store
from zog.archive_mirror.models import Archive


class ProviderCredentialTests(TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.base=Path(self.tmp.name)
        self.root=self.base/"store"
        self.host=str(uuid.uuid4())
        self.intent=self.base/"intent.json"
        self.config={
            "root":str(self.root),
            "collections":["sources","root-filesystems"],
            "host_id":self.host,
            "intent_file":str(self.intent),
            "endpoint":"https://mirror.example.test",
        }
        self.config_path=self.base/"configuration.json"
        self.config_path.write_text(json.dumps(self.config))
        self.override=override_settings(
            ARCHIVE_MIRROR_CONFIGURATION=str(self.config_path)
        );self.override.enable();self.addCleanup(self.override.disable)
        self.host_key=Ed25519PrivateKey.generate()
        self.set_role()
        self.scope={
            "schema":archive_credentials.PROVIDER_SCOPE_SCHEMA,
            "host_id":self.host,
            "host_fingerprint":signatures.fingerprint(self.host_key.public_key()),
            "installation_id":str(uuid.uuid4()),
            "state_volume_id":str(uuid.uuid4()),
            "registry_id":"hosts",
            "provider_id":"canonical-upstream",
            "provider_origin":"https://provider.example.test",
            "provider_role":archive_credentials.PROVIDER_ROLE,
            "role_revision":7,
            "collections":["sources"],
            "operations":["fetch"],
            "provider_credential_id":"source-read",
            "credential_revision":3,
        }

    def set_role(self,selected=True,revision=7,host_id=None):
        self.intent.write_text(json.dumps({
            "version":1,
            "host_id":host_id or self.host,
            "desired":{
                "version":1,"selected":selected,"revision":revision,
                "endpoint":"https://mirror.example.test" if selected else "",
                "lease_expires_at":int(time.time())+900,
                "retain_archives":True,
            },
        }))
        self.intent.chmod(0o640)

    def exchange(self,secret=b"provider-secret",scope=None,now=None,
                 action="deliver",previous_delivery_id=None):
        scope=scope or self.scope
        now=int(time.time()) if now is None else now
        selected=archive_credentials.provider_scope(scope)
        binding=archive_credentials.provider_binding(scope)
        authorization={
            "schema":credential_delivery.AUTHORIZATION_SCHEMA,
            "issuer":"https://authority.example.test",
            **binding,
            "credential_revision":selected["credential_revision"],
            "authorization_id":str(uuid.uuid4()),
            "revision":2,
            "status":"approved",
            "approved_at":now-30,
            "revoked_at":None,
            "expires_at":now+3600,
        }
        request=archive_credentials.request(
            scope,authorization,request_id=str(uuid.uuid4()),action=action,
            previous_delivery_id=previous_delivery_id,
            created_at=now,expires_at=now+90,
        )
        delivery={
            "schema":credential_delivery.DELIVERY_SCHEMA,
            "request_id":request["request_id"],
            "delivery_id":str(uuid.uuid4()),
            "authorization_id":authorization["authorization_id"],
            "authorization_revision":authorization["revision"],
            "credential_id":binding["credential_id"],
            "credential_revision":selected["credential_revision"],
            "consumer":binding["consumer"],
            "purpose":binding["purpose"],
            "issued_at":now,
            "expires_at":now+90,
            "secret_format":"base64",
            "secret":base64.b64encode(secret).decode("ascii"),
        }
        return authorization,request,delivery

    def install(self,secret=b"provider-secret",scope=None):
        scope=scope or self.scope
        authorization,request,delivery=self.exchange(secret,scope)
        result=provider_credentials.install_verified(
            scope,authorization,request,delivery,now=time.time()
        )
        return result,authorization,request,delivery

    def test_installs_private_provider_secret_and_returns_nonsecret_receipt_material(self):
        result,authorization,request,delivery=self.install()
        self.assertEqual(result["status"],"installed")
        self.assertFalse(result["replayed"])
        directory=self.root/"provider-credentials"
        self.assertEqual(stat.S_IMODE(directory.stat().st_mode),0o700)
        secret=directory/(result["scope_id"]+".secret")
        self.assertEqual(stat.S_IMODE(secret.stat().st_mode),0o600)
        self.assertEqual(secret.read_bytes(),b"provider-secret")
        metadata=(directory/(result["scope_id"]+".json")).read_text()
        self.assertNotIn("provider-secret",metadata)
        self.assertNotIn(delivery["secret"],metadata)
        with provider_credentials.open_for(
            self.scope,operation="fetch",collection="sources"
        ) as source:
            self.assertEqual(source.read(),b"provider-secret")

    def test_same_delivery_is_idempotent_without_replacing_secret(self):
        result,authorization,request,delivery=self.install()
        path=self.root/"provider-credentials"/(result["scope_id"]+".secret")
        inode=path.stat().st_ino
        replay=provider_credentials.install_verified(
            self.scope,authorization,request,delivery,now=time.time()
        )
        self.assertTrue(replay["replayed"])
        self.assertEqual(path.stat().st_ino,inode)

    def test_wrong_collection_and_operation_are_denied(self):
        self.install()
        with self.assertRaises(provider_credentials.ProviderCredentialError):
            provider_credentials.open_for(
                self.scope,operation="download",collection="sources"
            )
        with self.assertRaises(provider_credentials.ProviderCredentialError):
            provider_credentials.open_for(
                self.scope,operation="fetch",collection="root-filesystems"
            )

    def test_role_withdrawal_blocks_secret_but_retains_archive_contents(self):
        self.install()
        incoming=self.base/"source.bin";incoming.write_bytes(b"retained")
        archive=store.publish(
            incoming,"sources","source",{"test":True},
            source="credential-test",month="2026-10",commit="one",
        )
        object_path=self.root/"objects"/archive.digest
        self.assertTrue(object_path.exists())
        self.set_role(selected=False,revision=8)
        with self.assertRaises(provider_credentials.ProviderCredentialError):
            provider_credentials.open_for(
                self.scope,operation="fetch",collection="sources"
            )
        self.assertTrue(object_path.exists())
        self.assertTrue(Archive.objects.filter(pk=archive.pk).exists())

    def test_identity_and_role_revision_changes_fail_closed(self):
        self.install()
        self.set_role(revision=8)
        with self.assertRaisesRegex(
            provider_credentials.ProviderCredentialError,"role binding changed"
        ):
            provider_credentials.open_for(
                self.scope,operation="fetch",collection="sources"
            )
        self.set_role(revision=7,host_id=str(uuid.uuid4()))
        with self.assertRaises(provider_credentials.ProviderCredentialError):
            provider_credentials.open_for(
                self.scope,operation="fetch",collection="sources"
            )

    def test_expired_or_revoked_common_authorization_not_installable(self):
        now=int(time.time())
        authorization,request,delivery=self.exchange(now=now)
        authorization["expires_at"]=now-1
        with self.assertRaises(credential_delivery.CredentialProtocolError):
            provider_credentials.install_verified(
                self.scope,authorization,request,delivery,now=now+10
            )
        authorization,request,delivery=self.exchange(now=now)
        authorization["status"]="revoked";authorization["revoked_at"]=now
        with self.assertRaises(credential_delivery.CredentialProtocolError):
            provider_credentials.install_verified(
                self.scope,authorization,request,delivery,now=now
            )

    def test_inspect_is_secret_free_and_survives_reopen(self):
        result,_,_,delivery=self.install()
        status=provider_credentials.inspect(self.scope)
        self.assertEqual(status["status"],"installed")
        encoded=json.dumps(status)
        self.assertNotIn("provider-secret",encoded)
        self.assertNotIn(delivery["secret"],encoded)
        with provider_credentials.open_for(
            dict(self.scope),operation="fetch",collection="sources"
        ) as source:
            self.assertEqual(source.read(),b"provider-secret")

    def test_scope_rotation_requires_higher_credential_revision(self):
        first,_,_,first_delivery=self.install(b"old-secret")
        rotated={**self.scope,"credential_revision":4}
        authorization,request,delivery=self.exchange(
            b"new-secret",rotated,action="renew",
            previous_delivery_id=first_delivery["delivery_id"],
        )
        result=provider_credentials.install_verified(
            rotated,authorization,request,delivery,now=time.time()
        )
        self.assertEqual(result["scope_id"],first["scope_id"])
        with provider_credentials.open_for(
            rotated,operation="fetch",collection="sources"
        ) as source:
            self.assertEqual(source.read(),b"new-secret")
        with self.assertRaises(provider_credentials.ProviderCredentialError):
            provider_credentials.open_for(
                self.scope,operation="fetch",collection="sources"
            )


    def test_rotation_must_chain_exact_previous_delivery(self):
        first,_,_,first_delivery=self.install(b"old-secret")
        rotated={**self.scope,"credential_revision":4}
        authorization,request,delivery=self.exchange(
            b"new-secret",rotated,action="deliver"
        )
        with self.assertRaisesRegex(
            provider_credentials.ProviderCredentialError,"rotation is not chained"
        ):
            provider_credentials.install_verified(
                rotated,authorization,request,delivery,now=time.time()
            )
        authorization,request,delivery=self.exchange(
            b"new-secret",rotated,action="renew",
            previous_delivery_id=str(uuid.uuid4()),
        )
        with self.assertRaisesRegex(
            provider_credentials.ProviderCredentialError,"rotation is not chained"
        ):
            provider_credentials.install_verified(
                rotated,authorization,request,delivery,now=time.time()
            )

    def test_host_installation_state_and_registry_identity_changes_reject_existing_secret(self):
        result,_,_,delivery=self.install()
        original=(self.root/"provider-credentials"/(result["scope_id"]+".secret")).read_bytes()
        changes=(
            {"host_fingerprint":"a"*64},
            {"installation_id":str(uuid.uuid4())},
            {"state_volume_id":str(uuid.uuid4())},
            {"registry_id":"other-registry"},
        )
        for changed in changes:
            with self.subTest(changed=tuple(changed)):
                other={**self.scope,**changed}
                # The provider scope stays constant while the canonical
                # destination binding differs; neither may authorize reuse.
                self.assertEqual(
                    archive_credentials.provider_scope(other)["scope_id"],
                    result["scope_id"],
                )
                with self.assertRaisesRegex(
                    provider_credentials.ProviderCredentialError,
                    "does not match scope",
                ):
                    provider_credentials.open_for(
                        other,operation="fetch",collection="sources",
                    )
                self.assertEqual(provider_credentials.inspect(other)["status"],"blocked")
        self.assertEqual(
            (self.root/"provider-credentials"/(result["scope_id"]+".secret")).read_bytes(),
            original,
        )

    def test_changed_state_cannot_adopt_credential_by_rotation(self):
        result,_,_,previous=self.install()
        moved={
            **self.scope,
            "state_volume_id":str(uuid.uuid4()),
            "credential_revision":4,
        }
        authorization,request,delivery=self.exchange(
            b"replacement",moved,action="renew",
            previous_delivery_id=previous["delivery_id"],
        )
        with self.assertRaisesRegex(
            provider_credentials.ProviderCredentialError,
            "destination identity changed",
        ):
            provider_credentials.install_verified(
                moved,authorization,request,delivery,now=time.time(),
            )
        with provider_credentials.open_for(
            self.scope,operation="fetch",collection="sources",
        ) as stream:
            self.assertEqual(stream.read(),b"provider-secret")

    def test_tampered_record_identity_fails_closed_without_erasing_secret(self):
        result,_,_,_=self.install()
        directory=self.root/"provider-credentials"
        path=directory/(result["scope_id"]+".json")
        value=json.loads(path.read_text())
        value["installation_id"]=str(uuid.uuid4())
        path.write_text(json.dumps(value))
        self.assertEqual(provider_credentials.inspect(self.scope)["status"],"blocked")
        with self.assertRaises(provider_credentials.ProviderCredentialError):
            provider_credentials.open_for(
                self.scope,operation="fetch",collection="sources",
            )
        self.assertEqual(
            (directory/(result["scope_id"]+".secret")).read_bytes(),
            b"provider-secret",
        )

    def test_wrong_purpose_and_credential_revision_never_install(self):
        authorization,request,delivery=self.exchange()
        authorization["purpose"]="issuer-cloudflare-dns01"
        with self.assertRaises(archive_credentials.ArchiveCredentialPolicyError):
            provider_credentials.install_verified(
                self.scope,authorization,request,delivery,now=time.time(),
            )
        authorization,request,delivery=self.exchange()
        authorization["credential_revision"]+=1
        with self.assertRaises(archive_credentials.ArchiveCredentialPolicyError):
            provider_credentials.install_verified(
                self.scope,authorization,request,delivery,now=time.time(),
            )
        self.assertFalse((self.root/"provider-credentials").exists())

    def test_lower_revision_cannot_replace_rotated_provider_secret(self):
        first,_,_,previous=self.install(b"first")
        rotated={**self.scope,"credential_revision":4}
        authorization,request,delivery=self.exchange(
            b"second",rotated,action="renew",
            previous_delivery_id=previous["delivery_id"],
        )
        provider_credentials.install_verified(
            rotated,authorization,request,delivery,now=time.time(),
        )
        old_auth,old_request,old_delivery=self.exchange(b"old-replay")
        with self.assertRaisesRegex(
            provider_credentials.ProviderCredentialError,
            "revision rollback",
        ):
            provider_credentials.install_verified(
                self.scope,old_auth,old_request,old_delivery,now=time.time(),
            )
        with provider_credentials.open_for(
            rotated,operation="fetch",collection="sources",
        ) as stream:
            self.assertEqual(stream.read(),b"second")

    def test_legacy_v1_record_requires_protected_reprovisioning(self):
        result,_,_,previous=self.install()
        directory=self.root/"provider-credentials"
        record_path=directory/(result["scope_id"]+".json")
        record=json.loads(record_path.read_text())
        record["schema"]="zog-archive-provider-credential-installation-v1"
        for key in ("host_id","host_fingerprint","installation_id",
                    "state_volume_id","registry_id"):
            record.pop(key)
        record_path.write_text(json.dumps(record))
        self.assertEqual(provider_credentials.inspect(self.scope)["status"],"blocked")
        with self.assertRaises(provider_credentials.ProviderCredentialError):
            provider_credentials.open_for(
                self.scope,operation="fetch",collection="sources",
            )
        rotated={**self.scope,"credential_revision":4}
        authorization,request,delivery=self.exchange(
            b"renewal",rotated,action="renew",
            previous_delivery_id=previous["delivery_id"],
        )
        with self.assertRaisesRegex(
            provider_credentials.ProviderCredentialError,
            "invalid provider credential installation record",
        ):
            provider_credentials.install_verified(
                rotated,authorization,request,delivery,now=time.time(),
            )
        self.assertEqual(
            (directory/(result["scope_id"]+".secret")).read_bytes(),
            b"provider-secret",
        )
