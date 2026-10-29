import json
import tempfile
from pathlib import Path

from django.test import SimpleTestCase, override_settings

from zog.archive_mirror.config import configuration
from zog.archive_mirror.credentials import (
    ArchiveCredentialConfigurationError, inventory,
)


class ArchiveCredentialBoundaryTests(SimpleTestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)
        self.keyring=self.root/"public-keyring.json"
        self.keyring.write_text('{"version":1,"keys":{"one":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}}')
        self.base={
            "root":str(self.root/"store"),
            "collections":["sources","root-filesystems"],
            "host_id":"00000000-0000-4000-8000-000000000001",
            "intent_file":str(self.root/"mirror-intent.json"),
            "endpoint":"https://mirror.example.test",
            "issuer":"https://registry.example.test",
            "audience":"zog-archive-mirror",
            "keyring":str(self.keyring),
            "sources":[],
        }

    def configured(self,value):
        path=self.root/"configuration.json"
        path.write_text(json.dumps(value))
        return override_settings(ARCHIVE_MIRROR_CONFIGURATION=str(path))

    def test_inventory_is_sanitized_and_has_no_https_secret_purpose(self):
        with self.configured(self.base):
            value=inventory(configuration())
        self.assertEqual(value["schema"],"zog-archive-mirror-credential-inventory-v1")
        self.assertEqual(value["provider"]["https_delivery_purposes"],[])
        self.assertFalse(value["provider"]["archive_owned_service_secret"])
        self.assertFalse(value["provider"]["upstream_credentials_configured"])
        self.assertEqual(
            value["access_authorization"]["delivery"],
            "existing-authenticated-host-response",
        )
        self.assertEqual(
            value["classes"]["token-issuer-signing-key"]["transport"],
            "never-distribute-to-mirror",
        )
        serialized=json.dumps(value)
        self.assertNotIn(str(self.root),serialized)
        for secret in ("do-not-store","hidden","user:password"):
            self.assertNotIn(secret,serialized)

    def test_secret_configuration_fields_are_rejected(self):
        attempts=[
            {**self.base,"token":"do-not-store"},
            {**self.base,"password":"do-not-store"},
            {**self.base,"signing_key":"/secret/issuer.pem"},
            {**self.base,"credentials":{"provider":"shared"}},
            {**self.base,"sources":[{
                "name":"private","url":"https://upstream.example/project.git",
                "branch":"main","token":"hidden",
            }]},
        ]
        for value in attempts:
            with self.subTest(keys=set(value)-set(self.base)),self.configured(value):
                with self.assertRaises(ArchiveCredentialConfigurationError):
                    configuration()

    def test_credential_bearing_origins_are_rejected(self):
        for field,value in (
            ("endpoint","https://user:password@mirror.example.test"),
            ("issuer","https://user:password@registry.example.test"),
        ):
            changed={**self.base,field:value}
            with self.subTest(field=field),self.configured(changed):
                with self.assertRaises(ArchiveCredentialConfigurationError):
                    configuration()

    def test_current_upstream_collection_credentials_remain_unsupported(self):
        changed={**self.base,"sources":[{
            "name":"private",
            "url":"https://user:password@upstream.example/project.git",
            "branch":"main",
        }]}
        with self.configured(changed):
            with self.assertRaises(ArchiveCredentialConfigurationError):
                configuration()

    def test_unknown_configuration_field_cannot_become_secret_side_channel(self):
        changed={**self.base,"future_provider_auth":{"value":"secret"}}
        with self.configured(changed):
            with self.assertRaisesRegex(
                ArchiveCredentialConfigurationError,"unknown archive configuration"
            ):
                configuration()
