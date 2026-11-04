"""Synthetic archive application FD adapter regression, never a live receiver."""
import array
import base64
import hashlib
import json
import os
import socket
import fcntl
import multiprocessing

from django.test import TestCase
from tests.test_provider_credentials import ProviderCredentialTests
from zog.archive_mirror import provider_credential_fd as adapter
from zog.archive_mirror import provider_credentials as private
from zog.host_identify import credential_delivery as cd

class ProviderFDTests(ProviderCredentialTests):
    def make_fd(self, data=b"synthetic-source-only"):
        fd=os.memfd_create("archive-test-secret",os.MFD_ALLOW_SEALING)
        os.write(fd,data)
        fcntl.fcntl(fd,fcntl.F_ADD_SEALS,fcntl.F_SEAL_WRITE|
                    fcntl.F_SEAL_SHRINK|fcntl.F_SEAL_GROW|fcntl.F_SEAL_SEAL)
        return fd

    def admission(self, secret=b"synthetic-source-only", scope=None, *, action="deliver",
                  previous_delivery_id=None):
        scope=scope or self.scope
        auth,request,delivery=self.exchange(secret,scope,action=action,
                                               previous_delivery_id=previous_delivery_id)
        safe={k:v for k,v in delivery.items() if k not in ("secret","secret_format")}
        return dict(schema=adapter.SCHEMA,consumer=adapter.CONSUMER,
            purpose=adapter.PURPOSE,scope=scope,authorization=auth,request=request,
            delivery=safe,owner_fence={
                "status":"installing","request_id":request["request_id"],
                "delivery_id":delivery["delivery_id"],"revoked":False,
                "scope_id":__import__("zog.host_identify.archive_credentials",
                                      fromlist=["provider_scope"]).provider_scope(scope)["scope_id"],
                "authorization_revision":auth["revision"]},
            expected_sha256=hashlib.sha256(secret).hexdigest(),size=len(secret),
            recipient_uid=os.geteuid(),recipient_gid=os.getegid(),
            sender_uid=0,sender_gid=0)

    def test_disabled_and_exact_app_owner(self):
        item=self.admission();fd=self.make_fd()
        try:
            with self.assertRaisesRegex(private.ProviderCredentialError,"disabled"):
                adapter.install_verified_fd(item,fd,protected_scope=self.scope,
                    expected_uid=os.geteuid(),expected_gid=os.getegid())
            with self.assertRaisesRegex(private.ProviderCredentialError,"application UID"):
                adapter.install_verified_fd(item,fd,protected_scope=self.scope,
                    expected_uid=os.geteuid()+1,expected_gid=os.getegid(),enabled=True)
            self.assertFalse((self.root/"provider-credentials").exists())
        finally:os.close(fd)

    def test_real_private_install_from_fd_has_no_secret_in_receipt(self):
        item=self.admission();fd=self.make_fd()
        try:
            result=adapter.install_verified_fd(item,fd,protected_scope=self.scope,
                expected_uid=os.geteuid(),expected_gid=os.getegid(),enabled=True)
        finally:os.close(fd)
        self.assertEqual(result["status"],"installed-receipt-pending")
        self.assertFalse(result["native_acknowledged"])
        self.assertNotIn("synthetic-source-only",json.dumps(result))
        self.assertNotIn("synthetic-source-only",json.dumps(item))
        self.assertEqual(private.inspect(self.scope)["status"],"installed")
        with private.open_for(self.scope,operation="fetch",collection="sources") as stream:
            self.assertEqual(stream.read(),b"synthetic-source-only")
        with self.assertRaises(private.ProviderCredentialError):
            # No second FD transfer even when the original bytes are identical.
            fd=self.make_fd()
            try:adapter.install_verified_fd(item,fd,protected_scope=self.scope,
                expected_uid=os.geteuid(),expected_gid=os.getegid(),enabled=True)
            finally:os.close(fd)

    def test_forged_scope_wrong_purpose_or_unsealed_fd_denied(self):
        item=self.admission()
        fd=self.make_fd()
        try:
            for changed in (
                {**item,"purpose":"issuer-cloudflare-dns01"},
                {**item,"scope":{**self.scope,"installation_id":__import__("uuid").uuid4().hex}},
                {**item,"owner_fence":{**item["owner_fence"],"status":"delivered"}},
                {**item,"expected_sha256":"0"*64},
                {**item,"sender_uid":1001},
            ):
                with self.assertRaises((ValueError,private.ProviderCredentialError)):
                    adapter.install_verified_fd(changed,fd,protected_scope=self.scope,
                        expected_uid=os.geteuid(),expected_gid=os.getegid(),enabled=True)
        finally:os.close(fd)
        unsafe=os.memfd_create("unsafe")
        try:
            os.write(unsafe,b"synthetic-source-only")
            with self.assertRaises(private.ProviderCredentialError):
                adapter.install_verified_fd(item,unsafe,protected_scope=self.scope,
                    expected_uid=os.geteuid(),expected_gid=os.getegid(),enabled=True)
        finally:os.close(unsafe)

    def test_signed_revocation_blocks_application_fd_and_retains_archive_objects(self):
        item=self.admission();fd=self.make_fd()
        try:adapter.install_verified_fd(item,fd,protected_scope=self.scope,
            expected_uid=os.geteuid(),expected_gid=os.getegid(),enabled=True)
        finally:os.close(fd)
        signed,pub=self.signed_revocation(item["authorization"])
        private.apply_signed_revocation(self.scope,signed,pub,
            expected_issuer="https://authority.example.test")
        self.assertEqual(private.inspect(self.scope)["status"],"blocked")
        replacement=self.admission()
        fd=self.make_fd()
        try:
            with self.assertRaises(private.ProviderCredentialError):
                adapter.install_verified_fd(replacement,fd,protected_scope=self.scope,
                    expected_uid=os.geteuid(),expected_gid=os.getegid(),enabled=True)
        finally:os.close(fd)

    def test_separate_process_peer_credentials_cannot_claim_root(self):
        # The CI runner is not root. A real distinct child process is launched:
        # its kernel SO_PEERCRED cannot be manufactured as protected uid 0.
        parent,child=socket.socketpair(socket.AF_UNIX,socket.SOCK_SEQPACKET)
        ctx=multiprocessing.get_context("fork")
        def worker(channel):
            try:
                adapter._receive(channel,sender_uid=0,sender_gid=0)
                os._exit(2)
            except private.ProviderCredentialError:
                os._exit(0)
        proc=ctx.Process(target=worker,args=(child,))
        proc.start();child.close()
        proc.join(8);parent.close()
        self.assertEqual(proc.exitcode,0)
