"""Synthetic Linux archive application FD reception: no native grant or secrets."""
import array
import fcntl
import json
import multiprocessing
import os
import socket
import stat
import tempfile
import time
import uuid
from pathlib import Path
from unittest.mock import patch

from django.test import TestCase

from zog.archive_mirror import provider_fd_adapter as appfd
from zog.archive_mirror import provider_credentials
from tests.test_provider_credentials import ProviderCredentialTests


def sealed_secret(data=b"synthetic-provider-secret",*,seal=True):
    fd=os.memfd_create("synthetic-archive-provider",os.MFD_CLOEXEC|os.MFD_ALLOW_SEALING)
    os.write(fd,data)
    if seal:
        fcntl.fcntl(fd,fcntl.F_ADD_SEALS,
                    fcntl.F_SEAL_WRITE|fcntl.F_SEAL_SHRINK|
                    fcntl.F_SEAL_GROW|fcntl.F_SEAL_SEAL)
    return fd


def sender_process(path,payload,data,mode):
    """Different PID, same synthetic nonroot UID; never a privileged daemon."""
    sock=socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET)
    try:
        sock.connect(path)
        if mode=="disk":
            with tempfile.TemporaryFile() as f:
                f.write(data);f.flush()
                sock.sendmsg([payload],[(socket.SOL_SOCKET,socket.SCM_RIGHTS,
                                         array.array("i",[f.fileno()]))])
            return
        fds=[sealed_secret(data,seal=mode!="unsealed")]
        if mode=="multiple":
            fds.append(sealed_secret(data))
        try:
            sock.sendmsg([payload],[(socket.SOL_SOCKET,socket.SCM_RIGHTS,
                                     array.array("i",fds))])
        finally:
            for fd in fds:os.close(fd)
    finally:
        sock.close()


class ApplicationFdTests(TestCase):
    # Reuse the existing provider-role fixture without inheriting its tests.
    set_role = ProviderCredentialTests.set_role

    def setUp(self):
        ProviderCredentialTests.setUp(self)
        self.secret=b"synthetic-provider-secret"
        self.auth,self.request,self.delivery=ProviderCredentialTests.exchange(
            self,secret=self.secret,
        )
        self.metadata={
            **{k:v for k,v in self.delivery.items()
               if k not in ("secret","secret_format")},
            "schema":appfd.METADATA_SCHEMA,
        }
        self.policy={
            "schema":appfd.POLICY_SCHEMA,
            "consumer":appfd.CONSUMER,
            "purpose":appfd.PURPOSE,
            **{k:self.scope[k] for k in (
                "host_id","installation_id","state_volume_id","registry_id",
                "credential_revision",
            )},
            "scope_id":__import__("zog.host_identify.archive_credentials",
                                  fromlist=["provider_scope"]).provider_scope(
                                      self.scope)["scope_id"],
            "authority_revision":self.auth["revision"],
            "app_uid":os.geteuid(),"app_gid":os.getegid(),
            "app_pid":os.getpid(),
            "app_source_sha256":"sha256:"+"b"*64,
            "boot_id":str(uuid.uuid4()),"invocation_id":str(uuid.uuid4()),
        }
        self.state={
            "status":"installing",
            "request_id":self.request["request_id"],
            "delivery_id":self.delivery["delivery_id"],
            "revoked":False,
        }
        self.sender={"pid":os.getpid(),"uid":os.geteuid(),"gid":os.getegid()}
        self.group_patch=patch("zog.archive_mirror.provider_fd_adapter.os.getgroups",
                              return_value=[os.getegid()])
        self.group_patch.start();self.addCleanup(self.group_patch.stop)

    def transfer(self,**updates):
        result={
            "schema":appfd.TRANSFER_SCHEMA,
            "consumer":appfd.CONSUMER,
            "purpose":appfd.PURPOSE,
            "action":"deliver",
            **{k:self.policy[k] for k in (
                "host_id","registry_id","scope_id","installation_id",
                "state_volume_id","boot_id","invocation_id",
                "credential_revision","authority_revision",
            )},
            "request_id":self.request["request_id"],
            "delivery_id":self.delivery["delivery_id"],
        }
        result.update(updates)
        return result

    def send_once(self,*,payload=None,secret=None,sealed=True,
                  multiple=False,policy=None,sender=None,enabled=True,
                  metadata=None,state=None):
        left,right=socket.socketpair(socket.AF_UNIX,socket.SOCK_SEQPACKET)
        fds=[sealed_secret(secret or self.secret,seal=sealed)]
        if multiple:fds.append(sealed_secret(self.secret))
        try:
            left.sendmsg([payload or appfd._canonical(self.transfer())],
                         [(socket.SOL_SOCKET,socket.SCM_RIGHTS,
                           array.array("i",fds))])
            return appfd.receive_verified_fd(
                right,policy=policy or self.policy,
                selected_sender=sender or self.sender,
                scope=self.scope,authorization=self.auth,
                request=self.request,delivery_metadata=metadata or self.metadata,
                handoff_state=state or self.state,enabled=enabled,
            )
        finally:
            left.close();right.close()
            for fd in fds:os.close(fd)

    def test_disabled_by_default_never_installs(self):
        with self.assertRaises(appfd.ApplicationFdHold):
            self.send_once(enabled=False)
        self.assertFalse((self.root/"provider-credentials").exists())

    def test_separate_process_sealed_fd_is_app_owned_and_unattested(self):
        directory=Path(self.tmp.name)
        path=str(directory/"synthetic-archive-fd.sock")
        listener=socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET)
        listener.bind(path);listener.listen(1);listener.settimeout(8)
        context=multiprocessing.get_context("fork")
        child=context.Process(target=sender_process,
            args=(path,appfd._canonical(self.transfer()),self.secret,"sealed"))
        child.start()
        self.sender["pid"]=child.pid
        try:
            sock,_=listener.accept()
            try:
                result=appfd.receive_verified_fd(
                    sock,policy=self.policy,selected_sender=self.sender,
                    scope=self.scope,authorization=self.auth,request=self.request,
                    delivery_metadata=self.metadata,handoff_state=self.state,
                    enabled=True,
                )
            finally: sock.close()
        finally:
            child.join(8)
            if child.is_alive():child.terminate();child.join()
            listener.close()
        self.assertEqual(child.exitcode,0)
        self.assertEqual(result["status"],"installed-unattested")
        self.assertIs(result["native_accepted"],False)
        self.assertEqual(result["delivery_id"],self.delivery["delivery_id"])
        self.assertNotIn("secret",json.dumps(result))
        private=self.root/"provider-credentials"
        self.assertEqual(stat.S_IMODE(private.stat().st_mode),0o700)
        path=private/(result["scope_id"]+".secret")
        self.assertEqual(stat.S_IMODE(path.stat().st_mode),0o600)
        with provider_credentials.open_for(
            self.scope,operation="fetch",collection="sources",
        ) as stream:
            self.assertEqual(stream.read(),self.secret)

    def test_wrong_peer_and_wrong_application_identity_denied(self):
        with self.assertRaises(appfd.ApplicationFdHold):
            self.send_once(sender={**self.sender,"pid":self.sender["pid"]+1})
        with self.assertRaises(appfd.ApplicationFdHold):
            self.send_once(policy={**self.policy,"app_uid":self.policy["app_uid"]+1})
        self.assertFalse((self.root/"provider-credentials").exists())

    def test_scope_authority_and_fence_changes_denied(self):
        for policy in (
            {**self.policy,"purpose":"issuer-cloudflare-dns01"},
            {**self.policy,"scope_id":"a"*64},
            {**self.policy,"authority_revision":self.policy["authority_revision"]+1},
            {**self.policy,"state_volume_id":str(uuid.uuid4())},
            {**self.policy,"credential_revision":self.policy["credential_revision"]+1},
        ):
            with self.subTest(change=policy),self.assertRaises(appfd.ApplicationFdHold):
                self.send_once(policy=policy)
        for state in (
            {**self.state,"status":"delivered"},
            {**self.state,"revoked":True},
            {**self.state,"delivery_id":str(uuid.uuid4())},
        ):
            with self.subTest(state=state),self.assertRaises(appfd.ApplicationFdHold):
                self.send_once(state=state)
        self.assertFalse((self.root/"provider-credentials").exists())

    def test_unsealed_multiple_or_bad_frame_denied_without_install(self):
        with self.assertRaises(appfd.ApplicationFdHold):
            self.send_once(sealed=False)
        with self.assertRaises(appfd.ApplicationFdHold):
            self.send_once(multiple=True)
        with self.assertRaises(appfd.ApplicationFdHold):
            self.send_once(payload=b'{"fake":"control"}')
        with self.assertRaises(appfd.ApplicationFdHold):
            self.send_once(payload=appfd._canonical(
                self.transfer(purpose="different")))
        self.assertFalse((self.root/"provider-credentials").exists())

    def test_wrong_delivery_and_expiry_denied(self):
        with self.assertRaises(appfd.ApplicationFdHold):
            self.send_once(metadata={**self.metadata,
                         "request_id":str(uuid.uuid4())})
        with self.assertRaises(ValueError):
            self.send_once(metadata={**self.metadata,
                         "expires_at":int(time.time())-100})
        self.assertFalse((self.root/"provider-credentials").exists())

    def test_revocation_prevents_fd_installation_without_deleting_archives(self):
        envelope,key=ProviderCredentialTests.signed_revocation(
            self,self.auth,
        )
        provider_credentials.apply_signed_revocation(
            self.scope,envelope,key,expected_issuer=self.auth["issuer"],
            now=time.time(),
        )
        with self.assertRaises(appfd.ApplicationFdHold):
            self.send_once()
        self.assertFalse((self.root/"provider-credentials"/
            (self.policy["scope_id"]+".secret")).exists())

    def test_sealed_memfd_validation_rejects_disk_and_unsealed(self):
        file=Path(self.tmp.name)/"disk-secret"
        file.write_bytes(self.secret)
        with file.open("rb") as stream,self.assertRaises(appfd.ApplicationFdHold):
            appfd.validate_sealed_memfd(stream.fileno())
        fd=sealed_secret(self.secret,seal=False)
        try:
            with self.assertRaises(appfd.ApplicationFdHold):
                appfd.validate_sealed_memfd(fd)
        finally:os.close(fd)

    def test_no_second_fd_even_for_identical_completed_delivery(self):
        first=self.send_once()
        self.assertEqual(first["status"],"installed-unattested")
        before=(self.root/"provider-credentials"/
                (self.policy["scope_id"]+".secret")).stat().st_ino
        with self.assertRaises(appfd.ApplicationFdHold):
            self.send_once()
        self.assertEqual((self.root/"provider-credentials"/
                          (self.policy["scope_id"]+".secret")).stat().st_ino,before)

    def test_pending_fd_installation_blocks_redelivery_even_with_same_delivery(self):
        self.send_once()
        directory=self.root/"provider-credentials"
        marker=directory/(self.policy["scope_id"]+".pending.json")
        marker.write_text(json.dumps({
            "schema":provider_credentials.PENDING_SCHEMA,
            "scope_id":self.policy["scope_id"],
            "credential_id":self.auth["credential_id"],
            "credential_revision":self.auth["credential_revision"],
            "delivery_id":self.delivery["delivery_id"],
        }))
        marker.chmod(0o600)
        with self.assertRaises(appfd.ApplicationFdHold):
            self.send_once()
        self.assertTrue(marker.exists())

    def test_fd_renewal_is_chained_and_old_revision_cannot_be_used(self):
        self.send_once()
        previous=self.delivery["delivery_id"]
        self.scope={**self.scope,"credential_revision":4}
        self.auth,self.request,self.delivery=ProviderCredentialTests.exchange(
            self,secret=b"synthetic-rotated-provider",
            scope=self.scope,action="renew",previous_delivery_id=previous,
        )
        self.metadata={
            **{k:v for k,v in self.delivery.items()
               if k not in ("secret","secret_format")},
            "schema":appfd.METADATA_SCHEMA,
        }
        self.policy["credential_revision"]=4
        self.state={"status":"installing","request_id":self.request["request_id"],
                    "delivery_id":self.delivery["delivery_id"],"revoked":False}
        receipt=self.send_once(secret=b"synthetic-rotated-provider")
        self.assertEqual(receipt["credential_revision"],4)
        with provider_credentials.open_for(
            self.scope,operation="fetch",collection="sources",
        ) as stored:
            self.assertEqual(stored.read(),b"synthetic-rotated-provider")
        with self.assertRaises(appfd.ApplicationFdHold):
            self.send_once(secret=b"synthetic-rotated-provider")

    def test_role_withdrawal_disables_fd_and_keeps_private_archive_state(self):
        self.send_once()
        private=self.root/"provider-credentials"/(self.policy["scope_id"]+".secret")
        old=private.read_bytes()
        self.set_role(selected=False,revision=8)
        with self.assertRaises(appfd.ApplicationFdHold):
            self.send_once()
        with self.assertRaises(provider_credentials.ProviderCredentialError):
            provider_credentials.open_for(
                self.scope,operation="fetch",collection="sources",
            )
        self.assertEqual(private.read_bytes(),old)

    def test_fd_only_setting_refuses_legacy_in_memory_path(self):
        with patch.dict(os.environ,{"ARCHIVE_MIRROR_CREDENTIAL_FD_ONLY":"1"}):
            with self.assertRaisesRegex(
                provider_credentials.ProviderCredentialError,"in-memory",
            ):
                provider_credentials.install_verified(
                    self.scope,self.auth,self.request,self.delivery,
                )
            result=self.send_once()
        self.assertEqual(result["status"],"installed-unattested")

    def test_internal_fd_store_is_also_disabled_without_selected_reception(self):
        fd=sealed_secret(self.secret)
        try:
            with self.assertRaisesRegex(
                provider_credentials.ProviderCredentialError,"disabled",
            ):
                provider_credentials.install_verified_fd(
                    self.scope,self.auth,self.request,self.metadata,fd,
                )
        finally:
            os.close(fd)
        self.assertFalse((self.root/"provider-credentials").exists())
