"""Disabled-by-default application-owned archive-provider sealed-FD consumer.

The selected root-control/host-install owner authenticates authority, the
durable one-time installing fence, native process/socket provenance and
revocation BEFORE any FD transfer. This module owns only the archive process
end of one SOCK_SEQPACKET frame; it never opens a listener or grants authority.

This is a source candidate. enabled=True in synthetic tests is NOT native
admission or a replacement for the independently pinned installed-byte ACK.
"""
from __future__ import annotations

import array
import fcntl
import json
import os
import re
import socket
import stat
import struct
import sys
import time
import uuid

from zog.host_identify import archive_credentials, credential_delivery

POLICY_SCHEMA = "zog-archive-provider-protected-ipc-policy-v1"
TRANSFER_SCHEMA = "zog-archive-provider-fd-handoff-v1"
METADATA_SCHEMA = "zog-archive-provider-verified-delivery-metadata-v1"
RESULT_SCHEMA = "zog-archive-provider-application-fd-result-v1"
PURPOSE = "archive-mirror-upstream-fetch"
CONSUMER = "archive-mirror"
MAX_CONTROL = 4096
MAX_FDS = 16
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_SHA256 = re.compile(r"sha256:[0-9a-f]{64}\Z")
_POLICY_KEYS = frozenset({
    "schema", "consumer", "purpose", "host_id", "installation_id",
    "state_volume_id", "registry_id", "scope_id", "credential_revision",
    "authority_revision", "app_uid", "app_gid", "app_pid",
    "app_source_sha256", "boot_id", "invocation_id",
})
_TRANSFER_KEYS = frozenset({
    "schema", "host_id", "registry_id", "scope_id", "request_id",
    "delivery_id", "installation_id", "state_volume_id",
    "boot_id", "invocation_id", "credential_revision",
    "authority_revision", "action", "purpose", "consumer",
})
_META_KEYS = frozenset({
    "schema", "request_id", "delivery_id", "authorization_id",
    "authorization_revision", "credential_id", "credential_revision",
    "consumer", "purpose", "issued_at", "expires_at",
})


class ApplicationFdHold(ValueError):
    pass


def _hold():
    raise ApplicationFdHold("archive provider application FD reception unavailable")


def _uuid(value):
    try:
        return type(value) is str and str(uuid.UUID(value)) == value
    except (TypeError, AttributeError, ValueError):
        return False


def _canonical(value):
    return json.dumps(value,sort_keys=True,separators=(",",":"),
                      ensure_ascii=True,allow_nan=False).encode("ascii")


def validate_sealed_memfd(fd):
    """Inspect one owned, sealed and CLOEXEC anonymous Linux FD; do not read it."""
    if sys.platform != "linux" or type(fd) is not int or fd < 0:
        _hold()
    try:
        info=os.fstat(fd)
        seals=fcntl.fcntl(fd,fcntl.F_GET_SEALS)
        descriptor_flags=fcntl.fcntl(fd,fcntl.F_GETFD)
        name=os.readlink(f"/proc/self/fd/{fd}")
    except (OSError,ValueError):
        _hold()
    required=(fcntl.F_SEAL_WRITE | fcntl.F_SEAL_SHRINK |
              fcntl.F_SEAL_GROW | fcntl.F_SEAL_SEAL)
    if (not stat.S_ISREG(info.st_mode) or info.st_nlink!=0
            or not 1<=info.st_size<=credential_delivery.MAX_SECRET
            or seals & required != required
            or descriptor_flags & fcntl.FD_CLOEXEC != fcntl.FD_CLOEXEC
            or not name.startswith("/memfd:")):
        _hold()
    return info.st_size


def validate_delivery_metadata(scope,authorization,request,metadata,*,now=None):
    """Check a *secret-free* projection of an externally verified delivery.

    Canonical signing/HTTP verification and the original signed delivery stay
    with the protected owner; this projection is NOT itself a signature.
    """
    selected=archive_credentials.provider_scope(scope)
    moment=time.time() if now is None else float(now)
    if (type(metadata) is not dict or set(metadata)!=_META_KEYS
            or metadata["schema"]!=METADATA_SCHEMA):
        _hold()
    if (credential_delivery.binding(authorization) !=
            archive_credentials.provider_binding(scope)
            or authorization.get("credential_revision")!=
                selected["credential_revision"]):
        _hold()
    credential_delivery.validate_request(request,authorization,now=moment)
    if (not _uuid(metadata["request_id"]) or not _uuid(metadata["delivery_id"])
            or metadata["request_id"]!=request["request_id"]
            or metadata["authorization_id"]!=authorization["authorization_id"]
            or metadata["authorization_revision"]!=authorization["revision"]
            or metadata["credential_id"]!=selected["credential_id"]
            or metadata["credential_revision"]!=selected["credential_revision"]
            or metadata["consumer"]!=CONSUMER or metadata["purpose"]!=PURPOSE):
        _hold()
    issued,expires=metadata["issued_at"],metadata["expires_at"]
    if (type(issued) is not int or type(expires) is not int
            or issued<1 or not issued<expires
            or expires-issued>credential_delivery.DELIVERY_LIFETIME
            or issued>moment+credential_delivery.CLOCK_SKEW
            or expires<=moment-credential_delivery.CLOCK_SKEW):
        _hold()
    return metadata


def _validate_selected(policy,scope,authorization,request,metadata,handoff):
    """The policy, scope and operation fence must be *locally selected* inputs."""
    selected=archive_credentials.provider_scope(scope)
    if (type(policy) is not dict or set(policy)!=_POLICY_KEYS
            or policy["schema"]!=POLICY_SCHEMA
            or policy["purpose"]!=PURPOSE or policy["consumer"]!=CONSUMER
            or not all(_uuid(policy[name]) for name in
                       ("host_id","installation_id","state_volume_id",
                        "boot_id","invocation_id"))
            or type(policy["registry_id"]) is not str
            or not policy["registry_id"]
            or type(policy["scope_id"]) is not str
            or not _HEX64.fullmatch(policy["scope_id"])
            or type(policy["app_source_sha256"]) is not str
            or not _SHA256.fullmatch(policy["app_source_sha256"])
            or type(policy["app_uid"]) is not int or policy["app_uid"]<1
            or type(policy["app_gid"]) is not int or policy["app_gid"]<1
            or type(policy["app_pid"]) is not int or policy["app_pid"]<1
            or type(policy["credential_revision"]) is not int
            or policy["credential_revision"]<1
            or type(policy["authority_revision"]) is not int
            or policy["authority_revision"]<1):
        _hold()
    if (policy["app_uid"]!=os.geteuid()
            or policy["app_gid"]!=os.getegid()
            or policy["app_pid"]!=os.getpid()
            or set(os.getgroups())-{policy["app_gid"]}):
        _hold()
    for field in ("host_id","installation_id","state_volume_id","registry_id",
                  "credential_revision"):
        if policy[field]!=selected[field]:
            _hold()
    if (policy["scope_id"]!=selected["scope_id"]
            or policy["authority_revision"]!=authorization["revision"]
            or type(handoff) is not dict
            or handoff.get("status")!="installing"
            or handoff.get("request_id")!=request["request_id"]
            or handoff.get("delivery_id")!=metadata["delivery_id"]
            or handoff.get("revoked") is not False):
        _hold()
    return policy


def _validate_transfer(transfer,policy,request,metadata):
    if (type(transfer) is not dict or set(transfer)!=_TRANSFER_KEYS
            or transfer["schema"]!=TRANSFER_SCHEMA
            or transfer["action"]!="deliver"
            or transfer["purpose"]!=PURPOSE
            or transfer["consumer"]!=CONSUMER):
        _hold()
    for field in (
        "host_id","registry_id","scope_id","installation_id",
        "state_volume_id","boot_id","invocation_id",
        "credential_revision","authority_revision",
    ):
        if transfer[field]!=policy[field]:
            _hold()
    if (transfer["request_id"]!=request["request_id"]
            or transfer["delivery_id"]!=metadata["delivery_id"]
            or not _uuid(transfer["request_id"])
            or not _uuid(transfer["delivery_id"])):
        _hold()
    return transfer


def _kernel_sender(sock,selected_sender):
    if (type(selected_sender) is not dict
            or set(selected_sender)!={"pid","uid","gid"}
            or any(type(selected_sender[k]) is not int for k in selected_sender)
            or selected_sender["pid"]<=0 or selected_sender["uid"]<0
            or selected_sender["gid"]<0
            or sock.family!=socket.AF_UNIX
            or sock.type & 0xf!=socket.SOCK_SEQPACKET):
        _hold()
    try:
        actual=struct.unpack("3i",sock.getsockopt(
            socket.SOL_SOCKET,socket.SO_PEERCRED,struct.calcsize("3i")))
    except (OSError,ValueError,struct.error):
        _hold()
    if actual!=(selected_sender["pid"],selected_sender["uid"],
               selected_sender["gid"]):
        _hold()


def _decode_exact(raw):
    def unique(pairs):
        result={}
        for key,value in pairs:
            if key in result:_hold()
            result[key]=value
        return result
    try:
        value=json.loads(raw,object_pairs_hook=unique,parse_constant=lambda _: _hold())
        if type(value) is not dict or _canonical(value)!=raw:
            _hold()
    except (UnicodeError,ValueError,TypeError,OverflowError):
        _hold()
    return value


def receive_verified_fd(
    sock,*,policy,selected_sender,scope,authorization,request,
    delivery_metadata,handoff_state,enabled=False,now=None,
):
    """Consume exactly one app-owned descriptor; return *unattested* evidence.

    Native root-control must not interpret this return as a signed installation
    receipt. Only independent installed-byte attestation can authorize a
    terminal receipt, and no FD resend is allowed after a lost acknowledgement.
    """
    if enabled is not True:
        _hold()
    moment=time.time() if now is None else float(now)
    validate_delivery_metadata(
        scope,authorization,request,delivery_metadata,now=moment)
    _validate_selected(
        policy,scope,authorization,request,delivery_metadata,handoff_state)
    _kernel_sender(sock,selected_sender)
    fds=[]
    try:
        data,control,flags,_=sock.recvmsg(
            MAX_CONTROL+1,socket.CMSG_SPACE(MAX_FDS*array.array("i").itemsize),
            socket.MSG_CMSG_CLOEXEC)
        for level,kind,body in control:
            if level!=socket.SOL_SOCKET or kind!=socket.SCM_RIGHTS:
                _hold()
            ints=array.array("i")
            if len(body)%ints.itemsize:
                _hold()
            ints.frombytes(body)
            fds.extend(ints)
        if (flags & (socket.MSG_TRUNC|socket.MSG_CTRUNC)
                or not 0<len(data)<=MAX_CONTROL or len(fds)!=1):
            _hold()
        transfer=_decode_exact(data)
        _validate_transfer(transfer,policy,request,delivery_metadata)
        validate_sealed_memfd(fds[0])
        # Reuse existing v2 store, role, revocation, pending and renewal
        # invariants; the sealed FD never becomes an in-memory delivery secret.
        from .provider_credentials import install_verified_fd
        result=install_verified_fd(
            scope,authorization,request,delivery_metadata,fds[0],
            now=moment,enabled=True)
        if (result.get("status")!="installed"
                or result.get("scope_id")!=policy["scope_id"]
                or result.get("delivery_id")!=transfer["delivery_id"]):
            _hold()
        return {
            "schema":RESULT_SCHEMA,"status":"installed-unattested",
            "scope_id":policy["scope_id"],
            "request_id":request["request_id"],
            "delivery_id":transfer["delivery_id"],
            "credential_revision":policy["credential_revision"],
            "authority_revision":policy["authority_revision"],
            "native_accepted":False,
        }
    except (OSError,ValueError,TypeError):
        _hold()
    finally:
        for fd in fds:
            os.close(fd)
