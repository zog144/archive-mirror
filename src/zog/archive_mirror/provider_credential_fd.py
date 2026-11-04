"""DISABLED application-owned archive provider credential FD admission.

The root receiving owner must first persist an irreversible installing claim and
authenticate the canonical HTTPS delivery. This source module only accepts
a sealed, anonymous credential FD over a one-shot AF_UNIX SOCK_SEQPACKET link.
It never calls the legacy in-memory-secret install_verified API and never
creates a server socket, service or authorization pin.
"""
from __future__ import annotations
import array
import fcntl
import hashlib
import hmac
import json
import os
import socket
import stat
import struct
import time

from zog.host_identify import archive_credentials as archive, credential_delivery as cd
from . import provider_credentials as private

SCHEMA = "zog-archive-mirror-provider-fd-admission-v1"
MAX_CONTROL = 4096
MAX_SECRET = cd.MAX_SECRET
FIELDS = {"schema","consumer","purpose","scope","authorization","request",
          "delivery","owner_fence","expected_sha256","size","recipient_uid",
          "recipient_gid","sender_uid","sender_gid"}
CONSUMER="archive-mirror"
PURPOSE="archive-mirror-upstream-fetch"


def _hold(reason="archive provider FD reception held"):
    raise private.ProviderCredentialError(reason)

def _canonical(value):
    return json.dumps(value,sort_keys=True,separators=(",",":"),
                      ensure_ascii=True,allow_nan=False).encode("ascii")

def _pairs(pairs):
    result={}
    for key,value in pairs:
        if key in result: _hold("duplicate protected admission key")
        result[key]=value
    return result

def _uuid(value):
    import uuid
    try: return type(value) is str and str(uuid.UUID(value))==value
    except (TypeError,ValueError,AttributeError):return False

def _validate(admission, *, protected_scope, expected_uid, expected_gid):
    if type(admission) is not dict or set(admission)!=FIELDS or admission["schema"]!=SCHEMA:
        _hold("wrong archive FD admission schema")
    if admission["consumer"]!=CONSUMER or admission["purpose"]!=PURPOSE:
        _hold("archive purpose required")
    if (type(expected_uid) is not int or expected_uid<=0
            or type(expected_gid) is not int or expected_gid<=0
            or os.geteuid()!=expected_uid or os.getegid()!=expected_gid
            or admission["recipient_uid"]!=expected_uid
            or admission["recipient_gid"]!=expected_gid):
        _hold("unselected application UID/GID")
    if (admission["sender_uid"]!=0 or type(admission["sender_gid"]) is not int
            or admission["sender_gid"]<0):
        _hold("protected root sender required")
    selected=archive.provider_scope(protected_scope)
    if archive.provider_scope(admission["scope"])!=selected or admission["scope"]!=protected_scope:
        _hold("archive scope not independently selected")
    auth=admission["authorization"]
    request=admission["request"]
    delivery=admission["delivery"]
    if type(auth) is not dict or type(request) is not dict or type(delivery) is not dict:
        _hold("missing canonical nonsecret evidence")
    # Fail closed on ANY additional field: otherwise an untrusted message
    # could smuggle bytes into apparently nonsecret JSON metadata.
    delivery_fields={"schema","request_id","delivery_id","authorization_id",
                     "authorization_revision","credential_id",
                     "credential_revision","consumer","purpose","issued_at",
                     "expires_at"}
    if set(delivery)!=delivery_fields:
        _hold("credential bytes or unreviewed fields in IPC metadata")
    if cd.binding(auth)!=archive.provider_binding(protected_scope):
        _hold("wrong canonical archive authorization")
    if (auth.get("status")!="approved"
            or auth.get("credential_revision")!=selected["credential_revision"]):
        _hold("archive credential not approved")
    cd.validate_request(request,auth,now=admission.get("_test_now"))
    if (request.get("request_id")!=delivery.get("request_id")
            or delivery.get("authorization_id")!=auth.get("authorization_id")
            or delivery.get("authorization_revision")!=auth.get("revision")
            or delivery.get("credential_id")!=auth.get("credential_id")
            or delivery.get("credential_revision")!=selected["credential_revision"]
            or delivery.get("consumer")!=CONSUMER or delivery.get("purpose")!=PURPOSE
            or delivery.get("schema")!=cd.DELIVERY_SCHEMA):
        _hold("delivery differs from signed owner claim")
    if (type(delivery["issued_at"]) is not int or
            type(delivery["expires_at"]) is not int or
            delivery["issued_at"]>=delivery["expires_at"] or
            delivery["expires_at"]-delivery["issued_at"]>cd.DELIVERY_LIFETIME):
        _hold("invalid canonical archive delivery window")
    fence=admission["owner_fence"]
    if (type(fence) is not dict or set(fence)!={"status","request_id","delivery_id",
                                               "revoked","scope_id","authorization_revision"}
            or fence["status"]!="installing" or fence["revoked"] is not False
            or fence["request_id"]!=request["request_id"]
            or fence["delivery_id"]!=delivery["delivery_id"]
            or fence["scope_id"]!=selected["scope_id"]
            or fence["authorization_revision"]!=auth["revision"]):
        _hold("missing irreversible receiving-owner fence")
    if (not _uuid(request["request_id"]) or not _uuid(delivery["delivery_id"])
            or type(admission["size"]) is not int
            or not 1<=admission["size"]<=MAX_SECRET
            or type(admission["expected_sha256"]) is not str
            or len(admission["expected_sha256"])!=64
            or any(ch not in "0123456789abcdef" for ch in admission["expected_sha256"])):
        _hold("invalid credential FD commitment")
    return selected,auth,request,delivery

def _sealed(fd, expected_size):
    info=os.fstat(fd)
    if not stat.S_ISREG(info.st_mode) or info.st_nlink!=0 or info.st_size!=expected_size:
        _hold("unsafe anonymous credential descriptor")
    try:
        seals=fcntl.fcntl(fd,fcntl.F_GET_SEALS)
        name=os.readlink(f"/proc/self/fd/{fd}")
    except (OSError,ValueError):
        _hold("not a sealed memfd")
    required=(fcntl.F_SEAL_WRITE|fcntl.F_SEAL_GROW|fcntl.F_SEAL_SHRINK|fcntl.F_SEAL_SEAL)
    if seals & required != required or not name.startswith("/memfd:"):
        _hold("unsealed or named credential")
    return info

def _receive(sock, *, sender_uid, sender_gid):
    if sock.family!=socket.AF_UNIX or (sock.type & 0xf)!=socket.SOCK_SEQPACKET:
        _hold("archive IPC must be Unix seqpacket")
    pid,uid,gid=struct.unpack("3i",sock.getsockopt(socket.SOL_SOCKET,
                                       socket.SO_PEERCRED,struct.calcsize("3i")))
    if pid<=0 or (uid,gid)!=(sender_uid,sender_gid):
        _hold("kernel sender identity mismatch")
    fds=[]
    try:
        data,controls,flags,_=sock.recvmsg(
            MAX_CONTROL+1,socket.CMSG_SPACE(16*array.array("i").itemsize),
            getattr(socket,"MSG_CMSG_CLOEXEC",0))
        for level,kind,raw in controls:
            if level!=socket.SOL_SOCKET or kind!=socket.SCM_RIGHTS or len(raw)%4:
                _hold("unexpected ancillary control")
            values=array.array("i");values.frombytes(raw);fds.extend(values)
        if flags & (socket.MSG_TRUNC|socket.MSG_CTRUNC) or not 0<len(data)<=MAX_CONTROL or len(fds)!=1:
            _hold("truncated or multiple credential FDs")
        admission=json.loads(data,object_pairs_hook=_pairs,
                             parse_constant=lambda _: _hold("nonfinite IPC field"))
        if _canonical(admission)!=data:
            _hold("noncanonical admission frame")
        return admission,fds.pop()
    finally:
        for fd in fds: os.close(fd)

def install_verified_fd(admission, fd, *, protected_scope, expected_uid,
                        expected_gid, enabled=False, now=None):
    """Consume a verified FD as the archive application's own non-root UID.

    No legacy delivery secret dict, in-memory bytes receipt or root writer.
    Caller must independently authenticate current signed owner evidence.
    """
    if enabled is not True: _hold("archive FD installation disabled")
    selected,auth,request,delivery=_validate(
        admission,protected_scope=protected_scope,
        expected_uid=expected_uid,expected_gid=expected_gid)
    _sealed(fd,admission["size"])
    moment=time.time() if now is None else float(now)
    if not (auth["approved_at"]<=moment<auth["expires_at"]
            and delivery["issued_at"]<=moment<delivery["expires_at"]):
        _hold("stale archive authorization or delivery")
    private._active_role(selected)
    directory=private._private_root()
    secret_name,record_name,pending_name=private._names(selected)
    expected=private._installation(selected,auth,delivery,now=moment)
    with private.named_lock("provider-credential",selected["scope_id"]):
        private._active_role(selected)
        private._reject_revoked(directory,selected)
        old=private._read_json(directory,record_name,missing_ok=True)
        pending=private._read_json(directory,pending_name,missing_ok=True)
        if pending is not None:
            _hold("ambiguous previous archive FD installation: no retransfer")
        if old is not None:
            if (old.get("schema")!=private.INSTALL_SCHEMA or
                not private._record_identity_matches(old,selected)):
                _hold("archive installation identity changed")
            if type(old.get("credential_revision")) is not int:
                _hold("invalid installed credential revision")
            if old["credential_revision"]>=selected["credential_revision"]:
                _hold("FD replay, identity rollback or revision conflict")
            if (request.get("action")!="renew" or
                request.get("previous_delivery_id")!=old.get("delivery_id")):
                _hold("archive FD renewal predecessor mismatch")
        elif request.get("action")!="deliver":
            _hold("initial archive FD delivery must be deliver")
        private._atomic_json(directory,pending_name,{
            "schema":private.PENDING_SCHEMA,"scope_id":selected["scope_id"],
            "credential_id":selected["credential_id"],
            "credential_revision":selected["credential_revision"],
            "delivery_id":delivery["delivery_id"]})
        dfd=os.open(directory,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        temp="."+secret_name+"."+private.secrets.token_hex(8)
        try:
            out=os.open(temp,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,
                        0o600,dir_fd=dfd)
            try:
                os.fchmod(out,0o600)
                h=hashlib.sha256()
                total=0
                while total<admission["size"]:
                    block=os.pread(fd,min(8192,admission["size"]-total),total)
                    if not block: _hold("short sealed credential FD")
                    h.update(block)
                    offset=0
                    while offset<len(block):
                        written=os.write(out,block[offset:])
                        if written<=0: _hold("short application-private credential write")
                        offset+=written
                    total+=len(block)
                if not hmac.compare_digest(h.hexdigest(),admission["expected_sha256"]):
                    _hold("sealed FD bytes differ from owner commitment")
                os.fsync(out)
            finally: os.close(out)
            private._active_role(selected)
            private._reject_revoked(directory,selected)
            os.replace(temp,secret_name,src_dir_fd=dfd,dst_dir_fd=dfd)
            os.fsync(dfd)
        finally:
            try:os.unlink(temp,dir_fd=dfd)
            except FileNotFoundError:pass
            os.close(dfd)
        private._atomic_json(directory,record_name,expected)
        private._clear_pending(directory,pending_name)
    # Secret-free result. Native installed-byte witness remains a separate
    # application-private attestation requirement, NOT this local return value.
    return {"schema":private.INSTALL_SCHEMA,"status":"installed-receipt-pending",
            "scope_id":selected["scope_id"],"delivery_id":delivery["delivery_id"],
            "credential_revision":selected["credential_revision"],
            "native_acknowledged":False}

def receive_and_install_once(sock, *, protected_scope, expected_uid, expected_gid,
                             sender_uid=0, sender_gid=0, enabled=False, now=None):
    """One-shot application process entrypoint; never binds/listens on a socket."""
    if enabled is not True: _hold("archive FD reception disabled")
    admission,fd=_receive(sock,sender_uid=sender_uid,sender_gid=sender_gid)
    try:
        if admission.get("sender_uid")!=sender_uid or admission.get("sender_gid")!=sender_gid:
            _hold("inconsistent protected sender identity")
        return install_verified_fd(admission,fd,protected_scope=protected_scope,
            expected_uid=expected_uid,expected_gid=expected_gid,
            enabled=True,now=now)
    finally:os.close(fd)
