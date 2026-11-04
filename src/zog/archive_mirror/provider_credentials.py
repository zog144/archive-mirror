"""Protected local store for verified archive provider credential deliveries.

This module does not perform HTTPS or verify the Credential Authority signature.
The protected common receiver must first verify the canonical authorization and
delivery envelopes, persist its replay ledger, and then pass the verified
nonsecret objects plus delivery to install_verified().

Provider secrets are separate from short-lived archive consumer JWT grants.
"""
from __future__ import annotations

import hmac
import json
import os
import secrets
import stat
import time
from pathlib import Path

from zog.host_identify import archive_credentials, credential_delivery

from .config import configuration
from .lease import lease
from .store import named_lock, sync_directory

INSTALL_SCHEMA = "zog-archive-provider-credential-installation-v2"
PENDING_SCHEMA = "zog-archive-provider-credential-pending-v2"
REVOCATION_SCHEMA = "zog-archive-provider-credential-revocation-v1"


class ProviderCredentialError(ValueError):
    pass


def _deny(message="archive provider credential unavailable"):
    raise ProviderCredentialError(message) from None


def _private_root():
    root=Path(configuration()["root"])
    if root.is_symlink():
        _deny("unsafe archive root")
    root.mkdir(parents=True,exist_ok=True)
    path=root/"provider-credentials"
    if path.is_symlink():
        _deny("unsafe provider credential directory")
    try:
        path.mkdir(mode=0o700)
        sync_directory(root)
    except FileExistsError:
        pass
    info=path.lstat()
    if (
        not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode)
        or info.st_uid != os.geteuid()
        or stat.S_IMODE(info.st_mode) != 0o700
    ):
        _deny("unsafe provider credential directory")
    return path


def _names(selected):
    stem=selected["scope_id"]
    return stem+".secret",stem+".json",stem+".pending.json"


def _revocation_name(selected):
    return selected["scope_id"]+".revoked.json"


def _reject_revoked(directory,selected):
    # The protected receiver installs only signed, approved revocations.
    # Presence is permanently disabling, even if the record is damaged.
    if _read_json(directory,_revocation_name(selected),missing_ok=True) is not None:
        _deny("archive provider authorization revoked")


def _clear_pending(directory,name):
    dfd=os.open(directory,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:
        os.unlink(name,dir_fd=dfd)
        os.fsync(dfd)
    finally:
        os.close(dfd)


def _read_json(directory,name,*,missing_ok=False):
    dfd=os.open(directory,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:
        try:
            fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=dfd)
        except FileNotFoundError:
            if missing_ok:return None
            raise
        with os.fdopen(fd,"rb") as source:
            info=os.fstat(source.fileno())
            if (
                not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1
                or info.st_size > 16384
            ):
                _deny("unsafe provider credential metadata")
            raw=source.read(16385)
    finally:
        os.close(dfd)
    if len(raw)>16384:
        _deny("oversized provider credential metadata")
    try:
        value=json.loads(raw)
    except (ValueError,UnicodeError,TypeError):
        _deny("invalid provider credential metadata")
    if not isinstance(value,dict):
        _deny("invalid provider credential metadata")
    return value


def _atomic_json(directory,name,value):
    raw=json.dumps(value,sort_keys=True,separators=(",",":")).encode("ascii")
    if len(raw)>16384:
        _deny("oversized provider credential metadata")
    dfd=os.open(directory,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    temporary="."+name+"."+secrets.token_hex(8)
    try:
        fd=os.open(
            temporary,os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_CLOEXEC|os.O_NOFOLLOW,
            0o600,dir_fd=dfd,
        )
        try:
            os.fchmod(fd,0o600)
            os.write(fd,raw)
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(temporary,name,src_dir_fd=dfd,dst_dir_fd=dfd)
        os.fsync(dfd)
    finally:
        try:os.unlink(temporary,dir_fd=dfd)
        except FileNotFoundError:pass
        os.close(dfd)


def _active_role(selected):
    config=configuration()
    if any(name not in config["collections"] for name in selected["collections"]):
        _deny("provider credential collection is not configured")
    try:
        current=lease()
    except (ValueError,OSError,KeyError,TypeError):
        _deny("archive provider role unavailable")
    desired=current["desired"]
    if (
        current["host_id"] != selected["host_id"]
        or desired["revision"] != selected["role_revision"]
        or desired["selected"] is not True
    ):
        _deny("archive provider role binding changed")
    return current


def _installation(selected,authorization,delivery,*,now):
    return {
        "schema":INSTALL_SCHEMA,
        "scope_id":selected["scope_id"],
        "credential_id":selected["credential_id"],
        "credential_revision":selected["credential_revision"],
        "host_id":selected["host_id"],
        "host_fingerprint":selected["host_fingerprint"],
        "installation_id":selected["installation_id"],
        "state_volume_id":selected["state_volume_id"],
        "registry_id":selected["registry_id"],
        "provider_id":selected["provider_id"],
        "provider_origin":selected["provider_origin"],
        "provider_role":selected["provider_role"],
        "role_revision":selected["role_revision"],
        "collections":selected["collections"],
        "operations":selected["operations"],
        "authorization_id":authorization["authorization_id"],
        "authorization_revision":authorization["revision"],
        "delivery_id":delivery["delivery_id"],
        "installed_at":int(now),
    }


def _matching(record,expected):
    if not isinstance(record,dict) or not isinstance(expected,dict):
        return False
    stable=set(expected)-{"installed_at"}
    return (
        set(record)==set(expected)
        and all(record.get(key)==expected.get(key) for key in stable)
        and type(record.get("installed_at")) is int
    )


# An unchanged provider scope does not imply unchanged Host/installation/STATE.
# Compare the exact destination identity before replay, rotation, inspection or
# secret use; never adopt an old credential under a changed local identity.
_IDENTITY_FIELDS = (
    "host_id", "host_fingerprint", "installation_id",
    "state_volume_id", "registry_id",
)


def _record_identity_matches(record, selected):
    return (
        isinstance(record, dict)
        and all(record.get(key) == selected[key] for key in _IDENTITY_FIELDS)
    )


def _secret_file_ok(directory,name):
    dfd=os.open(directory,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:
        fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=dfd)
        info=os.fstat(fd)
        if (
            not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1
            or not 1 <= info.st_size <= credential_delivery.MAX_SECRET
        ):
            os.close(fd);_deny("unsafe provider credential file")
        return fd
    finally:
        os.close(dfd)


def install_verified(scope,authorization,request_value,delivery,*,now=None):
    """Legacy in-memory verified-delivery path; never a native FD receiver."""
    if os.environ.get("ARCHIVE_MIRROR_CREDENTIAL_FD_ONLY") == "1":
        _deny("in-memory provider credential installation disabled")
    moment=time.time() if now is None else float(now)
    archive_credentials.validate_delivery(
        scope,authorization,request_value,delivery,now=moment
    )
    secret=credential_delivery.secret_bytes(delivery)
    if not 1<=len(secret)<=credential_delivery.MAX_SECRET:
        _deny("invalid provider credential bytes")
    return _install_from_source(
        scope,authorization,request_value,delivery,
        byte_count=len(secret),
        read_chunk=lambda offset,length:secret[offset:offset+length],
        now=moment,
    )


def install_verified_fd(
    scope,authorization,request_value,delivery_metadata,fd,*,now=None,
    enabled=False,
):
    """Application-identity installation from one already-verified sealed FD.

    No shared byte buffer, delivery with secret field, or caller path. The native
    protected receiver remains responsible for authority signature, replay
    ledger, independent identity and installation acknowledgement.
    """
    if enabled is not True:
        _deny("archive provider FD installation disabled")
    from .provider_fd_adapter import validate_sealed_memfd, validate_delivery_metadata
    moment=time.time() if now is None else float(now)
    validate_delivery_metadata(
        scope,authorization,request_value,delivery_metadata,now=moment,
    )
    byte_count=validate_sealed_memfd(fd)
    return _install_from_source(
        scope,authorization,request_value,delivery_metadata,
        byte_count=byte_count,
        read_chunk=lambda offset,length:os.pread(fd,length,offset),
        now=moment,allow_redelivery=False,
    )


def _install_from_source(
    scope,authorization,request_value,delivery,*,byte_count,read_chunk,now,
    allow_redelivery=True,
):
    """One crash/revision/revocation-aware store path for bytes and sealed FD."""
    selected=archive_credentials.provider_scope(scope)
    moment=now
    _active_role(selected)
    directory=_private_root()
    secret_name,record_name,pending_name=_names(selected)
    expected=_installation(selected,authorization,delivery,now=moment)
    with named_lock("provider-credential",selected["scope_id"]):
        _active_role(selected)
        _reject_revoked(directory,selected)
        old=_read_json(directory,record_name,missing_ok=True)
        pending=_read_json(directory,pending_name,missing_ok=True)
        if pending is not None and not allow_redelivery:
            _deny("provider FD handoff uncertain; no redelivery")
        if pending is not None and (
            pending.get("schema") != PENDING_SCHEMA
            or pending.get("scope_id") != selected["scope_id"]
            or pending.get("delivery_id") != delivery["delivery_id"]
            or pending.get("credential_revision") != selected["credential_revision"]
        ):
            _deny("provider credential installation recovery required")
        if old is not None:
            if old.get("schema") != INSTALL_SCHEMA:
                _deny("invalid provider credential installation record")
            if not _record_identity_matches(old, selected):
                _deny("provider credential destination identity changed")
            old_revision=old.get("credential_revision")
            if type(old_revision) is not int:
                _deny("invalid provider credential installation record")
            if old_revision>selected["credential_revision"]:
                _deny("provider credential revision rollback")
            if old_revision==selected["credential_revision"]:
                if not allow_redelivery:
                    _deny("provider FD already delivered; no redelivery")
                if _matching(old,expected):
                    fd=_secret_file_ok(directory,secret_name)
                    with os.fdopen(fd,"rb") as installed:
                        if os.fstat(installed.fileno()).st_size != byte_count:
                            _deny("provider credential replay bytes differ")
                        for offset in range(0,byte_count,4096):
                            length=min(4096,byte_count-offset)
                            part=read_chunk(offset,length)
                            if (len(part)!=length or not hmac.compare_digest(
                                    os.pread(installed.fileno(),length,offset),part)):
                                _deny("provider credential replay bytes differ")
                    if pending is not None:
                        # Crash after record publication but before pending
                        # cleanup: only the exact same delivery may recover.
                        _clear_pending(directory,pending_name)
                    return {**old,"status":"installed","replayed":True}
                _deny("provider credential revision conflict")
            if (
                request_value.get("action") != "renew"
                or request_value.get("previous_delivery_id") != old.get("delivery_id")
            ):
                _deny("provider credential rotation is not chained")
        elif request_value.get("action") != "deliver":
            _deny("initial provider credential must use deliver")
        _atomic_json(directory,pending_name,{
            "schema":PENDING_SCHEMA,
            "scope_id":selected["scope_id"],
            "credential_id":selected["credential_id"],
            "credential_revision":selected["credential_revision"],
            "delivery_id":delivery["delivery_id"],
        })
        dfd=os.open(directory,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        temporary="."+secret_name+"."+secrets.token_hex(8)
        try:
            fd=os.open(
                temporary,os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_CLOEXEC|os.O_NOFOLLOW,
                0o600,dir_fd=dfd,
            )
            try:
                os.fchmod(fd,0o600)
                for offset in range(0,byte_count,4096):
                    length=min(4096,byte_count-offset)
                    part=read_chunk(offset,length)
                    if len(part)!=length:
                        _deny("incomplete provider credential input")
                    remaining=memoryview(part)
                    while remaining:
                        written=os.write(fd,remaining)
                        if written<=0:_deny("incomplete provider credential write")
                        remaining=remaining[written:]
                os.fsync(fd)
            finally:
                os.close(fd)
            # Withdrawal/identity/revision changes during installation fail closed.
            _active_role(selected)
            os.replace(temporary,secret_name,src_dir_fd=dfd,dst_dir_fd=dfd)
            os.fsync(dfd)
        finally:
            try:os.unlink(temporary,dir_fd=dfd)
            except FileNotFoundError:pass
            os.close(dfd)
        _atomic_json(directory,record_name,expected)
        dfd=os.open(directory,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:
            os.unlink(pending_name,dir_fd=dfd)
            os.fsync(dfd)
        finally:
            os.close(dfd)
    return {**expected,"status":"installed","replayed":False}


def open_for(scope,*,operation,collection):
    """Open the installed secret only for its exact active provider scope."""
    selected=archive_credentials.provider_scope(scope)
    if operation not in selected["operations"]:
        _deny("provider credential operation not authorized")
    if collection not in selected["collections"]:
        _deny("provider credential collection not authorized")
    _active_role(selected)
    directory=_private_root()
    secret_name,record_name,pending_name=_names(selected)
    _reject_revoked(directory,selected)
    if _read_json(directory,pending_name,missing_ok=True) is not None:
        _deny("provider credential installation pending")
    expected=_read_json(directory,record_name)
    if (
        expected.get("schema") != INSTALL_SCHEMA
        or expected.get("scope_id") != selected["scope_id"]
        or expected.get("credential_id") != selected["credential_id"]
        or expected.get("credential_revision") != selected["credential_revision"]
        or not _record_identity_matches(expected, selected)
        or expected.get("provider_id") != selected["provider_id"]
        or expected.get("provider_origin") != selected["provider_origin"]
        or expected.get("provider_role") != selected["provider_role"]
        or expected.get("role_revision") != selected["role_revision"]
        or expected.get("collections") != selected["collections"]
        or expected.get("operations") != selected["operations"]
    ):
        _deny("provider credential installation does not match scope")
    fd=_secret_file_ok(directory,secret_name)
    try:
        _active_role(selected)
        _reject_revoked(directory,selected)
    except Exception:
        os.close(fd);raise
    return os.fdopen(fd,"rb")


def inspect(scope):
    """Return only nonsecret installation state."""
    selected=archive_credentials.provider_scope(scope)
    directory=_private_root()
    secret_name,record_name,pending_name=_names(selected)
    revoked=_read_json(directory,_revocation_name(selected),missing_ok=True)
    if revoked is not None:
        return {"schema":INSTALL_SCHEMA,"status":"blocked",
                "scope_id":selected["scope_id"],"reason":"authorization-revoked"}
    pending=_read_json(directory,pending_name,missing_ok=True)
    if pending is not None:
        return {"schema":INSTALL_SCHEMA,"status":"blocked","scope_id":selected["scope_id"],
                "reason":"pending-installation"}
    record=_read_json(directory,record_name,missing_ok=True)
    if record is None:
        return {"schema":INSTALL_SCHEMA,"status":"unavailable",
                "scope_id":selected["scope_id"]}
    if (
        record.get("schema") != INSTALL_SCHEMA
        or not _record_identity_matches(record,selected)
        or record.get("scope_id") != selected["scope_id"]
        or record.get("credential_id") != selected["credential_id"]
        or record.get("credential_revision") != selected["credential_revision"]
        or record.get("role_revision") != selected["role_revision"]
    ):
        return {"schema":INSTALL_SCHEMA,"status":"blocked",
                "scope_id":selected["scope_id"],"reason":"scope-or-identity-mismatch"}
    try:
        fd=_secret_file_ok(directory,secret_name);os.close(fd)
    except (OSError,ProviderCredentialError):
        return {"schema":INSTALL_SCHEMA,"status":"blocked",
                "scope_id":selected["scope_id"],"reason":"private-file-unavailable"}
    return {
        "schema":INSTALL_SCHEMA,"status":"installed",
        "scope_id":selected["scope_id"],
        "credential_id":record.get("credential_id"),
        "credential_revision":record.get("credential_revision"),
        "role_revision":record.get("role_revision"),
        "delivery_id":record.get("delivery_id"),
    }


def apply_signed_revocation(
    scope,envelope,authority_key,*,expected_issuer,now=None,
):
    """Persist a signed, purpose/Host-bound revocation from the protected receiver.

    The caller must supply the independently pinned Credential Authority public
    key and first durably accept the revocation in the common ledger. This
    adapter never obtains authority from a caller-chosen key or a role lease.
    Revocation disables use/rotation but does not delete archive content.
    """
    selected=archive_credentials.provider_scope(scope)
    moment=time.time() if now is None else float(now)
    authorization=archive_credentials.verify_provider_authorization(
        envelope,authority_key,expected_issuer=expected_issuer,
        scope=scope,now=moment,
    )
    if authorization["status"]!="revoked":
        _deny("signed archive provider authorization is not revoked")
    record={
        "schema":REVOCATION_SCHEMA,
        "scope_id":selected["scope_id"],
        **{key:selected[key] for key in _IDENTITY_FIELDS},
        "credential_id":selected["credential_id"],
        "credential_revision":authorization["credential_revision"],
        "authorization_id":authorization["authorization_id"],
        "authorization_revision":authorization["revision"],
        "revoked_at":authorization["revoked_at"],
    }
    directory=_private_root()
    with named_lock("provider-credential",selected["scope_id"]):
        previous=_read_json(
            directory,_revocation_name(selected),missing_ok=True,
        )
        if previous is not None:
            if previous==record:
                return {"schema":REVOCATION_SCHEMA,
                        "status":"revoked","replayed":True,
                        "scope_id":selected["scope_id"]}
            _deny("conflicting provider authorization revocation")
        installed=_read_json(
            directory,_names(selected)[1],missing_ok=True,
        )
        if installed is not None:
            if (
                installed.get("schema")!=INSTALL_SCHEMA
                or not _record_identity_matches(installed,selected)
                or installed.get("authorization_id")!=authorization["authorization_id"]
            ):
                _deny("provider revocation does not match installed authority")
            if (
                authorization["revision"]<=installed.get("authorization_revision",0)
                or authorization["credential_revision"]<
                    installed.get("credential_revision",0)
            ):
                _deny("stale provider authorization revocation")
        _atomic_json(directory,_revocation_name(selected),record)
    return {"schema":REVOCATION_SCHEMA,"status":"revoked",
            "replayed":False,"scope_id":selected["scope_id"]}
