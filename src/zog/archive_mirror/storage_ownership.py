"""Bind archive-data to one controller-issued execution identity.

The durable marker records only immutable controller/storage identity and migration
origin. Mutable catalogue/object state is observed separately so ordinary mirroring
does not invalidate the ownership binding.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import os
import re
import stat
from pathlib import Path

from .store_verification import verify_store

SCHEMA = "zog-archive-storage-ownership-v2"
MARKER = ".zog-archive-ownership.json"
MIGRATION_MARKER = ".zog-state-migration.json"
IDENTITY = re.compile(r"[0-9a-f]{32}\Z")
MAX_ENTRIES = 250000
_ALLOWED_TOP = {
    "catalogue.sqlite3",
    "configuration.json",
    "public-keyring.json",
    "store",
    MIGRATION_MARKER,
    MARKER,
}
_CONFIG_KEYS = {
    "root", "collections", "host_id", "intent_file", "endpoint",
    "issuer", "audience", "keyring", "maximum_archive_bytes", "sources",
}


class StorageOwnershipError(ValueError):
    pass


def _sha(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def _plain_directory(path):
    path = Path(path)
    if not path.is_absolute() or str(path) == "/" or ".." in path.parts:
        raise StorageOwnershipError("noncanonical archive-data root")
    current = Path("/")
    for part in path.parts[1:]:
        current = current / part
        info = current.lstat()
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            raise StorageOwnershipError("archive-data root redirected")
    return path


def _identity(storage_id, grant_id, grant_version, uid, gid):
    if not isinstance(storage_id, str) or not IDENTITY.fullmatch(storage_id):
        raise StorageOwnershipError("invalid controller storage identity")
    if not isinstance(grant_id, str) or not IDENTITY.fullmatch(grant_id):
        raise StorageOwnershipError("invalid execution grant identity")
    if type(grant_version) is not int or grant_version < 1:
        raise StorageOwnershipError("invalid execution grant version")
    if type(uid) is not int or type(gid) is not int or not 0 < uid < 2**31 or not 0 < gid < 2**31:
        raise StorageOwnershipError("archive execution identity must be non-root numeric IDs")
    return {
        "grant_id": grant_id,
        "grant_version": grant_version,
        "uid": uid,
        "gid": gid,
        "storage_id": storage_id,
    }


def _process_identity(binding):
    if os.geteuid() != binding["uid"] or os.getegid() != binding["gid"]:
        raise StorageOwnershipError("runtime is not executing as bound archive grant")
    extra = set(os.getgroups()) - {binding["gid"]}
    if extra:
        raise StorageOwnershipError("archive execution identity has supplementary groups")


def _owned(path, uid, gid, *, directory=None):
    info = path.lstat()
    if info.st_uid != uid or info.st_gid != gid:
        raise StorageOwnershipError("archive-data ownership differs from bound grant")
    if info.st_mode & 0o002:
        raise StorageOwnershipError("archive-data contains world-writable state")
    if directory is True and not stat.S_ISDIR(info.st_mode):
        raise StorageOwnershipError("required archive directory is not a directory")
    if directory is False and (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1):
        raise StorageOwnershipError("required archive file is redirected or special")
    if stat.S_ISLNK(info.st_mode):
        raise StorageOwnershipError("archive-data contains redirected state")
    return info


def _owned_tree(root, uid, gid):
    count = 0
    for directory, directories, files in os.walk(root, topdown=True, followlinks=False):
        directory = Path(directory)
        for path in [directory / name for name in directories + files]:
            if path.name == MARKER:
                continue
            count += 1
            if count > MAX_ENTRIES:
                raise StorageOwnershipError("archive-data tree limit exceeded")
            info = _owned(path, uid, gid)
            if stat.S_ISDIR(info.st_mode):
                continue
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise StorageOwnershipError("archive-data contains redirected or special state")
            if path.name.endswith(("-wal", "-shm", "-journal")):
                raise StorageOwnershipError("archive catalogue checkpoint is not quiesced")
    _owned(root, uid, gid, directory=True)
    return count


def _public_keyring(root):
    path = root / "public-keyring.json"
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 65536:
        raise StorageOwnershipError("application-owned public keyring missing")
    try:
        value = json.loads(path.read_text())
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise StorageOwnershipError("invalid public keyring") from exc
    if type(value) is not dict or set(value) != {"version", "keys"} or value["version"] != 1:
        raise StorageOwnershipError("invalid public keyring")
    if not isinstance(value["keys"], dict) or not value["keys"]:
        raise StorageOwnershipError("empty public keyring")
    for name, encoded in value["keys"].items():
        if not isinstance(name, str) or not name or len(name) > 128 or not isinstance(encoded, str):
            raise StorageOwnershipError("invalid public keyring entry")
        try:
            raw = base64.b64decode(encoded, validate=True)
        except (ValueError, binascii.Error) as exc:
            raise StorageOwnershipError("invalid public keyring entry") from exc
        if len(raw) != 32:
            raise StorageOwnershipError("public keyring must contain Ed25519 public keys")
    return _sha(path)


def _configuration(root):
    path = root / "configuration.json"
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 65536:
        raise StorageOwnershipError("archive configuration missing")
    try:
        value = json.loads(path.read_text())
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise StorageOwnershipError("invalid archive configuration") from exc
    if type(value) is not dict or set(value) - _CONFIG_KEYS:
        raise StorageOwnershipError("unexpected archive configuration fields")
    if value.get("root") != "/var/lib/archive-mirror/store":
        raise StorageOwnershipError("archive store must use application-owned persistent path")
    if value.get("intent_file") != "/run/zog-host/mirror-live/mirror-intent.json":
        raise StorageOwnershipError("mirror intent must use controller-scoped live export")
    if value.get("keyring") != "/var/lib/archive-mirror/public-keyring.json":
        raise StorageOwnershipError("verification keyring must be application-owned public data")
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return value, hashlib.sha256(encoded).hexdigest()


def _migration_binding(root, storage_id):
    marker = root / MIGRATION_MARKER
    if not marker.exists():
        return None
    if marker.is_symlink() or not marker.is_file() or marker.stat().st_size > 65536:
        raise StorageOwnershipError("unsafe migration evidence")
    try:
        value = json.loads(marker.read_text())
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise StorageOwnershipError("invalid migration evidence") from exc
    if value.get("state") != "complete":
        raise StorageOwnershipError("archive migration is incomplete")
    ids = value.get("binding", {}).get("storage_ids")
    if not isinstance(ids, list) or storage_id not in ids:
        raise StorageOwnershipError("migration evidence does not bind archive storage")
    return _sha(marker)


def _marker(root):
    path = root / MARKER
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 65536:
        raise StorageOwnershipError("archive ownership marker missing")
    try:
        value = json.loads(path.read_text())
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise StorageOwnershipError("invalid archive ownership marker") from exc
    if (type(value) is not dict
            or set(value) != {"schema", "application", "binding",
                              "migration_evidence_sha256", "mirror_role_data_persistent"}
            or value.get("schema") != SCHEMA
            or value.get("application") != "archive-mirror"
            or value.get("mirror_role_data_persistent") is not True):
        raise StorageOwnershipError("unsupported archive ownership marker")
    expected = _identity(**{
        "storage_id": value.get("binding", {}).get("storage_id"),
        "grant_id": value.get("binding", {}).get("grant_id"),
        "grant_version": value.get("binding", {}).get("grant_version"),
        "uid": value.get("binding", {}).get("uid"),
        "gid": value.get("binding", {}).get("gid"),
    })
    if expected != value["binding"]:
        raise StorageOwnershipError("invalid archive ownership binding")
    migration = value.get("migration_evidence_sha256")
    if migration is not None and (not isinstance(migration, str) or not re.fullmatch(r"[0-9a-f]{64}", migration)):
        raise StorageOwnershipError("invalid migration evidence digest")
    return value


def runtime_guard(root):
    """Fast startup/runtime guard: immutable binding + kernel identity + top-level DAC."""
    root = _plain_directory(root)
    marker = _marker(root)
    binding = marker["binding"]
    _process_identity(binding)
    names = {path.name for path in root.iterdir()}
    if names - _ALLOWED_TOP:
        raise StorageOwnershipError("archive-data contains station or unreviewed top-level state")
    for name, directory in (
        ("catalogue.sqlite3", False),
        ("configuration.json", False),
        ("public-keyring.json", False),
        ("store", True),
        (MARKER, False),
    ):
        if name not in names:
            raise StorageOwnershipError("archive-data is incomplete")
        _owned(root / name, binding["uid"], binding["gid"], directory=directory)
    _owned(root, binding["uid"], binding["gid"], directory=True)
    _configuration(root)
    _public_keyring(root)
    if _migration_binding(root, binding["storage_id"]) != marker["migration_evidence_sha256"]:
        raise StorageOwnershipError("archive migration origin changed")
    return marker


def observe(root, *, require_marker=True, require_process_identity=True):
    """Fresh mutable-state observation; not persisted as ownership identity."""
    root = _plain_directory(root)
    if require_marker:
        marker = _marker(root)
        binding = marker["binding"]
    else:
        raise StorageOwnershipError("ownership marker required for mutable observation")
    if require_process_identity:
        _process_identity(binding)
    entries = _owned_tree(root, binding["uid"], binding["gid"])
    _, config_sha = _configuration(root)
    keyring_sha = _public_keyring(root)
    verification = verify_store(root / "store", root / "catalogue.sqlite3")
    return {
        "schema": "zog-archive-state-observation-v1",
        "binding": binding,
        "configuration_sha256": config_sha,
        "public_keyring_sha256": keyring_sha,
        "catalogue_sha256": verification["catalogue_sha256"],
        "object_manifest_sha256": verification["object_manifest_sha256"],
        "counts": verification["counts"],
        "owned_entries": entries,
    }


def bind(root, *, storage_id, grant_id, grant_version, uid, gid):
    """Create immutable ownership evidence after a full quiesced migration audit."""
    root = _plain_directory(root)
    binding = _identity(storage_id, grant_id, grant_version, uid, gid)
    _process_identity(binding)
    names = {path.name for path in root.iterdir()}
    if MARKER in names:
        recorded = _marker(root)
        if recorded["binding"] != binding:
            raise StorageOwnershipError("archive storage already bound to different identity")
        runtime_guard(root)
        return recorded
    if names - (_ALLOWED_TOP - {MARKER}):
        raise StorageOwnershipError("archive-data contains station or unreviewed top-level state")
    for required in ("catalogue.sqlite3", "configuration.json", "public-keyring.json", "store"):
        if required not in names:
            raise StorageOwnershipError("archive-data is incomplete")
    _owned_tree(root, uid, gid)
    _configuration(root)
    _public_keyring(root)
    verification = verify_store(root / "store", root / "catalogue.sqlite3")
    if verification.get("valid") is not True:
        raise StorageOwnershipError("archive store verification failed")
    evidence = {
        "schema": SCHEMA,
        "application": "archive-mirror",
        "binding": binding,
        "migration_evidence_sha256": _migration_binding(root, storage_id),
        "mirror_role_data_persistent": True,
    }
    path = root / MARKER
    data = json.dumps(evidence, sort_keys=True, separators=(",", ":")).encode()
    temporary = root / (MARKER + ".new")
    fd = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data); stream.flush(); os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        temporary.unlink(missing_ok=True)
    return evidence


def inspect(root, *, storage_id=None, grant_id=None, grant_version=None, uid=None, gid=None,
            require_process_identity=True, require_marker=True):
    """Compatibility audit entry point with optional expected binding comparison."""
    marker = runtime_guard(root) if require_process_identity else _marker(_plain_directory(root))
    supplied = (storage_id, grant_id, grant_version, uid, gid)
    if any(value is not None for value in supplied):
        if any(value is None for value in supplied):
            raise StorageOwnershipError("complete expected binding required")
        expected = _identity(storage_id, grant_id, grant_version, uid, gid)
        if marker["binding"] != expected:
            raise StorageOwnershipError("archive ownership marker differs from expected grant")
    observation = observe(root, require_marker=require_marker,
                          require_process_identity=require_process_identity)
    return {"ownership": marker, "observation": observation}


def main(argv=None):
    parser = argparse.ArgumentParser(description="Bind or verify archive-data execution identity ownership")
    parser.add_argument("operation", choices=("bind", "verify"))
    parser.add_argument("--root", required=True)
    parser.add_argument("--storage-id")
    parser.add_argument("--grant-id")
    parser.add_argument("--grant-version", type=int)
    parser.add_argument("--uid", type=int)
    parser.add_argument("--gid", type=int)
    args = parser.parse_args(argv)
    values = (args.storage_id, args.grant_id, args.grant_version, args.uid, args.gid)
    try:
        if args.operation == "bind":
            if any(value is None for value in values):
                raise StorageOwnershipError("bind requires complete controller grant arguments")
            result = bind(args.root, storage_id=args.storage_id, grant_id=args.grant_id,
                          grant_version=args.grant_version, uid=args.uid, gid=args.gid)
        else:
            kwargs = {}
            if any(value is not None for value in values):
                if any(value is None for value in values):
                    raise StorageOwnershipError("verify requires either zero or all expected binding arguments")
                kwargs = dict(storage_id=args.storage_id, grant_id=args.grant_id,
                              grant_version=args.grant_version, uid=args.uid, gid=args.gid)
            result = inspect(args.root, **kwargs)
    except (OSError, ValueError, KeyError, TypeError):
        print(json.dumps({"schema": SCHEMA, "valid": False, "safe_to_cut_over": False}))
        return 2
    print(json.dumps({**result, "valid": True, "safe_to_cut_over": False}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
