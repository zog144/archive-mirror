"""Offline archive store verification and archival catalogue extraction.

Pure standard library. Does not import Django or instantiate the archive store,
does not create archive objects, and never invokes prune. Inputs must be frozen
checkpoints from the deployment owner, not a running writer's changing files.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import stat
from pathlib import Path

TABLES = ("archive_mirror_archive", "archive_mirror_snapshot", "archive_mirror_pin",
          "archive_mirror_collectionstatus", "archive_mirror_sourcepinset",
          "archive_mirror_reviewedsource")
DIGEST = re.compile(r"[0-9a-f]{64}\Z")
MAX_ROWS = 100000
MAX_FILES = 200000


class StoreVerificationError(ValueError):
    pass


def _database(path):
    if path.is_symlink() or not path.is_file():
        raise StoreVerificationError("catalogue unavailable or redirected")
    return sqlite3.connect(f"file:{path.as_posix()}?mode=ro", uri=True)


def _tables(db):
    return {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}


def has_catalogue(path):
    with _database(Path(path)) as db:
        found = _tables(db)
    return set(TABLES).issubset(found)


def _rows(db, table, columns="*"):
    values = db.execute(f"SELECT {columns} FROM {table} LIMIT ?", (MAX_ROWS + 1,)).fetchall()
    if len(values) > MAX_ROWS:
        raise StoreVerificationError("catalogue row limit exceeded")
    return values


def export_catalogue(source_database, destination_database):
    """Extract only archive tables into a distinct SQLite database, preserving rows.

    The former integrated station database is an immutable migration input;
    no table is dropped or modified in it. Consumer cutover must configure the
    standalone archive application to use the exported catalogue exclusively.
    """
    source, destination = Path(source_database), Path(destination_database)
    if destination.exists() or destination.is_symlink():
        raise StoreVerificationError("archive catalogue destination is not empty")
    if not destination.parent.is_dir() or destination.parent.is_symlink():
        raise StoreVerificationError("archive catalogue parent unavailable")
    with _database(source) as src:
        tables = _tables(src)
        if not set(TABLES).issubset(tables):
            raise StoreVerificationError("integrated archive catalogue tables missing")
        schema = list(src.execute("SELECT type, name, sql FROM sqlite_master "
            "WHERE type IN ('table','index') AND sql IS NOT NULL ORDER BY type DESC, name"))
        # Never expose catalogue contents in a default-mode 0644 SQLite file,
        # even briefly while the export is being written.
        descriptor = os.open(destination, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
        os.close(descriptor)
        out = sqlite3.connect(str(destination))
        try:
            out.execute("PRAGMA foreign_keys=OFF")
            out.execute("BEGIN IMMEDIATE")
            for kind, name, ddl in schema:
                if name in TABLES or (kind == "index" and name.startswith("archive_mirror_")):
                    out.execute(ddl)
            for table in TABLES:
                count = int(src.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])
                if count > MAX_ROWS:
                    raise StoreVerificationError("catalogue row limit exceeded")
                columns = [row[1] for row in src.execute(f"PRAGMA table_info({table})")]
                if not columns:
                    raise StoreVerificationError("archive schema missing columns")
                marker = ",".join("?" for _ in columns)
                for row in src.execute(f"SELECT * FROM {table}"):
                    out.execute(f"INSERT INTO {table} VALUES ({marker})", row)
            if "django_migrations" in tables:
                out.execute("CREATE TABLE django_migrations (id integer PRIMARY KEY AUTOINCREMENT, "
                            "app varchar(255) NOT NULL, name varchar(255) NOT NULL, applied datetime NOT NULL)")
                for _,app,name,applied in src.execute(
                    "SELECT id,app,name,applied FROM django_migrations WHERE app='archive_mirror'"):
                    out.execute("INSERT INTO django_migrations (app,name,applied) VALUES (?,?,?)",
                                (app,name,applied))
            out.execute("COMMIT")
            if out.execute("PRAGMA foreign_key_check").fetchone():
                raise StoreVerificationError("archive catalogue has dangling references")
            if out.execute("PRAGMA integrity_check").fetchone() != ("ok",):
                raise StoreVerificationError("archive catalogue integrity failure")
            out.execute("VACUUM")
            out.close()
        except BaseException:
            out.close()
            destination.unlink(missing_ok=True)
            raise
    with destination.open("rb") as stream:
        os.fsync(stream.fileno())
    parent_fd = os.open(destination.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try: os.fsync(parent_fd)
    finally: os.close(parent_fd)
    return destination


def _sha256_file(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def verify_store(directory, catalogue_database, *, require_no_orphans=False):
    """Fail closed on lost/corrupt objects, dangling pins or pin sets.

    A retained orphan may be a deliberately unpublished/recoverable object.
    Report it, never delete it or claim that prune will be safe automatically.
    """
    root = Path(directory)
    if root.is_symlink() or not root.is_dir():
        raise StoreVerificationError("archive root missing or redirected")
    obj = root / "objects"
    if obj.is_symlink() or not obj.is_dir():
        raise StoreVerificationError("object directory missing or redirected")
    with _database(Path(catalogue_database)) as db:
        if db.execute("PRAGMA integrity_check").fetchone() != ("ok",):
            raise StoreVerificationError("catalogue integrity failure")
        if not set(TABLES).issubset(_tables(db)):
            raise StoreVerificationError("archive catalogue schema incomplete")
        if db.execute("PRAGMA foreign_key_check").fetchone():
            raise StoreVerificationError("catalogue foreign key violation")
        archives = _rows(db, TABLES[0], "id,collection,digest,size,kind,managed")
        snapshot_rows = _rows(db, TABLES[1], "id,archive_id,source,month")
        snapshots = [(row[1],) for row in snapshot_rows]
        # Mirror's prune retains the newest THREE snapshots per source before
        # evaluating managed archive retention. Simulate, never mutate.
        newest = {}
        for sid, aid, source, month in snapshot_rows:
            newest.setdefault(source, []).append((month, sid, aid))
        kept_snapshots = {
            aid for rows in newest.values()
            for month, sid, aid in sorted(rows, reverse=True)[:3]
        }
        snapshot_rows_pruned = sum(max(0, len(rows)-3) for rows in newest.values())
        pins = _rows(db, TABLES[2], "archive_id")
        sets = _rows(db, TABLES[4], "identity,complete,active")
        reviewed = _rows(db, TABLES[5], "pin_set_id,archive_id")
        status = _rows(db, TABLES[3])
        identifiers = {row[0] for row in archives}
        for (aid,) in snapshots + pins:
            if aid not in identifiers:
                raise StoreVerificationError("orphan snapshot/pin reference")
        set_ids = {row[0] for row in sets}
        for sid, aid in reviewed:
            if sid not in set_ids or aid not in identifiers:
                raise StoreVerificationError("dangling reviewed-source membership")
        for _,complete,active in sets:
            if active and not complete:
                raise StoreVerificationError("active incomplete source pin set")
        protected = kept_snapshots | {row[0] for row in pins}
        protected.update(aid for sid,aid in reviewed
                         if any(record[0] == sid and (record[2] or not record[1]) for record in sets))
        unique = {}
        for aid,collection,digest,size,kind,managed in archives:
            if not isinstance(digest,str) or not DIGEST.fullmatch(digest) or type(size) is not int or size < 0:
                raise StoreVerificationError("invalid catalogue archive identity")
            if digest in unique and unique[digest] != size:
                raise StoreVerificationError("duplicate object size disagreement")
            unique[digest] = size
        if len(unique) > MAX_FILES:
            raise StoreVerificationError("object count limit exceeded")
        for digest,size in unique.items():
            path=obj/digest
            info=path.lstat() if path.exists() or path.is_symlink() else None
            if info is None or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise StoreVerificationError("archive object missing or unsafe")
            if info.st_size != size or _sha256_file(path) != digest:
                raise StoreVerificationError("archive bytes do not match catalogue")
        unreferenced = 0
        for index,item in enumerate(obj.iterdir()):
            if index >= MAX_FILES:
                raise StoreVerificationError("unexpected object directory size")
            if item.is_symlink() or not item.is_file() or not DIGEST.fullmatch(item.name):
                raise StoreVerificationError("unsafe or unexpected object")
            if item.name not in unique:
                unreferenced += 1
        if require_no_orphans and unreferenced:
            raise StoreVerificationError("unreferenced objects require operator disposition")
        # Preserve incomplete sets even without currently attached sources.
        counts = {"archives":len(archives),"snapshots":len(snapshots),"pins":len(pins),
                  "collection_status":len(status),"source_pin_sets":len(sets),
                  "incomplete_source_pin_sets":sum(not x[1] for x in sets),
                  "active_source_pin_sets":sum(bool(x[2]) for x in sets),
                  "reviewed_sources":len(reviewed),"protected_archives":len(protected),
                  "objects":len(unique),"unreferenced_objects":unreferenced,
                  "snapshots_prunable_if_run":snapshot_rows_pruned}
        eligible = sum(bool(managed) and kind == "source" and aid not in protected
                       for aid,_,_,_,kind,managed in archives)
        counts["currently_prunable_managed_sources"] = eligible
        # Include notice sidecars in the integrity check, but never invent them
        # for older archives which never published notice evidence.
        notices=root/"notices"
        if notices.exists() or notices.is_symlink():
            if notices.is_symlink() or not notices.is_dir():
                raise StoreVerificationError("notice directory is unsafe")
            from .notice_contract import decode
            archive_by_key = {(row[1],row[2]): row[4] for row in archives}
            for index,notice in enumerate(notices.iterdir()):
                if index >= MAX_FILES:
                    raise StoreVerificationError("notice directory limit exceeded")
                if notice.is_symlink() or not notice.is_file():
                    raise StoreVerificationError("unsafe notice")
                with notice.open("rb") as stream:
                    value=decode(stream.read(524289))
                if (value["collection"],value["archive_digest"]) not in archive_by_key:
                    # Notice retention is independent of prune and may outlive
                    # its archive record: this is permitted, not an orphan grant.
                    continue
                if archive_by_key[(value["collection"],value["archive_digest"])] != value["artifact_kind"]:
                    raise StoreVerificationError("notice binding mismatch")
        return {"schema":"zog-archive-store-verification-v1","valid":True,
                "counts":counts,"catalogue_sha256":_sha256_file(Path(catalogue_database)),
                "object_manifest_sha256":hashlib.sha256(
                    "".join(f"{d}:{unique[d]}\n" for d in sorted(unique)).encode()).hexdigest(),
                "prune_performed":False}


def main(argv=None):
    import argparse
    parser = argparse.ArgumentParser(description="Read-only archive store and catalogue integrity verification")
    parser.add_argument("--root", required=True)
    parser.add_argument("--catalogue", required=True)
    parser.add_argument("--require-no-orphans", action="store_true")
    args=parser.parse_args(argv)
    try:
        result=verify_store(args.root,args.catalogue,require_no_orphans=args.require_no_orphans)
    except (OSError,ValueError,sqlite3.Error,KeyError,TypeError):
        print(json.dumps({"schema":"zog-archive-store-verification-v1","valid":False}))
        return 2
    print(json.dumps(result,sort_keys=True))
    return 0


if __name__=="__main__":
    raise SystemExit(main())
