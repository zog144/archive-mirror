"""Offline migration integrity: never rely on a live provider or prune."""
import hashlib
import sqlite3
import tempfile
import unittest
from pathlib import Path

from zog.archive_mirror.store_verification import (
    StoreVerificationError, export_catalogue, verify_store, has_catalogue,
)


def fixture(root):
    db = root / "station-access.sqlite3"
    content = b"the original archive bytes; never re-download"
    digest = hashlib.sha256(content).hexdigest()
    archive = root / "store"
    (archive / "objects").mkdir(parents=True)
    (archive / "objects" / digest).write_bytes(content)
    with sqlite3.connect(db) as conn:
        conn.executescript("""
            CREATE TABLE archive_mirror_archive (
                id integer PRIMARY KEY, collection varchar(64), digest varchar(64),
                size bigint, kind varchar(32), managed bool, provenance text, created text);
            CREATE TABLE archive_mirror_snapshot (
                id integer PRIMARY KEY, archive_id bigint REFERENCES archive_mirror_archive(id),
                source text, month text, "commit" text);
            CREATE TABLE archive_mirror_pin (
                id integer PRIMARY KEY, archive_id bigint REFERENCES archive_mirror_archive(id), name text);
            CREATE TABLE archive_mirror_collectionstatus (
                source varchar(128) PRIMARY KEY, last_attempt text, last_success text, error text);
            CREATE TABLE archive_mirror_sourcepinset (
                identity varchar(180) PRIMARY KEY, pin_date text, manifest_sha256 varchar(64),
                complete bool, active bool, created text);
            CREATE TABLE archive_mirror_reviewedsource (
                id integer PRIMARY KEY,
                pin_set_id text REFERENCES archive_mirror_sourcepinset(identity),
                archive_id integer REFERENCES archive_mirror_archive(id),
                package text, source text, canonical_url text);
            CREATE TABLE django_migrations (id integer PRIMARY KEY, app text, name text, applied text);
            CREATE TABLE auth_user (id integer PRIMARY KEY, password text);
        """)
        conn.execute("INSERT INTO archive_mirror_archive VALUES (1,?,?,?,?,?,?,?)",
                     ("sources",digest,len(content),"source",1,"{}","2026-10-11"))
        conn.execute("INSERT INTO archive_mirror_pin VALUES (1,1,'release')")
        conn.execute("INSERT INTO archive_mirror_sourcepinset VALUES ('review-1','2026-10-11',?,0,0,'2026-10-11')",
                     ("a"*64,))
        conn.execute("INSERT INTO archive_mirror_reviewedsource VALUES (1,'review-1',1,'example','src','https://source.example.org')")
        conn.execute("INSERT INTO django_migrations VALUES (1,'archive_mirror','0001_initial','2026-10-11')")
        conn.execute("INSERT INTO auth_user VALUES (1,'PRIVATE-DO-NOT-COPY')")
    return db, archive, digest


class StoreVerificationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.database, self.store, self.digest = fixture(self.root)
        self.export = self.root / "archive-catalogue.sqlite3"

    def test_archive_only_export_retains_pins_incomplete_sets_and_foreign_keys(self):
        export_catalogue(self.database, self.export)
        result = verify_store(self.store, self.export)
        self.assertTrue(result["valid"])
        self.assertEqual(result["counts"]["pins"], 1)
        self.assertEqual(result["counts"]["reviewed_sources"], 1)
        self.assertEqual(result["counts"]["incomplete_source_pin_sets"], 1)
        self.assertEqual(result["counts"]["protected_archives"], 1)
        self.assertEqual(result["counts"]["currently_prunable_managed_sources"], 0)
        self.assertEqual(result["counts"]["objects"], 1)
        with sqlite3.connect(self.export) as conn:
            tables = {name for (name,) in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            self.assertNotIn("auth_user", tables)
            self.assertEqual(conn.execute("SELECT count(*) FROM django_migrations").fetchone(), (1,))
        with self.assertRaises(StoreVerificationError):
            export_catalogue(self.database, self.export)
        self.assertTrue(has_catalogue(self.database))
        self.assertTrue(has_catalogue(self.export))

    def test_wrong_archive_bytes_fail_closed_and_source_is_not_modified(self):
        export_catalogue(self.database, self.export)
        obj = self.store / "objects" / self.digest
        obj.write_bytes(b"forged bytes")
        with self.assertRaises(StoreVerificationError):
            verify_store(self.store, self.export)
        self.assertEqual(self.database.exists(), True)

    def test_missing_pin_target_and_bad_reviewed_source_fail_closed(self):
        export_catalogue(self.database, self.export)
        with sqlite3.connect(self.export) as db:
            db.execute("PRAGMA foreign_keys=OFF")
            db.execute("UPDATE archive_mirror_pin SET archive_id=99")
        with self.assertRaises(StoreVerificationError):
            verify_store(self.store, self.export)

    def test_symlink_object_and_orphans_refused_when_requested(self):
        export_catalogue(self.database, self.export)
        target = self.store/"objects"/self.digest
        original = self.root/"original"
        original.write_bytes(target.read_bytes())
        target.unlink()
        target.symlink_to(original)
        with self.assertRaises(StoreVerificationError):
            verify_store(self.store,self.export)
        target.unlink()
        target.write_bytes(original.read_bytes())
        (self.store/"objects"/("f"*64)).write_bytes(b"orphan")
        report = verify_store(self.store,self.export)
        self.assertEqual(report["counts"]["unreferenced_objects"],1)
        with self.assertRaises(StoreVerificationError):
            verify_store(self.store,self.export,require_no_orphans=True)

    def test_simulated_three_snapshot_retention_marks_old_unpinned_object_as_prunable(self):
        # Prune removes old snapshots before deciding which managed sources
        # remain protected. One historical snapshot alone must not grant
        # indefinite protection after four monthly revisions.
        with sqlite3.connect(self.database) as db:
            db.execute("DELETE FROM archive_mirror_pin")
            db.execute("DELETE FROM archive_mirror_reviewedsource")
            db.execute("DELETE FROM archive_mirror_sourcepinset")
            for number in range(1,5):
                content=("month-" + str(number)).encode()
                digest=hashlib.sha256(content).hexdigest()
                (self.store/"objects"/digest).write_bytes(content)
                db.execute("INSERT INTO archive_mirror_archive VALUES (?,?,?,?,?,?,?,?)",
                           (1+number,"sources",digest,len(content),"source",1,"{}","2026-10-11"))
                db.execute("INSERT INTO archive_mirror_snapshot VALUES (?,?,?,?,?)",
                           (number,1+number,"project",f"2026-0{number}","commit"))
            # The original managed record is deliberately unreferenced here.
            db.execute("DELETE FROM archive_mirror_archive WHERE id=1")
        export_catalogue(self.database,self.export)
        report=verify_store(self.store,self.export)
        self.assertEqual(report["counts"]["snapshots_prunable_if_run"],1)
        self.assertEqual(report["counts"]["currently_prunable_managed_sources"],1)
        self.assertTrue((self.store/"objects").exists())
