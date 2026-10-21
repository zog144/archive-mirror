"""Production archive composition isolates credentials and mutable storage."""
import ast
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parents[1]


class ArchiveCompositionTests(unittest.TestCase):
    def test_production_uses_controller_application_identity(self):
        path=ROOT/'integration/production/archive-mirror/application.py'
        contents=path.read_text()
        ast.parse(contents)
        self.assertIn('name="archive-mirror"',contents)
        self.assertIn('persistent=True',contents)
        self.assertIn('execution_identity="application"',contents)
        self.assertIn('writable_mounts=("archive-data",)',contents)
        self.assertEqual(contents.count('"ARCHIVE_MIRROR_REQUIRE_OWNERSHIP": "1"'),2)
        self.assertIn('name="refresh-scheduler"',contents)
        self.assertIn('name="server"',contents)
        self.assertIn('"/var/lib/archive-mirror"',contents)
        self.assertNotIn('user=',contents)
        self.assertNotIn('group=',contents)
        self.assertNotIn('user="regular"',contents)
        self.assertNotIn('"/var/lib/station-access"',contents)
        self.assertNotIn('"/var/lib/host-discover/credentials"',contents)
        self.assertNotIn('mounts={"mirror-live"',contents)

    def test_legacy_regular_archive_templates_are_retired(self):
        # The reviewed public export excludes the private acceptance templates.
        self.assertFalse((ROOT/'integration/persistent-station').exists())
        for relative in (
            'integration/box-control/application.py',
        ):
            contents=(ROOT/relative).read_text()
            tree=ast.parse(contents)
            calls=[node for node in ast.walk(tree)
                   if isinstance(node,ast.Call) and isinstance(node.func,ast.Name)
                   and node.func.id=='application']
            self.assertEqual(calls,[])
            self.assertNotIn('user="regular"',contents)
            self.assertIn('RETIRED',contents)
