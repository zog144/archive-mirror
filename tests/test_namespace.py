import importlib.util
import unittest
from pathlib import Path

import zog.archive_mirror
from zog.archive_mirror import cli


class NamespaceTests(unittest.TestCase):
    def test_component_namespace_and_version(self):
        self.assertEqual(zog.archive_mirror.__version__, "0.4.2")
        self.assertTrue(callable(cli.main))
        self.assertIsNone(importlib.util.find_spec("archive_mirror"))

    def test_no_legacy_runtime_python_paths(self):
        root = Path(__file__).resolve().parents[1]
        forbidden = (
            "from archive_mirror",
            "import archive_mirror",
            "'archive_mirror.",
            '"archive_mirror.',
            "-m','archive_mirror",
            '-m","archive_mirror',
            "from host_identify",
            "import host_identify",
            "'host_identify.",
            '"host_identify.',
        )
        paths = list((root / "src").rglob("*.py")) + list((root / "tests").rglob("*.py"))
        paths += list((root / "integration").rglob("*.py"))
        for path in paths:
            if path == Path(__file__):
                continue
            text = path.read_text()
            for value in forbidden:
                # Django migrations serialize the stable app label, not the
                # Python import path. archive_mirror must remain the app label
                # so existing database migration identity is preserved.
                if "migrations" in path.parts and value in ("'archive_mirror.", '"archive_mirror.'):
                    continue
                self.assertNotIn(value, text, f"{value!r} remains in {path.relative_to(root)}")


if __name__ == "__main__":
    unittest.main()
