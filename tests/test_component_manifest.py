import json
import re
import tomllib
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
COMPONENT = ROOT / "src" / "zog" / "archive_mirror"


def version_from_init():
    text = (COMPONENT / "__init__.py").read_text()
    match = re.search(r'^__version__\s*=\s*["\']([^"\']+)["\']', text, re.MULTILINE)
    if not match:
        raise AssertionError("component __version__ missing")
    return match.group(1)


class ComponentManifestTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manifest = json.loads((ROOT / "zog-component.json").read_text())
        cls.project = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]

    def test_release_build_identity_matches_component(self):
        self.assertEqual(self.manifest["schema"], 2)
        self.assertEqual(self.manifest["program"], "archive-mirror")
        self.assertEqual(self.manifest["python_package"], "zog.archive_mirror")
        self.assertEqual(self.manifest["version"], version_from_init())
        self.assertEqual(self.project["version"], version_from_init())
        self.assertEqual(self.project["license"], "BSD-3-Clause OR GPL-3.0-only")
        self.assertEqual(
            self.manifest["scripts"],
            {"archive-mirror": "zog.archive_mirror.cli:main"},
        )
        self.assertEqual(
            self.project["scripts"],
            self.manifest["scripts"],
        )

    def test_component_and_external_dependencies_are_explicit(self):
        self.assertEqual(self.manifest["component_dependencies"], ["host-identify"])
        self.assertEqual(
            self.manifest["external_dependencies"],
            self.project["dependencies"],
        )
        runtime_text = "\n".join(
            path.read_text() for path in COMPONENT.rglob("*.py")
        )
        self.assertIn("zog.host_identify", runtime_text)
        self.assertIn("cryptography", runtime_text)
        self.assertIn("jwt", runtime_text.lower())

    def test_release_build_can_copy_component_without_rewrite(self):
        self.assertTrue(COMPONENT.is_dir())
        self.assertTrue((COMPONENT / "__init__.py").is_file())
        self.assertTrue((COMPONENT / "migrations" / "__init__.py").is_file())
        self.assertFalse((ROOT / "src" / "zog" / "__init__.py").exists())
        self.assertFalse((ROOT / "archive_mirror").exists())
        self.assertEqual(self.manifest["package_data"], [])

    def test_license_notice_inputs_exist(self):
        self.assertEqual(self.manifest["license_notice_paths"], ["LICENSE", "LICENSES/BSD-3-Clause.txt", "LICENSES/GPL-3.0-only.txt", "THIRD-PARTY-NOTICES.md"])
        for relative in self.manifest["license_notice_paths"]:
            path = ROOT / relative
            self.assertTrue(path.is_file(), f"missing license/notice input: {relative}")


if __name__ == "__main__":
    unittest.main()
