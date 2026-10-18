#!/usr/bin/env python3
"""Inspect source-only Python artifacts for namespace, licenses and unsafe copies."""
from pathlib import Path
import sys
from tarfile import open as open_tar
from zipfile import ZipFile

def main():
    dist = Path(sys.argv[1])
    wheels = list(dist.glob("*.whl"))
    sdists = list(dist.glob("*.tar.gz"))
    assert len(wheels) == 1 and len(sdists) == 1, "expected one wheel and one sdist"
    with ZipFile(wheels[0]) as z:
        paths = z.namelist()
        assert "zog/archive_mirror/__init__.py" in paths
        assert "zog/archive_mirror/migrations/__init__.py" in paths
        assert "zog/__init__.py" not in paths
        assert not any(p.startswith(("archive_mirror/", "tests/")) for p in paths)
        assert not any(p.endswith((".tar", ".zip", ".sqlite3")) for p in paths)
        licenses = [p for p in paths if p.endswith(("/LICENSE", "/THIRD-PARTY-NOTICES.md",
                                                     "/BSD-3-Clause.txt", "/GPL-3.0-only.txt"))]
        for required in ("LICENSE", "THIRD-PARTY-NOTICES.md",
                         "BSD-3-Clause.txt", "GPL-3.0-only.txt"):
            assert any(p.endswith("/"+required) for p in licenses), required
    with open_tar(sdists[0], "r:gz") as s:
        paths = s.getnames()
        for required in ("README.md", "LICENSE", "THIRD-PARTY-NOTICES.md",
                         "LICENSES/BSD-3-Clause.txt", "LICENSES/GPL-3.0-only.txt",
                         "integration/production/archive-mirror/application.py"):
            assert any(p.endswith("/"+required) for p in paths), required
        assert not any(p.endswith(("/COPYRIGHT", "/version-share-handoff.json",
                                  "/integration/station-access.patch")) for p in paths)
        assert not any("/integration/persistent-station/" in p for p in paths)
    print("archive-mirror source-only wheel/sdist namespace, notices and exclusions: PASS")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
