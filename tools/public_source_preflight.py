#!/usr/bin/env python3
"""Bounded static scan of the exact public archive-mirror development source."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import subprocess
import sys

FORBIDDEN = {"COPYRIGHT", "version-share-handoff.json", "integration/station-access.patch"}
FORBIDDEN_DIRS = ("integration/persistent-station/", "handoffs/", "review/", ".version-share/")
REQUIRED = {
    "LICENSE", "LICENSES/BSD-3-Clause.txt", "LICENSES/GPL-3.0-only.txt",
    "THIRD-PARTY-NOTICES.md", "README.md", "pyproject.toml",
    "zog-component.json", "src/zog/archive_mirror/__init__.py",
    ".github/workflows/python-namespace.yml",
}
SOURCE_LICENSE = "BSD-3-Clause OR GPL-3.0-only"
SCANS = {
    "private_repository_reference": re.compile(
        rb"zog144/(?:know" rb"-file|[a-z0-9-]+-old)\b", re.I),
    "private_grant": re.compile(
        rb"LicenseRef-Zog-" rb"Private|private development " rb"material|no public " rb"license", re.I),
    "private_token_path": re.compile(
        rb"github-token" rb"\.txt|--token" rb"-file|ZOG_CROSS_REPO_" rb"READ_TOKEN", re.I),
    "credential_bytes": re.compile(
        rb"-----BEGIN\s+[A-Z ]*PRIVATE KEY-----|"
        rb"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b|"
        rb"github_pat_[A-Za-z0-9_]{30,}", re.I),
    "instance_identity": re.compile(rb"\bi-[0-9a-f]{17}\b"),
}
BANNED_EXT = (".tar", ".tar.xz", ".tar.gz", ".zip", ".whl",
              ".so", ".a", ".o", ".pyc", ".db", ".sqlite3")

def audit(root: Path):
    raw = subprocess.check_output(["git", "-C", str(root), "ls-files", "--stage", "-z"])
    rows = []
    for item in filter(None, raw.decode("utf-8").split("\0")):
        metadata, name = item.split("\t")
        mode, blob, stage = metadata.split()
        rows.append((name, mode, blob))
    issues = []
    paths = {name for name, _, _ in rows}
    for name in sorted(REQUIRED - paths):
        issues.append([name, "required_missing"])
    for name, mode, _ in rows:
        if name in FORBIDDEN or name.startswith(FORBIDDEN_DIRS):
            issues.append([name, "private_or_historical_path"])
            continue
        f = root / name
        if mode != "100644" or f.is_symlink() or not f.is_file():
            issues.append([name, "nonregular_or_unsafe_mode"])
            continue
        if name.endswith(BANNED_EXT):
            issues.append([name, "raw_archive_or_binary_payload"])
        data = f.read_bytes()
        if b"\0" in data:
            issues.append([name, "binary_nul_payload"])
        try:
            data.decode("utf-8")
        except UnicodeDecodeError:
            issues.append([name, "non_utf8_source"])
        for label, matcher in SCANS.items():
            if matcher.search(data):
                issues.append([name, label])
    for filename in ("LICENSE", "pyproject.toml"):
        if filename in paths and SOURCE_LICENSE not in (root / filename).read_text():
            issues.append([filename, "missing_public_dual_license"])
    expected = [
        "LICENSE", "LICENSES/BSD-3-Clause.txt",
        "LICENSES/GPL-3.0-only.txt", "THIRD-PARTY-NOTICES.md",
    ]
    if "zog-component.json" in paths:
        v = json.loads((root / "zog-component.json").read_text())
        if v.get("license_notice_paths") != expected:
            issues.append(["zog-component.json", "incorrect_notice_manifest"])
    untracked = [
        str(p.relative_to(root)) for p in root.rglob("*")
        if p.is_file() and ".git" not in p.relative_to(root).parts
        and str(p.relative_to(root)) not in paths
    ]
    if untracked:
        issues.append([untracked[0], "untracked_source_file"])
    return {"schema": "archive-mirror-public-source-preflight-v1",
            "file_count": len(rows), "findings": issues, "passed": not issues}

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    args = parser.parse_args()
    report = audit(args.root.resolve())
    print(json.dumps(report, sort_keys=True))
    return 0 if report["passed"] else 1

if __name__ == "__main__":
    sys.exit(main())
