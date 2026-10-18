"""Bounded, read-only archive cutover evidence for host-deploy acceptance."""
from __future__ import annotations

import argparse
import fcntl
import json
import os
import stat
import time
from contextlib import contextmanager
from pathlib import Path

from .storage_ownership import runtime_guard, observe

SCHEMA = "zog-archive-cutover-evidence-v1"


@contextmanager
def _writer_snapshot(store):
    """Share the existing writer lock without creating or changing store state."""
    path = Path(store) / "writer.lock"
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise ValueError("archive writer lock is unsafe")
        fcntl.flock(fd, fcntl.LOCK_SH)
        yield
    finally:
        os.close(fd)


def _role(role_reader):
    try:
        value = role_reader()
        desired = value["desired"]
        return {
            "available": True,
            "status": "selected",
            "revision": desired["revision"],
            "lease_expires_at": desired["lease_expires_at"],
        }
    except (OSError, ValueError, KeyError, TypeError):
        return {"available": False, "status": "unavailable"}


def collect(root, *, role_reader=None, observed_at=None):
    root = Path(root)
    ownership = runtime_guard(root)
    if role_reader is None:
        from .lease import lease
        role_reader = lease
    with _writer_snapshot(root / "store"):
        state = observe(root)
    counts = state["counts"]
    retention = {
        key: counts[key] for key in (
            "archives", "snapshots", "pins", "source_pin_sets",
            "incomplete_source_pin_sets", "active_source_pin_sets",
            "reviewed_sources", "protected_archives", "objects",
            "unreferenced_objects", "snapshots_prunable_if_run",
            "currently_prunable_managed_sources",
        )
    }
    return {
        "schema": SCHEMA,
        "valid": True,
        "safe_to_cut_over": False,
        "observed_at": int(time.time() if observed_at is None else observed_at),
        "ownership": ownership,
        "runtime_identity": {
            "uid": os.geteuid(),
            "gid": os.getegid(),
            "supplementary_groups": sorted(set(os.getgroups()) - {os.getegid()}),
        },
        "store": {
            "catalogue_sha256": state["catalogue_sha256"],
            "object_manifest_sha256": state["object_manifest_sha256"],
            "owned_entries": state["owned_entries"],
            "retention": retention,
        },
        "role": _role(role_reader),
    }


def main(argv=None):
    parser=argparse.ArgumentParser(description="Emit read-only archive cutover evidence")
    parser.add_argument("--root", required=True)
    args=parser.parse_args(argv)
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "zog.archive_mirror.settings")
    try:
        import django
        django.setup()
        result=collect(args.root)
    except (OSError, ValueError, KeyError, TypeError):
        print(json.dumps({"schema":SCHEMA,"valid":False,"safe_to_cut_over":False}))
        return 2
    print(json.dumps(result,sort_keys=True))
    return 0


if __name__=="__main__":
    raise SystemExit(main())
