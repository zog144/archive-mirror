# Notice acceptance — local fixtures, 2026-09-30

- `DJANGO_SETTINGS_MODULE=tests.settings python -m pytest -q` from archive-mirror:
  **34 passed**. Existing collector, download, lease, snapshot retention and observation
  regressions plus immutable version binding, distinct package terms, conflict,
  missing/hash/size failures, interruption before/after atomic publication,
  collection authorization, text safety, pagination, rootfs dedup/exception/seed
  evidence, origin/path rejection and literal source-record verification including exact CRLF notice bytes.
- `python tools/test-image-build-receipts.py ../image-build`: **passed**, using actual
  image-build `preserve()` receipts from unstable
  `c0ba0d8b61cdfee051b1ad9092761d976c61bb71`. Verifies archive/receipt/text hashes,
  retained source inputs, stage identity, private origin redaction and conservative
  seed coverage. No compilation or full rootfs was run.
- Companion `python tools/archive-inventory/test-provider.py ../archive-mirror`
  from station-access: **1 passed**. Actual local mirror with signed v1/v2 reporter,
  exact approved host ingestion, notice document roundtrip, collection-scoped bytes,
  role withdrawal and shared portal remaining accessible.
- Station-access's notice consumer/authentication tests, frontend tests and Chromium
  layout fixtures are recorded in its `docs/ARCHIVE-NOTICES-TEST-RESULTS.md`.

Test Python is the workspace's Python 3.12, not image-build's unfinished Python.
Django 5.2.17 and canonical host-identify
`0927bf4091d7016dedb9cbf52aa60192d68fe050` were used. Initial test invocations without
Django settings/import paths failed at collection; corrected commands above passed.
No AWS, DNS, remote archive, persistent service, reboot or real generation acceptance
is claimed. The staged receiver-first rollout is documented but not deployed.
