#!/bin/bash
set -euo pipefail
: "${HOST_IDENTIFY_SOURCE_DIRECTORY:?Set the exact retrieved host-identify source directory}"
mkdir -p evidence
if ! command -v python3.12 >/dev/null; then
    dnf install -y python3.12 python3.12-pip git
fi
python3.12 -m venv /var/tmp/archive-mirror-acceptance-environment
PYTHON=/var/tmp/archive-mirror-acceptance-environment/bin/python
"$PYTHON" -m pip install "$HOST_IDENTIFY_SOURCE_DIRECTORY" . > evidence/dependencies.log 2>&1
PYTHONPATH="$PWD/src" DJANGO_SETTINGS_MODULE=tests.settings "$PYTHON" -m django test tests --verbosity 2 > evidence/unit-tests.log 2>&1
PYTHONPATH="$PWD" "$PYTHON" tests/runtime_acceptance.py > evidence/runtime.log 2>&1
"$PYTHON" -m pip freeze > evidence/packages.txt
