#!/usr/bin/env bash
# signing component entrypoint — starts the sign-under-seal service
# from this repository's signing tree. Custody material is supplied
# on-site via the rendered signing config (see OPERATOR__SLOTS.md).
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
exec python3 "$HERE/../../signing/skap_signing.py" "$@"
