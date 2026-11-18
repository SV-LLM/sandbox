#!/usr/bin/env bash
# endpoint component entrypoint — starts the governed crossing endpoint
# from this repository's operation tree. Site values come from the
# rendered config (see OPERATOR__SLOTS.md); nothing site-specific is
# hardcoded here.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
exec python3 "$HERE/../../operation/endpoint.py" "$@"
