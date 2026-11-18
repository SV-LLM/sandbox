#!/usr/bin/env bash
# exposure component entrypoint — starts the path-filtered public
# proxy from this repository's operation tree.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
exec python3 "$HERE/../../operation/public_proxy.py" "$@"
