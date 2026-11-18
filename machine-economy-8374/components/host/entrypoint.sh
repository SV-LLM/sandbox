#!/usr/bin/env bash
# host component entrypoint — bootstrap a lane instance of the
# operation from a bare checkout of this repository.
#   entrypoint.sh --source <checkout> --target <instance-tree> [flags]
# See COMPONENT.md and bootstrap.py --help for the slot flags.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
exec python3 "$HERE/bootstrap.py" "$@"
