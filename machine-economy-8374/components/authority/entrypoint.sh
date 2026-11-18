#!/usr/bin/env bash
# authority component entrypoint — the site Authority store CLI.
#   entrypoint.sh --store <instance>/signing/custody/authority_store.json <issue|revoke|list|verify-log> ...
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
exec python3 "$HERE/../../signing/authority.py" "$@"
