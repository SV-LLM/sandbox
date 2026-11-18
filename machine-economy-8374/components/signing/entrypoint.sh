#!/usr/bin/env bash
# signing component entrypoint — starts the LANE-FORM signing service
# (BUILD-Q-33: Authority-grant admission, site-born specimen) from
# this repository's signing tree. The production-form service
# (skap_signing.py, ecosystem SKAP retrieval) remains in the tree as
# the coordinator node's form; a lane site runs lane_signing.py.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
exec python3 "$HERE/../../signing/lane_signing.py" "$@"
