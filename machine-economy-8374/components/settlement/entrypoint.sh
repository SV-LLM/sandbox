#!/usr/bin/env bash
# settlement component entrypoint — settlement runs in-process inside
# the endpoint; this handle exercises the module's route discovery so
# a lane can verify the send path before a live crossing.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
exec python3 -c "
import sys; sys.path.insert(0, '$HERE/../../operation')
import settlement
cands = settlement._proxy_candidates()
print('proxy candidates:', cands)
rpc = settlement.Rpc(cands)
print('block:', rpc.call('eth_blockNumber', []))
"
