#!/usr/bin/env python3
"""Replay/check for a router receipt chain (the production
replay.py pattern): recompute every receipt digest, verify
linkage and pair matching and payment-nonce single-use, compare
the terminal anchor. Usage:
    python3 replay_router.py [--segments DIR]
Exit code 0 on MATCH, 1 on MISMATCH. Read-only: importing
router.py loads its chain object against ROUTER_RECEIPTS_DIR
(or the router dir default) but replay here runs against the
--segments dir given."""
import json, os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import router as router_mod

if __name__ == "__main__":
    d = os.environ.get("ROUTER_RECEIPTS_DIR",
                       os.path.join(router_mod.STATE_DIR, "receipts"))
    if "--segments" in sys.argv:
        d = sys.argv[sys.argv.index("--segments") + 1]
    r = router_mod.replay(d)
    print(json.dumps(r, indent=1))
    sys.exit(0 if r["verdict"] == "MATCH" else 1)
