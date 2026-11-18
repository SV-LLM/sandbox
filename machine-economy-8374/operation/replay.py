#!/usr/bin/env python3
"""Replay/check for the machine-economy endpoint receipt chain.

Recomputes every receipt digest from its (predecessor, content), verifies
linkage and pair matching across all segments, and compares the recomputed
terminal digest against the stored terminal anchor. Usage:
    python3 replay.py [--segments DIR]
Exit code 0 on MATCH, 1 on MISMATCH."""
import json, os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from endpoint import replay, SEG_DIR

if __name__ == "__main__":
    d = SEG_DIR
    if "--segments" in sys.argv:
        d = sys.argv[sys.argv.index("--segments") + 1]
    r = replay(d)
    print(json.dumps(r, indent=1))
    sys.exit(0 if r["verdict"] == "MATCH" else 1)
