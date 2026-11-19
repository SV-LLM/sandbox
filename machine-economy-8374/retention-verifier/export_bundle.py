#!/usr/bin/env python3
"""export_bundle.py — provider-side exporter for a customer retention bundle.

Reads a receipt chain (READ-ONLY) and emits a self-contained retention
bundle JSON for one named pair. The bundle carries everything the
chain's verification rules consume, so a customer can verify the pair
later with verify_bundle.py alone — after the provider is unavailable.

Chain rules implemented by the endpoint (endpoint.py, ReceiptChain /
replay / seal_digest_of), rules version "receipt-chain-rules/1":

  R1  record form {i, prev, content, hash}; indices consecutive from 1
  R2  canonical(obj) = json.dumps(obj, sort_keys=True,
      separators=(",", ":")).encode()          (UTF-8)
  R3  hash = SHA256(prev.encode() || canonical(content))  (hex)
  R4  the first record's prev is the string "GENESIS"
  R5  linkage: every later record's prev == the previous record's hash
  R6  a pair is two consecutive records sharing pair_id, index_in_pair
      0 then 1; member 1's content carries pair_anchor == member 0 hash
  R7  a verified payment authorization's nonce stands under exactly
      one pair in the chain (nonce single-use)
  R8  sub-lane segment seal (sub-lane chains only; the parent chain
      carries no seal over its own segments):
      seal_digest = SHA256(canonical({sublane, segment_index,
      terminal_anchor, entry_count, pair_count, prev_seal_digest}))

Usage:
  python3 export_bundle.py PAIR-000020 [--receipts DIR] [--out FILE]
      [--chain NAME]
Default --receipts is the live endpoint chain next to this build's
parent workspace; the exporter only ever opens chain files for reading.
"""

import argparse
import json
import os
import sys

RULES_VERSION = "receipt-chain-rules/1"
BUNDLE_FORM = "RETENTION_BUNDLE/1"

DEFAULT_RECEIPTS = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), os.pardir,
    "machine-economy-endpoint", "receipts")


def read_chain(seg_dir):
    """All complete records of a chain directory, in chain order.
    Read-only. Mirrors the endpoint's segment scan order (segment-*.jsonl
    sorted by name, lines in file order)."""
    entries = []
    for name in sorted(os.listdir(seg_dir)):
        if name.startswith("segment-") and name.endswith(".jsonl"):
            with open(os.path.join(seg_dir, name), "r") as f:
                for line in f:
                    if line.strip():
                        entries.append(json.loads(line))
    return entries


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("pair_id")
    ap.add_argument("--receipts", default=DEFAULT_RECEIPTS)
    ap.add_argument("--chain", default="parent")
    ap.add_argument("--out", default=None)
    args = ap.parse_args()

    entries = read_chain(args.receipts)
    if not entries:
        print(f"no chain entries under {args.receipts}", file=sys.stderr)
        return 2

    idx = [k for k, r in enumerate(entries)
           if r["content"].get("pair_id") == args.pair_id]
    if len(idx) != 2:
        print(f"{args.pair_id}: found {len(idx)} records, need exactly 2",
              file=sys.stderr)
        return 2
    first, last = idx[0], idx[1]
    pair_records = [entries[first], entries[last]]

    # The span: genesis through the pair's second member. Verification of
    # the span never depends on anything appended after the pair, so the
    # bundle stays valid as the live chain keeps growing.
    span = entries[:last + 1]

    # The pair this pair settles, when it is a settlement pair: its
    # records are inside the span already; carry them as a named section
    # so the settlement -> crossing binding is checkable from the bundle.
    settles_section = None
    settled_pair_id = pair_records[0]["content"].get("settles_pair_id")
    if settled_pair_id:
        s_idx = [k for k, r in enumerate(entries)
                 if r["content"].get("pair_id") == settled_pair_id]
        if len(s_idx) == 2:
            settles_section = {
                "pair_id": settled_pair_id,
                "records": [entries[s_idx[0]], entries[s_idx[1]]],
            }

    settlement = pair_records[0]["content"].get("settlement")
    settlement_reference = None
    if settlement is not None:
        settlement_reference = {
            k: settlement.get(k) for k in (
                "status", "tx_hash", "block_number", "value_micro_usdc",
                "asset", "payTo", "nonce", "mode")
        }

    bundle = {
        "bundle": BUNDLE_FORM,
        "rules_version": RULES_VERSION,
        "chain": args.chain,
        "pair_id": args.pair_id,
        # Informational only: the live chain's terminal anchor at export
        # time. Verification NEVER uses it — the span terminates at the
        # pair, so later appends cannot affect the verdict.
        "exported_from_anchor": entries[-1]["hash"],
        "span": {
            "anchor_before_span": "GENESIS",
            "entries": span,
            "anchor_after_span": pair_records[1]["hash"],
        },
        "pair": pair_records,
        "settles": settles_section,
        "settlement_reference": settlement_reference,
        # Parent-chain segments carry no seal (rule R8 binds sub-lane
        # segment seals only); a sub-lane bundle would carry the seal
        # dict here and the verifier would recompute its digest.
        "segment_seal": None,
    }

    out = args.out or f"bundle_{args.pair_id.lower()}.json"
    with open(out, "w") as f:
        json.dump(bundle, f, indent=1, sort_keys=True)
        f.write("\n")
    print(f"exported {args.pair_id}: span entries 1..{span[-1]['i']}, "
          f"anchor_after_span {bundle['span']['anchor_after_span']}, "
          f"-> {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
