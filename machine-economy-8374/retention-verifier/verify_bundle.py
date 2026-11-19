#!/usr/bin/env python3
"""verify_bundle.py — STANDALONE customer-side retention verifier.

Reads ONLY a retention bundle file (produced by export_bundle.py, or
issued by the endpoint at crossing time) and re-implements the receipt
chain's rules from the bundle alone. It imports nothing from the
provider's workspace, opens no socket, and reads no other file: it is
meant to run after the provider is unavailable.

Dependencies: Python 3 standard library only (hashlib, json, sys).

Chain rules ("receipt-chain-rules/1", extracted from the endpoint's
ReceiptChain / replay / seal_digest_of):

  R1  record form {i, prev, content, hash}; indices consecutive from 1
  R2  canonical(obj) = json.dumps(obj, sort_keys=True,
      separators=(",", ":")).encode()          (UTF-8)
  R3  hash = SHA256(prev.encode() || canonical(content))  (hex)
  R4  the first record's prev is the string "GENESIS"
  R5  linkage: every later record's prev == the previous record's hash
  R6  a pair is two consecutive records sharing pair_id, index_in_pair
      0 then 1; member 1's content carries pair_anchor == member 0 hash
  R7  a verified payment authorization's nonce stands under exactly
      one pair in the verified span (nonce single-use)
  R8  sub-lane segment seal: seal_digest = SHA256(canonical({sublane,
      segment_index, terminal_anchor, entry_count, pair_count,
      prev_seal_digest})) — checked when a bundle carries a seal;
      parent-chain bundles carry none.

Verdict: prints VALID, or INVALID with the exact failed predicate:
  MISSING_MEMBER, BUNDLE_FORM_UNSUPPORTED, INDEX_GAP, LINKAGE_BREAK,
  HASH_MISMATCH, HELD_RECORD_DIVERGES, SPAN_ANCHOR_MISMATCH,
  PAIR_STRUCTURE, PAIR_ANCHOR_MISMATCH, SETTLEMENT_REFERENCE_MISMATCH,
  SETTLEMENT_BINDING_MISMATCH, NONCE_REUSE, SEAL_DIGEST_MISMATCH.
Exit code 0 = VALID, 1 = INVALID, 2 = unreadable bundle file.

Usage: python3 verify_bundle.py BUNDLE.json
"""

import hashlib
import json
import sys

RULES_VERSION = "receipt-chain-rules/1"
BUNDLE_FORM = "RETENTION_BUNDLE/1"
SEAL_FIELDS = ("sublane", "segment_index", "terminal_anchor",
               "entry_count", "pair_count", "prev_seal_digest")


def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


def digest(prev, content):
    return hashlib.sha256(prev.encode() + canonical(content)).hexdigest()


def seal_digest_of(seal):
    core = {k: seal[k] for k in SEAL_FIELDS}
    return hashlib.sha256(canonical(core)).hexdigest()


class Invalid(Exception):
    def __init__(self, predicate, detail):
        self.predicate = predicate
        self.detail = detail


def require(cond, predicate, detail):
    if not cond:
        raise Invalid(predicate, detail)


def check_record_hash(rec, where):
    require(isinstance(rec, dict) and
            all(k in rec for k in ("i", "prev", "content", "hash")),
            "MISSING_MEMBER", f"{where}: record lacks i/prev/content/hash")
    require(digest(rec["prev"], rec["content"]) == rec["hash"],
            "HASH_MISMATCH",
            f"{where}: entry {rec['i']} stored hash does not recompute "
            f"from (prev, content)")


def verify(bundle):
    require(bundle.get("bundle") == BUNDLE_FORM and
            bundle.get("rules_version") == RULES_VERSION,
            "BUNDLE_FORM_UNSUPPORTED",
            f"bundle form {bundle.get('bundle')!r} / rules "
            f"{bundle.get('rules_version')!r}, this verifier implements "
            f"{BUNDLE_FORM} / {RULES_VERSION}")
    pair_id = bundle.get("pair_id")
    require(pair_id, "MISSING_MEMBER", "bundle carries no pair_id")
    span = bundle.get("span")
    require(isinstance(span, dict) and isinstance(span.get("entries"), list)
            and span["entries"],
            "MISSING_MEMBER", "bundle carries no span entries")
    held = bundle.get("pair")
    require(isinstance(held, list),
            "MISSING_MEMBER", "bundle carries no held pair records")
    require(len(held) == 2,
            "MISSING_MEMBER",
            f"held pair has {len(held)} record(s); a pair requires "
            f"exactly 2 members")

    # Held pair: structure, then each record's own hash (a tampered held
    # record fails here, before any comparison with the span).
    held = sorted(held, key=lambda r: r["content"].get("index_in_pair", -1))
    for r in held:
        require(r["content"].get("pair_id") == pair_id,
                "PAIR_STRUCTURE",
                f"held record names pair {r['content'].get('pair_id')!r}, "
                f"bundle is for {pair_id!r}")
    require([r["content"].get("index_in_pair") for r in held] == [0, 1],
            "PAIR_STRUCTURE", "held pair members are not index_in_pair 0,1")
    for r in held:
        check_record_hash(r, "held pair")
    require(held[1]["content"].get("pair_anchor") == held[0]["hash"],
            "PAIR_ANCHOR_MISMATCH",
            "member 1 pair_anchor does not equal member 0 hash")
    require(held[1]["prev"] == held[0]["hash"],
            "LINKAGE_BREAK", "member 1 prev does not continue member 0")

    # Span: walk from the stated anchor, recomputing every rule the
    # endpoint's replay enforces — index continuity, prev linkage, and
    # every stored hash.
    entries = span["entries"]
    anchor_before = span.get("anchor_before_span")
    require(anchor_before is not None,
            "MISSING_MEMBER", "span carries no anchor_before_span")
    prev = anchor_before
    by_i = {}
    pairs_in_span = {}
    for pos, rec in enumerate(entries):
        require(rec["i"] == pos + 1,
                "INDEX_GAP",
                f"span position {pos}: stored index {rec['i']}, "
                f"expected {pos + 1}")
        require(rec["prev"] == prev,
                "LINKAGE_BREAK",
                f"entry {rec['i']}: prev does not equal the preceding "
                f"record's hash (or the span anchor at the head)")
        check_record_hash(rec, "span")
        prev = rec["hash"]
        by_i[rec["i"]] = rec
        c = rec["content"]
        pairs_in_span.setdefault(c.get("pair_id"), []).append(rec)

    # The span must terminate AT this pair: its last record is the
    # pair's second member, and the stated span anchor equals its hash.
    # Verification therefore never depends on later appends.
    require(entries[-1]["i"] == held[1]["i"] and
            entries[-1]["hash"] == held[1]["hash"],
            "SPAN_ANCHOR_MISMATCH",
            "span does not terminate at the pair's second member")
    require(span.get("anchor_after_span") == held[1]["hash"],
            "SPAN_ANCHOR_MISMATCH",
            "anchor_after_span does not equal the pair's terminal hash")

    # Held records must be the span's records, byte-for-byte at the
    # canonical level — what the customer holds is what the chain holds.
    for r in held:
        twin = by_i.get(r["i"])
        require(twin is not None and canonical(twin) == canonical(r),
                "HELD_RECORD_DIVERGES",
                f"held record at index {r['i']} differs from the span "
                f"record at that index")

    # Pair structure inside the span: exactly two members, consecutive,
    # index_in_pair 0 then 1.
    members = pairs_in_span.get(pair_id, [])
    require(len(members) == 2,
            "PAIR_STRUCTURE",
            f"{pair_id} has {len(members)} member(s) in the span")
    require(members[1]["i"] == members[0]["i"] + 1 and
            [m["content"].get("index_in_pair") for m in members] == [0, 1],
            "PAIR_STRUCTURE",
            f"{pair_id} members are not consecutive index_in_pair 0,1")

    # Settlement reference: the bundle's reference must agree with the
    # settlement object carried identically on both pair members.
    c0, c1 = held[0]["content"], held[1]["content"]
    if c0.get("settlement") is not None or c1.get("settlement") is not None:
        require(canonical(c0.get("settlement")) ==
                canonical(c1.get("settlement")),
                "SETTLEMENT_REFERENCE_MISMATCH",
                "the two pair members carry different settlement objects")
        ref = bundle.get("settlement_reference")
        require(isinstance(ref, dict),
                "MISSING_MEMBER",
                "pair carries a settlement but the bundle carries no "
                "settlement_reference")
        st = c0["settlement"]
        for k, v in ref.items():
            require(st.get(k) == v,
                    "SETTLEMENT_REFERENCE_MISMATCH",
                    f"settlement_reference.{k} = {v!r} but the pair "
                    f"records carry {st.get(k)!r}")
        if c0.get("pair_class") == "SETTLEMENT":
            require(st.get("status") == "SETTLED" and st.get("tx_hash"),
                    "SETTLEMENT_REFERENCE_MISMATCH",
                    "settlement pair does not carry status SETTLED with "
                    "a transaction hash")

    # Settlement binding: a SETTLEMENT pair must settle a real pair that
    # stands in the same span — an ALLOW EVALUATION pair whose payment
    # authorization nonce is the nonce the settlement executed.
    if c0.get("pair_class") == "SETTLEMENT":
        settled_id = c0.get("settles_pair_id")
        require(settled_id and settled_id in pairs_in_span,
                "SETTLEMENT_BINDING_MISMATCH",
                f"settles_pair_id {settled_id!r} names no pair in the span")
        sm = pairs_in_span[settled_id]
        require(len(sm) == 2 and
                sm[0]["content"].get("pair_class") == "EVALUATION" and
                sm[0]["content"].get("disposition") == "ALLOW",
                "SETTLEMENT_BINDING_MISMATCH",
                f"{settled_id} is not an ALLOW EVALUATION pair")
        sec = bundle.get("settles")
        require(isinstance(sec, dict) and sec.get("pair_id") == settled_id
                and isinstance(sec.get("records"), list)
                and len(sec["records"]) == 2,
                "MISSING_MEMBER",
                "bundle carries no settles records for the settled pair")
        for r in sec["records"]:
            twin = by_i.get(r["i"])
            require(twin is not None and canonical(twin) == canonical(r),
                    "HELD_RECORD_DIVERGES",
                    f"settles record at index {r['i']} differs from the "
                    f"span record at that index")
        pay_nonce = (sm[0]["content"].get("payment") or {}).get("nonce")
        st_nonce = (c0.get("settlement") or {}).get("nonce")
        require(pay_nonce is not None and st_nonce is not None and
                str(pay_nonce).lower() == str(st_nonce).lower(),
                "SETTLEMENT_BINDING_MISMATCH",
                "settlement nonce does not equal the settled pair's "
                "payment authorization nonce")

    # R7: nonce single-use across the verified span.
    nonce_owner = {}
    for pid, ms in pairs_in_span.items():
        for m in ms:
            pay = m["content"].get("payment")
            if pay and pay.get("nonce"):
                n = str(pay["nonce"]).lower()
                owner = nonce_owner.setdefault(n, pid)
                require(owner == pid,
                        "NONCE_REUSE",
                        f"payment nonce stands under two pairs "
                        f"({owner} and {pid})")
                break

    # R8: a carried segment seal must recompute, and its terminal
    # anchor must be an anchor the span actually reaches.
    seal = bundle.get("segment_seal")
    seal_checked = False
    if seal is not None:
        require(all(k in seal for k in SEAL_FIELDS + ("seal_digest",)),
                "MISSING_MEMBER", "segment_seal lacks a required field")
        require(seal_digest_of(seal) == seal["seal_digest"],
                "SEAL_DIGEST_MISMATCH",
                "seal_digest does not recompute from the seal's "
                "state-bearing fields")
        span_hashes = {r["hash"] for r in entries}
        require(seal["terminal_anchor"] in span_hashes and
                seal["entry_count"] <= len(entries),
                "SEAL_DIGEST_MISMATCH",
                "seal terminal_anchor is not reached by the span")
        seal_checked = True

    return {
        "verdict": "VALID",
        "pair_id": pair_id,
        "chain": bundle.get("chain"),
        "rules_version": RULES_VERSION,
        "span_entries_verified": len(entries),
        "pair_terminal_anchor": held[1]["hash"],
        "settlement_tx": (bundle.get("settlement_reference") or {})
                          .get("tx_hash"),
        "segment_seal": "checked" if seal_checked else
                        "not carried (parent-chain bundle)",
    }


def main(argv):
    if len(argv) != 2:
        print("usage: verify_bundle.py BUNDLE.json", file=sys.stderr)
        return 2
    try:
        with open(argv[1], "r") as f:
            bundle = json.load(f)
    except (OSError, ValueError) as e:
        print(f"INVALID UNREADABLE_BUNDLE: {e}")
        return 2
    try:
        report = verify(bundle)
    except Invalid as e:
        print(f"INVALID {e.predicate}: {e.detail}")
        return 1
    print("VALID")
    print(json.dumps(report, indent=1, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
