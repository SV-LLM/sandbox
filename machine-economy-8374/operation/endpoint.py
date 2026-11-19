#!/usr/bin/env python3
"""Machine Economy governed endpoint — BUILD-Q-13 proving build.

Implements MACHINE__ECONOMY__ENTRY__SUITE GEN 03 ENDPOINT__SPEC__01.md:
admissibility evaluation at the signing boundary (ALLOW / DENY /
FAIL_CLOSED, six-field grammar on non-ALLOW), dual-recorded hash-chained
receipt pairs (one pair per resolved evaluation, ALLOW or NON-ALLOW —
1 receipt pair = 1 unit of compute), refusal record pairs for refused
attempts, x402-shaped 402 responses before evaluation, and a custody
signing route wired (BUILD-Q-14) to the SKAP sign-under-seal operation:
under the principal's intent-signing ruling of 2026-11-16 23:52 CST
intent signing is not a lesser act; every signature is custody-grade;
no policy/operational-key signing path exists. This service holds no
keys and no credentials; signatures issue solely from the SKAP seal
via the operation. Manifold intake (BUILD-Q-15): 8374 decomposes into
sub-lanes (names, not identities, not separately keyed) receipting on
per-sub-lane segment chains; segments seal and fold onto the parent
chain; POST /sign-segment signs a segment's recomputed seal digest
under the admitted authorization, amortizing custody per segment.
Activation (BUILD-Q-17/18, 2026-11-17): the identity is registered as
8374@StegVerse.ai with a declared receptor (tonight's operating
configuration), and POST /crossing verifies real x402 "exact"-scheme
payment authorizations (EIP-3009 transferWithAuthorization, USDC on
Base) cryptographically BEFORE evaluation — the pre-activation
fee_arrangement acknowledgment path is replaced. SETTLEMENT (Gate 2, 2026-11-17): a verified authorization is
submitted for on-chain settlement by this endpoint's own gas-only
relayer (settlement.py) over the Base public RPC; the outcome --
tx hash or a named SETTLEMENT_* failure code -- is receipted in
the crossing's pair. The relayer holds no USDC and no ecosystem
material; it pays gas only. Offer v07 (BUILD-Q-43, 2026-11-18):
the ratified tiers are the governance fee ALONE; settlement gas is
an additional charge on the crossing, quoted at challenge time
from live Base gas conditions and the live ETH/USD rate, and the
total a payer authorizes is governance fee + settlement charge.
If no live quote can be produced, no paid challenge is issued
(SETTLEMENT_CHARGE_QUOTE_UNAVAILABLE) -- gas is never silently
absorbed. Pair-first migration (BUILD-Q-45, 2026-11-18): the
receipt pair is written FIRST, from locally-decidable predicates
only (signature recovery, receptor match, value, validity window,
evidence rules, and the nonce checked against the registry the
receipt chain itself is), with settlement_state PENDING -- before
any settlement RPC -- so a total egress outage at crossing time no
longer defers the crossing. Settlement is an eventual leg:
attempted immediately when the RPC answers, swept while PENDING
(background sweep + POST /settle-pair), and its outcome receipted
as an appended record bound to the pair (SETTLEMENT pair on
success, SETTLEMENT-FAILURE pair on terminal on-chain failure);
the pair's disposition never changes. Under an outage the
settlement charge serves its last successful quote with
quote_stale: true; the charge leg fails closed only when no quote
has ever been obtained. Stdlib only. Binds localhost.
"""
import base64, hashlib, json, os, threading, time
import urllib.error, urllib.request
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from keccak_pure import keccak256, eip55
import settlement as settle_mod
import funds as funds_mod
import urllib.parse

BASE = os.path.dirname(os.path.abspath(__file__))
CONFIG = json.load(open(os.path.join(BASE, "config.json")))
SCOPES = json.load(open(os.path.join(BASE, "scopes.json")))["scopes"]
OFFER_BASE = json.load(open(os.path.join(BASE, "offer.base.json")))
SEG_DIR = os.path.join(BASE, "receipts")
PORT = int(os.environ.get("ME_ENDPOINT_PORT", str(CONFIG.get("port", 8794))))
SEGMENT_MAX = 500
os.makedirs(SEG_DIR, exist_ok=True)

OWNING_GOAL = "MACHINE-ECONOMY-ENTRY-01 / BUILD-Q-13"
OWNING_GOAL_Q15 = "MACHINE-ECONOMY-ENTRY-01 / BUILD-Q-15"
CUSTODY_PREDICATE = CONFIG["gate"]["signing_failed_predicate"]
SIGNING_OP_URL = CONFIG["gate"].get("signing_operation_url", "http://127.0.0.1:8795")

def gate_settled():
    return CONFIG["gate"].get("custody_signing_path") == "SETTLED"

def signing_state():
    if gate_settled():
        return ("SETTLED — custody-grade via the SKAP sign-under-seal "
                "operation (BUILD-Q-14, " + SIGNING_OP_URL + ")")
    return "FAIL_CLOSED / " + CUSTODY_PREDICATE

def now():
    return datetime.now(timezone.utc).isoformat()

def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()

def digest(prev, content):
    return hashlib.sha256(prev.encode() + canonical(content)).hexdigest()

# ---------------- durability (BUILD-Q-16): fsync + torn-tail scan ----------------
def _fsync_dir(d):
    fd = os.open(d, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)

def _scan_segment(path):
    """Scan one segment file's raw bytes. Returns (entries, torn_bytes):
    the complete records in order, and the count of trailing bytes that
    form an incomplete final line (unterminated or undecodable) — 0 when
    the file is clean. Raises ValueError when a NON-final line fails to
    decode (corruption inside the sealed span, never a torn tail)."""
    with open(path, "rb") as f:
        data = f.read()
    entries = []
    pos, n = 0, len(data)
    torn = 0
    while pos < n:
        nl = data.find(b"\n", pos)
        if nl == -1:
            torn = n - pos
            break
        raw = data[pos:nl]
        if raw.strip():
            try:
                entries.append(json.loads(raw))
            except ValueError:
                if nl == n - 1:
                    torn = n - pos
                else:
                    raise ValueError(
                        f"{os.path.basename(path)}: undecodable line inside "
                        f"the sealed span at byte {pos}")
                break
        pos = nl + 1
    return entries, torn

# ---------------- receipt chain: append-only segments, hash-chained ----------------
class ReceiptChain:
    """Each receipt: {i, prev, content, hash}; hash = SHA256(prev || canonical(content))
    in the patent spec S4 tuple form (index, predecessor digest, state-bearing
    content, receipt digest). Pairs occupy two consecutive entries."""
    def __init__(self, seg_dir):
        self.dir = seg_dir
        self.lock = threading.Lock()
        self.i = 0
        self.prev = "GENESIS"
        self.pairs = 0
        self.pair_seq = 0
        self.units = 0
        self.by_disp = {"ALLOW": 0, "DENY": 0, "FAIL_CLOSED": 0}
        self.seg_no = 1
        self.seg_count = 0
        self.torn_recovery = None
        self._load()

    def _segments(self):
        out = []
        for n in sorted(os.listdir(self.dir)):
            if n.startswith("segment-") and n.endswith(".jsonl"):
                out.append(os.path.join(self.dir, n))
        return out

    def _load(self):
        segs = self._segments()
        last_torn, last_path = 0, None
        for si, path in enumerate(segs):
            self.seg_no = int(os.path.basename(path)[8:12])
            self.seg_count = 0
            entries, torn = _scan_segment(path)
            if torn and si != len(segs) - 1 \
                    and ".torn-" not in os.path.basename(path):
                raise ValueError(
                    f"{os.path.basename(path)}: torn tail ({torn} bytes) in "
                    "a sealed segment with no recovery record")
            for r in entries:
                self.i = r["i"]
                self.prev = r["hash"]
                self.seg_count += 1
                c = r["content"]
                pid = c.get("pair_id", "")
                if pid.startswith("PAIR-"):
                    self.pair_seq = max(self.pair_seq, int(pid[5:]))
                if c.get("index_in_pair") == 1:
                    self.pairs += 1
                    if c.get("pair_class", "EVALUATION") in ("EVALUATION", "SIGNATURE"):
                        self.units += 1
                    d = c.get("disposition")
                    if d in self.by_disp:
                        self.by_disp[d] += 1
            if si == len(segs) - 1:
                last_torn, last_path = torn, path
        if last_torn and last_path is not None:
            self._recover_torn_tail(last_path, last_torn)

    def _recover_torn_tail(self, path, torn_bytes):
        """Torn-tail recovery (BUILD-Q-16): seal the affected segment
        file in place under a preserved name (its bytes are never
        deleted or rewritten), then continue the chain in a NEW segment
        whose first entries are a RECOVERY pair receipting the event —
        the pair's prev is the last complete anchor, and its content
        names the preserved torn file and the torn byte count. Nothing
        is ever appended after torn bytes."""
        base = os.path.basename(path)
        if ".torn-" in base:
            preserved = base
        else:
            preserved = f"segment-{self.seg_no:04d}.torn-{torn_bytes}.jsonl"
            os.rename(path, os.path.join(self.dir, preserved))
            _fsync_dir(self.dir)
        last_anchor = self.prev
        self.seg_no += 1
        self.seg_count = 0
        self.pair_seq += 1
        pair_id = f"PAIR-{self.pair_seq:06d}"
        base_c = {"pair_id": pair_id, "pair_class": "RECOVERY",
                  "disposition": "CHAIN_RECOVERY", "ts": now(),
                  "recovery": {"event": "TORN_TAIL_RECOVERY",
                               "torn_file": preserved,
                               "torn_bytes": torn_bytes,
                               "last_complete_anchor": last_anchor}}
        a = self._append({**base_c, "kind": "RECOVERY_TORN_TAIL",
                          "index_in_pair": 0, "side": "chain",
                          "recorded_by": "machine-economy-endpoint (StegVerse LLC)"})
        self._append({**base_c, "kind": "RECOVERY_ANCHOR",
                      "index_in_pair": 1, "side": "chain",
                      "recorded_by": "machine-economy-endpoint (StegVerse LLC)",
                      "pair_anchor": a["hash"]})
        self.pairs += 1
        self.torn_recovery = {"torn_file": preserved,
                              "torn_bytes": torn_bytes,
                              "recovery_pair_id": pair_id,
                              "last_complete_anchor": last_anchor}

    def _append(self, content):
        if self.seg_count >= SEGMENT_MAX:
            self.seg_no += 1
            self.seg_count = 0
        self.i += 1
        rec = {"i": self.i, "prev": self.prev, "content": content}
        rec["hash"] = digest(self.prev, content)
        path = os.path.join(self.dir, f"segment-{self.seg_no:04d}.jsonl")
        created = not os.path.exists(path)
        with open(path, "a") as f:
            f.write(json.dumps(rec, sort_keys=True) + "\n")
            f.flush()
            os.fsync(f.fileno())
        if created:
            _fsync_dir(self.dir)
        self.prev = rec["hash"]
        self.seg_count += 1
        return rec

    def issue_pair(self, kind, crossing, disposition, disposition_detail=None,
                   payment=None, settlement=None):
        """Issue exactly one pair (two chained receipts) for one resolved
        evaluation. kind: 'RECEIPT' (ALLOW) or 'REFUSAL' (non-ALLOW).
        payment (BUILD-Q-18): the verified x402 payment evidence dict,
        carried identically on both pair members as the fee-leg evidence
        of the crossing. Returns (pair_id, [rec_a, rec_b]). Caller holds
        no lock; locked here."""
        with self.lock:
            self.pair_seq += 1
            pair_id = f"PAIR-{self.pair_seq:06d}"
            base = {"pair_id": pair_id, "pair_class": "EVALUATION",
                    "crossing": crossing,
                    "disposition": disposition, "ts": now()}
            if payment is not None:
                base["payment"] = payment
            if settlement is not None:
                base["settlement"] = settlement
            if kind == "RECEIPT":
                a_content = {**base, "kind": "RECEIPT_ENDPOINT_SIDE",
                             "index_in_pair": 0, "side": "endpoint",
                             "recorded_by": "machine-economy-endpoint (StegVerse LLC)"}
                a = self._append(a_content)
                b_content = {**base, "kind": "RECEIPT_COUNTERPARTY_SIDE",
                             "index_in_pair": 1, "side": "counterparty",
                             "recorded_by": crossing.get("counterparty"),
                             "pair_anchor": a["hash"]}
                b = self._append(b_content)
            else:
                a_content = {**base, "kind": "REFUSAL_ATTEMPT",
                             "index_in_pair": 0, "side": "attempt",
                             "recorded_by": "machine-economy-endpoint (StegVerse LLC)",
                             "executed": False}
                a = self._append(a_content)
                b_content = {**base, "kind": "REFUSAL_DISPOSITION",
                             "index_in_pair": 1, "side": "disposition",
                             "recorded_by": "machine-economy-endpoint (StegVerse LLC)",
                             "pair_anchor": a["hash"], "executed": False,
                             "disposition_detail": disposition_detail or {}}
                b = self._append(b_content)
            self.pairs += 1
            self.units += 1
            if disposition in self.by_disp:
                self.by_disp[disposition] += 1
            return pair_id, [a, b]

    def issue_fold_pair(self, seal):
        """Append a SEGMENT SEAL FOLD pair (BUILD-Q-15): the seal of one
        sub-lane segment, folded onto this (parent) chain. A fold is a
        structural record, not a resolved evaluation: it counts as a pair
        on the chain but NOT as a unit of compute."""
        with self.lock:
            self.pair_seq += 1
            pair_id = f"PAIR-{self.pair_seq:06d}"
            base = {"pair_id": pair_id, "pair_class": "FOLD",
                    "disposition": "SEAL_FOLD", "ts": now(), "seal": seal}
            a = self._append({**base, "kind": "SEAL_FOLD_ENDPOINT_SIDE",
                              "index_in_pair": 0, "side": "endpoint",
                              "recorded_by": "machine-economy-endpoint (StegVerse LLC)"})
            b = self._append({**base, "kind": "SEAL_FOLD_PARENT_ANCHOR",
                              "index_in_pair": 1, "side": "parent_anchor",
                              "recorded_by": "machine-economy-endpoint (StegVerse LLC)",
                              "pair_anchor": a["hash"]})
            self.pairs += 1
            return pair_id, [a, b]

    def issue_settlement_pair(self, settlement_record, settles_pair_id):
        """Append a SETTLEMENT RESUBMISSION pair (Gate 2 repair): the
        settlement outcome for an earlier EVALUATION pair whose fee
        authorization verified at its crossing but was not collected
        on-chain (its settlement leg failed closed). Structural like
        a FOLD pair: it counts as a pair on the chain but NOT as a
        new unit of compute -- the unit stands under the settled
        pair. The pair carries the settlement record and the settled
        pair's id only, never a second 'payment' block: the
        authorization's nonce stands under exactly one pair, which
        replay enforces."""
        with self.lock:
            self.pair_seq += 1
            pair_id = f"PAIR-{self.pair_seq:06d}"
            base = {"pair_id": pair_id, "pair_class": "SETTLEMENT",
                    "disposition": "SETTLEMENT_RESUBMISSION",
                    "ts": now(), "settles_pair_id": settles_pair_id,
                    "settlement": settlement_record}
            a = self._append({**base, "kind": "SETTLEMENT_ENDPOINT_SIDE",
                              "index_in_pair": 0, "side": "endpoint",
                              "recorded_by": "machine-economy-endpoint (StegVerse LLC)"})
            b = self._append({**base, "kind": "SETTLEMENT_PARENT_ANCHOR",
                              "index_in_pair": 1, "side": "parent_anchor",
                              "recorded_by": "machine-economy-endpoint (StegVerse LLC)",
                              "pair_anchor": a["hash"]})
            self.pairs += 1
            return pair_id, [a, b]

    def issue_settlement_failure_pair(self, settlement_record,
                                      settles_pair_id):
        """Append a SETTLEMENT-FAILURE pair (BUILD-Q-45 pair-first
        migration): the terminal on-chain failure of an earlier
        EVALUATION pair's settlement leg (the authorization's nonce
        consumed elsewhere, or the payer's balance insufficient --
        the settlement can never land). Appended, never a rewrite:
        the settled pair's own record keeps settlement_state PENDING
        and its disposition never changes; this pair is the terminal
        settlement state bound to it. Structural like a SETTLEMENT
        pair: counts as a pair, NOT as a new unit of compute, and
        carries no 'payment' block (the nonce stands under the
        original pair only)."""
        with self.lock:
            self.pair_seq += 1
            pair_id = f"PAIR-{self.pair_seq:06d}"
            base = {"pair_id": pair_id, "pair_class": "SETTLEMENT",
                    "disposition": "SETTLEMENT_FAILED",
                    "ts": now(), "settles_pair_id": settles_pair_id,
                    "settlement": settlement_record}
            a = self._append({**base, "kind": "SETTLEMENT_FAILURE_ENDPOINT_SIDE",
                              "index_in_pair": 0, "side": "endpoint",
                              "recorded_by": "machine-economy-endpoint (StegVerse LLC)"})
            b = self._append({**base, "kind": "SETTLEMENT_FAILURE_PARENT_ANCHOR",
                              "index_in_pair": 1, "side": "parent_anchor",
                              "recorded_by": "machine-economy-endpoint (StegVerse LLC)",
                              "pair_anchor": a["hash"]})
            self.pairs += 1
            return pair_id, [a, b]

    def issue_signature_pair(self, record):
        """Append a SEGMENT SIGNATURE pair (BUILD-Q-15): the custody
        signature over a sealed segment's seal digest, bound to its fold
        entry. A resolved signing evaluation: counts as a unit of compute,
        as POST /sign pairs do."""
        with self.lock:
            self.pair_seq += 1
            pair_id = f"PAIR-{self.pair_seq:06d}"
            base = {"pair_id": pair_id, "pair_class": "SIGNATURE",
                    "disposition": "ALLOW", "ts": now(),
                    "segment_signature": record}
            a = self._append({**base, "kind": "SEGMENT_SIGNATURE_ENDPOINT_SIDE",
                              "index_in_pair": 0, "side": "endpoint",
                              "recorded_by": "machine-economy-endpoint (StegVerse LLC)"})
            b = self._append({**base, "kind": "SEGMENT_SIGNATURE_PARENT_ANCHOR",
                              "index_in_pair": 1, "side": "parent_anchor",
                              "recorded_by": "machine-economy-endpoint (StegVerse LLC)",
                              "pair_anchor": a["hash"]})
            self.pairs += 1
            self.units += 1
            self.by_disp["ALLOW"] += 1
            return pair_id, [a, b]

    def totals(self):
        return {"receipt_pairs": self.pairs,
                "units_of_compute": self.units,
                "by_disposition": dict(self.by_disp),
                "chain_entries": self.i,
                "terminal_anchor": self.prev}

CHAIN = ReceiptChain(SEG_DIR)

def replay(seg_dir=SEG_DIR):
    """Recompute the chain from the segment files and verify: every stored
    hash recomputes from (prev, content); linkage is unbroken; every pair is
    matched (two members, second anchored to the first); the recomputed
    terminal digest equals the stored terminal anchor.

    Torn tail (BUILD-Q-16): a segment file whose final line is incomplete
    (unterminated or undecodable) verifies up to its last complete entry.
    If the tear is unrecovered (it is the chain's active tail), the verdict
    is MATCH_WITH_TORN_TAIL with the torn byte count and the last complete
    anchor named — never a silent pass, never an opaque crash. A tear
    already sealed by a RECOVERY pair is reported under recovered_tails and
    the verdict stays MATCH. A torn line anywhere other than a file's tail
    remains a hard MISMATCH."""
    prev = "GENESIS"
    i = 0
    pairs = {}
    problems = []
    names = [n for n in sorted(os.listdir(seg_dir))
             if n.startswith("segment-") and n.endswith(".jsonl")]
    per_file = []
    recovery_records = []
    for n in names:
        try:
            entries, torn = _scan_segment(os.path.join(seg_dir, n))
        except ValueError as e:
            problems.append(str(e))
            entries, torn = [], 0
        file_anchor = prev
        last_meta = None
        for r in entries:
            i += 1
            if r["i"] != i:
                problems.append(f"entry {i}: index gap (stored {r['i']})")
            if r["prev"] != prev:
                problems.append(f"entry {i}: prev linkage broken")
            if digest(r["prev"], r["content"]) != r["hash"]:
                problems.append(f"entry {i}: hash does not recompute")
            prev = r["hash"]
            file_anchor = prev
            c = r["content"]
            last_meta = (c.get("pair_id"), c.get("index_in_pair"))
            pairs.setdefault(c["pair_id"], []).append(c)
            if c.get("pair_class") == "RECOVERY" and c.get("index_in_pair") == 0:
                recovery_records.append(c.get("recovery") or {})
        per_file.append((n, torn, file_anchor, last_meta))
    # A pair whose first member is the last complete entry before a torn
    # tail is explained BY the tear (its second member never committed;
    # the torn bytes held it). It is reported as the torn file's dangling
    # pair, not as an unmatched-pair problem.
    explained = {}
    for n, torn, _fa, last_meta in per_file:
        if torn and last_meta and last_meta[1] == 0 \
                and len(pairs.get(last_meta[0], [])) == 1:
            explained[last_meta[0]] = n
    for pid, members in pairs.items():
        if len(members) != 2:
            if pid in explained:
                continue
            problems.append(f"{pid}: {len(members)} members, pair unmatched")
        else:
            m0, m1 = sorted(members, key=lambda c: c["index_in_pair"])
            if m1.get("pair_anchor") is None:
                problems.append(f"{pid}: second member carries no pair anchor")
    # Payment nonce single-use (BUILD-Q-18): a verified x402
    # authorization's nonce may stand under exactly ONE pair on the
    # chain (both members of that pair carry the same payment evidence;
    # the authorization digest in the pair is the fee-leg evidence).
    # The same nonce under two different pairs means a replayed
    # authorization was receipted twice — a hard problem.
    nonce_owner = {}
    for pid, members in pairs.items():
        for c in members:
            pay = c.get("payment")
            if pay and pay.get("nonce"):
                nonce = str(pay["nonce"]).lower()
                owner = nonce_owner.setdefault(nonce, pid)
                if owner != pid:
                    problems.append(
                        f"payment nonce {nonce} recorded under two pairs "
                        f"({owner} and {pid}): authorization replayed")
                break
    recovered_files = {rec.get("torn_file") for rec in recovery_records}
    torn_tail = None
    recovered_tails = []
    for fi, (n, torn, file_anchor, last_meta) in enumerate(per_file):
        if not torn:
            continue
        info = {"file": n, "torn_bytes": torn,
                "last_complete_anchor": file_anchor}
        if last_meta and explained.get(last_meta[0]) == n:
            info["dangling_pair_id"] = last_meta[0]
        if n in recovered_files:
            recovered_tails.append(info)
        elif fi == len(per_file) - 1:
            torn_tail = info
        else:
            problems.append(f"{n}: torn tail ({torn} bytes) in a sealed "
                            "segment with no recovery record")
    if problems:
        verdict = "MISMATCH"
    elif torn_tail is not None:
        verdict = "MATCH_WITH_TORN_TAIL"
    else:
        verdict = "MATCH"
    return {"verdict": verdict,
            "entries": i, "pairs": len(pairs),
            "terminal_anchor": prev, "problems": problems,
            "torn_tail": torn_tail, "recovered_tails": recovered_tails}

# ---------------- manifold intake: sub-lanes + segment folding (BUILD-Q-15) ----------------
# 8374 decomposes into sub-lanes named 8374.<name>; a sub-lane is a NAME
# (routing), not an identity, and is not separately keyed — signing always
# resolves to 8374's one SKAP specimen. The name grammar is CONFIGURATION
# (config.json "manifold"), not invariant. Each sub-lane receipts on its own
# segment chain; segments seal and fold onto the parent chain, so the parent
# grows per segment, not per crossing; a segment's seal digest is the unit
# the custody path signs (per-segment, amortized from per-crossing).
MANIFOLD_CFG = CONFIG.get("manifold", {})
SUBLANE_CHARSET = set(MANIFOLD_CFG.get("sublane_charset",
                                       "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"))
SUBLANE_LENGTH = int(MANIFOLD_CFG.get("sublane_length", 2))
SEGMENT_SIZE = int(MANIFOLD_CFG.get("segment_size_crossings", 100))
SUBLANE_ROOT = os.path.join(SEG_DIR, "sublanes")
MANIFOLD_LOCK = threading.Lock()
# Serializes the crossing sequence verify -> resolve -> settle ->
# issue (BUILD-Q-45 repair, 2026-11-17): the nonce registry is read at
# verification and written at pair issuance, so without this lock two
# concurrent presentations of the SAME authorization could both pass
# verification before either pair lands. Lock ordering: CROSSING_LOCK
# is always taken before MANIFOLD_LOCK, never the reverse.
CROSSING_LOCK = threading.Lock()

def sublane_valid(name):
    return (isinstance(name, str) and len(name) == SUBLANE_LENGTH
            and all(c in SUBLANE_CHARSET for c in name))

def read_entries(seg_dir):
    entries = []
    if not os.path.isdir(seg_dir):
        return entries
    for n in sorted(os.listdir(seg_dir)):
        if n.startswith("segment-") and n.endswith(".jsonl"):
            es, _torn = _scan_segment(os.path.join(seg_dir, n))
            entries.extend(es)
    return entries

def seal_digest_of(seal):
    """Digest over the seal's state-bearing fields (everything but the
    digest itself and fold bookkeeping)."""
    core = {k: seal[k] for k in ("sublane", "segment_index", "terminal_anchor",
                                  "entry_count", "pair_count", "prev_seal_digest")}
    return hashlib.sha256(canonical(core)).hexdigest()

def _parent_fold_seals():
    """All fold seals recorded on the parent chain, in chain order:
    [(seal_dict_with_fold_pair_id)]."""
    out = []
    for r in read_entries(SEG_DIR):
        c = r["content"]
        if c.get("pair_class") == "FOLD" and c.get("index_in_pair") == 0:
            s = dict(c["seal"])
            s["fold_pair_id"] = c["pair_id"]
            out.append(s)
    return out

def _parent_signature_records():
    """All segment-signature records on the parent chain, in chain order:
    [(record_dict_with_pair_id)]."""
    out = []
    for r in read_entries(SEG_DIR):
        c = r["content"]
        if c.get("pair_class") == "SIGNATURE" and c.get("index_in_pair") == 0:
            rec = dict(c["segment_signature"])
            rec["pair_id"] = c["pair_id"]
            out.append(rec)
    return out

class SubLane:
    """One named intake path of identity 8374: its own receipt chain under
    receipts/sublanes/<NAME>/, its segments sealing onto the parent chain.
    Holds no key material and no identity of its own."""
    def __init__(self, name):
        self.name = name
        self.dir = os.path.join(SUBLANE_ROOT, name)
        os.makedirs(self.dir, exist_ok=True)
        self.chain = ReceiptChain(self.dir)
        self.segments = []      # sealed segments, in order
        self.open_pairs = 0     # pairs in the current open segment
        self._rebuild()

    def _rebuild(self):
        consumed = 0
        for s in _parent_fold_seals():
            if s["sublane"] != self.name:
                continue
            seg = {k: s[k] for k in ("sublane", "segment_index", "terminal_anchor",
                                     "entry_count", "pair_count",
                                     "prev_seal_digest", "seal_digest")}
            seg["fold_pair_id"] = s["fold_pair_id"]
            seg["signed"] = False
            self.segments.append(seg)
            consumed += s["entry_count"]
        for rec in _parent_signature_records():
            if rec.get("sublane") == self.name:
                idx = rec.get("segment_index")
                if isinstance(idx, int) and 0 <= idx < len(self.segments):
                    self.segments[idx]["signed"] = True
                    self.segments[idx]["signature_pair_id"] = rec["pair_id"]
        self.open_pairs = (self.chain.i - consumed) // 2

    @property
    def next_segment_index(self):
        return len(self.segments)

    def seal_open_segment(self):
        """Seal the open segment and fold the seal onto the parent chain.
        Caller holds MANIFOLD_LOCK. Returns the sealed segment dict, or
        None when the open segment is empty."""
        if self.open_pairs == 0:
            return None
        seal = {"sublane": self.name,
                "segment_index": self.next_segment_index,
                "terminal_anchor": self.chain.prev,
                "entry_count": self.open_pairs * 2,
                "pair_count": self.open_pairs,
                "prev_seal_digest": (self.segments[-1]["seal_digest"]
                                     if self.segments else "GENESIS")}
        seal["seal_digest"] = seal_digest_of(seal)
        fold_pair_id, _recs = CHAIN.issue_fold_pair(seal)
        seg = {**seal, "fold_pair_id": fold_pair_id, "signed": False}
        self.segments.append(seg)
        self.open_pairs = 0
        return seg

    def recompute_seal_digest(self, segment_index):
        """Recompute a sealed segment's seal digest from this chain's own
        entries (span-derived counts and terminal anchor; seal linkage
        from the segments before it). Never trusts a stored digest."""
        entries = read_entries(self.dir)
        consumed = 0
        prev_sd = "GENESIS"
        for idx in range(segment_index + 1):
            seg = self.segments[idx]
            span = entries[consumed:consumed + seg["entry_count"]]
            if idx == segment_index:
                if len(span) != seg["entry_count"]:
                    return None
                core = {"sublane": self.name, "segment_index": idx,
                        "terminal_anchor": span[-1]["hash"],
                        "entry_count": len(span),
                        "pair_count": len(span) // 2,
                        "prev_seal_digest": prev_sd}
                return hashlib.sha256(canonical(core)).hexdigest()
            consumed += seg["entry_count"]
            prev_sd = seg["seal_digest"]
        return None

SUBLANES = {}

def get_lane(name, create=True):
    lane = SUBLANES.get(name)
    if lane is None:
        if not create and not os.path.isdir(os.path.join(SUBLANE_ROOT, name)):
            return None
        lane = SubLane(name)
        SUBLANES[name] = lane
    return lane

def _discover_sublanes():
    if os.path.isdir(SUBLANE_ROOT):
        for n in sorted(os.listdir(SUBLANE_ROOT)):
            if os.path.isdir(os.path.join(SUBLANE_ROOT, n)) and sublane_valid(n):
                get_lane(n)

_discover_sublanes()

def identity_totals():
    parent = CHAIN.totals()
    lanes = {name: lane.chain.totals() for name, lane in sorted(SUBLANES.items())}
    return {"units_of_compute": parent["units_of_compute"]
            + sum(t["units_of_compute"] for t in lanes.values()),
            "receipt_pairs": parent["receipt_pairs"]
            + sum(t["receipt_pairs"] for t in lanes.values()),
            "parent": parent, "sublanes": lanes}

def manifold_state():
    return {"build": "BUILD-Q-15",
            "sublane_grammar": {"charset": "".join(sorted(SUBLANE_CHARSET)),
                                "length": SUBLANE_LENGTH,
                                "form": "8374.<name>",
                                "status": "configuration, not invariant"},
            "segment_size_crossings": SEGMENT_SIZE,
            "sealed_segments": [
                {"sublane": lane.name, "segment_index": s["segment_index"],
                 "seal_digest": s["seal_digest"], "fold_pair_id": s["fold_pair_id"],
                 "pair_count": s["pair_count"], "signed": s.get("signed", False)}
                for lane in (SUBLANES[n] for n in sorted(SUBLANES))
                for s in lane.segments]}

def manifold_replay():
    """Full-manifold verdict: the parent chain replays; every sub-lane
    chain replays; every seal fold on the parent chain recomputes from
    the sub-lane chain it seals (span counts, terminal anchor, digest,
    seal-to-seal linkage). MATCH only if all verify."""
    parent = replay()
    problems = list(parent["problems"])
    folds = {}
    for s in _parent_fold_seals():
        folds[(s["sublane"], s["segment_index"])] = s
    names = set(SUBLANES)
    if os.path.isdir(SUBLANE_ROOT):
        names |= {n for n in os.listdir(SUBLANE_ROOT)
                  if os.path.isdir(os.path.join(SUBLANE_ROOT, n))}
    names |= {n for (n, _i) in folds}
    sub = {}
    seals_checked = []
    for name in sorted(names):
        d = os.path.join(SUBLANE_ROOT, name)
        rep = replay(d)
        sub[name] = rep
        problems += [f"sublane {name}: {p}" for p in rep["problems"]]
        entries = read_entries(d)
        consumed = 0
        prev_sd = "GENESIS"
        for idx in sorted(i for (n, i) in folds if n == name):
            s = folds[(name, idx)]
            span = entries[consumed:consumed + s["entry_count"]]
            core = {"sublane": name, "segment_index": idx,
                    "terminal_anchor": span[-1]["hash"] if span else None,
                    "entry_count": len(span), "pair_count": len(span) // 2,
                    "prev_seal_digest": prev_sd}
            recomputed = hashlib.sha256(canonical(core)).hexdigest()
            ok = (len(span) == s["entry_count"]
                  and core["terminal_anchor"] == s["terminal_anchor"]
                  and core["pair_count"] == s["pair_count"]
                  and s["prev_seal_digest"] == prev_sd
                  and recomputed == s["seal_digest"]
                  and seal_digest_of(s) == s["seal_digest"])
            seals_checked.append({"sublane": name, "segment_index": idx,
                                  "seal_digest": s["seal_digest"],
                                  "fold_pair_id": s["fold_pair_id"],
                                  "verified": ok})
            if not ok:
                problems.append(f"seal {name}/{idx}: fold does not recompute "
                                "from the sub-lane chain")
            consumed += s["entry_count"]
            prev_sd = s["seal_digest"]
    chain_verdicts = [parent["verdict"]] + [r["verdict"] for r in sub.values()]
    if problems:
        verdict = "MISMATCH"
    elif any(v == "MATCH_WITH_TORN_TAIL" for v in chain_verdicts):
        verdict = "MATCH_WITH_TORN_TAIL"
    elif any(v != "MATCH" for v in chain_verdicts):
        verdict = "MISMATCH"
    else:
        verdict = "MATCH"
    return {"verdict": verdict, "entries": parent["entries"],
            "pairs": parent["pairs"],
            "terminal_anchor": parent["terminal_anchor"],
            "problems": problems,
            "manifold": {"parent": parent, "sublanes": sub,
                         "seals": seals_checked}}

def sublane_invalid_detail(name):
    return six_field(
        "SUBLANE_NAME_NOT_ADMITTED",
        "the sub-lane name is two-character alphanumeric (A-Z, 0-9) under "
        "identity 8374, per the manifold grammar held in configuration",
        "present sublane as exactly two characters from A-Z and 0-9 "
        "(e.g. 'AA', 'B7', '99'), or omit sublane for the parent lane",
        "POST /crossing with a conforming sublane name",
        "caller correction", owning=OWNING_GOAL_Q15)

# ---------------- fee / x402 (BUILD-Q-18: real payment verification) ----------------
# The receptor is declared (BUILD-Q-17, 8374@StegVerse.ai) under
# tonight's operating configuration, revisable by a later principal
# determination: scheme x402 "exact", network Base (eip155:8453),
# asset USDC on Base, payTo = 8374's own address. POST /crossing
# verifies the X-PAYMENT header cryptographically BEFORE evaluation:
# an EIP-3009 transferWithAuthorization signed under the USDC EIP-712
# domain. Every failed check is FAIL_CLOSED on the payment predicate
# (six-field grammar, refusal pair receipted) — distinct from a
# governed DENY of the crossing itself.
#
# SETTLEMENT (Gate 2, 2026-11-17): the endpoint submits verified
# authorizations for on-chain settlement via its gas-only relayer
# (settlement.py) and receipts the outcome -- tx hash or a named
# SETTLEMENT_* failure code -- in the crossing's pair. Settlement
# never changes the crossing's disposition: under pricing mode
# (a) the fee follows the evaluation, and a settlement FAIL_CLOSED
# records an earned-but-uncollected fee, not a refused crossing.
# Claims of settlement are made only from the mined receipt.
SETTLEMENT = CONFIG.get("settlement", {})
SETTLE_CFG = SETTLEMENT.get("submission", {})
X402_SCHEME = SETTLEMENT.get("scheme", "exact")
X402_NETWORK = SETTLEMENT.get("network")
X402_ASSET = SETTLEMENT.get("asset")
X402_PAYTO = SETTLEMENT.get("payTo")
X402_CHAIN_ID = 8453
X402_ASSET_NAME = "USD Coin"        # USDC EIP-712 domain name
X402_ASSET_VERSION = "2"            # USDC EIP-712 domain version
X402_TIERS_MICRO = {}
for _t, _v in SETTLEMENT.get("tiers_micro_usdc", {}).items():
    X402_TIERS_MICRO[_t] = int(_v)
for _t in CONFIG["pricing"]["tiers"]:
    X402_TIERS_MICRO.setdefault(
        _t, int(round(CONFIG["pricing"]["tiers"][_t]["fee_usd"] * 1_000_000)))

# --- settlement charge (BUILD-Q-43, offer v07) ---
# The principal's determination of 2026-11-18: the ratified tiers
# are the governance fee ALONE; settlement gas is an ADDITIONAL fee
# charged on the crossing, never absorbed by StegVerse (absorbing
# volatile gas could bankrupt StegVerse during gas-price spikes).
# The charge is quoted at challenge time from live Base conditions:
#   charge = ceil(SETTLEMENT_GAS_UNITS_BASIS * max_fee_per_gas
#                 * eth_usd / 1e18) in micro-USDC,
# with max_fee_per_gas = 2 * pending baseFee + priority fee -- the
# fee basis the settlement leg itself provisions with -- read via
# eth_feeHistory / eth_maxPriorityFeePerGas, and eth_usd the live
# Coinbase spot. The gas-units basis is the settlement leg's
# receipted eth_estimateGas for one transferWithAuthorization
# settlement (86,679 units; PAIR-000024 / PAIR-000034 records): the
# volatile inputs (fee basis, ETH/USD) are read live at challenge
# time; the units basis is the measured constant. All reads transit
# the service's existing proxy-discovery transport (settlement.Rpc
# discovers the egress proxy at call time; the spot read uses the
# same candidate list). A quote is cached for
# SETTLEMENT_QUOTE_TTL_SECONDS so the challenge a payer answers and
# the verification of their answer are priced on the same quote.
# If no live quote can be produced, the endpoint fails closed: no
# paid challenge is issued (SETTLEMENT_CHARGE_QUOTE_UNAVAILABLE)
# rather than the gas being silently absorbed.
SETTLEMENT_GAS_UNITS_BASIS = 86679
SETTLEMENT_QUOTE_TTL_SECONDS = 45
SETTLEMENT_QUOTE_FAILURE = "SETTLEMENT_CHARGE_QUOTE_UNAVAILABLE"
_quote_cache = {"at": 0.0, "quote": None}
_quote_lock = threading.Lock()

class SettlementQuoteUnavailable(Exception):
    pass

def _eth_usd_spot():
    """Live ETH/USD spot (Coinbase) over the discovered egress
    proxies; raises SettlementQuoteUnavailable on total failure."""
    errors = []
    openers = [(p, urllib.request.build_opener(
        urllib.request.ProxyHandler({"http": p, "https": p})))
        for p in settle_mod._proxy_candidates()]
    openers.append((None, urllib.request.build_opener()))
    for proxy, opener in openers:
        try:
            req = urllib.request.Request(
                "https://api.coinbase.com/v2/prices/ETH-USD/spot",
                headers={"User-Agent": "curl/8.5.0"})
            with opener.open(req, timeout=15) as r:
                amount = float(json.load(r)["data"]["amount"])
            if amount > 0:
                return amount
            errors.append("non-positive spot price")
        except Exception as e:
            errors.append(f"{type(e).__name__}: {e}"[:120])
    raise SettlementQuoteUnavailable(
        "ETH/USD spot read failed on every egress route: "
        + " | ".join(errors))

_QUOTE_CACHE_FILE = os.path.join(BASE, "quote-cache.json")

def _persist_quote(quote):
    """Persist the last successful quote (fsync) so a restart during
    an egress outage can still serve it as a stale quote (BUILD-Q-45
    pair-first migration): the charge leg fails closed only when no
    quote has EVER been obtained."""
    try:
        with open(_QUOTE_CACHE_FILE, "w") as f:
            json.dump(quote, f, sort_keys=True)
            f.flush()
            os.fsync(f.fileno())
    except Exception:
        pass

def _serve_stale_quote(reason):
    """The last successful quote (memory cache first, then the
    persisted cache), marked stale; None when no quote has ever
    been obtained."""
    q = None
    with _quote_lock:
        if _quote_cache["quote"] is not None:
            q = dict(_quote_cache["quote"])
    if q is None:
        try:
            with open(_QUOTE_CACHE_FILE) as f:
                q = json.load(f)
        except Exception:
            q = None
    if not isinstance(q, dict) \
            or "settlement_charge_micro_usdc" not in q:
        return None
    q["quote_stale"] = True
    q["stale_reason"] = str(reason)[:200]
    q["served_stale_at_unix"] = int(time.time())
    return q

def settlement_charge_quote():
    """The current settlement-charge quote, or raise
    SettlementQuoteUnavailable. Cached for the TTL so one crossing
    (challenge -> payment) is priced on a single quote. Pair-first
    (BUILD-Q-45): when the live read fails, the LAST SUCCESSFUL
    quote is served with quote_stale: true (and persisted across
    restarts); the charge leg fails closed only when no quote has
    ever been obtained."""
    now = time.time()
    with _quote_lock:
        q = _quote_cache["quote"]
        if q is not None and now - _quote_cache["at"] \
                < SETTLEMENT_QUOTE_TTL_SECONDS:
            return q
    try:
        rpc = settle_mod.Rpc([SETTLE_CFG.get(
            "rpc_primary", "https://mainnet.base.org"),
            SETTLE_CFG.get("rpc_fallback",
                           "https://base-rpc.publicnode.com")])
        fee_hist = rpc.call("eth_feeHistory", ["0x1", "latest", []])
        base_fee = int(fee_hist["baseFeePerGas"][-1], 16)
        try:
            priority = int(rpc.call("eth_maxPriorityFeePerGas", []), 16)
        except settle_mod.RpcError:
            priority = 100000
        eth_usd = _eth_usd_spot()
    except Exception as e:
        stale = _serve_stale_quote(
            f"live quote read failed: {type(e).__name__}: {e}")
        if stale is not None:
            return stale
        if isinstance(e, SettlementQuoteUnavailable):
            raise
        raise SettlementQuoteUnavailable(
            f"Base fee read failed: {type(e).__name__}: {e}"[:200])
    max_fee = 2 * base_fee + priority
    cost_wei = SETTLEMENT_GAS_UNITS_BASIS * max_fee
    eth_usd_milli = int(round(eth_usd * 1000))
    charge_micro = -(-(cost_wei * eth_usd_milli * 1_000_000) // 10**21)
    quote = {"settlement_charge_micro_usdc": int(charge_micro),
             "gas_units_basis": SETTLEMENT_GAS_UNITS_BASIS,
             "base_fee_per_gas_wei": base_fee,
             "priority_fee_per_gas_wei": priority,
             "max_fee_per_gas_wei": max_fee,
             "eth_usd": eth_usd,
             "quoted_at_unix": int(now),
             "quote_stale": False,
             "quote_ttl_seconds": SETTLEMENT_QUOTE_TTL_SECONDS,
             "formula": "ceil(gas_units_basis * (2*base_fee_per_gas + "
                        "priority_fee_per_gas) * eth_usd / 1e18, "
                        "to the next micro-USDC)"}
    with _quote_lock:
        _quote_cache["at"] = now
        _quote_cache["quote"] = quote
    _persist_quote(quote)
    return quote

def crossing_total_micro(tier):
    """(total, quote): the exact amount a payer authorizes for this
    crossing = the tier's governance fee + the settlement charge
    quoted now. Raises SettlementQuoteUnavailable when no live
    quote can be produced."""
    quote = settlement_charge_quote()
    return (X402_TIERS_MICRO[tier]
            + quote["settlement_charge_micro_usdc"]), quote

def _quote_fail_detail():
    return six_field(
        SETTLEMENT_QUOTE_FAILURE,
        "a live settlement-charge quote (Base fee basis + ETH/USD) "
        "is available before a paid challenge is issued or a "
        "presented payment is verified",
        "the settlement charge is never absorbed silently "
        "(principal determination, 2026-11-18, BUILD-Q-43): retry "
        "the crossing when the Base RPC / ETH-USD reads recover "
        "over the node's egress proxy",
        "POST /crossing (retry)",
        "caller retries the crossing; no authorization was consumed",
        owning=OWNING_GOAL_Q18)

OWNING_GOAL_Q18 = "MACHINE-ECONOMY-ENTRY-01 / BUILD-Q-18"

# --- secp256k1 recovery (pure python; same curve math as the manifold
# battery's independent verifier, written for 65-byte r||s||v form) ---
_EC_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
_EC_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
_EC_G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
         0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)

def _ec_add(p, q):
    if p is None: return q
    if q is None: return p
    if p[0] == q[0] and (p[1] + q[1]) % _EC_P == 0: return None
    if p == q:
        m = (3 * p[0] * p[0]) * pow(2 * p[1], -1, _EC_P) % _EC_P
    else:
        m = (q[1] - p[1]) * pow(q[0] - p[0], -1, _EC_P) % _EC_P
    x = (m * m - p[0] - q[0]) % _EC_P
    return (x, (m * (p[0] - x) - p[1]) % _EC_P)

def _ec_mul(k, p):
    r = None
    while k:
        if k & 1: r = _ec_add(r, p)
        p = _ec_add(p, p)
        k >>= 1
    return r

def _ec_recover_address(digest_bytes, r, s, recid):
    """Recover the signer address (EIP-55) from an ECDSA signature over
    digest_bytes, or None when recovery is impossible."""
    if not (1 <= r < _EC_N and 1 <= s < _EC_N):
        return None
    x = r + (recid // 2) * _EC_N
    if x >= _EC_P:
        return None
    y2 = (pow(x, 3, _EC_P) + 7) % _EC_P
    y = pow(y2, (_EC_P + 1) // 4, _EC_P)
    if (y * y) % _EC_P != y2:
        return None
    if y % 2 != recid % 2:
        y = _EC_P - y
    z = int.from_bytes(digest_bytes, "big")
    rinv = pow(r, -1, _EC_N)
    q = _ec_add(_ec_mul(s * rinv % _EC_N, (x, y)),
                _ec_mul((-z * rinv) % _EC_N, _EC_G))
    if q is None:
        return None
    unc = q[0].to_bytes(32, "big") + q[1].to_bytes(32, "big")
    return eip55(keccak256(unc)[-20:].hex())

# --- EIP-712 encoding for the USDC transferWithAuthorization domain ---
def _u256(n):
    return int(n).to_bytes(32, "big")

def _addr_word(a):
    return b"\x00" * 12 + bytes.fromhex(a[2:] if a.startswith("0x") else a)

_DOMAIN_TYPEHASH = keccak256(
    b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)")
_AUTH_TYPEHASH = keccak256(
    b"TransferWithAuthorization(address from,address to,uint256 value,"
    b"uint256 validAfter,uint256 validBefore,bytes32 nonce)")

def _domain_separator():
    return keccak256(_DOMAIN_TYPEHASH
                     + keccak256(X402_ASSET_NAME.encode())
                     + keccak256(X402_ASSET_VERSION.encode())
                     + _u256(X402_CHAIN_ID)
                     + _addr_word(X402_ASSET))

def _authorization_digest(auth):
    """The EIP-712 digest the payer signs; recorded in the receipt pair
    as the authorization digest (the fee-leg evidence)."""
    nonce = auth["nonce"]
    nonce = nonce[2:] if nonce.startswith("0x") else nonce
    struct_hash = keccak256(
        _AUTH_TYPEHASH
        + _addr_word(auth["from"]) + _addr_word(auth["to"])
        + _u256(auth["value"]) + _u256(auth["validAfter"])
        + _u256(auth["validBefore"]) + bytes.fromhex(nonce))
    return keccak256(b"\x19\x01" + _domain_separator() + struct_hash)

def _norm_nonce(nonce):
    if not isinstance(nonce, str):
        return None
    n = nonce[2:] if nonce.startswith("0x") else nonce
    if len(n) != 64:
        return None
    try:
        bytes.fromhex(n)
    except ValueError:
        return None
    return "0x" + n.lower()

def pair_members(pair_id):
    """Both receipt contents of one pair on the parent chain, read
    from the segment files -- the chain is the record."""
    return [r["content"] for r in read_entries(SEG_DIR)
            if r["content"].get("pair_id") == pair_id]


def used_payment_nonces():
    """Every payment nonce already receipted anywhere on the manifold
    (parent chain + every sub-lane chain), read from the receipt
    records themselves — the chain is the nonce registry."""
    nonces = set()
    dirs = [SEG_DIR]
    if os.path.isdir(SUBLANE_ROOT):
        dirs += [os.path.join(SUBLANE_ROOT, n) for n in os.listdir(SUBLANE_ROOT)
                 if os.path.isdir(os.path.join(SUBLANE_ROOT, n))]
    for d in dirs:
        for r in read_entries(d):
            pay = r["content"].get("payment")
            if pay and pay.get("nonce"):
                nonces.add(str(pay["nonce"]).lower())
    return nonces

# ---------------- discovery extension (Bazaar / x402scan) ----------------
# Registries (x402scan endpoint-only registration; the CDP Bazaar
# catalog) mark a payable route non-invocable ("skipped") when its 402
# challenge carries no input schema (finding of REGISTRATION__RECORD__01,
# 2026-11-17). The challenge therefore declares the Bazaar discovery
# extension: `info` holds the actual discovery values (an example
# invocation of POST /crossing and an example response), `schema` is
# the JSON Schema that validates `info`. The same discovery info is
# mirrored into the accepts entry's `outputSchema`, the x402 v1
# discovery location. Additive only: the payment requirements
# themselves are unchanged.
CROSSING_BODY_SCHEMA = {
    "type": "object",
    "properties": {
        "tier": {"type": "string",
                 "enum": ["receipt-only", "full-evaluation"],
                 "description": "Posted fee tier for this crossing (see the offer document); defaults to receipt-only."},
        "counterparty": {"type": "string",
                         "description": "Caller's declared identity for the crossing record."},
        "action": {"type": "string",
                   "description": "The governed action requested at this crossing."},
        "scope_ref": {"type": "string",
                      "description": "Reference to the admitted scope under which the action is requested."},
        "resource": {"type": "string",
                     "description": "The resource the action targets."},
        "sublane": {"type": "string",
                    "description": "Optional routing name (two uppercase alphanumeric characters, e.g. \"AA\"); receipts land on that sub-lane's chain under 8374's one identity."}},
    "required": ["counterparty", "action", "scope_ref", "resource"],
    "additionalProperties": True}

def bazaar_discovery(tier):
    """The Bazaar discovery info + schema for POST /crossing."""
    info = {"input": {"type": "http", "method": "POST",
                      "bodyType": "json",
                      "body": {"tier": tier,
                               "counterparty": "0x0000000000000000000000000000000000000000",
                               "action": "evaluate",
                               "scope_ref": "specimen",
                               "resource": "governed-evaluation"}},
            "output": {"type": "json",
                       "example": {"disposition": "ALLOW",
                                   "executed": True,
                                   "pair_id": "PAIR-000000",
                                   "settlement": {"status": "SETTLED",
                                                  "tx_hash": "0x..."}}}}
    schema = {"$schema": "https://json-schema.org/draft/2020-12/schema",
              "type": "object",
              "properties": {
                  "input": {"type": "object",
                            "properties": {
                                "type": {"type": "string", "const": "http"},
                                "method": {"type": "string", "const": "POST"},
                                "bodyType": {"type": "string", "const": "json"},
                                "body": CROSSING_BODY_SCHEMA},
                            "required": ["type", "method", "bodyType", "body"],
                            "additionalProperties": False},
                  "output": {"type": "object",
                             "properties": {
                                 "type": {"type": "string", "const": "json"},
                                 "example": {"type": "object"}},
                             "required": ["type"],
                             "additionalProperties": True}},
              "required": ["input"]}
    return info, schema

def _public_origin():
    """The public origin this endpoint is exposed under, read from the
    tunnel's pointer file; None when no public exposure is pinned."""
    try:
        with open(os.path.join(BASE, "public-url.txt")) as f:
            url = f.read().strip()
        return url or None
    except OSError:
        return None


def openapi_document():
    """BUILD-Q-28 discovery surface: the OpenAPI 3.1 document the x402
    directories read. Built from the same constants as the live 402
    challenge (CROSSING_BODY_SCHEMA, the ratified tiers, the declared
    receptor), so the catalog copy cannot drift from the live terms.
    The /crossing operation carries the x-payment-info hint at the
    full-evaluation tier; the receipt-only tier is named in the
    description and selected via the body's tier field."""
    origin = _public_origin()
    doc = {
        "openapi": "3.1.0",
        "info": {
            "title": "0R10N15-8374 - Governed Crossing Evaluation",
            "version": OFFER_BASE.get("version", "07"),
            "description": (
                "Governed evaluation at a signing boundary, operated "
                "by StegVerse LLC. Each crossing is a manifest-governed "
                "packet evaluated against the admitted scope; every "
                "crossing, ALLOW or NON-ALLOW, produces a matched "
                "receipt pair, and the fee is paid either way. Posted "
                "tiers: receipt-only $0.0005; full-evaluation $0.015 "
                "(select via the body's tier field; defaults to "
                "receipt-only). The posted tiers are the governance "
                "fee; settlement gas is charged additionally on each "
                "crossing, quoted live at challenge time, and the "
                "402 challenge amount is the total authorized "
                "(governance fee + settlement charge). Payment: x402 "
                "exact scheme, USDC on "
                "Base, to the recipient published in the service's "
                "authenticated offer; authorizations are accepted "
                "only for that recipient. Patent pending: U.S. "
                "Application No. 64/198,910.")},
        "paths": {
            "/crossing": {
                "post": {
                    "summary": "Submit a governed crossing for evaluation",
                    "operationId": "submitCrossing",
                    "requestBody": {
                        "required": True,
                        "content": {"application/json": {
                            "schema": CROSSING_BODY_SCHEMA}}},
                    "responses": {
                        "200": {"description": "Crossing evaluated; the response carries the disposition, the receipt pair identifiers, and the caller's retention bundle (BUILD-Q-44)."},
                        "402": {"description": "Payment required (x402): see the challenge body's accepts[] and extensions.bazaar."},
                        "422": {"description": "Crossing refused (NON-ALLOW); the response carries the refusal receipt pair."}},
                    "x-payment-info": {
                        "price": {"mode": "fixed", "currency": "USD",
                                  "amount": "0.015"},
                        "protocols": ["x402"]}}}}}
    if origin:
        doc["servers"] = [{"url": origin}]
    return doc


def wellknown_x402():
    """The /.well-known/x402 resource list (directory checklist)."""
    origin = _public_origin()
    resources = [origin + "/crossing"] if origin else []
    return {"version": 1, "resources": resources}


def retention_bundle(pair_id, seg_dir, chain_name, segment_seal=None):
    """BUILD-Q-44 issuance: the customer's retention bundle for the
    pair just issued, in RETENTION_BUNDLE/1 form (rules
    receipt-chain-rules/1) — the chain span from genesis through the
    pair's second member, so the customer can verify the pair later
    with a standalone verifier while this provider is unavailable.
    Mirrors the provider-side exporter (export_bundle.py) exactly.
    Read-only over the segment files; returns None when the pair is
    not found complete (issuance never fails a crossing)."""
    try:
        entries = read_entries(seg_dir)
        idx = [k for k, r in enumerate(entries)
               if r["content"].get("pair_id") == pair_id]
        if len(idx) != 2:
            return None
        first, last = idx
        pair_records = [entries[first], entries[last]]
        settles_section = None
        settled_pair_id = pair_records[0]["content"].get("settles_pair_id")
        if settled_pair_id:
            s_idx = [k for k, r in enumerate(entries)
                     if r["content"].get("pair_id") == settled_pair_id]
            if len(s_idx) == 2:
                settles_section = {
                    "pair_id": settled_pair_id,
                    "records": [entries[s_idx[0]], entries[s_idx[1]]]}
        settlement = pair_records[0]["content"].get("settlement")
        settlement_reference = None
        if settlement is not None:
            settlement_reference = {
                k: settlement.get(k) for k in (
                    "status", "tx_hash", "block_number", "value_micro_usdc",
                    "asset", "payTo", "nonce", "mode")}
        return {"bundle": "RETENTION_BUNDLE/1",
                "rules_version": "receipt-chain-rules/1",
                "chain": chain_name,
                "pair_id": pair_id,
                "exported_from_anchor": entries[-1]["hash"],
                "span": {"anchor_before_span": "GENESIS",
                         "entries": entries[:last + 1],
                         "anchor_after_span": pair_records[1]["hash"]},
                "pair": pair_records,
                "settles": settles_section,
                "settlement_reference": settlement_reference,
                "segment_seal": segment_seal}
    except Exception:
        return None

def payment_requirements(tier, total=None, quote=None):
    t = CONFIG["pricing"]["tiers"][tier]
    _info, _schema = bazaar_discovery(tier)
    if total is None:
        total, quote = crossing_total_micro(tier)
    return {"x402Version": 1,
            "error": "payment required: the governed crossing bears the posted fee under the active pricing mode",
            "accepts": [{
                "scheme": X402_SCHEME,
                "network": X402_NETWORK, "asset": X402_ASSET,
                "payTo": X402_PAYTO,
                "maxAmountRequired": str(total),
                "mimeType": "application/json", "maxTimeoutSeconds": 60,
                "resource": "governed-evaluation / receipt-pair-issuance",
                "tier": tier, "amount_usd": t["fee_usd"], "unit": t["unit"],
                "amount_status": t["status"],
                "governance_fee_micro_usdc": X402_TIERS_MICRO[tier],
                "settlement_charge_micro_usdc":
                    quote["settlement_charge_micro_usdc"],
                "settlement_charge_quote": quote,
                "total_micro_usdc": total,
                "extra": {"name": X402_ASSET_NAME, "version": X402_ASSET_VERSION,
                          "settlement": SETTLEMENT.get("settlement_note", "")},
                "note": "Receptor declared 2026-11-17 (BUILD-Q-17, 8374@StegVerse.ai) as tonight's operating configuration, revisable by a later principal determination. Present the payment authorization in the X-PAYMENT header (x402 exact scheme; EIP-3009 transferWithAuthorization signed under the USDC domain on Base). The amount is the TOTAL for this crossing: the tier governance fee plus the settlement charge quoted at challenge time (BUILD-Q-43, offer v07) -- settlement gas is charged on the crossing, never absorbed.",
                          "outputSchema": _info}],
            "extensions": {"bazaar": {"info": _info, "schema": _schema}},
            "pricing": {"active_mode": CONFIG["pricing"]["active_mode"],
                        "fee_negotiable": CONFIG["pricing"]["fee_negotiable"],
                        "fee_paid_either_way": CONFIG["pricing"]["fee_paid_either_way"],
                        "settlement_charge": quote,
                        "governance_fee_micro_usdc": X402_TIERS_MICRO[tier],
                        "total_micro_usdc": total}}

def _b64_json(obj):
    return base64.b64encode(
        json.dumps(obj, separators=(",", ":")).encode()).decode()


def payment_required_v2(tier, total=None, quote=None):
    """BUILD-Q-48: the x402 v2 PaymentRequired object for the same
    posted terms — the v2 envelope over the identical receptor and
    tier amounts (the envelope is not the transition). Carried
    base64 in the PAYMENT-REQUIRED response header, the v2 canonical
    wire location; the 402 response body remains the v1 challenge so
    v1 clients keep working (dual-stack). Shape verified against
    specs/x402-specification-v2.md (x402-foundation/x402), 2026-11-18:
    accepts entries carry `amount` (atomic units, string), the
    EIP-712 domain in `extra`, and the Bazaar discovery extension
    rides in `extensions` as it does in the v1 body."""
    _info, _schema = bazaar_discovery(tier)
    origin = _public_origin()
    if total is None:
        total, quote = crossing_total_micro(tier)
    return {"x402Version": 2,
            "error": "payment required: the governed crossing bears the posted fee under the active pricing mode",
            "resource": {
                "url": (origin + "/crossing") if origin else "/crossing",
                "description": "Governed crossing evaluation: a manifest-governed packet evaluated against the admitted scope; every crossing, ALLOW or NON-ALLOW, produces a matched receipt pair and the fee is paid either way.",
                "mimeType": "application/json",
                "serviceName": "0R10N15-8374"},
            "accepts": [{
                "scheme": X402_SCHEME,
                "network": X402_NETWORK,
                "amount": str(total),
                "asset": X402_ASSET,
                "payTo": X402_PAYTO,
                "maxTimeoutSeconds": 60,
                "extra": {"name": X402_ASSET_NAME,
                          "version": X402_ASSET_VERSION}}],
            "extensions": {"bazaar": {"info": _info, "schema": _schema}},
            "pricing": {"governance_fee_micro_usdc":
                            X402_TIERS_MICRO[tier],
                        "settlement_charge_micro_usdc":
                            quote["settlement_charge_micro_usdc"],
                        "settlement_charge_quote": quote,
                        "total_micro_usdc": total}}


def verify_x402_payment(header_b64, tier):
    """Verify an X-PAYMENT header (x402 v1) against the declared
    receptor and the ratified tier amount. Returns
    (payment_evidence, None) on pass or (None, six_field_detail) on
    failure; every failure is FAIL_CLOSED on the payment predicate.
    The evidence dict is what the receipt pair carries as the
    fee-leg record."""
    def fail(code, predicate, repair):
        return None, six_field(code, predicate, repair,
                               "POST /crossing with a valid X-PAYMENT header",
                               "caller presents a valid payment authorization",
                               owning=OWNING_GOAL_Q18)
    try:
        payload = json.loads(base64.b64decode(header_b64, validate=True))
    except Exception:
        return fail("PAYMENT_PAYLOAD_MALFORMED",
                    "the X-PAYMENT header is base64 JSON in the x402 payment payload shape",
                    "present X-PAYMENT as base64 of {x402Version, scheme, network, payload:{signature, authorization:{from,to,value,validAfter,validBefore,nonce}}}")
    if not isinstance(payload, dict):
        return fail("PAYMENT_PAYLOAD_MALFORMED",
                    "the X-PAYMENT header is base64 JSON in the x402 payment payload shape",
                    "present X-PAYMENT as base64 of the x402 payment payload object")
    evidence, detail = _verify_payment_dict(
        payload, tier, "POST /crossing with a valid X-PAYMENT header")
    if evidence is not None:
        evidence["x402_version"] = 1
        evidence["payment_header"] = "X-PAYMENT"
    return evidence, detail


def verify_x402_payment_v2(header_b64, tier):
    """BUILD-Q-48: verify a PAYMENT-SIGNATURE header (x402 v2). The
    v2 envelope restructures the payload (an `accepted` requirements
    object echoed by the client, plus the scheme payload), but the
    exact-scheme core is the same EIP-3009 authorization — so after
    the envelope is checked against the declared requirements for
    the requested tier, verification reuses the v1 core on a
    normalized envelope. Every failure is FAIL_CLOSED on the payment
    predicate, in the same six-field grammar."""
    def fail(code, predicate, repair):
        return None, six_field(code, predicate, repair,
                               "POST /crossing with a valid PAYMENT-SIGNATURE header",
                               "caller presents a valid payment authorization",
                               owning=OWNING_GOAL_Q18)
    try:
        payload = json.loads(base64.b64decode(header_b64, validate=True))
    except Exception:
        return fail("PAYMENT_PAYLOAD_MALFORMED",
                    "the PAYMENT-SIGNATURE header is base64 JSON in the x402 v2 payment payload shape",
                    "present PAYMENT-SIGNATURE as base64 of {x402Version: 2, accepted:{scheme, network, amount, asset, payTo, maxTimeoutSeconds, extra}, payload:{signature, authorization:{from,to,value,validAfter,validBefore,nonce}}}")
    if not isinstance(payload, dict):
        return fail("PAYMENT_PAYLOAD_MALFORMED",
                    "the PAYMENT-SIGNATURE header is base64 JSON in the x402 v2 payment payload shape",
                    "present PAYMENT-SIGNATURE as base64 of the x402 v2 payment payload object")
    if payload.get("x402Version") != 2:
        return fail("PAYMENT_VERSION_UNSUPPORTED",
                    "the payment payload declares x402Version 2 in the PAYMENT-SIGNATURE envelope",
                    "present the payment in the x402 v2 envelope (x402Version 2), or use the v1 X-PAYMENT header")
    acc = payload.get("accepted")
    if not isinstance(acc, dict):
        return fail("PAYMENT_PAYLOAD_MALFORMED",
                    "the payment payload carries the accepted payment requirements object",
                    "echo the accepted entry from the 402 challenge's accepts[] as `accepted`")
    try:
        required, _quote = crossing_total_micro(tier)
    except SettlementQuoteUnavailable:
        return None, _quote_fail_detail()
    try:
        accepted_amount = int(acc.get("amount"))
    except (TypeError, ValueError):
        accepted_amount = None
    if acc.get("scheme") != X402_SCHEME \
            or acc.get("network") != X402_NETWORK \
            or str(acc.get("asset", "")).lower() != X402_ASSET.lower() \
            or str(acc.get("payTo", "")).lower() != X402_PAYTO.lower() \
            or accepted_amount != required:
        return fail("PAYMENT_REQUIREMENTS_MISMATCH",
                    "the accepted requirements are the declared requirements for the requested tier (scheme exact, network eip155:8453, asset USDC on Base, payTo the declared receptor, amount the quoted total for the tier: governance fee + settlement charge)",
                    f"accept the requirements stated in the PAYMENT-REQUIRED challenge for tier '{tier}': amount {required} micro-USDC to payTo {X402_PAYTO}")
    pl = payload.get("payload")
    if not isinstance(pl, dict) \
            or not isinstance(pl.get("authorization"), dict) \
            or not isinstance(pl.get("signature"), str):
        return fail("PAYMENT_PAYLOAD_MALFORMED",
                    "the payment payload carries payload.signature and payload.authorization",
                    "present payload:{signature, authorization:{from,to,value,validAfter,validBefore,nonce}}")
    normalized = {"scheme": X402_SCHEME, "network": X402_NETWORK,
                  "payload": pl}
    evidence, detail = _verify_payment_dict(
        normalized, tier,
        "POST /crossing with a valid PAYMENT-SIGNATURE header")
    if evidence is not None:
        evidence["x402_version"] = 2
        evidence["payment_header"] = "PAYMENT-SIGNATURE"
    return evidence, detail


def _verify_payment_dict(payload, tier, retry_entrypoint):
    """The shared exact-scheme verification core (BUILD-Q-18):
    requirements match, EIP-3009 authorization shape, payee, value,
    validity window, signature recovery, single-use nonce."""
    def fail(code, predicate, repair):
        return None, six_field(code, predicate, repair,
                               retry_entrypoint,
                               "caller presents a valid payment authorization",
                               owning=OWNING_GOAL_Q18)
    if payload.get("scheme") != X402_SCHEME or payload.get("network") != X402_NETWORK:
        return fail("PAYMENT_REQUIREMENTS_MISMATCH",
                    "the payment payload matches the declared requirements (scheme exact, network eip155:8453)",
                    "pay under the requirements stated in the 402 response: scheme 'exact', network 'eip155:8453', asset USDC on Base, payTo the declared receptor")
    if payload.get("asset") is not None \
            and str(payload["asset"]).lower() != X402_ASSET.lower():
        return fail("PAYMENT_REQUIREMENTS_MISMATCH",
                    "the payment asset is the declared asset (USDC on Base)",
                    "pay in the declared asset: " + X402_ASSET)
    pl = payload.get("payload")
    if not isinstance(pl, dict) or not isinstance(pl.get("authorization"), dict) \
            or not isinstance(pl.get("signature"), str):
        return fail("PAYMENT_PAYLOAD_MALFORMED",
                    "the payment payload carries payload.signature and payload.authorization",
                    "present payload:{signature, authorization:{from,to,value,validAfter,validBefore,nonce}}")
    auth = pl["authorization"]
    for k in ("from", "to", "value", "validAfter", "validBefore", "nonce"):
        if k not in auth:
            return fail("PAYMENT_PAYLOAD_MALFORMED",
                        "the authorization carries from, to, value, validAfter, validBefore, nonce",
                        f"present authorization.{k} in the EIP-3009 authorization")
    if not (isinstance(auth["from"], str) and isinstance(auth["to"], str)
            and auth["from"].startswith("0x") and auth["to"].startswith("0x")
            and len(auth["from"]) == 42 and len(auth["to"]) == 42):
        return fail("PAYMENT_PAYLOAD_MALFORMED",
                    "authorization.from and authorization.to are 20-byte hex addresses",
                    "present from/to as 0x-prefixed 20-byte addresses")
    if auth["to"].lower() != X402_PAYTO.lower():
        return fail("PAYMENT_PAYEE_MISMATCH",
                    "the authorization pays the declared receptor (to == payTo)",
                    "authorize the transfer to payTo " + X402_PAYTO)
    try:
        value = int(auth["value"]); valid_after = int(auth["validAfter"])
        valid_before = int(auth["validBefore"])
    except (TypeError, ValueError):
        return fail("PAYMENT_PAYLOAD_MALFORMED",
                    "authorization value, validAfter, validBefore are integers (value in the asset's smallest unit)",
                    "present value/validAfter/validBefore as integers")
    try:
        required, quote = crossing_total_micro(tier)
    except SettlementQuoteUnavailable:
        return None, _quote_fail_detail()
    if value != required:
        return fail(
            "PAYMENT_VALUE_INSUFFICIENT" if value < required
            else "PAYMENT_VALUE_MISMATCH",
            f"the authorized value equals exactly the quoted total for '{tier}' (governance fee {X402_TIERS_MICRO[tier]} + settlement charge {quote['settlement_charge_micro_usdc']} = {required} micro-USDC, quoted at challenge time under BUILD-Q-43)",
            f"authorize exactly {required} micro-USDC for the '{tier}' tier, as stated in the 402 challenge")
    now_ts = int(time.time())
    if not (valid_after <= now_ts < valid_before):
        return fail("PAYMENT_AUTHORIZATION_NOT_IN_WINDOW",
                    "the authorization is inside its validity window (validAfter <= now < validBefore)",
                    "sign a fresh authorization whose window covers the crossing time")
    nonce = _norm_nonce(auth["nonce"])
    if nonce is None:
        return fail("PAYMENT_PAYLOAD_MALFORMED",
                    "the authorization nonce is a 32-byte hex value",
                    "present nonce as 32 bytes of hex (0x-prefixed or bare)")
    sig_hex = pl["signature"]
    sig_hex = sig_hex[2:] if sig_hex.startswith("0x") else sig_hex
    try:
        sig = bytes.fromhex(sig_hex)
    except ValueError:
        sig = b""
    if len(sig) != 65:
        return fail("PAYMENT_SIGNATURE_INVALID",
                    "the EIP-3009 signature is a 65-byte secp256k1 signature that recovers to authorization.from",
                    "sign the EIP-712 transferWithAuthorization digest under the USDC domain (name 'USD Coin', version '2', chainId 8453, verifyingContract the asset) with the payer key")
    r = int.from_bytes(sig[0:32], "big")
    s = int.from_bytes(sig[32:64], "big")
    v = sig[64]
    recid = v - 27 if v in (27, 28) else v
    if recid not in (0, 1):
        return fail("PAYMENT_SIGNATURE_INVALID",
                    "the EIP-3009 signature is a 65-byte secp256k1 signature that recovers to authorization.from",
                    "present v as 27/28 (or 0/1) with r,s over the EIP-712 authorization digest")
    digest_bytes = _authorization_digest({**auth, "nonce": nonce,
                                          "value": value,
                                          "validAfter": valid_after,
                                          "validBefore": valid_before})
    recovered = _ec_recover_address(digest_bytes, r, s, recid)
    if recovered is None or recovered.lower() != auth["from"].lower():
        return fail("PAYMENT_SIGNATURE_INVALID",
                    "the EIP-3009 signature recovers to authorization.from over the authorization digest",
                    "sign the EIP-712 transferWithAuthorization digest under the USDC domain (name 'USD Coin', version '2', chainId 8453, verifyingContract the asset) with the payer key")
    if nonce in used_payment_nonces():
        return fail("PAYMENT_NONCE_REUSED",
                    "the authorization nonce has never been used (single-use; the receipt chain is the nonce registry)",
                    "sign a fresh authorization with a fresh nonce")
    evidence = {"scheme": X402_SCHEME, "network": X402_NETWORK,
                "asset": X402_ASSET, "payTo": X402_PAYTO,
                "from": auth["from"], "to": auth["to"],
                "value": str(value), "value_micro_usdc": value,
                 "required_micro_usdc": required, "tier": tier,
                "governance_fee_micro_usdc": X402_TIERS_MICRO[tier],
                "settlement_charge_micro_usdc":
                    quote["settlement_charge_micro_usdc"],
                "settlement_charge_quote": quote,
                "total_authorized_micro_usdc": required,
                "valid_after": valid_after, "valid_before": valid_before,
                "nonce": nonce,
                "authorization_digest": "0x" + digest_bytes.hex(),
                "signature_verified": True,
                "signature": "0x" + sig_hex,
                "settlement": "authorization verified at crossing; settlement is submitted by the endpoint's gas-only relayer (Gate 2) and the outcome is receipted in this pair under 'settlement'"}
    return evidence, None

# ---------------- evaluation ----------------
def six_field(failure_code, failed_predicate, repair, retry, next_attempt,
              owning=OWNING_GOAL):
    return {"failure_code": failure_code, "failed_predicate": failed_predicate,
            "required_evidence_or_repair": repair, "retry_entrypoint": retry,
            "owning_goal": owning, "next_attempt": next_attempt}

def custody_disposition():
    if gate_settled():
        return six_field(
            "SIGNING_VIA_DEDICATED_OPERATION",
            "signing is performed only through the dedicated custody operation (POST /sign), never embedded in a crossing evaluation",
            "submit the signing request to POST /sign with the admitted authorization record; the SKAP sign-under-seal operation (BUILD-Q-14) performs it under governed retrieval",
            "POST /sign",
            "caller submits via the dedicated signing route")
    return six_field(
        "CUSTODY_SIGNING_REQUIRED", CUSTODY_PREDICATE,
        "the production SKAP custody signing path settled and wired; under the principal's ruling of 2026-11-16 intent signing is custody-grade and no lesser signing path exists",
        "POST /sign after the custody signing path is wired at gated activation",
        "custody path wiring (gated activation work)")

def evaluate(req):
    """Returns (disposition, detail_dict). Pure evaluation; receipting is the
    caller's step. Conjuncts per ENDPOINT__SPEC S3: scope admission, standing,
    action in scope, custody slot, and (full-evaluation tier) the commit-time
    record conjuncts."""
    cp = req.get("counterparty")
    action = req.get("action")
    scope_ref = req.get("scope_ref")
    tier = req.get("tier", "receipt-only")
    if not cp or not action or not scope_ref:
        return "FAIL_CLOSED", six_field(
            "REQUEST_FIELDS_MISSING",
            "the crossing request names counterparty, action, and scope_ref",
            "present counterparty, action, and scope_ref in the crossing request",
            "POST /crossing with the complete request",
            "caller correction")
    if tier not in CONFIG["pricing"]["tiers"]:
        return "FAIL_CLOSED", six_field(
            "TIER_NOT_OFFERED", "the requested evaluation tier is an offered tier",
            "request tier 'receipt-only' or 'full-evaluation'",
            "POST /crossing with an offered tier", "caller correction")
    scope = SCOPES.get(scope_ref)
    if scope is None:
        return "DENY", six_field(
            "SCOPE_NOT_ADMITTED",
            "the proposed transition is within an admitted scope (scope_ref names an admitted scope)",
            "present a scope_ref admitted in the endpoint's scope registry, or seek admission of the scope as a governed act",
            "POST /crossing with an admitted scope_ref", "caller correction")
    if not scope.get("standing"):
        return "FAIL_CLOSED", six_field(
            "NO_STANDING_RECEIVER",
            "the scope's receiver stands (is not dissolved)",
            "the scope's receiver must be re-instantiated by a governed act before crossings resume",
            "POST /crossing after the receiver is re-instantiated",
            "scope owner re-instantiation")
    if action not in scope["actions"]:
        return "DENY", six_field(
            "ACTION_NOT_IN_SCOPE",
            "the proposed action is within the admitted scope's actions",
            f"request one of the scope's admitted actions: {scope['actions']}",
            "POST /crossing with an admitted action", "caller correction")
    if req.get("requires_signature") or action in ("sign", "settle"):
        d = custody_disposition()
        d["note"] = "evaluation and receipting proceed without signing; settlement/signing is the custody slot and fails closed"
        return "FAIL_CLOSED", d
    if tier == "full-evaluation":
        ev = req.get("evidence")
        if not isinstance(ev, dict):
            return "FAIL_CLOSED", six_field(
                "KNOWN_EVIDENCE_MISSING",
                "the commit-time record is presented for full evaluation",
                "present the evidence object: authority, delegation, evidence_refs, exclusions, policy, validity_at_commit",
                "POST /crossing with the evidence object", "caller correction")
        checks = [
            ("authority", "AUTHORITY_NOT_RECONSTRUCTABLE",
             "the actor's authority is reconstructable at commit time",
             "present evidence.authority naming the authority and its basis"),
            ("delegation", "DELEGATION_NOT_RECONSTRUCTABLE",
             "any delegation is reconstructable at commit time",
             "present evidence.delegation (or an explicit no-delegation statement)"),
            ("evidence_refs", "KNOWN_EVIDENCE_MISSING",
             "the evidence known at the transition is preserved and referenced",
             "present evidence.evidence_refs as a non-empty list of references"),
        ]
        for key, code, pred, repair in checks:
            v = ev.get(key)
            if v is None or (isinstance(v, (list, str)) and len(v) == 0):
                return "FAIL_CLOSED", six_field(code, pred, repair,
                    "POST /crossing with the repaired evidence object", "caller correction")
        if "exclusions" not in ev:
            return "FAIL_CLOSED", six_field(
                "EXCLUSIONS_NOT_STATED",
                "material exclusions, with their reasons, are stated at commit time",
                "present evidence.exclusions (an empty list is a statement; absence is not)",
                "POST /crossing with the repaired evidence object", "caller correction")
        if ev.get("policy") != CONFIG["current_policy"]:
            return "FAIL_CLOSED", six_field(
                "POLICY_NOT_CURRENT",
                "policy identity and version are current at commit time",
                f"present evidence.policy = {CONFIG['current_policy']}",
                "POST /crossing under the current policy", "caller correction")
        if ev.get("validity_at_commit") is not True:
            return "FAIL_CLOSED", six_field(
                "COMMIT_TIME_VALIDITY_NOT_ESTABLISHED",
                "validity was evaluated at commit time, not inferred later",
                "present evidence.validity_at_commit = true, established at commit time",
                "POST /crossing with commit-time validity established", "caller correction")
    return "ALLOW", {"tier": tier, "scope_ref": scope_ref,
                     "note": "admissible on the record as presented; execution and receipt-pair issuance proceed"}

# FAIL_CLOSED classes caused by the provider's own state rather than
# the caller's presentation (BUILD-Q-45 determination, 2026-11-17):
# NO_STANDING_RECEIVER -- the scope's receiver stands dissolved in the
# endpoint's own scope registry; SIGNING_VIA_DEDICATED_OPERATION /
# CUSTODY_SIGNING_REQUIRED -- the custody-slot boundary: the action
# belongs to the dedicated signing route, a boundary of the service's
# own grammar. Crossings failing closed for these reasons never
# submit settlement: the fee is not collected for the provider's own
# failure.
PROVIDER_SIDE_FAIL_CODES = {"NO_STANDING_RECEIVER",
                            "SIGNING_VIA_DEDICATED_OPERATION",
                            "CUSTODY_SIGNING_REQUIRED"}


def settlement_withheld(payment, detail):
    """The settlement record for a provider-caused FAIL_CLOSED
    (BUILD-Q-45): settlement is NOT submitted, the EIP-3009 nonce is
    not consumed on-chain, and the authorization stands under the
    refusal pair only."""
    return {"build": "GATE-2", "mode": "self-relayer",
            "attempted": False, "status": "NOT_SUBMITTED",
            "failure_code":
                "SETTLEMENT_WITHHELD_PROVIDER_SIDE_DISPOSITION",
            "failed_predicate":
                "settlement is submitted only for dispositions "
                "determined by the caller's own presentation; this "
                "disposition was caused by the provider's own state",
            "required_evidence_or_repair":
                detail.get("required_evidence_or_repair"),
            "owning_goal": OWNING_GOAL,
            "disposition_failure_code": detail.get("failure_code"),
            "asset": payment.get("asset"), "payTo": payment.get("payTo"),
            "value_micro_usdc": payment.get("value_micro_usdc"),
            "nonce": payment.get("nonce"),
            "note": "the authorization was not submitted on-chain; "
                    "its EIP-3009 nonce is unconsumed on-chain"}


def journal_settlement(crossing, disposition, payment, settle_rec,
                       error, pair_id=None):
    """Emergency record (BUILD-Q-45 repair): if a settlement reached
    SETTLED/SUBMITTED on-chain but the crossing pair could not be
    written, the on-chain fact is journaled to a plain fsync'd file
    beside the segments so it is never silently lost; operator
    reconciliation checks the chain first, then receipts it onto the
    chain. Returns True if the journal write succeeded."""
    entry = {"ts": now(), "event": "SETTLEMENT_WITHOUT_PAIR",
             "crossing": crossing, "disposition": disposition,
             "payment": payment, "settlement": settle_rec,
             "pair_id_if_issued": pair_id,
             "error": f"{type(error).__name__}: {error}"[:300]}
    try:
        path = os.path.join(SEG_DIR, "SETTLEMENT_JOURNAL.jsonl")
        created = not os.path.exists(path)
        with open(path, "a") as f:
            f.write(json.dumps(entry, sort_keys=True) + "\n")
            f.flush()
            os.fsync(f.fileno())
        if created:
            _fsync_dir(SEG_DIR)
        return True
    except Exception:
        return False


# ---------------- pair-first settlement state (BUILD-Q-45 migration) ----
# The pair is written FIRST, from locally-decidable predicates only,
# with settlement_state PENDING; settlement is an eventual leg. Its
# outcome is receipted as an APPENDED record bound to the pair (a
# SETTLEMENT pair on success, a SETTLEMENT-FAILURE pair on terminal
# on-chain failure) -- never a rewrite of the pair, never a silent
# drop, and never a change to the pair's disposition. Retryable
# failures leave the pair PENDING for the sweep. The pending set is
# derived from the receipt chain itself (every PENDING pair stands
# on the chain), so no second store can diverge from the record.
SETTLEMENT_TERMINAL_CODES = {"SETTLEMENT_SIMULATION_REVERTED",
                             "SETTLEMENT_REVERTED_ONCHAIN"}
SWEEP_INTERVAL_SECONDS = int(SETTLE_CFG.get("sweep_interval_seconds", 60))
_PENDING_CLAIMS = set()
_PENDING_CLAIMS_LOCK = threading.Lock()

def _claim_pending(pair_id):
    with _PENDING_CLAIMS_LOCK:
        if pair_id in _PENDING_CLAIMS:
            return False
        _PENDING_CLAIMS.add(pair_id)
        return True

def _release_pending(pair_id):
    with _PENDING_CLAIMS_LOCK:
        _PENDING_CLAIMS.discard(pair_id)

def pending_settlement_record(payment):
    """The settlement record a pair is born with under pair-first:
    PENDING, not yet attempted, written before any RPC call."""
    return {"build": "GATE-2", "mode": "self-relayer",
            "attempted": False, "status": "PENDING",
            "settlement_state": "PENDING",
            "asset": payment.get("asset"), "payTo": payment.get("payTo"),
            "value_micro_usdc": payment.get("value_micro_usdc"),
            "nonce": payment.get("nonce"),
            "note": "pair-first (BUILD-Q-45): this pair was written "
                    "before any settlement submission; settlement is "
                    "an eventual leg -- attempted immediately when "
                    "the RPC answers, swept while PENDING, and its "
                    "outcome is receipted as an appended settlement "
                    "record bound to this pair"}

def _confirm_terminal_onchain(payment):
    """On-chain confirmation for a simulation revert: the revert is
    terminal only when chain state itself says the authorization
    can never settle -- its nonce already consumed by another
    settlement, or the payer's balance below the authorized value.
    An RPC's revert response alone is not chain state (a degraded
    route can report a revert the chain does not sustain -- the
    PAIR-000049/50 lesson, 2026-11-18: the failure pair stood while
    the nonce was unconsumed and the simulation succeeded on a
    direct read), so an unconfirmed revert leaves the pair
    PENDING. Returns an evidence dict when terminal, else None --
    including when the read itself fails: unprovable is not
    terminal."""
    try:
        rpc = settle_mod.Rpc([SETTLE_CFG.get("rpc_primary"),
                              SETTLE_CFG.get("rpc_fallback")])
        asset = payment.get("asset")
        payer = payment.get("from")
        nonce = payment.get("nonce") or ""
        nonce_hex = nonce[2:] if nonce.startswith("0x") else nonce
        sel = settle_mod.keccak256(
            b"authorizationState(address,bytes32)")[:4].hex()
        data = "0x" + sel + "0" * 24 + payer[2:].lower() + nonce_hex
        consumed = int(rpc.call("eth_call",
                                [{"to": asset, "data": data},
                                 "latest"]), 16)
        bal_data = "0x70a08231" + "0" * 24 + payer[2:].lower()
        balance = int(rpc.call("eth_call",
                               [{"to": asset, "data": bal_data},
                                "latest"]), 16)
        value = int(payment.get("value_micro_usdc") or 0)
        if consumed:
            return {"authorization_state": "consumed",
                    "payer_balance_micro_usdc": balance}
        if balance < value:
            return {"authorization_state": "unconsumed",
                    "payer_balance_micro_usdc": balance,
                    "authorized_value_micro_usdc": value}
    except Exception:
        return None
    return None


def _chain_settlement_index(seg_dir):
    """(settled, failed, pending) for one chain, read from its own
    records: settled/failed map settles_pair_id -> the settlement
    record of the appended outcome pair; pending lists
    (pair_id, payment) for EVALUATION pairs born PENDING with no
    outcome pair yet. A SETTLEMENT-FAILURE pair marks its target
    failed only when its record carries terminal_confirmed -- an
    unconfirmed failure record does not bar a later settlement;
    when the settlement pair lands, it is the pair's outcome."""
    settled, failed, pending = {}, {}, []
    for r in read_entries(seg_dir):
        c = r["content"]
        if c.get("index_in_pair") != 0:
            continue
        if c.get("pair_class") == "SETTLEMENT":
            rec = c.get("settlement") or {}
            target = c.get("settles_pair_id")
            if c.get("disposition") == "SETTLEMENT_FAILED" \
                    and rec.get("terminal_confirmed") is True:
                failed[target] = rec
            elif rec.get("status") in ("SETTLED", "SUBMITTED"):
                settled[target] = rec
        elif c.get("pair_class") == "EVALUATION":
            s = c.get("settlement") or {}
            if s.get("status") == "PENDING" and c.get("payment"):
                pending.append((c["pair_id"], c["payment"]))
    pending = [(pid, pay) for pid, pay in pending
               if pid not in settled and pid not in failed]
    return settled, failed, pending

def attempt_and_receipt(chain, pair_id, payment):
    """One settlement attempt for a PENDING pair, with its outcome
    receipted on the pair's own chain. Returns
    {settlement_state, settlement, settlement_pair_id} -- the state
    is PENDING (retryable failure; no outcome pair appended),
    SETTLED/SUBMITTED (SETTLEMENT pair appended), or FAILED_TERMINAL
    (SETTLEMENT-FAILURE pair appended). Returns None when another
    attempt for this pair is already in flight."""
    if not _claim_pending(pair_id):
        return None
    try:
        rec = settle_mod.attempt_settlement(payment, SETTLE_CFG, BASE)
        status = rec.get("status")
        if status in ("SETTLED", "SUBMITTED"):
            rec = {**rec, "settlement_state": status}
            spid, _r = chain.issue_settlement_pair(rec, pair_id)
            return {"settlement_state": status, "settlement": rec,
                    "settlement_pair_id": spid}
        code = rec.get("failure_code")
        if code == "SETTLEMENT_REVERTED_ONCHAIN":
            # A mined status-0 receipt is chain state itself:
            # terminal as it stands.
            rec = {**rec, "settlement_state": "FAILED_TERMINAL",
                   "terminal_confirmed": True,
                   "terminal_evidence": {
                       "basis": "mined receipt status 0x0",
                       "tx_hash": rec.get("tx_hash")}}
            spid, _r = chain.issue_settlement_failure_pair(rec, pair_id)
            return {"settlement_state": "FAILED_TERMINAL",
                    "settlement": rec, "settlement_pair_id": spid}
        if code == "SETTLEMENT_SIMULATION_REVERTED":
            evidence = _confirm_terminal_onchain(payment)
            if evidence is not None:
                rec = {**rec, "settlement_state": "FAILED_TERMINAL",
                       "terminal_confirmed": True,
                       "terminal_evidence": evidence}
                spid, _r = chain.issue_settlement_failure_pair(
                    rec, pair_id)
                return {"settlement_state": "FAILED_TERMINAL",
                        "settlement": rec, "settlement_pair_id": spid}
            rec = {**rec, "terminal_check":
                   "simulation revert NOT confirmed against on-chain "
                   "state (nonce unconsumed and payer funded, or the "
                   "confirmation read failed); the pair remains "
                   "PENDING -- an RPC response is not chain state"}
            return {"settlement_state": "PENDING", "settlement": rec,
                    "settlement_pair_id": None}
        return {"settlement_state": "PENDING", "settlement": rec,
                "settlement_pair_id": None}
    finally:
        _release_pending(pair_id)

def _all_chains():
    out = [(CHAIN, SEG_DIR, "parent")]
    if os.path.isdir(SUBLANE_ROOT):
        for n in sorted(os.listdir(SUBLANE_ROOT)):
            d = os.path.join(SUBLANE_ROOT, n)
            if os.path.isdir(d) and sublane_valid(n):
                lane = get_lane(n)
                out.append((lane.chain, lane.dir, n))
    return out

def sweep_pending_settlements():
    """The eventual leg's sweep: attempt every PENDING pair on
    every chain (parent + sub-lanes) and receipt the outcomes.
    Returns a per-pair summary list."""
    results = []
    for chain, seg_dir, name in _all_chains():
        _s, _f, pending = _chain_settlement_index(seg_dir)
        for pair_id, payment in pending:
            out = attempt_and_receipt(chain, pair_id, payment)
            if out is None:
                results.append({"pair_id": pair_id, "chain": name,
                                "settlement_state": "IN_FLIGHT"})
                continue
            results.append({"pair_id": pair_id, "chain": name,
                            "settlement_state": out["settlement_state"],
                            "settlement_pair_id":
                                out["settlement_pair_id"],
                            "failure_code":
                                out["settlement"].get("failure_code"),
                            "tx_hash":
                                out["settlement"].get("tx_hash")})
    return results

def _settlement_sweeper():
    while True:
        time.sleep(SWEEP_INTERVAL_SECONDS)
        try:
            sweep_pending_settlements()
        except Exception:
            pass

def find_pair_location(pair_id):
    """(chain, seg_dir, members) for a pair on the parent chain or
    any sub-lane chain; (None, None, []) when absent."""
    members = pair_members(pair_id)
    if members:
        return CHAIN, SEG_DIR, members
    if os.path.isdir(SUBLANE_ROOT):
        for n in sorted(os.listdir(SUBLANE_ROOT)):
            d = os.path.join(SUBLANE_ROOT, n)
            if not (os.path.isdir(d) and sublane_valid(n)):
                continue
            ms = [r["content"] for r in read_entries(d)
                  if r["content"].get("pair_id") == pair_id]
            if ms:
                return get_lane(n).chain, d, ms
    return None, None, []

# ---------------- /inspect: the one-link inspection surface ----------------
# GET /inspect serves, in ONE response, everything an arbitrary
# inspector (human or LLM) needs to determine functionality cold:
# live service state, receipt-chain state with a live replay, the
# on-chain settlement evidence with the payTo balance read live,
# pointers that resolve (suite conformance proof, retention
# verifier, lane home), and a compact determination block tying
# each claim to the check that decides it. Pointers live in
# inspect_pointers.json beside the endpoint (updated at carriage
# time); the state sections are computed at request time.
INSPECT_POINTERS_FILE = os.path.join(BASE, "inspect_pointers.json")
_INSPECT_POINTER_DEFAULTS = {
    "lane_home": {"repo": "SV-LLM/sandbox",
                  "branch": "machine-economy-8374",
                  "folder": "machine-economy-8374/"},
    "retention_verifier": {
        "form": "RETENTION_BUNDLE/1 verifier (verify_bundle.py), "
                "rules receipt-chain-rules/1",
        "kv_drive_id": "1C06p8DWlSL1DrUakGgw8tUv2qEv01Uyt"},
    "suite": {"name": "MACHINE__ECONOMY__ENTRY__SUITE",
              "generation": None, "manifest_sha256": None,
              "kv_zip_drive_id": None,
              "conformance_proof": "CONFORMANCE__PROOF__01.json "
                                   "(in-suite member)"}}

def _payto_balance_micro():
    """8374's USDC balance at payTo, read live from Base; None when
    no RPC answers (the inspect document then names the failure
    rather than stating a stale balance)."""
    data = "0x70a08231" + "0" * 24 + X402_PAYTO[2:].lower()
    rpc = settle_mod.Rpc([SETTLE_CFG.get(
        "rpc_primary", "https://mainnet.base.org"),
        SETTLE_CFG.get("rpc_fallback",
                       "https://base-rpc.publicnode.com")])
    return int(rpc.call("eth_call",
                        [{"to": X402_ASSET, "data": data}, "latest"]), 16)

def inspect_document():
    rep = replay()
    settled = []
    seen_settled = set()
    for r in read_entries(SEG_DIR):
        c = r["content"]
        s = c.get("settlement") or {}
        if s.get("status") == "SETTLED" and s.get("tx_hash"):
            key = (c["pair_id"], s["tx_hash"])
            if key in seen_settled:
                continue  # both pair members carry the record
            seen_settled.add(key)
            settled.append({
                "pair_id": c["pair_id"],
                "settles_pair_id": c.get("settles_pair_id"),
                "tx_hash": s["tx_hash"],
                "block_number": s.get("block_number"),
                "value_micro_usdc": s.get("value_micro_usdc")})
    # Pending = born PENDING with no outcome pair yet, by the same
    # chain index the sweep works from (a pair settled through its
    # appended settlement pair is not pending).
    _s, _f, _pending = _chain_settlement_index(SEG_DIR)
    pending_count = len(_pending)
    try:
        balance = _payto_balance_micro()
        balance_state = "read live from Base at inspection time"
    except Exception as e:
        balance = None
        balance_state = f"unavailable: {type(e).__name__}: {e}"[:160]
    try:
        quote = settlement_charge_quote()
    except SettlementQuoteUnavailable:
        quote = {"status": SETTLEMENT_QUOTE_FAILURE}
    pointers = dict(_INSPECT_POINTER_DEFAULTS)
    try:
        with open(INSPECT_POINTERS_FILE) as f:
            stored = json.load(f)
        for k, v in stored.items():
            if isinstance(v, dict) and isinstance(pointers.get(k), dict):
                pointers[k] = {**pointers[k], **v}
            else:
                pointers[k] = v
    except Exception:
        pass
    return {
        "document": "INSPECT__8374",
        "service": "0R10N15-8374 — governed-crossing endpoint "
                   "(StegVerse LLC, 8374@StegVerse.ai)",
        "generated_at": now(),
        "service_state": {
            "status": "ok",
            "offer_version": OFFER_BASE.get("version"),
            "receptor": {"scheme": X402_SCHEME, "network": X402_NETWORK,
                         "asset": X402_ASSET, "payTo": X402_PAYTO},
            "tiers_micro_usdc": X402_TIERS_MICRO,
            "settlement_charge": {
                "basis": "governance fee + settlement charge; the "
                         "charge is quoted live at challenge time "
                         "from Base gas conditions (86,679 gas units "
                         "basis) and the live ETH/USD rate; under an "
                         "egress outage the last successful quote is "
                         "served with quote_stale: true",
                "live_quote": quote},
            "settlement_grammar": "pair-first (BUILD-Q-45): the "
                "receipt pair is written from locally-decidable "
                "predicates before any RPC call, with "
                "settlement_state PENDING; settlement is an eventual "
                "leg whose outcome is receipted as an appended "
                "record bound to the pair"},
        "receipt_chain": {
            "pairs": rep["pairs"], "entries": rep["entries"],
            "replay_verdict": rep["verdict"],
            "terminal_anchor": rep["terminal_anchor"],
            "pairs_with_settlement_pending": pending_count},
        "settlement_evidence": {
            "payTo": X402_PAYTO,
            "payTo_balance_micro_usdc": balance,
            "payTo_balance_state": balance_state,
            "settled_pairs": settled,
            "spot_check": "verify any tx_hash on a public Base "
                          "explorer or via eth_getTransactionReceipt "
                          "on any public Base RPC"},
        "pointers": pointers,
        "determination": {
            "supported": [
                {"claim": "functional: governed crossings evaluate "
                          "and receipt matched pairs",
                 "check": "receipt_chain.pairs and replay_verdict "
                          "above; POST /crossing"},
                {"claim": "settled on-chain: crossing fees have "
                          "moved on Base",
                 "check": "settlement_evidence.settled_pairs "
                          "tx_hash/block_number, spot-verifiable"},
                {"claim": "chain integrity: the receipt chain "
                          "recomputes end to end",
                 "check": "replay_verdict MATCH at "
                          "terminal_anchor above; retention bundles "
                          "verify offline with the retention "
                          "verifier"}],
            "not_supported": [
                {"claim": "external demand",
                 "check": "every settled pair to date is an insider "
                          "specimen; the first external crossing "
                          "(P1) is still open"},
                {"claim": "profitability",
                 "check": "payTo_balance_micro_usdc above against "
                          "operating cost; no profitability "
                          "determination is made"}]}}

def inspect_html(doc):
    sc = doc["service_state"]
    rc = doc["receipt_chain"]
    se = doc["settlement_evidence"]
    rows = "".join(
        f"<tr><td>{s['pair_id']}</td><td>{s['tx_hash']}</td>"
        f"<td>{s['block_number']}</td>"
        f"<td>{s['value_micro_usdc']}</td></tr>"
        for s in se["settled_pairs"])
    det = "".join(
        f"<li>SUPPORTED — {d['claim']} (check: {d['check']})</li>"
        for d in doc["determination"]["supported"]) + "".join(
        f"<li>NOT SUPPORTED — {d['claim']} (check: {d['check']})</li>"
        for d in doc["determination"]["not_supported"])
    return ("<!DOCTYPE html><html><head><meta charset='utf-8'>"
            "<title>0R10N15-8374 — inspect</title></head><body>"
            "<h1>0R10N15-8374 — inspection</h1>"
            f"<p>{doc['service']} · generated {doc['generated_at']} · "
            "<a href='/inspect?format=json'>JSON</a></p>"
            f"<h2>Service</h2><p>status {sc['status']} · offer "
            f"v{sc['offer_version']} · tiers "
            f"{json.dumps(sc['tiers_micro_usdc'])} micro-USDC · "
            f"payTo {sc['receptor']['payTo']}</p>"
            f"<h2>Receipt chain</h2><p>{rc['pairs']} pairs · replay "
            f"{rc['replay_verdict']} · terminal anchor "
            f"{rc['terminal_anchor']} · settlement pending on "
            f"{rc['pairs_with_settlement_pending']} pairs</p>"
            f"<h2>Settlement evidence</h2><p>payTo balance: "
            f"{se['payTo_balance_micro_usdc']} micro-USDC "
            f"({se['payTo_balance_state']})</p>"
            "<table border='1'><tr><th>pair</th><th>tx</th>"
            f"<th>block</th><th>micro-USDC</th></tr>{rows}</table>"
            f"<h2>Determination</h2><ul>{det}</ul>"
            f"<h2>Pointers</h2><pre>"
            f"{json.dumps(doc['pointers'], indent=1)}</pre>"
            "</body></html>")

# ---------------- public pages (2026-11-18) ----------------
# The customer-facing read surfaces on the permanent origin:
# GET / (landing), GET /frozen-test (the frozen test document,
# byte-exact, plus an HTML rendering generated from the same
# bytes), GET /conformance (suite, batteries, discovery standing;
# HTML + ?format=json), GET /compare (the frozen test's scoring
# with the reference result and the open reporting table).
# Live claims (offer terms, chain state) are computed at request
# time from the same sources /inspect reads; historical claims are
# record content and are labeled with the record's date. No page
# claims external demand or profitability (the /inspect
# determination governs every summary of standing).
import html as _html_mod
import re as _re_mod

PATENT_LINE = "Patent pending (U.S. Prov. App. No. 64/198,910)"
FROZEN_TEST_FILE = os.path.join(
    BASE, "FROZEN__TEST__PAIR__FIRST__OUTAGE__01.md")
FROZEN_TEST_SHA256 = ("bfde4c87960b9c24570644626eacd029a489a158"
                      "eae8c41ee38982086a699e1f")
PAGES_RECORD_DATE = "2026-11-18"


def _e(s):
    return _html_mod.escape(str(s))


def _page_shell(title, body):
    return ("<!DOCTYPE html><html><head><meta charset='utf-8'>"
            f"<title>{_e(title)}</title></head><body>{body}"
            f"<hr><p>{PATENT_LINE} · StegVerse LLC · "
            "8374@StegVerse.ai</p></body></html>")


def _md_inline(s):
    s = _html_mod.escape(s)
    s = _re_mod.sub(r"`([^`]+)`", r"<code>\1</code>", s)
    s = _re_mod.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", s)
    s = _re_mod.sub(r"\[([^\]]+)\]\(([^)]+)\)",
                    r"<a href='\2'>\1</a>", s)
    s = _re_mod.sub(r"(?<![='\"])https?://[^\s<]+",
                    r"<a href='\g<0>'>\g<0></a>", s)
    return s


def markdown_to_html(md_text):
    """A small, stdlib-only markdown rendering sufficient for the
    frozen test document: headings, paragraphs, ordered/unordered
    lists, tables, fenced code, bold and inline code. It renders
    the document it is given; the canonical bytes are the ones
    served at /frozen-test."""
    out = []
    lines = md_text.split("\n")
    i = 0
    para = []

    def flush_para():
        if para:
            out.append("<p>" + _md_inline(" ".join(para)) + "</p>")
            para.clear()

    while i < len(lines):
        line = lines[i]
        if line.startswith("```"):
            flush_para()
            buf = []
            i += 1
            while i < len(lines) and not lines[i].startswith("```"):
                buf.append(lines[i])
                i += 1
            i += 1
            out.append("<pre>" + _html_mod.escape("\n".join(buf))
                       + "</pre>")
            continue
        if not line.strip():
            flush_para()
            i += 1
            continue
        m = _re_mod.match(r"^(#{1,4})\s+(.*)$", line)
        if m:
            flush_para()
            lvl = len(m.group(1))
            out.append(f"<h{lvl}>" + _md_inline(m.group(2))
                       + f"</h{lvl}>")
            i += 1
            continue
        if line.lstrip().startswith("|") and i + 1 < len(lines) \
                and _re_mod.match(r"^\s*\|[\s:|-]+\|\s*$",
                                  lines[i + 1]):
            flush_para()
            head = [c.strip() for c in
                    line.strip().strip("|").split("|")]
            out.append("<table border='1'><tr>" + "".join(
                f"<th>{_md_inline(c)}</th>" for c in head) + "</tr>")
            i += 2
            while i < len(lines) and lines[i].lstrip().startswith("|"):
                cells = [c.strip() for c in
                         lines[i].strip().strip("|").split("|")]
                out.append("<tr>" + "".join(
                    f"<td>{_md_inline(c)}</td>" for c in cells)
                    + "</tr>")
                i += 1
            out.append("</table>")
            continue
        if _re_mod.match(r"^\s*-\s+", line):
            flush_para()
            items = []
            while i < len(lines) and _re_mod.match(
                    r"^\s*-\s+", lines[i]):
                items.append(_re_mod.sub(r"^\s*-\s+", "",
                                         lines[i]))
                i += 1
            out.append("<ul>" + "".join(
                f"<li>{_md_inline(x)}</li>" for x in items) + "</ul>")
            continue
        if _re_mod.match(r"^\s*\d+\.\s+", line):
            flush_para()
            items = []
            while i < len(lines) and _re_mod.match(
                    r"^\s*\d+\.\s+", lines[i]):
                items.append(_re_mod.sub(r"^\s*\d+\.\s+", "",
                                         lines[i]))
                i += 1
            out.append("<ol>" + "".join(
                f"<li>{_md_inline(x)}</li>" for x in items) + "</ol>")
            continue
        para.append(line.strip())
        i += 1
    flush_para()
    return "\n".join(out)


def frozen_test_bytes():
    with open(FROZEN_TEST_FILE, "rb") as f:
        return f.read()


def frozen_test_html():
    raw = frozen_test_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    note = ("<p>This page is a rendering of the frozen document. "
            "The canonical bytes are served at "
            "<a href='/frozen-test'>/frozen-test</a> "
            "(text/markdown); their SHA-256, computed at request "
            f"time, is <code>{digest}</code> — the filed hash is "
            f"<code>{FROZEN_TEST_SHA256}</code>. Hash what you "
            "download and compare.</p>")
    return _page_shell("0R10N15-8374 — frozen test",
                       note + markdown_to_html(raw.decode("utf-8")))


def landing_html():
    doc = inspect_document()
    sc = doc["service_state"]
    rc = doc["receipt_chain"]
    tier_rows = "".join(
        f"<tr><td>{_e(k)}</td><td>{_e(v)} micro-USDC</td></tr>"
        for k, v in sorted(sc["tiers_micro_usdc"].items()))
    quote = (sc.get("settlement_charge") or {}).get("live_quote")
    body = (
        "<h1>0R10N15-8374 — governed crossings for machines</h1>"
        f"<p>{doc['service']}</p>"
        "<h2>What it is</h2>"
        "<p>Governed crossings for machine transactions. One "
        "receipt pair per crossing — ALLOW or NON-ALLOW — and the "
        "fee is paid either way. Pair-first: the proof issues on "
        "locally-decidable evidence at the crossing; settlement is "
        "an eventual leg, receipted when it lands.</p>"
        "<h2>Terms (from the live offer)</h2>"
        f"<p>Offer version {_e(sc['offer_version'])} · receptor: "
        f"{_e(sc['receptor']['scheme'])} on "
        f"{_e(sc['receptor']['network'])}, asset "
        f"{_e(sc['receptor']['asset'])}, payTo "
        f"{_e(sc['receptor']['payTo'])} (fixed, server-side).</p>"
        "<table border='1'><tr><th>tier</th><th>governance fee"
        f"</th></tr>{tier_rows}</table>"
        "<p>Settlement charge: "
        f"{_e(sc['settlement_charge']['basis'])}</p>"
        f"<p>Live quote at page time: <code>{_e(json.dumps(quote))}"
        "</code> · full terms at <a href='/offer'>/offer</a>.</p>"
        "<h2>How it works</h2><ol>"
        "<li><strong>Challenge.</strong> An unpaid POST /crossing "
        "returns the 402 challenge (x402 v1 + v2), quoting the "
        "governance fee plus the settlement charge as one total.</li>"
        "<li><strong>Authorization.</strong> The payer signs an "
        "EIP-3009 transferWithAuthorization for the quoted total; "
        "the payee is fixed server-side and cannot be redirected "
        "by the payer.</li>"
        "<li><strong>Pair.</strong> The endpoint decides on "
        "locally-decidable predicates — signature recovery, "
        "receptor and amount match against its own offer, validity "
        "window, evidence rules, and the authorization's nonce "
        "checked against the registry the receipt chain itself is "
        "— and writes the receipt pair first, with "
        "settlement_state PENDING, before any network call.</li>"
        "<li><strong>Settlement.</strong> The relayer submits "
        "on-chain; the outcome is appended as a record bound to "
        "the pair (SETTLEMENT, or SETTLEMENT-FAILURE on terminal "
        "on-chain failure). The pair's disposition never "
        "changes.</li></ol>"
        "<h2>The outage property</h2>"
        "<p>When the network drops at the moment of a crossing, "
        "the crossing still completes: the pair is the proof, "
        "issued locally, and settlement waits for the network and "
        "lands exactly once. Pair-first is built and live in "
        f"production (record, {PAGES_RECORD_DATE}). Proof: the "
        "outage battery, 8/8 run twice — RPC blackholed, the "
        "crossing returned ALLOW with its pair written PENDING, "
        "the same nonce re-presented was refused locally "
        "(PAYMENT_NONCE_REUSED), settlement on restore was exact, "
        "and replay verified MATCH including the outage pairs. "
        "The frozen test lets any framework run the same "
        "scenario: <a href='/frozen-test'>/frozen-test</a>.</p>"
        "<h2>Live state</h2>"
        f"<p>{rc['pairs']} pairs · replay {rc['replay_verdict']} "
        f"· terminal anchor <code>{rc['terminal_anchor']}</code> "
        f"· settlement pending on "
        f"{rc['pairs_with_settlement_pending']} pairs (computed "
        "at page time; the full live determination is at "
        "<a href='/inspect'>/inspect</a>).</p>"
        "<h2>Inspect and conform</h2><ul>"
        "<li><a href='/inspect'>/inspect</a> — one-link live "
        "inspection and determination</li>"
        "<li><a href='/frozen-test'>/frozen-test</a> — the frozen "
        "pair-first outage test (byte-exact; hash it)</li>"
        "<li><a href='/conformance'>/conformance</a> — suite, "
        "batteries, discovery standing</li>"
        "<li><a href='/compare'>/compare</a> — test comparisons: "
        "the reference result and the open table</li>"
        "<li><a href='/offer'>/offer</a> — the public offer</li>"
        "<li><a href='/openapi.json'>/openapi.json</a> — the API "
        "document</li></ul>"
        "<p>Standing, per the /inspect determination: supported — "
        "functional, settled on-chain, chain integrity. Not "
        "claimed — external demand, profitability.</p>")
    return _page_shell("0R10N15-8374 — governed crossings", body)


def conformance_document():
    doc = inspect_document()
    pointers = doc["pointers"]
    suite = dict(pointers.get("suite") or {})
    suite.update({
        "conformance": "CONFORMANT — CONFORMANCE__PROOF__01.json "
                       "is a hashed member of the suite's own "
                       "manifest; elements E1–E5 PASS",
        "self_check": "55 PASS / 0 FAIL",
        "members": 23,
        "record_date": PAGES_RECORD_DATE})
    return {
        "document": "CONFORMANCE__8374",
        "generated_at": now(),
        "live_chain": doc["receipt_chain"],
        "suite": suite,
        "batteries": {
            "record_date": PAGES_RECORD_DATE,
            "run_against": "throwaway instances of the production "
                           "code (never the live chain)",
            "results": {"x402": "10/10", "x402_v2": "8/8",
                        "settlement": "5/5", "agreement": "5/5",
                        "outage": "8/8, run twice (RPC toggled "
                                  "live / blackholed)"}},
        "discovery": {
            "record_date": PAGES_RECORD_DATE,
            "402_index": "ACTIVE — domain verified",
            "x402scan": "registered (origin "
                        "f73c0f76-be8b-47d8-af4f-8095f2eaf085)",
            "cdp_bazaar": "not listed — cataloging follows a "
                          "CDP-facilitated settlement; the "
                          "facilitator determination is the "
                          "principal's and has not been made"},
        "retention_verifier": pointers.get("retention_verifier"),
        "lane_home": pointers.get("lane_home"),
        "frozen_test": {
            "document": "FROZEN__TEST__PAIR__FIRST__OUTAGE__01",
            "sha256": FROZEN_TEST_SHA256,
            "served_at": "/frozen-test"},
        "determination": doc["determination"]}


def conformance_html(doc):
    suite = doc["suite"]
    bat = "".join(
        f"<tr><td>{_e(k)}</td><td>{_e(v)}</td></tr>"
        for k, v in doc["batteries"]["results"].items())
    disc = "".join(
        f"<tr><td>{_e(k)}</td><td>{_e(v)}</td></tr>"
        for k, v in doc["discovery"].items() if k != "record_date")
    det = "".join(
        f"<li>SUPPORTED — {_e(d['claim'])}</li>"
        for d in doc["determination"]["supported"]) + "".join(
        f"<li>NOT SUPPORTED — {_e(d['claim'])}</li>"
        for d in doc["determination"]["not_supported"])
    body = (
        "<h1>0R10N15-8374 — conformance</h1>"
        f"<p>Live chain at page time: {doc['live_chain']['pairs']} "
        f"pairs · replay {doc['live_chain']['replay_verdict']} · "
        f"anchor <code>{doc['live_chain']['terminal_anchor']}"
        "</code>. Record content below is labeled with its date; "
        "the JSON twin is at "
        "<a href='/conformance?format=json'>"
        "/conformance?format=json</a>.</p>"
        "<h2>Suite</h2>"
        f"<p>{_e(suite.get('name'))} {_e(suite.get('generation'))}"
        f" — {_e(suite.get('conformance'))}<br>"
        f"manifest SHA-256 <code>{_e(suite.get('manifest_sha256'))}"
        f"</code> · self-check {_e(suite.get('self_check'))} · "
        f"{_e(suite.get('members'))} members · KV zip Drive "
        f"{_e(suite.get('kv_zip_drive_id'))} · record "
        f"{_e(suite.get('record_date'))}</p>"
        "<h2>Batteries</h2>"
        f"<p>Record {doc['batteries']['record_date']}, run "
        f"against {doc['batteries']['run_against']}:</p>"
        f"<table border='1'><tr><th>battery</th><th>result</th>"
        f"</tr>{bat}</table>"
        "<h2>Discovery standing</h2>"
        f"<p>Record {doc['discovery']['record_date']}:</p>"
        f"<table border='1'>{disc}</table>"
        "<h2>Retention verifier</h2>"
        f"<pre>{_e(json.dumps(doc['retention_verifier'], indent=1))}"
        "</pre>"
        "<h2>Lane home</h2>"
        f"<pre>{_e(json.dumps(doc['lane_home'], indent=1))}</pre>"
        "<h2>Frozen test</h2>"
        f"<p>{_e(doc['frozen_test']['document'])} · SHA-256 "
        f"<code>{_e(doc['frozen_test']['sha256'])}</code> · served "
        "at <a href='/frozen-test'>/frozen-test</a></p>"
        f"<h2>Determination</h2><ul>{det}</ul>")
    return _page_shell("0R10N15-8374 — conformance", body)


def _reference_settlement_rows():
    """The frozen test's reference pairs, read from the live chain
    at page time: (pair_id, tx_hash, block, value) for the two
    production crossings the reference result cites."""
    want = {"PAIR-000049", "PAIR-000055"}
    rows = {}
    for r in read_entries(SEG_DIR):
        c = r["content"]
        s = c.get("settlement") or {}
        pid = c.get("settles_pair_id") or c["pair_id"]
        if pid in want and s.get("status") == "SETTLED" \
                and s.get("tx_hash"):
            rows[pid] = (c["pair_id"], s["tx_hash"],
                         s.get("block_number"),
                         s.get("value_micro_usdc"))
    return rows


def compare_html():
    ref = _reference_settlement_rows()
    ev = []
    for pid in ("PAIR-000049", "PAIR-000055"):
        if pid in ref:
            sp, tx, blk, val = ref[pid]
            ev.append(f"{pid} settled by {sp}: tx <code>{tx}</code>"
                      f", block {blk}, {val} micro-USDC (read from "
                      "the live chain at page time)")
        else:
            ev.append(f"{pid}: settlement record not found in the "
                      "live chain at page time")
    ref_rows = [
        ("1. Authorization obtained", "PASS",
         "Authorizations obtained for the battery runs and the "
         "production specimens (record)"),
        ("2. Network cut", "PASS",
         "Egress blackholed in the battery (RPC at an unreachable "
         "address); production transport windows receipted as "
         "SETTLEMENT_RPC_UNREACHABLE (record)"),
        ("3. Crossing presented offline", "PASS",
         "Crossing completed offline; pair written PENDING — "
         "battery crossings ALLOW, and production PAIR-000049 and "
         "PAIR-000054 born PENDING on the pair-first path "
         "(record)"),
        ("4. Same authorization re-presented offline", "PASS",
         "Refused locally from the chain-derived nonce registry: "
         "422 PAYMENT_NONCE_REUSED, no network read (record)"),
        ("5. Network restored — settlement", "PASS",
         "Settled exactly once: " + "; ".join(ev)),
        ("5b. Full record replay/recompute", "PASS",
         "Replay MATCH including the outage pairs — verify live "
         "at <a href='/inspect'>/inspect</a>"),
    ]
    ref_html = "".join(
        f"<tr><td>{_e(a)}</td><td>{_e(b)}</td><td>{c}</td></tr>"
        for a, b, c in ref_rows)
    steps = ["1. Authorization obtained",
             "2. Network cut (egress to chain/facilitator "
             "confirmed down)",
             "3. Crossing presented offline",
             "4. Same authorization re-presented offline",
             "5. Network restored — settlement",
             "5b. Full record replay/recompute"]
    open_rows = "".join(
        f"<tr><td>{_e(s)}</td><td></td><td></td><td></td></tr>"
        for s in steps)
    body = (
        "<h1>0R10N15-8374 — test comparisons</h1>"
        "<p>The frozen test "
        "<a href='/frozen-test'>FROZEN__TEST__PAIR__FIRST__"
        "OUTAGE__01</a> scores a framework on three outcomes: "
        "Step 3 completes offline AND Step 4 is refused from local "
        "state AND Step 5 settles exactly once. Every other "
        "combination is a FAIL, named by its mode: availability "
        "failure (Step 3), replay failure (Step 4 accepted), "
        "settlement integrity failure (Step 5 settles zero times "
        "or more than once). A Step 4 refusal produced only by "
        "consulting a facilitator's or the chain's state after "
        "reconnection scores as a Step 4 FAIL.</p>"
        "<h2>Reference result — 0R10N15-8374 (production)</h2>"
        f"<p>Record {PAGES_RECORD_DATE}: outage battery 8/8, run "
        "twice, plus the production pair-first crossings. The "
        "Step 5 settlement evidence below is read from the live "
        "chain at page time.</p>"
        "<table border='1'><tr><th>step</th><th>result</th>"
        f"<th>evidence</th></tr>{ref_html}</table>"
        "<h2>Report yours</h2>"
        "<p>Run the frozen test against your own framework, your "
        "own funds, testnet or mainnet — state which, and state "
        "every substitution. Fill in this table and publish it "
        "where you publish your work:</p>"
        "<table border='1'><tr><th>step</th><th>result "
        "(PASS/FAIL)</th><th>evidence (record id / tx hash / "
        f"error returned)</th><th>notes</th></tr>{open_rows}"
        "</table>"
        "<p>External framework results on record: <strong>none "
        f"yet</strong> (as of {PAGES_RECORD_DATE}). The table is "
        "open for theirs. A result reported without the Step 4 "
        "evidence is a claim, not a run.</p>")
    return _page_shell("0R10N15-8374 — test comparisons", body)


# ---------------- HTTP surface ----------------
class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass
    def _json(self, code, obj):
        b = json.dumps(obj, indent=1).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)
    def _text(self, code, text):
        b = text.encode()
        self.send_response(code)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)
    def _bytes(self, code, b, content_type):
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)
    def _html(self, code, text):
        self._bytes(code, text.encode(), "text/html; charset=utf-8")
    def _json_h(self, code, obj, extra_headers):
        b = json.dumps(obj, indent=1).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b)))
        for k, v in extra_headers.items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(b)
    def _challenge(self, tier):
        """The dual-stack 402 (BUILD-Q-48): the v1 challenge body,
        unchanged for v1 clients, plus the PAYMENT-REQUIRED header
        carrying the v2 PaymentRequired for the same terms. Offer
        v07 (BUILD-Q-43): both stacks declare the same TOTAL --
        governance fee + the settlement charge from one quote taken
        at challenge time. If no live quote can be produced, the
        endpoint fails closed (503, SETTLEMENT_CHARGE_QUOTE_
        UNAVAILABLE) and issues no paid challenge at all, rather
        than silently absorbing gas."""
        try:
            total, quote = crossing_total_micro(tier)
            v1 = payment_requirements(tier, total, quote)
            v2 = payment_required_v2(tier, total, quote)
        except SettlementQuoteUnavailable:
            self._json(503, {"disposition": "FAIL_CLOSED",
                             "executed": False,
                             **_quote_fail_detail()})
            return
        self._json_h(402, v1, {"PAYMENT-REQUIRED": _b64_json(v2)})
    def _json_crossing(self, code, obj):
        """A post-settlement crossing response: when this request
        paid under x402 v2, the response also carries the
        PAYMENT-RESPONSE header (the v2 SettlementResponse)."""
        hdr = getattr(self, "_payment_response", None)
        if hdr:
            self._json_h(code, obj, {"PAYMENT-RESPONSE": hdr})
        else:
            self._json(code, obj)
    def _body(self):
        n = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(n) if n else b"{}"
        return json.loads(raw or b"{}")
    def do_GET(self):
        _split = urllib.parse.urlsplit(self.path)
        if _split.path == "/funds":
            # Operator surface only: this server binds 127.0.0.1 and
            # /funds is not in the public proxy allowlist (same
            # restriction class as POST /settle-pair). The complete
            # funds projection: every ecosystem address, reconciled.
            try:
                doc = funds_mod.funds_document()
            except Exception as e:
                self._json(503, {"error": "funds projection unavailable",
                                 "failure_code": "FUNDS_PROJECTION_UNAVAILABLE",
                                 "detail": str(e)[:200]})
                return
            if urllib.parse.parse_qs(_split.query).get("format") == ["html"]:
                body = funds_mod.render_html(doc).encode()
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            else:
                self._json(200, doc)
            return
        if _split.path == "/inspect":
            # The one-link public inspection surface: one response
            # carrying live service state, chain state with a live
            # replay, on-chain settlement evidence, resolving
            # pointers, and the compact determination block. JSON
            # via ?format=json or an application/json Accept;
            # otherwise the compact HTML page (whose JSON twin is
            # the same document).
            try:
                doc = inspect_document()
            except Exception as e:
                self._json(503, {"error": "inspect unavailable",
                                 "failure_code": "INSPECT_UNAVAILABLE",
                                 "detail": str(e)[:200]})
                return
            want_json = urllib.parse.parse_qs(
                _split.query).get("format") == ["json"] \
                or "application/json" in (
                    self.headers.get("Accept") or "")
            if want_json:
                self._json(200, doc)
            else:
                body = inspect_html(doc).encode()
                self.send_response(200)
                self.send_header("Content-Type",
                                 "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            return
        if _split.path == "/":
            # The landing page on the permanent origin: what 8374
            # is, the live terms, how a crossing works, the outage
            # property, and the inspection/conformance links.
            try:
                self._html(200, landing_html())
            except Exception as e:
                self._json(503, {"error": "landing unavailable",
                                 "failure_code": "LANDING_UNAVAILABLE",
                                 "detail": str(e)[:200]})
            return
        if _split.path == "/frozen-test":
            # The frozen test document itself: byte-exact markdown
            # by default (hash what you download against the filed
            # hash), an HTML rendering generated from the same
            # bytes at ?format=html.
            try:
                raw = frozen_test_bytes()
            except OSError:
                self._json(404, {"error": "not found"})
                return
            if urllib.parse.parse_qs(
                    _split.query).get("format") == ["html"]:
                self._html(200, frozen_test_html())
            else:
                self._bytes(200, raw, "text/markdown; charset=utf-8")
            return
        if _split.path == "/conformance":
            try:
                doc = conformance_document()
            except Exception as e:
                self._json(503, {"error": "conformance unavailable",
                                 "failure_code":
                                     "CONFORMANCE_UNAVAILABLE",
                                 "detail": str(e)[:200]})
                return
            if urllib.parse.parse_qs(
                    _split.query).get("format") == ["json"]:
                self._json(200, doc)
            else:
                self._html(200, conformance_html(doc))
            return
        if _split.path == "/compare":
            try:
                self._html(200, compare_html())
            except Exception as e:
                self._json(503, {"error": "compare unavailable",
                                 "failure_code": "COMPARE_UNAVAILABLE",
                                 "detail": str(e)[:200]})
            return
        if self.path == "/health":
            self._json(200, {"status": "ok", "service": CONFIG["service"],
                             "port": PORT, "project_id": CONFIG["project_id"],
                             "queue_item": CONFIG["queue_item"],
                             "identity": {"designation": CONFIG["identity"]["designation"],
                                          "form": CONFIG["identity"]["form"],
                                          "expansion": CONFIG["identity"]["expansion"],
                                          "status": CONFIG["identity"]["status"]},
                             "gate": {"custody_signing_path": CONFIG["gate"]["custody_signing_path"],
                                      "signing": signing_state()},
                             "receptor": {"scheme": X402_SCHEME,
                                          "network": X402_NETWORK,
                                          "asset": X402_ASSET,
                                          "payTo": X402_PAYTO,
                                          "status": SETTLEMENT.get("status"),
                                          "payment_verification": "x402 exact-scheme EIP-3009 authorizations verified cryptographically at POST /crossing (BUILD-Q-18); settlement is submitted by the endpoint's gas-only relayer (Gate 2) and the outcome is receipted in the crossing pair"},
                             "metering": {**CHAIN.totals(),
                                          "identity": identity_totals()},
                             "manifold": manifold_state(),
                             "settlement_submission": settle_mod.public_state(SETTLE_CFG, BASE)})
        elif self.path == "/offer":
            offer = dict(OFFER_BASE)
            try:
                _sc_quote = settlement_charge_quote()
            except SettlementQuoteUnavailable:
                _sc_quote = {"status": SETTLEMENT_QUOTE_FAILURE}
            offer["service_view"] = {
                "served_by": "machine-economy-endpoint (BUILD-Q-13 proving build)",
                "identity": {"designation": CONFIG["identity"]["designation"],
                             "form": CONFIG["identity"]["form"],
                             "expansion": CONFIG["identity"]["expansion"],
                             "note": CONFIG["identity"]["note"],
                             "status": CONFIG["identity"]["status"]},
                "pricing_configuration": {
                    "active_mode": CONFIG["pricing"]["active_mode"],
                    "modes": CONFIG["pricing"]["modes"],
                    "fee_negotiable": CONFIG["pricing"]["fee_negotiable"],
                    "fee_paid_either_way": CONFIG["pricing"]["fee_paid_either_way"],
                    "fee_position": CONFIG["pricing"]["fee_position"],
                    "configured_tier_amounts": CONFIG["pricing"]["tiers"]},
                "signing": signing_state() +
                           " (intent signing is custody-grade; the endpoint holds no key material — signatures issue solely from the SKAP seal via the sign-under-seal operation)",
                "receptor": {"declaration": "8374@StegVerse.ai (BUILD-Q-17, SV-LLM/.github namespace/stegverse.ai/8374/DEFINITION.md)",
                             "scheme": X402_SCHEME, "network": X402_NETWORK,
                             "asset": X402_ASSET, "payTo": X402_PAYTO,
                             "status": SETTLEMENT.get("status"),
                             "tiers_micro_usdc": X402_TIERS_MICRO,
                             "settlement_charge": {
                                 "determination": "BUILD-Q-43 (2026-11-18): the tiers are the governance fee alone; settlement gas is an additional charge on the crossing, quoted at challenge time (see the offer's pricing.settlement_charge)",
                                 "live_quote": _sc_quote},
                             "payment_verification": "POST /crossing verifies x402 exact-scheme EIP-3009 payment authorizations cryptographically before evaluation (BUILD-Q-18); a failed verification is FAIL_CLOSED on the payment predicate with a refusal pair, distinct from a governed DENY",
                             "settlement": SETTLEMENT.get("settlement_note")},
                "metering": "1 receipt pair = 1 unit of compute, ALLOW or NON-ALLOW"}
            self._json(200, offer)
        elif self.path == "/openapi.json":
            self._json(200, openapi_document())
        elif self.path == "/.well-known/x402":
            self._json(200, wellknown_x402())
        elif self.path == "/.well-known/402index-verify.txt":
            # 402 Index domain-verification file (BUILD-Q-50 entry
            # push, 2026-11-18): serves the claim hash issued for
            # 8374.stegverse.org; content lives in the file beside
            # this module so the claim can rotate without a code edit.
            try:
                with open(os.path.join(BASE, "402index-verify.txt")) as f:
                    self._text(200, f.read().strip())
            except OSError:
                self._json(404, {"error": "not found"})
        elif self.path == "/replay":
            self._json(200, manifold_replay())
        elif self.path == "/crossing":
            # Discovery probes (directory validators, x402 clients)
            # ask the resource itself what payment it requires. A
            # GET carries no crossing body and no payment header, so
            # it receives the same 402 challenge an unpaid POST with
            # an empty body receives — default tier, no receipt,
            # nothing evaluated.
            self._challenge("receipt-only")
        else:
            self._json(404, {"error": "not found"})
    def do_HEAD(self):
        if self.path == "/crossing":
            try:
                total, quote = crossing_total_micro("receipt-only")
                b = json.dumps(
                    payment_requirements("receipt-only", total, quote),
                    indent=1).encode()
                v2h = _b64_json(
                    payment_required_v2("receipt-only", total, quote))
            except SettlementQuoteUnavailable:
                self.send_response(503)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            self.send_response(402)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(b)))
            self.send_header("PAYMENT-REQUIRED", v2h)
            self.end_headers()
        else:
            b = json.dumps({"error": "not found"}).encode()
            self.send_response(404)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(b)))
            self.end_headers()
    def do_POST(self):
        try:
            if self.path == "/crossing":
                self._crossing()
            elif self.path == "/sign":
                self._sign()
            elif self.path == "/seal":
                self._seal()
            elif self.path == "/sign-segment":
                self._sign_segment()
            elif self.path == "/settle-pair":
                self._settle_pair()
            else:
                self._json(404, {"error": "not found"})
        except Exception:
            self._json(500, {"error": "internal error",
                             "failure_code": "ENDPOINT_INTERNAL"})
    def _settle_pair(self):
        """Operator route (Gate 2 repair): re-submit the verified fee
        authorization of an earlier crossing pair whose settlement
        leg failed closed, and receipt the outcome as a SETTLEMENT
        pair referencing it (ReceiptChain.issue_settlement_pair).
        The authorization is read from the pair itself -- its payment
        evidence is self-contained -- and is never re-receipted as a
        payment: its nonce stands under the original pair only, and
        the settlement consumes it on-chain.

        Pair-first (BUILD-Q-45 migration): the route is also the
        sweep. POST {"sweep": true} attempts every PENDING pair on
        every chain and receipts the outcomes. For a single pair,
        the outcome is receipted only when it is terminal for now
        (SETTLED/SUBMITTED -> SETTLEMENT pair; terminal on-chain
        failure -> SETTLEMENT-FAILURE pair); a retryable failure
        leaves the pair PENDING and appends nothing."""
        req = self._body()
        if req.get("sweep") is True:
            results = sweep_pending_settlements()
            return self._json(200, {"sweep": True,
                                    "attempted": len(results),
                                    "results": results,
                                    "totals": CHAIN.totals()})
        pair_id = req.get("pair_id")
        chain, seg_dir, members = (find_pair_location(pair_id)
                                   if pair_id else (None, None, []))
        if not members:
            return self._json(404, {"error": f"pair not found: {pair_id}"})
        first = sorted(members, key=lambda c: c.get("index_in_pair", 0))[0]
        payment = first.get("payment")
        if not payment or not payment.get("signature"):
            return self._json(422, {
                "error": f"pair {pair_id} carries no submittable payment evidence"})
        if (first.get("settlement") or {}).get("status") == "SETTLED":
            return self._json(409, {
                "error": f"pair {pair_id} already settled at its crossing"})
        settled, failed, _p = _chain_settlement_index(seg_dir)
        if pair_id in settled:
            return self._json(409, {
                "error": f"pair {pair_id} already settled by an appended settlement pair"})
        if pair_id in failed:
            return self._json(409, {
                "error": f"pair {pair_id} settlement failed terminally "
                         f"({failed[pair_id].get('failure_code')}); "
                         "the failure stands receipted on the chain"})
        out = attempt_and_receipt(chain, pair_id, payment)
        if out is None:
            return self._json(409, {
                "error": f"pair {pair_id} settlement attempt already in flight"})
        chain_name = "parent" if seg_dir == SEG_DIR else \
            os.path.basename(seg_dir)
        bundle = retention_bundle(out["settlement_pair_id"], seg_dir,
                                  chain_name) \
            if out["settlement_pair_id"] else None
        self._json(200, {"pair_id": out["settlement_pair_id"],
                         "settles_pair_id": pair_id,
                         "settlement": out["settlement"],
                         "settlement_state": out["settlement_state"],
                         "retention_bundle": bundle})

    def _issue_parent(self, kind, crossing, disp, detail, payment,
                      settle_rec):
        """Issue a pair on the parent chain, guarding the chain-write
        step (BUILD-Q-45 repair): if the write fails after a
        SETTLED/SUBMITTED settlement, the on-chain fact is journaled
        and a named 500 is answered. Returns (pair_id, recs), or None
        when the failure response has already been written."""
        try:
            return CHAIN.issue_pair(kind, crossing, disp, detail,
                                    payment=payment,
                                    settlement=settle_rec)
        except Exception as e:
            self._chain_write_failure(crossing, disp, payment,
                                      settle_rec, e)
            return None

    def _chain_write_failure(self, crossing, disp, payment, settle_rec,
                             exc, pair_id=None):
        journaled = False
        if (settle_rec or {}).get("status") in ("SETTLED", "SUBMITTED"):
            journaled = journal_settlement(crossing, disp, payment,
                                           settle_rec, exc,
                                           pair_id=pair_id)
        self._json(500, {
            "error": "chain write failed",
            "disposition": "FAIL_CLOSED", "executed": False,
            "failure_code": "ENDPOINT_CHAIN_WRITE",
            "failed_predicate": "the crossing's receipt pair is written to the receipt chain",
            "required_evidence_or_repair": "endpoint chain-write repair; a settlement that reached the chain is journaled beside the segments for operator reconciliation",
            "settlement": settle_rec,
            "settlement_journaled": journaled})

    def _finish_settlement(self, chain, pair_id, payment,
                           provider_side, settle_rec):
        """Pair-first eventual leg for a just-issued pair: attempt
        settlement now (the RPC may or may not answer) and receipt
        the outcome as an appended record bound to the pair.
        Returns (response_settlement, settlement_state,
        settlement_pair_id). Provider-side pairs are never
        submitted: their state is NOT_SUBMITTED and the pair's
        withheld record is the response record."""
        if provider_side:
            return settle_rec, "NOT_SUBMITTED", None
        out = attempt_and_receipt(chain, pair_id, payment)
        if out is None:
            return settle_rec, "PENDING", None
        return (out["settlement"], out["settlement_state"],
                out["settlement_pair_id"])

    def _v2_response(self, payment, resp_settlement, settlement_state):
        """BUILD-Q-48: the v2 SettlementResponse for this crossing,
        carried in the PAYMENT-RESPONSE header of whichever response
        the crossing produces. Under pair-first, success is stated
        only when the settlement leg has actually SETTLED by
        response time; a PENDING leg is named, never implied."""
        if payment.get("x402_version") != 2:
            return
        _ok = settlement_state == "SETTLED"
        _sr = {"success": _ok,
               "transaction": (resp_settlement.get("tx_hash") or "")
               if _ok else "",
               "network": X402_NETWORK,
               "payer": payment.get("from"),
               "amount": str(payment.get("value_micro_usdc"))}
        if not _ok:
            _sr["errorReason"] = resp_settlement.get("failure_code") \
                or ("SETTLEMENT_PENDING"
                    if settlement_state == "PENDING"
                    else settlement_state)
        self._payment_response = _b64_json(_sr)

    def _crossing(self):
        # BUILD-Q-45 repair: the verify -> resolve -> settle -> issue
        # sequence runs under CROSSING_LOCK (see its definition).
        with CROSSING_LOCK:
            self._crossing_inner()

    def _crossing_inner(self):
        req = self._body()
        tier = req.get("tier", "receipt-only")
        if tier not in CONFIG["pricing"]["tiers"]:
            tier = "receipt-only"
        crossing = {"counterparty": req.get("counterparty"),
                    "action": req.get("action"),
                    "scope_ref": req.get("scope_ref"),
                    "resource": req.get("resource"),
                    "tier": tier}
        sublane = req.get("sublane")
        # x402 (BUILD-Q-18; v2 added BUILD-Q-48): payment
        # verification precedes evaluation. No payment header -> 402
        # with the dual-stack challenge, no receipt (nothing was
        # evaluated). A presented authorization that fails
        # verification -> FAIL_CLOSED on the payment predicate with a
        # refusal pair, distinct from a governed DENY. When both
        # headers are presented, PAYMENT-SIGNATURE (v2) governs.
        xpay = self.headers.get("X-PAYMENT")
        sig2 = self.headers.get("PAYMENT-SIGNATURE")
        if not xpay and not sig2:
            self._challenge(tier)
            return
        if sig2:
            payment, pay_detail = verify_x402_payment_v2(sig2, tier)
        else:
            payment, pay_detail = verify_x402_payment(xpay, tier)
        if payment is None:
            if sublane is not None:
                crossing["sublane"] = sublane
            pair_id, recs = CHAIN.issue_pair("REFUSAL", crossing,
                                             "FAIL_CLOSED", pay_detail)
            self._json(422, {"disposition": "FAIL_CLOSED", "executed": False,
                             **pay_detail,
                             "refusal_pair_id": pair_id,
                             "refusal_record_pair": recs,
                             "metering": {"unit": "1 receipt pair = 1 unit of compute",
                                          "totals": CHAIN.totals(),
                                          "identity_totals": identity_totals()}})
            return
        # Disposition resolution (BUILD-Q-45 repair, 2026-11-17).
        # Evaluation is pure, so the disposition is resolved BEFORE
        # any settlement submission: a provider-side failure during
        # resolution can then never follow a submitted settlement.
        # A resolution exception is a provider-caused FAIL_CLOSED --
        # a refusal pair WITHOUT the payment block, exactly like the
        # verification-failure path above: the authorization is not
        # submitted and is not consumed beyond the refusal record.
        try:
            if sublane is not None and not sublane_valid(sublane):
                disp, detail = ("FAIL_CLOSED",
                                sublane_invalid_detail(sublane))
            else:
                disp, detail = evaluate(req)
        except Exception:
            detail = six_field(
                "ENDPOINT_EVALUATION_ERROR",
                "the endpoint resolves the crossing's disposition from the presented request",
                "the endpoint's evaluation raised an internal error; the failure is the provider's -- no settlement was submitted and the authorization is unconsumed; retry the crossing",
                "POST /crossing (retry)", "endpoint repair")
            pair_id, recs = CHAIN.issue_pair("REFUSAL", crossing,
                                             "FAIL_CLOSED", detail)
            self._json(422, {"disposition": "FAIL_CLOSED",
                             "executed": False,
                             **detail,
                             "refusal_pair_id": pair_id,
                             "refusal_record_pair": recs,
                             "metering": {"unit": "1 receipt pair = 1 unit of compute",
                                          "totals": CHAIN.totals(),
                                          "identity_totals": identity_totals()}})
            return
        # Pair-first (BUILD-Q-45 migration): the pair is written
        # FIRST -- from the locally-decidable predicates alone
        # (signature recovery, receptor match, value, window,
        # evidence rules, and the nonce checked against the local
        # registry the receipt chain itself is) -- with
        # settlement_state PENDING, before any settlement RPC. A
        # crossing during a total egress outage therefore returns
        # its disposition and pair exactly as in normal operation.
        # Settlement is attempted afterwards as an eventual leg and
        # its outcome is receipted as an appended record bound to
        # the pair; it never alters the disposition resolved above.
        # Provider-caused FAIL_CLOSED dispositions
        # (PROVIDER_SIDE_FAIL_CODES) never submit settlement: the
        # fee is not collected for the provider's own failure, and
        # the pair carries the withheld record instead of PENDING.
        provider_side = disp == "FAIL_CLOSED" and \
            detail.get("failure_code") in PROVIDER_SIDE_FAIL_CODES
        if provider_side:
            settle_rec = settlement_withheld(payment, detail)
        else:
            settle_rec = pending_settlement_record(payment)
        if sublane is not None and not sublane_valid(sublane):
            # Manifold grammar failure: FAIL_CLOSED, refusal pair on the
            # PARENT chain, nothing created for the invalid name. The
            # verified payment is carried on the pair (mode (a): the fee
            # follows all dispositions).
            crossing["sublane"] = sublane
            issued = self._issue_parent("REFUSAL", crossing, "FAIL_CLOSED",
                                        detail, payment, settle_rec)
            if issued is None:
                return
            pair_id, recs = issued
            resp_settlement, settlement_state, settlement_pair_id = \
                self._finish_settlement(CHAIN, pair_id, payment,
                                        provider_side, settle_rec)
            self._v2_response(payment, resp_settlement, settlement_state)
            self._json_crossing(422, {"disposition": "FAIL_CLOSED", "executed": False,
                             **detail,
                             "payment": payment,
                             "settlement": resp_settlement,
                             "settlement_state": settlement_state,
                             "settlement_pair_id": settlement_pair_id,
                             "refusal_pair_id": pair_id,
                             "refusal_record_pair": recs,
                             "retention_bundle": retention_bundle(
                                 pair_id, SEG_DIR, "parent"),
                             "metering": {"unit": "1 receipt pair = 1 unit of compute",
                                          "totals": CHAIN.totals(),
                                          "identity_totals": identity_totals()}})
            return
        if sublane is None:
            if disp == "ALLOW":
                issued = self._issue_parent("RECEIPT", crossing, "ALLOW",
                                            None, payment, settle_rec)
                if issued is None:
                    return
                pair_id, recs = issued
                resp_settlement, settlement_state, settlement_pair_id = \
                    self._finish_settlement(CHAIN, pair_id, payment,
                                            provider_side, settle_rec)
                self._v2_response(payment, resp_settlement,
                                  settlement_state)
                self._json_crossing(200, {"disposition": "ALLOW", "executed": True,
                                 "pair_id": pair_id,
                                 "receipt_pair": recs,
                                 "retention_bundle": retention_bundle(
                                     pair_id, SEG_DIR, "parent"),
                                 "payment": payment,
                                 "settlement": resp_settlement,
                                 "settlement_state": settlement_state,
                                 "settlement_pair_id": settlement_pair_id,
                                 "pair_anchor_terminal": recs[1]["hash"],
                                 "metering": {"unit": "1 receipt pair = 1 unit of compute",
                                              "totals": CHAIN.totals()},
                                 "detail": detail})
            else:
                issued = self._issue_parent("REFUSAL", crossing, disp,
                                            detail, payment, settle_rec)
                if issued is None:
                    return
                pair_id, recs = issued
                resp_settlement, settlement_state, settlement_pair_id = \
                    self._finish_settlement(CHAIN, pair_id, payment,
                                            provider_side, settle_rec)
                self._v2_response(payment, resp_settlement,
                                  settlement_state)
                self._json_crossing(422, {"disposition": disp, "executed": False,
                                 **detail,
                                 "payment": payment,
                                 "settlement": resp_settlement,
                                 "settlement_state": settlement_state,
                                 "settlement_pair_id": settlement_pair_id,
                                 "refusal_pair_id": pair_id,
                                 "refusal_record_pair": recs,
                                 "retention_bundle": retention_bundle(
                                     pair_id, SEG_DIR, "parent"),
                                 "metering": {"unit": "1 receipt pair = 1 unit of compute",
                                              "totals": CHAIN.totals()}})
            return
        # Sub-lane crossing: receipts land on the sub-lane's own chain.
        # Pair-first (BUILD-Q-45 migration): the pair issues under
        # MANIFOLD_LOCK with settlement_state PENDING; the eventual
        # settlement leg runs after issuance, outside the lock, and
        # receipts its outcome on the same sub-lane chain. A chain
        # write failure at issuance is guarded like the parent path.
        crossing["sublane"] = sublane
        pair_id = None
        try:
            with MANIFOLD_LOCK:
                lane = get_lane(sublane)
                if disp == "ALLOW":
                    pair_id, recs = lane.chain.issue_pair("RECEIPT", crossing, "ALLOW",
                                                          payment=payment, settlement=settle_rec)
                    kind = "RECEIPT"
                else:
                    pair_id, recs = lane.chain.issue_pair("REFUSAL", crossing, disp,
                                                          detail, payment=payment, settlement=settle_rec)
                    kind = "REFUSAL"
                lane.open_pairs += 1
                sealed = None
                if lane.open_pairs >= SEGMENT_SIZE:
                    sealed = lane.seal_open_segment()
                _seal = None
                if sealed is not None:
                    _seal = {k: sealed[k] for k in (
                        "sublane", "segment_index", "terminal_anchor",
                        "entry_count", "pair_count", "prev_seal_digest",
                        "seal_digest")}
                bundle = retention_bundle(
                    pair_id, lane.dir, sublane, segment_seal=_seal)
                lane_totals = lane.chain.totals()
        except Exception as e:
            self._chain_write_failure(crossing, disp, payment,
                                      settle_rec, e, pair_id=pair_id)
            return
        resp_settlement, settlement_state, settlement_pair_id = \
            self._finish_settlement(lane.chain, pair_id, payment,
                                    provider_side, settle_rec)
        self._v2_response(payment, resp_settlement, settlement_state)
        body = {"disposition": disp, "executed": disp == "ALLOW",
                "sublane": sublane, "payment": payment,
                "settlement": resp_settlement,
                "settlement_state": settlement_state,
                "settlement_pair_id": settlement_pair_id,
                "metering": {"unit": "1 receipt pair = 1 unit of compute",
                             "totals": lane_totals,
                             "identity_totals": identity_totals()},
                "detail": detail}
        if kind == "RECEIPT":
            body.update({"pair_id": pair_id, "receipt_pair": recs,
                         "pair_anchor_terminal": recs[1]["hash"]})
        else:
            body.update({**detail, "refusal_pair_id": pair_id,
                         "refusal_record_pair": recs})
        if sealed is not None:
            body["segment_sealed"] = sealed
        body["retention_bundle"] = bundle
        self._json_crossing(200 if disp == "ALLOW" else 422, body)
    def _sign(self):
        """Custody signing route (BUILD-Q-14 wiring): forwards the signing
        request to the SKAP sign-under-seal operation and returns its
        result. This endpoint holds no key material. Operation ALLOW ->
        receipt pair here + the signature; operation non-ALLOW ->
        FAIL_CLOSED propagation carrying the operation's failed_predicate,
        plus a refusal pair here; operation unreachable -> FAIL_CLOSED
        SKAP_SIGNING_OPERATION_UNREACHABLE plus a refusal pair."""
        req = self._body()
        crossing = {"counterparty": req.get("counterparty"),
                    "action": "sign",
                    "scope_ref": req.get("scope_ref"),
                    "resource": req.get("resource"),
                    "tier": req.get("tier", "receipt-only"),
                    "signing_request": True,
                    "payload_digest": req.get("payload_digest")}
        op_req = {"identity": req.get("identity", CONFIG["identity"]["designation"]),
                  "payload_digest": req.get("payload_digest"),
                  "authorization_ref": req.get("authorization_ref"),
                  "requester": "machine-economy-endpoint"}
        try:
            r = urllib.request.Request(SIGNING_OP_URL + "/sign",
                                       data=json.dumps(op_req).encode(),
                                       headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(r, timeout=30) as resp:
                op = json.load(resp)
        except urllib.error.HTTPError as e:
            op = json.load(e)
            detail = {k: op.get(k) for k in
                      ("failure_code", "failed_predicate",
                       "required_evidence_or_repair", "retry_entrypoint",
                       "owning_goal", "next_attempt")}
            detail["operation_refusal_pair_id"] = op.get("refusal_pair_id")
            disp = op.get("disposition", "FAIL_CLOSED")
            pair_id, recs = CHAIN.issue_pair("REFUSAL", crossing, disp, detail)
            self._json(422, {"disposition": disp, "executed": False,
                             "signed": False, **detail,
                             "refusal_pair_id": pair_id,
                             "refusal_record_pair": recs,
                             "metering": {"unit": "1 receipt pair = 1 unit of compute",
                                          "totals": CHAIN.totals()}})
            return
        except Exception:
            detail = six_field(
                "SKAP_SIGNING_OPERATION_UNREACHABLE",
                "the SKAP sign-under-seal operation answers at " + SIGNING_OP_URL,
                "restore the skap-signing service (systemctl start skap-signing.service, or its install.sh after VM replacement)",
                "POST /sign after the operation is restored",
                "operation restoration")
            pair_id, recs = CHAIN.issue_pair("REFUSAL", crossing, "FAIL_CLOSED", detail)
            self._json(422, {"disposition": "FAIL_CLOSED", "executed": False,
                             "signed": False, **detail,
                             "refusal_pair_id": pair_id,
                             "refusal_record_pair": recs,
                             "metering": {"unit": "1 receipt pair = 1 unit of compute",
                                          "totals": CHAIN.totals()}})
            return
        crossing["signature_sha256"] = hashlib.sha256(
            bytes.fromhex(op["signature"])).hexdigest()
        crossing["public_address"] = op["public_address"]
        crossing["operation_pair_id"] = op["pair_id"]
        pair_id, recs = CHAIN.issue_pair("RECEIPT", crossing, "ALLOW")
        self._json(200, {"disposition": "ALLOW", "executed": True, "signed": True,
                         "signature": op["signature"],
                         "signature_format": op["signature_format"],
                         "public_address": op["public_address"],
                         "operation_pair_id": op["pair_id"],
                         "operation_receipt_pair": op["receipt_pair"],
                         "pair_id": pair_id,
                         "receipt_pair": recs,
                         "pair_anchor_terminal": recs[1]["hash"],
                         "metering": {"unit": "1 receipt pair = 1 unit of compute",
                                      "totals": CHAIN.totals()}})

    def _refuse_parent(self, crossing, detail, disp="FAIL_CLOSED"):
        """Issue a refusal pair for a manifold request on the parent chain
        and answer 422 with the six-field disposition."""
        pair_id, recs = CHAIN.issue_pair("REFUSAL", crossing, disp, detail)
        self._json(422, {"disposition": disp, "executed": False, **detail,
                         "refusal_pair_id": pair_id,
                         "refusal_record_pair": recs,
                         "metering": {"unit": "1 receipt pair = 1 unit of compute",
                                      "totals": CHAIN.totals(),
                                      "identity_totals": identity_totals()}})

    def _seal(self):
        """POST /seal {sublane}: seal the sub-lane's current open segment
        and fold the seal onto the parent chain as exactly one fold pair."""
        req = self._body()
        name = req.get("sublane")
        crossing = {"counterparty": req.get("counterparty"),
                    "action": "seal", "scope_ref": req.get("scope_ref"),
                    "sublane": name, "tier": "receipt-only"}
        if not sublane_valid(name):
            self._refuse_parent(crossing, sublane_invalid_detail(name))
            return
        with MANIFOLD_LOCK:
            lane = get_lane(name, create=False)
            if lane is None or lane.open_pairs == 0:
                detail = six_field(
                    "SEGMENT_EMPTY",
                    "the sub-lane's open segment holds at least one receipted crossing",
                    "submit crossings naming this sublane before sealing, or seal a sub-lane whose open segment is non-empty",
                    "POST /seal for a sub-lane with an open non-empty segment",
                    "caller submits crossings first", owning=OWNING_GOAL_Q15)
                self._refuse_parent(crossing, detail)
                return
            seg = lane.seal_open_segment()
            self._json(200, {"disposition": "ALLOW", "sealed": True,
                             "sublane": name,
                             "segment_index": seg["segment_index"],
                             "seal": seg,
                             "fold_pair_id": seg["fold_pair_id"],
                             "metering": {"unit": "1 receipt pair = 1 unit of compute",
                                          "totals": CHAIN.totals(),
                                          "identity_totals": identity_totals()}})

    def _sign_segment(self):
        """POST /sign-segment {sublane, segment_index, authorization_ref}:
        custody amortization (BUILD-Q-15). The endpoint recomputes the
        seal digest from its own sub-lane chain — never accepting a
        caller-supplied digest — submits THAT digest to the SKAP
        sign-under-seal operation under the admitted authorization, and
        records the returned signature on the parent chain as a signature
        pair bound to the seal's fold entry. One governed retrieval now
        covers the whole segment instead of one crossing."""
        req = self._body()
        name = req.get("sublane")
        idx = req.get("segment_index")
        crossing = {"counterparty": req.get("counterparty"),
                    "action": "sign-segment",
                    "scope_ref": req.get("scope_ref"),
                    "sublane": name, "segment_index": idx,
                    "tier": "receipt-only", "signing_request": True}
        if not sublane_valid(name):
            self._refuse_parent(crossing, sublane_invalid_detail(name))
            return
        with MANIFOLD_LOCK:
            lane = get_lane(name, create=False)
            seg = None
            if lane is not None and isinstance(idx, int) \
                    and 0 <= idx < len(lane.segments):
                seg = lane.segments[idx]
            if seg is None:
                detail = six_field(
                    "SEGMENT_NOT_SEALED",
                    "the named sub-lane segment is sealed (its fold entry stands on the parent chain)",
                    "seal the segment first (POST /seal), then sign its anchor",
                    "POST /sign-segment for a sealed segment",
                    "caller seals the segment first", owning=OWNING_GOAL_Q15)
                self._refuse_parent(crossing, detail)
                return
            seal_digest = lane.recompute_seal_digest(idx)
            if seal_digest is None or seal_digest != seg["seal_digest"]:
                detail = six_field(
                    "SEAL_DIGEST_MISMATCH",
                    "the seal digest recomputed from the sub-lane chain equals the digest recorded in the fold entry",
                    "the sub-lane chain and the parent fold disagree; reconcile the chains from the segment files before signing",
                    "POST /sign-segment after chain reconciliation",
                    "chain reconciliation", owning=OWNING_GOAL_Q15)
                self._refuse_parent(crossing, detail)
                return
            op_req = {"identity": CONFIG["identity"]["designation"],
                      "payload_digest": seal_digest,
                      "authorization_ref": req.get("authorization_ref"),
                      "requester": "machine-economy-endpoint"}
            try:
                r = urllib.request.Request(SIGNING_OP_URL + "/sign",
                                           data=json.dumps(op_req).encode(),
                                           headers={"Content-Type": "application/json"})
                with urllib.request.urlopen(r, timeout=30) as resp:
                    op = json.load(resp)
            except urllib.error.HTTPError as e:
                op = json.load(e)
                detail = {k: op.get(k) for k in
                          ("failure_code", "failed_predicate",
                           "required_evidence_or_repair", "retry_entrypoint",
                           "owning_goal", "next_attempt")}
                detail["operation_refusal_pair_id"] = op.get("refusal_pair_id")
                self._refuse_parent(crossing, detail,
                                    op.get("disposition", "FAIL_CLOSED"))
                return
            except Exception:
                detail = six_field(
                    "SKAP_SIGNING_OPERATION_UNREACHABLE",
                    "the SKAP sign-under-seal operation answers at " + SIGNING_OP_URL,
                    "restore the skap-signing service (systemctl start skap-signing.service, or its install.sh after VM replacement)",
                    "POST /sign-segment after the operation is restored",
                    "operation restoration")
                self._refuse_parent(crossing, detail)
                return
            record = {"sublane": name, "segment_index": idx,
                      "seal_digest": seal_digest,
                      "fold_pair_id": seg["fold_pair_id"],
                      "signature": op["signature"],
                      "signature_format": op["signature_format"],
                      "signature_sha256": hashlib.sha256(
                          bytes.fromhex(op["signature"])).hexdigest(),
                      "public_address": op["public_address"],
                      "operation_pair_id": op["pair_id"]}
            pair_id, recs = CHAIN.issue_signature_pair(record)
            seg["signed"] = True
            seg["signature_pair_id"] = pair_id
            self._json(200, {"disposition": "ALLOW", "executed": True,
                             "signed": True, "sublane": name,
                             "segment_index": idx, "seal_digest": seal_digest,
                             "fold_pair_id": seg["fold_pair_id"],
                             "signature": op["signature"],
                             "signature_format": op["signature_format"],
                             "public_address": op["public_address"],
                             "operation_pair_id": op["pair_id"],
                             "operation_receipt_pair": op["receipt_pair"],
                             "pair_id": pair_id, "receipt_pair": recs,
                             "pair_anchor_terminal": recs[1]["hash"],
                             "metering": {"unit": "1 receipt pair = 1 unit of compute",
                                          "totals": CHAIN.totals(),
                                          "identity_totals": identity_totals()}})

if __name__ == "__main__":
    print(f"machine-economy-endpoint on 127.0.0.1:{PORT}, identity "
          f"{CONFIG['identity']['form']}, signing: {signing_state()}, "
          f"chain: {CHAIN.totals()}")
    # Pair-first eventual leg (BUILD-Q-45): the background sweep
    # retries PENDING settlements; the operator route POST
    # /settle-pair {"sweep": true} runs the same sweep on demand.
    threading.Thread(target=_settlement_sweeper, daemon=True,
                     name="settlement-sweeper").start()
    ThreadingHTTPServer(("127.0.0.1", PORT), H).serve_forever()
