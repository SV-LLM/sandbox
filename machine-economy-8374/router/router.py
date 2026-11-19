#!/usr/bin/env python3
"""8374 router layer v1 — relay + settle third-party crossings
(ROUTER-V1, off-production candidate).

The router/index layer for the x402 machine economy with NO
middleman pricing, built under the principal's direction of
2026-11-19 ("Build it — relay + settle third-party crossings"):

  - Sellers register FREE and self-serve (POST /router/register):
    the router crawls the origin's /.well-known/x402 and
    /openapi.json, enumerates its paid resources, and probes one
    live 402 challenge per resource to record its terms. No
    listing fee, no account, no review queue, no "proven seller"
    gate — provenance is the replayable receipt chain, recomputed,
    never granted.
  - Buyers route calls through it (POST /router/route). Every
    routed call is a governed crossing under 8374: evaluated at
    the boundary (production evaluation + evidence rules), the
    disposition resolves FIRST (ALLOW / DENY / FAIL_CLOSED), and
    only on ALLOW is anything relayed or settled — the ordering
    defect found and cured in production (settlement attempted
    before evaluation) is preserved as cured here. On NON-ALLOW:
    the pair issues, no payment is relayed, no settlement is
    attempted.
  - Posture: relay + settle, NON-CUSTODIAL. The router relays
    buyer-signed EIP-3009 authorizations to the seller; it never
    accepts, stores, or generates buyer/seller private keys. In
    settle mode our gas-only relayer additionally submits the
    buyer→seller transferWithAuthorization on-chain (and the fee
    leg to 8374's payTo), charging the posted settlement charge —
    live-quoted gas, charged, never absorbed.
  - Pair-first (BUILD-Q-45 semantics): the receipt pair is born
    with settlement_state PENDING before any settlement RPC;
    settlement is an eventual leg whose outcome is receipted as
    an appended record bound to the pair (SETTLEMENT pair on
    success, SETTLEMENT-FAILURE pair on terminal on-chain
    failure); the pair's disposition never changes.
  - 8374's only take is the posted crossing fee (offer v07):
    receipt-only $0.0005, full evaluation (ME-EVAL-01) $0.015,
    plus the live-quoted settlement charge. Total = fee + charge.
    No percentage skim.
  - Routing name 8374.@router — a NAME (routing), not an
    identity; signing resolves to 8374's one SKAP specimen via
    the production signing-service pattern. This service holds
    no identity keys: its only key is a gas-only relayer key
    (dust ETH, no USDC), exactly the production Gate 2 pattern.
  - 8374's own origin is self-registered at startup (listed by
    construction); its catalog provenance carries the live pair
    count, terminal anchor, and replay verdict read READ-ONLY
    from the production chain files.
  - The router PUBLISHES its registry as a Bazaar-format
    discovery feed (GET /router/discovery/resources, the CDP
    discovery schema — items + pagination, generated live from
    the registry): as a facilitator (relay + settle) it is a
    source aggregators ingest, not only a service they admit.
    Fields the registry does not know are omitted, never
    fabricated; a seller's extensions.bazaar block is mirrored
    verbatim from its own 402 challenge when it declares one.

The chain, replay, evaluation, quote, and settlement-outcome
constructions are vendored from the production endpoint
(machine-economy-endpoint/endpoint.py, BUILD-Q-13/18/43/45;
settlement.py, Gate 2) and adapted to the router's own receipts
dir — the router NEVER writes to production's chain. Stdlib
only. Binds localhost.

State (all inside the router's own dir, overridable by env):
  ROUTER_CONFIG_PATH  config JSON (default ./router_config.json)
  ROUTER_RECEIPTS_DIR receipt segments (default ./receipts)
  ROUTER_REGISTRY_PATH registry JSON (default ./registry.json)
  ROUTER_PORT         listen port (default config port / 8797)
"""
import base64, hashlib, json, os, re, threading, time
import urllib.error, urllib.parse, urllib.request
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import settlement as settle_mod
import x402kit

BASE = os.path.dirname(os.path.abspath(__file__))
STATE_DIR = os.environ.get("ROUTER_DIR", BASE)
CONFIG_PATH = os.environ.get(
    "ROUTER_CONFIG_PATH", os.path.join(STATE_DIR, "router_config.json"))
CONFIG = json.load(open(CONFIG_PATH))
SEG_DIR = os.environ.get(
    "ROUTER_RECEIPTS_DIR", os.path.join(STATE_DIR, "receipts"))
REGISTRY_PATH = os.environ.get(
    "ROUTER_REGISTRY_PATH", os.path.join(STATE_DIR, "registry.json"))
PORT = int(os.environ.get("ROUTER_PORT", str(CONFIG.get("port", 8797))))
SEGMENT_MAX = 500
os.makedirs(SEG_DIR, exist_ok=True)

OWNING_GOAL = "MACHINE-ECONOMY-ENTRY-01 / ROUTER-V1"
ROUTING_NAME = CONFIG.get("routing_name", "8374.@router")
IDENTITY = CONFIG.get("identity", "8374@StegVerse.ai")
X402_NETWORK = CONFIG.get("network", "eip155:8453")
X402_ASSET = CONFIG.get("asset", x402kit.USDC_BASE)
X402_SCHEME = CONFIG.get("scheme", "exact")
ROUTER_PAYTO = CONFIG["payTo"]
TIERS_MICRO = {k: int(v) for k, v in
               CONFIG.get("tiers_micro_usdc",
                          {"receipt-only": 500,
                           "full-evaluation": 15000}).items()}
CURRENT_POLICY = CONFIG.get("current_policy", "ME-POLICY-01")
SETTLE_CFG = dict(CONFIG.get("settlement", {}))
SETTLE_CFG.setdefault("enabled", True)
SETTLE_CFG.setdefault("mode", "self-relayer")
SETTLE_CFG.setdefault("build", "ROUTER-V1")
# The relayer key path resolves against the router's own state dir.
if not os.path.isabs(SETTLE_CFG.get("relayer_key_file", "")):
    SETTLE_CFG["relayer_key_file"] = os.path.join(
        STATE_DIR, SETTLE_CFG.get("relayer_key_file",
                                  "router_relayer.json"))
SELF_ORIGIN = CONFIG.get("self_origin", "https://8374.stegverse.org")

# Scope registry: production's admitted set (scopes.json,
# BUILD-Q-13/49), carried verbatim — scopes are admitted by
# governed act; the router admits no scopes of its own.
SCOPES = {
    "ME-AGREE-01": {"actions": ["record-agreement"], "standing": True},
    "ME-DISSOLVED-01": {"actions": ["evaluate", "issue-receipt-pair"],
                        "standing": False},
    "ME-EVAL-01": {"actions": ["evaluate", "issue-receipt-pair"],
                   "standing": True},
}

# Serializes the route sequence verify -> resolve -> relay ->
# settle -> receipt outcomes (the production CROSSING_LOCK
# pattern): the nonce registry is read at verification and
# written at pair issuance.
ROUTE_LOCK = threading.Lock()


def now():
    return datetime.now(timezone.utc).isoformat()


def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


def digest(prev, content):
    return hashlib.sha256(prev.encode() + canonical(content)).hexdigest()


def _fsync_dir(d):
    fd = os.open(d, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _scan_segment(path):
    """(entries, torn_bytes) — production construction (BUILD-Q-16)."""
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
                        f"{os.path.basename(path)}: undecodable line "
                        f"inside the sealed span at byte {pos}")
                break
        pos = nl + 1
    return entries, torn


def read_entries(seg_dir):
    out = []
    for n in sorted(os.listdir(seg_dir)):
        if n.startswith("segment-") and n.endswith(".jsonl"):
            entries, _torn = _scan_segment(os.path.join(seg_dir, n))
            out.extend(entries)
    return out


# ---------------- receipt chain (vendored from production) ----------------
class ReceiptChain:
    """Each receipt: {i, prev, content, hash}; hash = SHA256(prev ||
    canonical(content)). Pairs occupy two consecutive entries.
    The router's own chain, in the router's own receipts dir."""

    RECORDED_BY = "8374.@router (StegVerse LLC)"

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
                    f"{os.path.basename(path)}: torn tail ({torn} "
                    "bytes) in a sealed segment with no recovery record")
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
                    if c.get("pair_class", "EVALUATION") in (
                            "EVALUATION", "SIGNATURE"):
                        self.units += 1
                    d = c.get("disposition")
                    if d in self.by_disp:
                        self.by_disp[d] += 1
            if si == len(segs) - 1:
                last_torn, last_path = torn, path
        if last_torn and last_path is not None:
            self._recover_torn_tail(last_path, last_torn)

    def _recover_torn_tail(self, path, torn_bytes):
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
                          "recorded_by": self.RECORDED_BY})
        self._append({**base_c, "kind": "RECOVERY_ANCHOR",
                      "index_in_pair": 1, "side": "chain",
                      "recorded_by": self.RECORDED_BY,
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

    def issue_pair(self, kind, crossing, disposition,
                   disposition_detail=None, payment=None,
                   route_payment=None, settlement=None, route=None):
        """Issue exactly one pair for one resolved routed crossing.
        kind: 'RECEIPT' (ALLOW) or 'REFUSAL' (non-ALLOW). payment is
        the verified 8374 fee-leg evidence; route_payment the
        verified buyer→seller authorization evidence. Both ride
        both pair members identically (production pattern)."""
        with self.lock:
            self.pair_seq += 1
            pair_id = f"PAIR-{self.pair_seq:06d}"
            base = {"pair_id": pair_id, "pair_class": "EVALUATION",
                    "crossing": crossing, "disposition": disposition,
                    "ts": now(), "router": ROUTING_NAME}
            if payment is not None:
                base["payment"] = payment
            if route_payment is not None:
                base["route_payment"] = route_payment
            if settlement is not None:
                base["settlement"] = settlement
            if route is not None:
                base["route"] = route
            if kind == "RECEIPT":
                a_content = {**base, "kind": "RECEIPT_ROUTER_SIDE",
                             "index_in_pair": 0, "side": "router",
                             "recorded_by": self.RECORDED_BY}
                a = self._append(a_content)
                b_content = {**base, "kind": "RECEIPT_COUNTERPARTY_SIDE",
                             "index_in_pair": 1, "side": "counterparty",
                             "recorded_by": crossing.get("counterparty"),
                             "pair_anchor": a["hash"]}
                b = self._append(b_content)
            else:
                a_content = {**base, "kind": "REFUSAL_ATTEMPT",
                             "index_in_pair": 0, "side": "attempt",
                             "recorded_by": self.RECORDED_BY,
                             "executed": False}
                a = self._append(a_content)
                b_content = {**base, "kind": "REFUSAL_DISPOSITION",
                             "index_in_pair": 1, "side": "disposition",
                             "recorded_by": self.RECORDED_BY,
                             "pair_anchor": a["hash"], "executed": False,
                             "disposition_detail": disposition_detail or {}}
                b = self._append(b_content)
            self.pairs += 1
            self.units += 1
            if disposition in self.by_disp:
                self.by_disp[disposition] += 1
            return pair_id, [a, b]

    def issue_settlement_pair(self, settlement_record, settles_pair_id):
        """Append a SETTLEMENT pair: the settlement outcome for an
        earlier EVALUATION pair. Structural: counts as a pair, NOT
        a unit of compute; carries no payment block (the nonce
        stands under the original pair only). Production pattern."""
        with self.lock:
            self.pair_seq += 1
            pair_id = f"PAIR-{self.pair_seq:06d}"
            base = {"pair_id": pair_id, "pair_class": "SETTLEMENT",
                    "disposition": "SETTLEMENT_RESUBMISSION",
                    "ts": now(), "settles_pair_id": settles_pair_id,
                    "settlement": settlement_record,
                    "router": ROUTING_NAME}
            a = self._append({**base, "kind": "SETTLEMENT_ROUTER_SIDE",
                              "index_in_pair": 0, "side": "router",
                              "recorded_by": self.RECORDED_BY})
            b = self._append({**base, "kind": "SETTLEMENT_PARENT_ANCHOR",
                              "index_in_pair": 1, "side": "parent_anchor",
                              "recorded_by": self.RECORDED_BY,
                              "pair_anchor": a["hash"]})
            self.pairs += 1
            return pair_id, [a, b]

    def issue_settlement_failure_pair(self, settlement_record,
                                      settles_pair_id):
        """Append a SETTLEMENT-FAILURE pair: the terminal on-chain
        failure of an earlier pair's settlement leg. Appended,
        never a rewrite. Production pattern (BUILD-Q-45)."""
        with self.lock:
            self.pair_seq += 1
            pair_id = f"PAIR-{self.pair_seq:06d}"
            base = {"pair_id": pair_id, "pair_class": "SETTLEMENT",
                    "disposition": "SETTLEMENT_FAILED",
                    "ts": now(), "settles_pair_id": settles_pair_id,
                    "settlement": settlement_record,
                    "router": ROUTING_NAME}
            a = self._append(
                {**base, "kind": "SETTLEMENT_FAILURE_ROUTER_SIDE",
                 "index_in_pair": 0, "side": "router",
                 "recorded_by": self.RECORDED_BY})
            b = self._append(
                {**base, "kind": "SETTLEMENT_FAILURE_PARENT_ANCHOR",
                 "index_in_pair": 1, "side": "parent_anchor",
                 "recorded_by": self.RECORDED_BY,
                 "pair_anchor": a["hash"]})
            self.pairs += 1
            return pair_id, [a, b]

    def issue_route_pair(self, route_record, route_for_pair_id,
                         disposition):
        """Append a ROUTE pair: the delivery outcome of an ALLOW
        pair's relay leg (delivered / failed / ambiguous). The
        pair's disposition never changes; this pair is the route
        outcome bound to it. Structural: counts as a pair, NOT a
        unit of compute, carries no payment block."""
        with self.lock:
            self.pair_seq += 1
            pair_id = f"PAIR-{self.pair_seq:06d}"
            base = {"pair_id": pair_id, "pair_class": "ROUTE",
                    "disposition": disposition, "ts": now(),
                    "route_for_pair_id": route_for_pair_id,
                    "route": route_record, "router": ROUTING_NAME}
            a = self._append({**base, "kind": "ROUTE_ROUTER_SIDE",
                              "index_in_pair": 0, "side": "router",
                              "recorded_by": self.RECORDED_BY})
            b = self._append({**base, "kind": "ROUTE_PARENT_ANCHOR",
                              "index_in_pair": 1, "side": "parent_anchor",
                              "recorded_by": self.RECORDED_BY,
                              "pair_anchor": a["hash"]})
            self.pairs += 1
            return pair_id, [a, b]

    def totals(self):
        return {"receipt_pairs": self.pairs,
                "units_of_compute": self.units,
                "by_disposition": dict(self.by_disp),
                "chain_entries": self.i,
                "terminal_anchor": self.prev}


CHAIN = ReceiptChain(SEG_DIR)


def replay(seg_dir=SEG_DIR):
    """Recompute the router chain from its segment files and
    verify: hashes, linkage, pair matching, and payment-nonce
    single-use across BOTH payment blocks (fee leg 'payment' and
    seller leg 'route_payment'). Production replay construction."""
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
            if c.get("pair_class") == "RECOVERY" \
                    and c.get("index_in_pair") == 0:
                recovery_records.append(c.get("recovery") or {})
        per_file.append((n, torn, file_anchor, last_meta))
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
    nonce_owner = {}
    for pid, members in pairs.items():
        for c in members:
            for key in ("payment", "route_payment"):
                pay = c.get(key)
                if pay and pay.get("nonce"):
                    nonce = str(pay["nonce"]).lower()
                    owner = nonce_owner.setdefault(nonce, pid)
                    if owner != pid:
                        problems.append(
                            f"payment nonce {nonce} recorded under two "
                            f"pairs ({owner} and {pid}): authorization "
                            "replayed")
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
    return {"verdict": verdict, "entries": i, "pairs": len(pairs),
            "terminal_anchor": prev, "problems": problems,
            "torn_tail": torn_tail, "recovered_tails": recovered_tails}


def used_payment_nonces():
    """Every payment nonce already receipted on the router chain
    (fee legs and seller legs) — the chain is the nonce registry
    (production construction)."""
    nonces = set()
    for r in read_entries(SEG_DIR):
        for key in ("payment", "route_payment"):
            pay = r["content"].get(key)
            if pay and pay.get("nonce"):
                nonces.add(str(pay["nonce"]).lower())
    return nonces


# ---------------- production provenance (READ-ONLY) ----------------
def production_provenance():
    """8374's provenance, recomputed from the production chain
    FILES (read-only — this function opens segment files 'rb' and
    never writes): pair count, entry count, terminal anchor, and
    the replay verdict recomputed over the stored records."""
    seg_dir = CONFIG.get("production_receipts_dir")
    if not seg_dir or not os.path.isdir(seg_dir):
        return {"status": "UNAVAILABLE",
                "reason": "production receipts dir not configured/readable"}
    prev = "GENESIS"
    i = 0
    pairs = set()
    problems = []
    for n in sorted(os.listdir(seg_dir)):
        if not (n.startswith("segment-") and n.endswith(".jsonl")):
            continue
        entries, torn = _scan_segment(os.path.join(seg_dir, n))
        for r in entries:
            i += 1
            if r["prev"] != prev:
                problems.append(f"entry {i}: prev linkage broken")
            if digest(r["prev"], r["content"]) != r["hash"]:
                problems.append(f"entry {i}: hash does not recompute")
            prev = r["hash"]
            pairs.add(r["content"].get("pair_id"))
    return {"status": "RECOMPUTED",
            "source": "production receipt chain files (read-only)",
            "pairs": len(pairs), "entries": i,
            "terminal_anchor": prev,
            "replay_verdict": "MATCH" if not problems else "MISMATCH",
            "problems": problems[:5]}


# ---------------- six-field dispositions + evaluation ----------------
def six_field(failure_code, failed_predicate, repair, retry, next_attempt,
              owning=OWNING_GOAL):
    return {"failure_code": failure_code,
            "failed_predicate": failed_predicate,
            "required_evidence_or_repair": repair,
            "retry_entrypoint": retry,
            "owning_goal": owning,
            "next_attempt": next_attempt}


def evaluate(req):
    """Production evaluation (BUILD-Q-13 S3 conjuncts), carried
    verbatim in substance: scope admission, standing, action in
    scope, custody slot, and (full-evaluation tier) the commit-time
    record conjuncts — including KNOWN_EVIDENCE_MISSING."""
    cp = req.get("counterparty")
    action = req.get("action")
    scope_ref = req.get("scope_ref")
    tier = req.get("tier", "receipt-only")
    if not cp or not action or not scope_ref:
        return "FAIL_CLOSED", six_field(
            "REQUEST_FIELDS_MISSING",
            "the crossing request names counterparty, action, and scope_ref",
            "present counterparty, action, and scope_ref in the crossing request",
            "POST /router/route with the complete request",
            "caller correction")
    if tier not in TIERS_MICRO:
        return "FAIL_CLOSED", six_field(
            "TIER_NOT_OFFERED",
            "the requested evaluation tier is an offered tier",
            "request tier 'receipt-only' or 'full-evaluation'",
            "POST /router/route with an offered tier", "caller correction")
    scope = SCOPES.get(scope_ref)
    if scope is None:
        return "DENY", six_field(
            "SCOPE_NOT_ADMITTED",
            "the proposed transition is within an admitted scope (scope_ref names an admitted scope)",
            "present a scope_ref admitted in the scope registry, or seek admission of the scope as a governed act",
            "POST /router/route with an admitted scope_ref",
            "caller correction")
    if not scope.get("standing"):
        return "FAIL_CLOSED", six_field(
            "NO_STANDING_RECEIVER",
            "the scope's receiver stands (is not dissolved)",
            "the scope's receiver must be re-instantiated by a governed act before crossings resume",
            "POST /router/route after the receiver is re-instantiated",
            "scope owner re-instantiation")
    if action not in scope["actions"]:
        return "DENY", six_field(
            "ACTION_NOT_IN_SCOPE",
            "the proposed action is within the admitted scope's actions",
            f"request one of the scope's admitted actions: {scope['actions']}",
            "POST /router/route with an admitted action",
            "caller correction")
    if req.get("requires_signature") or action in ("sign", "settle"):
        d = six_field(
            "CUSTODY_SIGNING_REQUIRED",
            "signing is performed only through the dedicated custody operation, never embedded in a crossing evaluation",
            "submit the signing request to the dedicated signing route with the admitted authorization record; the SKAP sign-under-seal operation performs it under governed retrieval",
            "the dedicated signing route",
            "caller submits via the dedicated signing route")
        d["note"] = ("evaluation and receipting proceed without signing; "
                     "settlement/signing is the custody slot and fails closed")
        return "FAIL_CLOSED", d
    if tier == "full-evaluation":
        ev = req.get("evidence")
        if not isinstance(ev, dict):
            return "FAIL_CLOSED", six_field(
                "KNOWN_EVIDENCE_MISSING",
                "the commit-time record is presented for full evaluation",
                "present the evidence object: authority, delegation, evidence_refs, exclusions, policy, validity_at_commit",
                "POST /router/route with the evidence object",
                "caller correction")
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
                return "FAIL_CLOSED", six_field(
                    code, pred, repair,
                    "POST /router/route with the repaired evidence object",
                    "caller correction")
        if "exclusions" not in ev:
            return "FAIL_CLOSED", six_field(
                "EXCLUSIONS_NOT_STATED",
                "material exclusions, with their reasons, are stated at commit time",
                "present evidence.exclusions (an empty list is a statement; absence is not)",
                "POST /router/route with the repaired evidence object",
                "caller correction")
        if ev.get("policy") != CURRENT_POLICY:
            return "FAIL_CLOSED", six_field(
                "POLICY_NOT_CURRENT",
                "policy identity and version are current at commit time",
                f"present evidence.policy = {CURRENT_POLICY}",
                "POST /router/route under the current policy",
                "caller correction")
        if ev.get("validity_at_commit") is not True:
            return "FAIL_CLOSED", six_field(
                "COMMIT_TIME_VALIDITY_NOT_ESTABLISHED",
                "validity was evaluated at commit time, not inferred later",
                "present evidence.validity_at_commit = true, established at commit time",
                "POST /router/route with commit-time validity established",
                "caller correction")
    return "ALLOW", {"tier": tier, "scope_ref": scope_ref,
                     "note": "admissible on the record as presented; "
                             "relay and receipt-pair issuance proceed"}


# ---------------- settlement charge quote (BUILD-Q-43 / offer v07) --------
SETTLEMENT_GAS_UNITS_BASIS = 86679
SETTLEMENT_QUOTE_TTL_SECONDS = 45
SETTLEMENT_QUOTE_FAILURE = "SETTLEMENT_CHARGE_QUOTE_UNAVAILABLE"
_quote_cache = {"at": 0.0, "quote": None}
_quote_lock = threading.Lock()
_QUOTE_CACHE_FILE = os.path.join(STATE_DIR, "router-quote-cache.json")


class SettlementQuoteUnavailable(Exception):
    pass


def _eth_usd_spot():
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


def _persist_quote(quote):
    try:
        with open(_QUOTE_CACHE_FILE, "w") as f:
            json.dump(quote, f, sort_keys=True)
            f.flush()
            os.fsync(f.fileno())
    except Exception:
        pass


def _serve_stale_quote(reason):
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
    """charge = ceil(86679 * max_fee_per_gas * eth_usd / 1e18)
    micro-USDC, max_fee = 2*pending baseFee + priority — the
    production formula, live-quoted; stale quote served under
    outage; fails closed only when no quote has ever been
    obtained (gas is never silently absorbed)."""
    now_ts = time.time()
    with _quote_lock:
        q = _quote_cache["quote"]
        if q is not None and now_ts - _quote_cache["at"] \
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
             "quoted_at_unix": int(now_ts),
             "quote_stale": False,
             "quote_ttl_seconds": SETTLEMENT_QUOTE_TTL_SECONDS,
             "formula": "ceil(gas_units_basis * (2*base_fee_per_gas + "
                        "priority_fee_per_gas) * eth_usd / 1e18, "
                        "to the next micro-USDC)"}
    with _quote_lock:
        _quote_cache["at"] = now_ts
        _quote_cache["quote"] = quote
    _persist_quote(quote)
    return quote


def fee_total_micro(tier):
    """(total, quote): the exact amount a buyer authorizes to
    8374 for this routed crossing = the tier's governance fee +
    the settlement charge quoted now."""
    quote = settlement_charge_quote()
    return TIERS_MICRO[tier] + quote["settlement_charge_micro_usdc"], quote


def _quote_fail_detail():
    return six_field(
        SETTLEMENT_QUOTE_FAILURE,
        "a live settlement-charge quote (Base fee basis + ETH/USD) "
        "is available before a routed crossing is priced",
        "the settlement charge is never absorbed silently "
        "(principal determination, 2026-11-18, BUILD-Q-43): retry "
        "the crossing when the Base RPC / ETH-USD reads recover",
        "POST /router/route (retry)",
        "caller retries the crossing; no authorization was consumed")


# ---------------- pair-first settlement outcome machinery ----------------
SETTLEMENT_TERMINAL_CODES = {"SETTLEMENT_SIMULATION_REVERTED",
                             "SETTLEMENT_REVERTED_ONCHAIN"}
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
    return {"build": SETTLE_CFG.get("build", "ROUTER-V1"),
            "mode": SETTLE_CFG.get("mode", "self-relayer"),
            "attempted": False, "status": "PENDING",
            "settlement_state": "PENDING",
            "asset": payment.get("asset"), "payTo": payment.get("payTo"),
            "value_micro_usdc": payment.get("value_micro_usdc"),
            "nonce": payment.get("nonce"),
            "note": "pair-first (BUILD-Q-45): this pair was written "
                    "before any settlement submission; settlement is "
                    "an eventual leg and its outcome is receipted as "
                    "an appended settlement record bound to this pair"}


def settlement_withheld_record(payment, detail, leg):
    """The settlement record for a NON-ALLOW routed crossing: no
    settlement is attempted, no payment relayed — the disposition
    resolved first and nothing moved."""
    return {"build": SETTLE_CFG.get("build", "ROUTER-V1"),
            "mode": SETTLE_CFG.get("mode", "self-relayer"),
            "attempted": False, "status": "NOT_SUBMITTED",
            "settlement_state": "NOT_SUBMITTED",
            "failure_code": "SETTLEMENT_WITHHELD_NON_ALLOW_DISPOSITION",
            "failed_predicate":
                "settlement is submitted only on ALLOW; this "
                "crossing resolved " + str(detail.get("failure_code")),
            "owning_goal": OWNING_GOAL,
            "disposition_failure_code": detail.get("failure_code"),
            "leg": leg,
            "asset": payment.get("asset") if payment else None,
            "payTo": payment.get("payTo") if payment else None,
            "value_micro_usdc":
                payment.get("value_micro_usdc") if payment else None,
            "nonce": payment.get("nonce") if payment else None,
            "note": "the authorization was not relayed and not "
                    "submitted on-chain"}


def _confirm_terminal_onchain(payment):
    """Production construction: a simulation revert is terminal
    only when chain state itself says the authorization can never
    settle (nonce consumed, or payer balance below the value).
    Returns an evidence dict when terminal, else None — including
    when the read fails: unprovable is not terminal."""
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


def attempt_and_receipt(chain, pair_id, payment):
    """One settlement attempt for a PENDING leg, its outcome
    receipted on the router chain (production construction).
    Returns {settlement_state, settlement, settlement_pair_id} or
    None when another attempt for this pair is in flight."""
    claim_key = pair_id + ":" + str(payment.get("nonce"))[:18]
    if not _claim_pending(claim_key):
        return None
    try:
        rec = settle_mod.attempt_settlement(payment, SETTLE_CFG, STATE_DIR)
        status = rec.get("status")
        if status in ("SETTLED", "SUBMITTED"):
            rec = {**rec, "settlement_state": status}
            spid, _r = chain.issue_settlement_pair(rec, pair_id)
            return {"settlement_state": status, "settlement": rec,
                    "settlement_pair_id": spid}
        code = rec.get("failure_code")
        if code == "SETTLEMENT_REVERTED_ONCHAIN":
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
                   "state; the leg remains PENDING — an RPC response "
                   "is not chain state"}
            return {"settlement_state": "PENDING", "settlement": rec,
                    "settlement_pair_id": None}
        return {"settlement_state": "PENDING", "settlement": rec,
                "settlement_pair_id": None}
    finally:
        _release_pending(claim_key)


# ---------------- settlement sweep (pair-first eventual leg) ----------------
def _chain_settlement_index(seg_dir):
    """(settled, failed) keyed by (pair_id, nonce), and the route
    delivery outcomes by pair_id — read from the router chain
    itself (production construction): a leg is settled when a
    SETTLEMENT pair bound to its pair carries its nonce with
    status SETTLED/SUBMITTED; terminally failed when a
    SETTLEMENT-FAILURE pair with terminal_confirmed does."""
    settled, failed, delivered = {}, {}, {}
    for r in read_entries(seg_dir):
        c = r["content"]
        if c.get("index_in_pair") != 0:
            continue
        if c.get("pair_class") == "SETTLEMENT":
            rec = c.get("settlement") or {}
            key = (c.get("settles_pair_id"), str(rec.get("nonce") or ""))
            if c.get("disposition") == "SETTLEMENT_FAILED" \
                    and rec.get("terminal_confirmed") is True:
                failed[key] = rec
            elif rec.get("status") in ("SETTLED", "SUBMITTED"):
                settled[key] = rec
        elif c.get("pair_class") == "ROUTE":
            delivered[c.get("route_for_pair_id")] = c.get("disposition")
    return settled, failed, delivered


def pending_legs():
    """[(pair_id, leg_name, payment)] — the ALLOW pairs' legs
    still awaiting a settlement outcome: the fee leg of every
    ALLOW pair (born PENDING), and the seller leg of settle-mode
    pairs whose relay delivered cleanly."""
    settled, failed, delivered = _chain_settlement_index(SEG_DIR)
    out = []
    for r in read_entries(SEG_DIR):
        c = r["content"]
        if c.get("pair_class") != "EVALUATION" \
                or c.get("index_in_pair") != 0 \
                or c.get("disposition") != "ALLOW":
            continue
        pid = c["pair_id"]
        crossing = c.get("crossing") or {}
        legs = []
        if c.get("payment"):
            legs.append(("fee", c["payment"]))
        if crossing.get("settlement_mode") == "settle" \
                and delivered.get(pid) == "ROUTE_DELIVERED" \
                and c.get("route_payment"):
            legs.append(("seller", c["route_payment"]))
        for leg, payment in legs:
            key = (pid, str(payment.get("nonce") or ""))
            if key not in settled and key not in failed:
                out.append((pid, leg, payment))
    return out


def sweep_pending_settlements():
    """One sweep pass: attempt every pending leg once, receipting
    outcomes on the chain (production sweep pattern)."""
    results = []
    for pid, leg, payment in pending_legs():
        res = attempt_and_receipt(CHAIN, pid, payment)
        if res is not None:
            results.append({"pair_id": pid, "leg": leg, **res})
    return results


def _settlement_sweeper():
    interval = int(SETTLE_CFG.get("sweep_interval_seconds", 60))
    while True:
        time.sleep(interval)
        try:
            sweep_pending_settlements()
        except Exception:
            pass


# ---------------- HTTP fetch (probe / relay) ----------------
def _is_local(url):
    host = urllib.parse.urlparse(url).hostname or ""
    return host in ("127.0.0.1", "localhost", "::1")


def _opener_for(url, proxy):
    if proxy and not _is_local(url):
        return urllib.request.build_opener(
            urllib.request.ProxyHandler({"http": proxy, "https": proxy}))
    return urllib.request.build_opener(urllib.request.ProxyHandler({}))


def http_fetch(url, method="GET", body=None, headers=None, timeout=25):
    """One logical HTTP call. Returns (status, headers, raw_bytes)
    for ANY completed HTTP response. Raises TransportError on
    transport failure BEFORE the request could have been delivered
    (connect/DNS errors), and AmbiguousTransport when the request
    may have been delivered but the response was lost — the
    distinction the route leg's honesty depends on. Non-local
    URLs fail over the discovered egress proxies (idempotent
    reads and probes); callers making a paid relay attempt get
    exactly ONE attempt on the first candidate — a paid
    authorization is never re-presented."""
    data = None
    hdrs = {"User-Agent": "8374-Router/1.0 (ROUTER-V1)",
            "Accept": "application/json"}
    if body is not None:
        data = body if isinstance(body, (bytes, bytearray)) \
            else json.dumps(body).encode()
        hdrs["Content-Type"] = "application/json"
    hdrs.update(headers or {})
    proxies = [None] if _is_local(url) else \
        settle_mod._proxy_candidates() + [None]
    last_exc = None
    for proxy in proxies:
        req = urllib.request.Request(url, data=data, method=method,
                                     headers=hdrs)
        try:
            with _opener_for(url, proxy).open(req, timeout=timeout) as r:
                return r.status, {k.lower(): v for k, v in
                                  r.headers.items()}, r.read()
        except urllib.error.HTTPError as e:
            try:
                raw = e.read()
            except Exception as read_exc:
                raise AmbiguousTransport(
                    f"HTTP {e.code} response body unreadable: {read_exc}")
            return e.code, {k.lower(): v for k, v in
                            (e.headers.items() if e.headers else [])}, raw
        except Exception as e:
            last_exc = e
            # A failure that can only mean "never delivered" is
            # final for local targets; for proxied targets try the
            # next candidate — the request never left this node.
            if _is_local(url):
                break
    raise TransportError(f"{type(last_exc).__name__}: {last_exc}")


class TransportError(Exception):
    """The request could not be delivered (or delivery is
    provably not in question): connection refused / DNS / proxy
    refusal before send."""


class AmbiguousTransport(Exception):
    """The request may have been delivered but its outcome is
    unreadable (timeout after send, dropped connection, truncated
    body). The component doctrine: surface it, never retry."""


def _relay(url, body, payment_header, timeout=30):
    """The single paid relay attempt. Exactly ONE transport
    attempt (first proxy candidate for non-local, direct for
    local): re-presenting a single-use authorization after an
    ambiguous failure would mask the true outcome. Returns
    (status, headers, raw) on any completed response; raises
    TransportError / AmbiguousTransport."""
    data = json.dumps(body).encode() if body is not None else None
    hdrs = {"User-Agent": "8374-Router/1.0 (ROUTER-V1)",
            "Content-Type": "application/json",
            "Accept": "application/json",
            "X-PAYMENT": payment_header}
    proxies = [None] if _is_local(url) else \
        settle_mod._proxy_candidates()[:1]
    proxy = proxies[0] if proxies else None
    req = urllib.request.Request(url, data=data, method="POST",
                                 headers=hdrs)
    try:
        with _opener_for(url, proxy).open(req, timeout=timeout) as r:
            return r.status, {k.lower(): v for k, v in r.headers.items()}, \
                r.read()
    except urllib.error.HTTPError as e:
        try:
            raw = e.read()
        except Exception as read_exc:
            raise AmbiguousTransport(
                f"HTTP {e.code} response body unreadable: {read_exc}")
        return e.code, {k.lower(): v for k, v in
                        (e.headers.items() if e.headers else [])}, raw
    except Exception as e:
        msg = f"{type(e).__name__}: {e}"
        # Connection refused / DNS failure: the request provably
        # never reached the seller. Anything else after the bytes
        # may have left (timeout, reset mid-stream) is ambiguous.
        if isinstance(e, urllib.error.URLError) \
                and isinstance(getattr(e, "reason", None),
                               ConnectionRefusedError):
            raise TransportError(msg)
        if "Connection refused" in msg or "Name or service not known" in msg \
                or "getaddrinfo" in msg:
            raise TransportError(msg)
        raise AmbiguousTransport(msg)


# ---------------- registry ----------------
def normalize_origin(origin):
    if not isinstance(origin, str):
        return None
    o = origin.strip().rstrip("/")
    p = urllib.parse.urlparse(o)
    if p.scheme not in ("http", "https") or not p.netloc:
        return None
    return f"{p.scheme}://{p.netloc}"


class Registry:
    """Seller registry: a JSON document in the router's own dir,
    written tmp+rename+fsync. Registration is free; re-registering
    an origin refreshes its entry in place."""

    def __init__(self, path):
        self.path = path
        self.lock = threading.Lock()
        self.entries = {}
        if os.path.exists(path):
            try:
                doc = json.load(open(path))
                self.entries = doc.get("sellers", {})
            except Exception:
                self.entries = {}

    def _persist(self):
        tmp = self.path + ".tmp"
        with open(tmp, "w") as f:
            json.dump({"router": ROUTING_NAME,
                       "sellers": self.entries}, f, sort_keys=True)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, self.path)
        _fsync_dir(os.path.dirname(self.path) or ".")

    def put(self, entry):
        with self.lock:
            prev = self.entries.get(entry["origin"])
            if prev:
                entry["registered_at"] = prev.get("registered_at",
                                                  entry["registered_at"])
            self.entries[entry["origin"]] = entry
            self._persist()
            return entry

    def get(self, origin):
        with self.lock:
            e = self.entries.get(origin)
            return json.loads(json.dumps(e)) if e else None

    def all(self):
        with self.lock:
            return json.loads(json.dumps(self.entries))


REGISTRY = Registry(REGISTRY_PATH)


def _parse_json(raw):
    try:
        return json.loads(raw or b"{}")
    except Exception:
        return None


def _terms_from_challenge(chal, resource_url):
    """Recorded terms from a live 402 challenge body (v1 shape):
    accepts[0] carries scheme/network/asset/payTo and the amount
    under maxAmountRequired (v2: amount). Also records the
    discovery facts the challenge itself declares — description,
    maxTimeoutSeconds, the asset-domain extra (name/version), and
    the extensions.bazaar block — verbatim from the challenge,
    never synthesized (the Bazaar discovery feed mirrors them)."""
    if not isinstance(chal, dict):
        return None
    acc = (chal.get("accepts") or [{}])[0]
    amount = acc.get("maxAmountRequired", acc.get("amount"))
    try:
        amount = int(amount)
    except (TypeError, ValueError):
        return None
    if not acc.get("payTo"):
        return None
    terms = {"scheme": acc.get("scheme"), "network": acc.get("network"),
             "asset": acc.get("asset"), "payTo": acc.get("payTo"),
             "amount_micro_usdc": amount, "resource": resource_url,
             "mime_type": acc.get("mimeType")}
    desc = acc.get("description")
    if not desc and isinstance(acc.get("resource"), str) \
            and not acc["resource"].startswith(("http://", "https://")):
        # v1 challenges from some servers carry the description in
        # the accepts resource field (the production endpoint does).
        desc = acc["resource"]
    if not desc and isinstance(chal.get("description"), str):
        desc = chal["description"]
    if desc:
        terms["description"] = desc
    mts = acc.get("maxTimeoutSeconds")
    if isinstance(mts, int) and mts > 0:
        terms["max_timeout_seconds"] = mts
    extra = acc.get("extra")
    if isinstance(extra, dict):
        ev = {k: extra[k] for k in ("name", "version") if extra.get(k)}
        if ev:
            terms["extra"] = ev
    bz = (chal.get("extensions") or {}).get("bazaar")
    if isinstance(bz, dict) and bz:
        terms["bazaar"] = bz
    return terms


def probe_resource(origin, path, method_hint=None):
    """Probe one resource for its live 402 challenge (unpaid —
    a challenge request receipts nothing on a conforming x402
    server). Returns (terms_or_None, probe_note)."""
    url = origin + path
    methods = [method_hint] if method_hint else []
    for m in ("POST", "GET"):
        if m not in methods:
            methods.append(m)
    notes = []
    for m in methods:
        try:
            status, _h, raw = http_fetch(
                url, method=m, body={} if m == "POST" else None,
                timeout=20)
        except (TransportError, AmbiguousTransport) as e:
            notes.append(f"{m}: transport {e}")
            continue
        if status == 402:
            terms = _terms_from_challenge(_parse_json(raw), url)
            if terms:
                terms["method"] = m
                return terms, f"{m} probe: live 402 challenge recorded"
            notes.append(f"{m}: 402 without parseable accepts")
            continue
        notes.append(f"{m}: HTTP {status} (no 402 challenge)")
    return None, "; ".join(notes)


def crawl_origin(origin):
    """Enumerate an origin's paid resources from its
    /.well-known/x402 and /openapi.json, then probe each for its
    live terms. Returns the registry entry (not yet persisted)."""
    resources = {}
    sources = {"wellknown_x402": False, "openapi": False}
    try:
        status, _h, raw = http_fetch(origin + "/.well-known/x402",
                                     timeout=20)
        if status == 200:
            doc = _parse_json(raw) or {}
            for r in doc.get("resources", []):
                if isinstance(r, str):
                    path = urllib.parse.urlparse(r).path or "/"
                    resources.setdefault(path, None)
                    sources["wellknown_x402"] = True
    except (TransportError, AmbiguousTransport):
        pass
    try:
        status, _h, raw = http_fetch(origin + "/openapi.json",
                                     timeout=20)
        if status == 200:
            doc = _parse_json(raw) or {}
            for path, ops in (doc.get("paths") or {}).items():
                if not isinstance(ops, dict):
                    continue
                for method, op in ops.items():
                    if not isinstance(op, dict):
                        continue
                    if "x-payment-info" in op or "402" in (
                            op.get("responses") or {}):
                        resources.setdefault(
                            path, method.upper())
                        sources["openapi"] = True
    except (TransportError, AmbiguousTransport):
        pass
    probed = []
    for path, method_hint in sorted(resources.items())[:25]:
        terms, note = probe_resource(origin, path, method_hint)
        probed.append({"path": path, "url": origin + path,
                       "method": (terms or {}).get("method",
                                                   method_hint or "POST"),
                       "terms": terms, "probe_note": note})
    return {"origin": origin, "registered_at": now(),
            "refreshed_at": now(), "sources": sources,
            "resources": probed,
            "registration": "free self-serve; no account; no listing "
                            "fee; no proven-seller gate"}


def self_entry_from_local_record():
    """8374's own entry synthesized from the production offer /
    config documents (local record) when the live self-probe
    cannot run: terms from the declared receptor configuration."""
    cfg_path = CONFIG.get("production_config_path")
    resources = []
    if cfg_path and os.path.exists(cfg_path):
        pcfg = json.load(open(cfg_path))
        st = pcfg.get("settlement", {})
        for tier, micro in (st.get("tiers_micro_usdc") or {}).items():
            resources.append({
                "path": "/crossing", "url": SELF_ORIGIN + "/crossing",
                "method": "POST",
                "terms": {"scheme": st.get("scheme"),
                          "network": st.get("network"),
                          "asset": st.get("asset"),
                          "payTo": st.get("payTo"),
                          "amount_micro_usdc": None,
                          "governance_fee_micro_usdc": int(micro),
                          "tier": tier,
                          "note": "the crossing total is the tier "
                                  "governance fee + the live-quoted "
                                  "settlement charge (offer v07)"},
                "probe_note": "terms from the declared receptor "
                              "configuration (local record)"})
    return {"origin": SELF_ORIGIN, "registered_at": now(),
            "refreshed_at": now(),
            "sources": {"wellknown_x402": False, "openapi": False,
                        "local_record": True},
            "resources": resources,
            "registration": "self-registered (listed by construction)"}


def register_origin(origin):
    """Crawl + probe + persist one origin. 8374's own origin
    falls back to the local record when the live crawl finds no
    probed resources (e.g. egress-restricted dev nodes)."""
    entry = crawl_origin(origin)
    if origin == SELF_ORIGIN and not any(
            r.get("terms") for r in entry["resources"]):
        entry = self_entry_from_local_record()
    entry["refreshed_at"] = now()
    return REGISTRY.put(entry)


def catalog_document():
    sellers = []
    for origin, entry in sorted(REGISTRY.all().items()):
        e = dict(entry)
        if origin == SELF_ORIGIN:
            e["provenance"] = {
                "kind": "replayable receipt chain",
                **production_provenance(),
                "note": "8374's provenance is recomputed from its "
                        "receipt chain, never granted"}
        else:
            e["provenance"] = {
                "kind": "registered terms",
                "status": "routable — provenance not yet established",
                "note": "no proven-seller gate: the seller is "
                        "routable on its registered terms; its "
                        "provenance establishes itself in replayable "
                        "records as routed crossings settle"}
        sellers.append(e)
    return {"router": ROUTING_NAME, "identity": IDENTITY,
            "document": "ROUTER__CATALOG__01",
            "generated_at": now(),
            "pricing": {"middleman": "none — no percentage skim, no "
                                     "listing fee",
                        "crossing_fee": "the posted 8374 fee only: "
                                        "tier governance fee + "
                                        "live-quoted settlement "
                                        "charge (offer v07)",
                        "tiers_micro_usdc": TIERS_MICRO,
                        "network": X402_NETWORK, "asset": X402_ASSET,
                        "payTo": ROUTER_PAYTO},
            "sellers": sellers}


def provenance_document(origin):
    entry = REGISTRY.get(origin)
    if origin == SELF_ORIGIN:
        return {"origin": origin, "router": ROUTING_NAME,
                "provenance": {"kind": "replayable receipt chain",
                               **production_provenance()},
                "registered": entry is not None,
                "entry": entry}
    if entry is None:
        return {"origin": origin, "router": ROUTING_NAME,
                "registered": False,
                "provenance": {"kind": "none",
                               "status": "not registered — register "
                                         "free at POST /router/register"}}
    return {"origin": origin, "router": ROUTING_NAME,
            "registered": True,
            "provenance": {"kind": "registered terms",
                           "status": "routable — provenance not yet "
                                     "established",
                           "note": "provenance is never granted by "
                                   "the router; it establishes itself "
                                   "in replayable records"},
            "entry": entry}


# ---------------- Bazaar discovery feed ----------------
# GET /router/discovery/resources — the router publishes its
# registry in the CDP Bazaar discovery schema (grounded live
# 2026-11-19 against api.cdp.coinbase.com/platform/v2/x402/
# discovery/resources and facilitator.payai.network/discovery/
# resources): {x402Version: 2, items: [...], pagination:
# {limit, offset, total}}. Item core: resource, type "http",
# x402Version, lastUpdated, accepts[{scheme, network, asset,
# payTo, amount, maxTimeoutSeconds?, extra?}], plus description /
# mimeType / extensions.bazaar when the seller's own challenge
# declared them. Fields the registry does not know are OMITTED,
# never fabricated (aggregator-computed fields such as CDP's
# "quality" are not ours to state). Generated live from the
# registry on every call; 8374's own items are built from the
# declared receptor configuration (the local record's tier
# resources) enriched by a live challenge harvest, because the
# crossing total floats with the settlement quote and only the
# endpoint's challenge states it whole.

def _iso_z(iso_str):
    """Registry timestamps (+00:00) in the feed's Z form."""
    try:
        dt = datetime.fromisoformat(iso_str)
    except (TypeError, ValueError):
        return iso_str
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    dt = dt.astimezone(timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + \
        f"{dt.microsecond // 1000:03d}Z"


_SELF_CHAL_CACHE = {"by_tier": {}}
_SELF_CHAL_TTL = 120


def _self_challenge_urls():
    """Where 8374's own 402 challenge can be read: the
    endpoint's local listener first (the production config
    declares its port; localhost carriage never crosses the
    public edge — the public origin's CDN refuses this
    service's user agent, the same reason self-registration
    falls back to the local record), then the public origin."""
    urls = []
    cfg_path = CONFIG.get("production_config_path")
    if cfg_path and os.path.exists(cfg_path):
        try:
            port = json.load(open(cfg_path)).get("port")
            if isinstance(port, int):
                urls.append(f"http://127.0.0.1:{port}/crossing")
        except Exception:
            pass
    urls.append(SELF_ORIGIN + "/crossing")
    return urls


def _harvest_self_challenge(tier):
    """Best-effort live harvest of 8374's own 402 challenge for
    one tier (the endpoint serves the live total and the
    extensions.bazaar block there; a challenge request receipts
    nothing). Returns the parsed challenge dict or None; cached
    briefly so feed generation stays cheap."""
    hit = _SELF_CHAL_CACHE["by_tier"].get(tier)
    if hit and time.time() - hit[0] < _SELF_CHAL_TTL:
        return hit[1]
    body = {} if tier == "receipt-only" else {
        "tier": "full-evaluation",
        "counterparty": "8374-router-discovery",
        "action": "evaluate", "scope_ref": "ME-EVAL-01"}
    chal = None
    for url in _self_challenge_urls():
        try:
            status, _h, raw = http_fetch(url, method="POST",
                                         body=body, timeout=20)
            if status == 402:
                chal = _parse_json(raw)
                if chal:
                    break
        except (TransportError, AmbiguousTransport):
            continue
    _SELF_CHAL_CACHE["by_tier"][tier] = (time.time(), chal)
    return chal


def _feed_item(resource_url, terms, amount_micro, last_updated,
               bazaar=None):
    acc = {"scheme": terms.get("scheme"),
           "network": terms.get("network"),
           "asset": terms.get("asset"),
           "payTo": terms.get("payTo"),
           "amount": str(int(amount_micro))}
    if terms.get("max_timeout_seconds"):
        acc["maxTimeoutSeconds"] = int(terms["max_timeout_seconds"])
    if terms.get("extra"):
        acc["extra"] = terms["extra"]
    item = {"resource": resource_url, "type": "http",
            "x402Version": 2, "lastUpdated": last_updated,
            "accepts": [acc]}
    if terms.get("description"):
        item["description"] = terms["description"]
    if terms.get("mime_type"):
        item["mimeType"] = terms["mime_type"]
    bz = bazaar if bazaar is not None else terms.get("bazaar")
    if isinstance(bz, dict) and bz:
        item["extensions"] = {"bazaar": bz}
    return item


def _self_feed_items(last_updated):
    """8374's own feed items — one per tier resource of the
    declared receptor configuration. The amount is the live
    crossing total for the tier: harvested from the endpoint's
    own challenge when reachable, else the router's own
    BUILD-Q-43 quote (the same formula the crossing is priced
    by). A tier whose total cannot be stated whole is omitted
    rather than understated."""
    out = []
    for r in self_entry_from_local_record().get("resources", []):
        terms = dict(r.get("terms") or {})
        tier = terms.get("tier")
        amount = None
        bazaar = None
        chal = _harvest_self_challenge(tier) if tier else None
        if chal:
            ct = _terms_from_challenge(chal, r.get("url"))
            if ct:
                amount = ct["amount_micro_usdc"]
                bazaar = ct.get("bazaar")
                for k in ("description", "max_timeout_seconds",
                          "extra", "mime_type"):
                    if ct.get(k) is not None:
                        terms[k] = ct[k]
        if amount is None and tier in TIERS_MICRO:
            try:
                amount, _q = fee_total_micro(tier)
            except SettlementQuoteUnavailable:
                amount = None
        if amount is None:
            continue
        out.append(_feed_item(r.get("url"), terms, amount,
                              last_updated, bazaar=bazaar))
    return out


def discovery_document(limit=20, offset=0):
    """The Bazaar-format discovery feed, generated live from
    the registry: every registered seller's probed resources,
    plus 8374's own tier resources by construction."""
    groups = []
    entries = REGISTRY.all()
    for origin, entry in sorted(entries.items()):
        updated = _iso_z(entry.get("refreshed_at")
                         or entry.get("registered_at") or now())
        if origin == SELF_ORIGIN:
            groups.append((origin, _self_feed_items(updated)))
            continue
        items = []
        for r in entry.get("resources", []):
            terms = r.get("terms")
            if not terms or terms.get("amount_micro_usdc") is None:
                continue
            items.append(_feed_item(r.get("url"), terms,
                                    terms["amount_micro_usdc"],
                                    updated))
        groups.append((origin, items))
    if SELF_ORIGIN not in entries:
        groups.append((SELF_ORIGIN, _self_feed_items(_iso_z(now()))))
        groups.sort(key=lambda g: g[0])
    items = [it for _o, g in groups for it in g]
    total = len(items)
    page = items[offset:offset + limit] if offset < total else []
    return {"x402Version": 2, "items": page,
            "pagination": {"limit": limit, "offset": offset,
                           "total": total}}


# ---------------- the routed crossing ----------------
def _verify_presented(header_b64, expected_payto, expected_value,
                      asset, leg):
    """Decode + verify one presented authorization. Returns
    (evidence, None) or (None, six_field_detail). A garbled
    header is PAYMENT_PAYLOAD_MALFORMED (production codes)."""
    payload = x402kit.decode_payment_header(header_b64)
    if payload is None:
        return None, six_field(
            "PAYMENT_PAYLOAD_MALFORMED",
            f"the {leg} payment header is a base64-encoded x402 "
            "payment payload object",
            "present the X-PAYMENT payload produced by an x402 "
            "client (base64 of the payment payload JSON)",
            "POST /router/route",
            "caller presents a valid payment authorization")
    try:
        ev = x402kit.verify_authorization(
            payload, expected_payto, expected_value,
            int(time.time()), asset)
    except x402kit.VerifyFail as e:
        return None, six_field(
            e.code, e.predicate, e.repair, "POST /router/route",
            "caller presents a valid payment authorization")
    return ev, None


def _nonce_reused_detail(leg):
    return six_field(
        "PAYMENT_NONCE_REUSED",
        f"the {leg} authorization nonce has never been used "
        "(single-use; the router receipt chain is the nonce registry)",
        "sign a fresh authorization with a fresh nonce",
        "POST /router/route",
        "caller presents a fresh authorization")


def do_route(body):
    """One routed crossing. Returns (http_status, response_dict).
    The disposition resolves FIRST, from locally-decidable
    predicates only (registry, quote, signature recovery, payee,
    value, window, nonce registry, evidence rules); only on ALLOW
    is the pair issued and the payment relayed / settled."""
    counterparty = body.get("counterparty")
    seller_origin = normalize_origin(body.get("seller_origin"))
    resource = body.get("resource")
    scope_req = body.get("scope", "receipt-only")
    mode = body.get("settlement", "relay")
    if mode not in ("relay", "settle"):
        mode = "relay"
    tier = {"receipt-only": "receipt-only",
            "ME-EVAL-01": "full-evaluation"}.get(scope_req, scope_req)
    crossing = {"counterparty": counterparty, "action": "evaluate",
                "scope_ref": "ME-EVAL-01", "tier": tier,
                "router": ROUTING_NAME, "seller_origin": seller_origin,
                "resource": resource, "settlement_mode": mode,
                "scope_requested": scope_req}
    if body.get("evidence") is not None:
        crossing["evidence"] = body["evidence"]

    def refuse(disposition, detail, payment=None, route_payment=None,
               settlement=None):
        pid, _recs = CHAIN.issue_pair(
            "REFUSAL", crossing, disposition,
            disposition_detail=detail, payment=payment,
            route_payment=route_payment, settlement=settlement)
        return (403 if disposition == "DENY" else 422), {
            "disposition": disposition, "pair_id": pid,
            "router": ROUTING_NAME, "detail": detail,
            "route": {"mode": mode, "delivered": False,
                      "note": "no payment relayed and no settlement "
                              "attempted on a non-ALLOW disposition"},
            "settlement": {"mode": mode, "state": "NOT_SUBMITTED"}}

    with ROUTE_LOCK:
        used = used_payment_nonces()
        # Registry predicates.
        entry = REGISTRY.get(seller_origin) if seller_origin else None
        if entry is None:
            return refuse("FAIL_CLOSED", six_field(
                "SELLER_NOT_REGISTERED",
                "the seller origin is registered with the router",
                "register the origin free at POST /router/register "
                "(self-serve; the router crawls its /.well-known/x402 "
                "and /openapi.json)",
                "POST /router/register, then POST /router/route",
                "seller registers, then the caller retries"))
        resource_entry = None
        for r in entry.get("resources", []):
            if resource in (r.get("path"), r.get("url")):
                resource_entry = r
                break
        if resource_entry is None:
            return refuse("FAIL_CLOSED", six_field(
                "RESOURCE_NOT_REGISTERED",
                "the resource is among the seller origin's "
                "registered paid resources",
                "route to a resource enumerated in the seller's "
                "registry entry (GET /router/catalog), or "
                "re-register the origin to refresh it",
                "POST /router/route with a registered resource",
                "caller correction"))
        terms = resource_entry.get("terms")
        if not terms:
            return refuse("FAIL_CLOSED", six_field(
                "SELLER_TERMS_UNPROBED",
                "the resource's live 402 terms were probed at "
                "registration (scheme, network, asset, payTo, amount)",
                "re-register the origin (POST /router/register) "
                "when the seller is reachable and issuing 402 "
                "challenges",
                "POST /router/register, then POST /router/route",
                "seller reachable, then the caller retries"))
        # Tier validity is evaluation's predicate; an unknown
        # scope names an unknown tier and fails there, unpriced.
        if tier not in TIERS_MICRO:
            disposition, detail = evaluate(crossing)
            return refuse(disposition, detail)
        # Price the crossing (fee + live settlement charge).
        try:
            total, quote = fee_total_micro(tier)
        except SettlementQuoteUnavailable:
            return refuse("FAIL_CLOSED", _quote_fail_detail())
        # Verify the 8374 fee leg (to the router's payTo).
        fee_ev, fee_detail = _verify_presented(
            body.get("fee_payment"), ROUTER_PAYTO, total, X402_ASSET,
            "fee")
        if fee_detail is not None:
            return refuse("FAIL_CLOSED", fee_detail)
        fee_ev.update({
            "tier": tier,
            "governance_fee_micro_usdc": TIERS_MICRO[tier],
            "settlement_charge_micro_usdc":
                quote["settlement_charge_micro_usdc"],
            "settlement_charge_quote": quote,
            "total_authorized_micro_usdc": total,
            "required_micro_usdc": total,
            "settlement": "authorization verified at crossing; "
                          "settlement is eventual (pair-first)"})
        if fee_ev["nonce"] in used:
            return refuse("DENY", _nonce_reused_detail("fee"))
        # Verify the buyer→seller leg (to the seller's probed payTo,
        # for exactly the probed amount).
        seller_ev, seller_detail = _verify_presented(
            body.get("payment"), terms["payTo"],
            int(terms["amount_micro_usdc"]),
            terms.get("asset") or X402_ASSET, "seller")
        if seller_detail is not None:
            return refuse("FAIL_CLOSED", seller_detail)
        seller_ev.update({
            "seller_origin": seller_origin,
            "resource": resource_entry.get("url"),
            "settlement": "buyer-signed authorization; relayed to "
                          "the seller by the router, and in settle "
                          "mode also submitted on-chain by the "
                          "router's gas-only relayer"})
        if seller_ev["nonce"] in used:
            return refuse("DENY", _nonce_reused_detail("seller"))
        # Governance evaluation (production rules, evidence incl.).
        eval_req = {"counterparty": counterparty, "action": "evaluate",
                    "scope_ref": "ME-EVAL-01", "tier": tier}
        if body.get("evidence") is not None:
            eval_req["evidence"] = body["evidence"]
        disposition, detail = evaluate(eval_req)
        if disposition != "ALLOW":
            withheld = settlement_withheld_record(fee_ev, detail, "fee")
            return refuse(disposition, detail, payment=fee_ev,
                          route_payment=seller_ev, settlement=withheld)
        # ALLOW: the pair is born PENDING (pair-first), then the
        # relay leg runs, then (settle mode) the settlement legs.
        route_rec = {"mode": mode, "seller_origin": seller_origin,
                     "resource": resource_entry.get("url"),
                     "delivery": "PENDING"}
        pair_id, _recs = CHAIN.issue_pair(
            "RECEIPT", crossing, "ALLOW", payment=fee_ev,
            route_payment=seller_ev,
            settlement=pending_settlement_record(fee_ev),
            route=route_rec)
        # Relay: exactly ONE paid transport attempt.
        seller_url = resource_entry.get("url")
        ambiguous_note = None
        try:
            status, _h, raw = _relay(seller_url,
                                     body.get("resource_body") or {},
                                     body.get("payment"), timeout=30)
            seller_response = _parse_json(raw)
            if seller_response is None:
                seller_response = {
                    "raw": raw.decode(errors="replace")[:2000]}
            route_rec = {**route_rec, "delivery": "DELIVERED",
                         "seller_status": status,
                         "seller_response": seller_response}
            CHAIN.issue_route_pair(route_rec, pair_id, "ROUTE_DELIVERED")
            delivered = True
        except TransportError as e:
            route_rec = {**route_rec, "delivery": "FAILED",
                         "ambiguous": False, "error": str(e)[:300],
                         "note": "the authorization was never "
                                 "delivered to the seller; nothing "
                                 "was settled"}
            CHAIN.issue_route_pair(route_rec, pair_id, "ROUTE_FAILED")
            delivered = False
        except AmbiguousTransport as e:
            route_rec = {**route_rec, "delivery": "AMBIGUOUS",
                         "ambiguous": True, "error": str(e)[:300],
                         "note": "the paid relay attempt's outcome "
                                 "is unreadable; the authorization "
                                 "was NOT re-presented and NOT "
                                 "settled by the router — reconcile "
                                 "against the seller before signing "
                                 "a fresh authorization"}
            CHAIN.issue_route_pair(route_rec, pair_id, "ROUTE_AMBIGUOUS")
            delivered = False
            ambiguous_note = (
                "AmbiguousOutcome: the signed authorization may "
                "already have been delivered to the seller; it was "
                "NOT re-presented and NOT settled by the router. "
                "Reconcile against the seller's records before "
                "signing a fresh authorization.")
        # Settlement legs (settle mode, clean delivery only).
        settlement_out = {"mode": mode}
        if mode == "settle" and delivered:
            s_res = attempt_and_receipt(CHAIN, pair_id, seller_ev)
            f_res = attempt_and_receipt(CHAIN, pair_id, fee_ev)
            settlement_out["seller_leg"] = s_res or {
                "settlement_state": "PENDING",
                "note": "attempt already in flight"}
            settlement_out["fee_leg"] = f_res or {
                "settlement_state": "PENDING",
                "note": "attempt already in flight"}
        elif mode == "settle":
            settlement_out["seller_leg"] = {
                "settlement_state": "NOT_ATTEMPTED",
                "note": "settlement runs only on a cleanly "
                        "delivered relay"}
            settlement_out["fee_leg"] = {
                "settlement_state": "PENDING",
                "note": "pair-first: the fee leg remains PENDING "
                        "for the settlement sweep"}
        else:
            settlement_out["seller_leg"] = {
                "settlement_state": "RELAYED",
                "note": "relay mode: the seller's own leg settles "
                        "the authorization; the router submitted "
                        "nothing on-chain"}
            settlement_out["fee_leg"] = {
                "settlement_state": "PENDING",
                "note": "pair-first: the fee authorization is "
                        "verified and receipted; its settlement is "
                        "an eventual leg"}
        resp = {"disposition": "ALLOW", "pair_id": pair_id,
                "router": ROUTING_NAME,
                "crossing": {"tier": tier,
                             "governance_fee_micro_usdc":
                                 TIERS_MICRO[tier],
                             "settlement_charge_micro_usdc":
                                 quote["settlement_charge_micro_usdc"],
                             "total_authorized_micro_usdc": total,
                             "seller_amount_micro_usdc":
                                 int(terms["amount_micro_usdc"]),
                             "seller_payTo": terms["payTo"]},
                "route": route_rec, "settlement": settlement_out}
        if ambiguous_note:
            resp["outcome"] = "AMBIGUOUS"
            resp["ambiguous_outcome"] = ambiguous_note
        return 200, resp


# ---------------- HTTP surface ----------------
class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        pass

    def _send(self, code, obj):
        raw = json.dumps(obj, sort_keys=True).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def _body(self):
        n = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(n) if n else b""
        try:
            obj = json.loads(raw or b"{}")
        except Exception:
            return None
        return obj if isinstance(obj, dict) else None

    def do_GET(self):
        p = urllib.parse.urlparse(self.path)
        qs = urllib.parse.parse_qs(p.query)
        if p.path == "/health":
            self._send(200, {
                "status": "ok", "service": "8374-router",
                "router": ROUTING_NAME, "identity": IDENTITY,
                "chain": CHAIN.totals(),
                "registry_sellers": len(REGISTRY.all()),
                "settlement_submission": settle_mod.public_state(
                    SETTLE_CFG, STATE_DIR),
                "payTo": ROUTER_PAYTO, "network": X402_NETWORK,
                "asset": X402_ASSET})
        elif p.path == "/":
            self._send(200, {
                "service": "8374-router", "router": ROUTING_NAME,
                "identity": IDENTITY,
                "document": "ROUTER__SERVICE__01",
                "routes": {
                    "POST /router/register":
                        "free self-serve seller registration "
                        "{origin} — crawls /.well-known/x402 + "
                        "/openapi.json, probes live 402 terms",
                    "GET /router/catalog":
                        "machine-readable catalog of registered "
                        "sellers/resources with probed terms and "
                        "provenance",
                    "GET /router/discovery/resources":
                        "Bazaar-format discovery feed (the CDP "
                        "discovery schema): every registered "
                        "seller's resources with their probed "
                        "terms, generated live from the registry "
                        "— the feed aggregators ingest; accepts "
                        "?limit= and ?offset=",
                    "GET /router/provenance?origin=":
                        "provenance for one origin (8374: replayable "
                        "chain facts, recomputed read-only)",
                    "GET /router/quote?tier=":
                        "the posted crossing price for a tier: "
                        "governance fee + live settlement charge",
                    "POST /router/route":
                        "route one governed crossing {seller_origin, "
                        "resource, scope: receipt-only|ME-EVAL-01, "
                        "settlement: relay|settle, payment, "
                        "fee_payment, evidence?}",
                    "POST /router/settle-pair":
                        "force one settlement attempt per pending "
                        "leg of {pair_id}, or {sweep: true} for all "
                        "pending legs (pair-first eventual leg)"},
                "pricing": {
                    "middleman": "none — no percentage skim, no "
                                 "listing fee, no proven-seller gate",
                    "tiers_micro_usdc": TIERS_MICRO,
                    "settlement_charge": "live-quoted gas "
                                         "(BUILD-Q-43 formula), "
                                         "charged, never absorbed",
                    "total": "governance fee + settlement charge"},
                "patent_pending": "U.S. Provisional Patent "
                                  "Application No. 64/198,910, "
                                  "filed November 14, 2026"})
        elif p.path == "/router/catalog":
            self._send(200, catalog_document())
        elif p.path == "/router/discovery/resources":
            try:
                limit = int((qs.get("limit") or ["20"])[0])
            except ValueError:
                limit = 20
            try:
                offset = int((qs.get("offset") or ["0"])[0])
            except ValueError:
                offset = 0
            self._send(200, discovery_document(
                min(max(limit, 1), 100), max(offset, 0)))
        elif p.path == "/router/provenance":
            origin = normalize_origin((qs.get("origin") or [None])[0])
            if origin is None:
                self._send(400, {"error": "origin query parameter "
                                          "required"})
            else:
                self._send(200, provenance_document(origin))
        elif p.path == "/router/quote":
            tier = (qs.get("tier") or ["receipt-only"])[0]
            if tier not in TIERS_MICRO:
                self._send(400, {"error": "tier must be one of "
                                          f"{sorted(TIERS_MICRO)}"})
                return
            try:
                total, quote = fee_total_micro(tier)
            except SettlementQuoteUnavailable:
                self._send(503, {"disposition": "FAIL_CLOSED",
                                 "detail": _quote_fail_detail()})
                return
            self._send(200, {
                "tier": tier,
                "governance_fee_micro_usdc": TIERS_MICRO[tier],
                "settlement_charge_micro_usdc":
                    quote["settlement_charge_micro_usdc"],
                "total_micro_usdc": total, "payTo": ROUTER_PAYTO,
                "network": X402_NETWORK, "asset": X402_ASSET,
                "scheme": X402_SCHEME, "quote": quote})
        elif p.path == "/router/replay":
            self._send(200, replay())
        else:
            self._send(404, {"error": "not found"})

    def do_POST(self):
        p = urllib.parse.urlparse(self.path)
        body = self._body()
        if body is None:
            self._send(400, {"error": "JSON object body required"})
            return
        if p.path == "/router/register":
            origin = normalize_origin(body.get("origin"))
            if origin is None:
                self._send(400, {"error": "origin must be an "
                                          "http(s) origin"})
                return
            entry = register_origin(origin)
            self._send(200, {"registered": True, "entry": entry})
        elif p.path == "/router/route":
            if not (isinstance(body.get("counterparty"), str)
                    and body.get("seller_origin")
                    and body.get("resource")):
                self._send(400, {"error": "counterparty, "
                                          "seller_origin and "
                                          "resource are required to "
                                          "form a crossing record"})
                return
            code, resp = do_route(body)
            self._send(code, resp)
        elif p.path == "/router/settle-pair":
            # The production POST /settle-pair pattern: force one
            # settlement attempt per pending leg of one pair, or
            # ({"sweep": true}) one sweep over all pending legs.
            if body.get("sweep") is True:
                self._send(200, {"sweep": True,
                                 "results": sweep_pending_settlements()})
                return
            pair_id = body.get("pair_id")
            if not pair_id:
                self._send(400, {"error": "pair_id required (or "
                                          "{\"sweep\": true})"})
                return
            results = []
            for pid, leg, payment in pending_legs():
                if pid != pair_id:
                    continue
                res = attempt_and_receipt(CHAIN, pid, payment)
                if res is not None:
                    results.append({"leg": leg, **res})
            self._send(200, {"pair_id": pair_id, "results": results,
                             "pending_remaining":
                                 [leg for pid, leg, _p in pending_legs()
                                  if pid == pair_id]})
        else:
            self._send(404, {"error": "not found"})


def main():
    # 8374 is listed by construction: self-register at startup
    # (live crawl when egress allows; the local-record entry
    # otherwise). Registration failure never blocks the service.
    def _self_register():
        try:
            register_origin(SELF_ORIGIN)
        except Exception:
            try:
                REGISTRY.put(self_entry_from_local_record())
            except Exception:
                pass
    threading.Thread(target=_self_register, daemon=True).start()
    threading.Thread(target=_settlement_sweeper, daemon=True).start()
    srv = ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
    print(f"8374 router ({ROUTING_NAME}) listening on 127.0.0.1:{PORT} "
          f"state={STATE_DIR}", flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
