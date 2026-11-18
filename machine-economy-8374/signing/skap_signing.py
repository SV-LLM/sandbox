#!/usr/bin/env python3
"""SKAP sign-under-seal operation — BUILD-Q-14.

The production custody signing path for machine-economy identity 8374.
The signing key (specimen SKI-SIGNING_KEY-31c77c60) resides only in the
Ecosystem KV's SKAP seal (deposit seq 42, PP-2 production form). Per
signing call this operation:

  1. admits the request (identity 8374; well-formed SHA-256 payload
     digest; authorization_ref equal to the admitted BUILD-Q-14
     authorization artifact digest),
  2. performs governed SKAP retrieval (C-02): a fresh grant is issued
     by the production TV/TVC Authority and the specimen is released
     under it — GRANT / USAGE / RETRIEVAL are receipted on the SKAP
     chain for every call,
  3. signs the payload digest in memory (ECDSA / secp256k1, Prehashed),
  4. zeroizes the material (best-effort within CPython) and returns
     {signature, public_address, receipt_pair} — the pair being dual
     records on this operation's own hash-chained, replayable chain.

Non-ALLOW carries the six-field disposition grammar plus a refusal
record pair; nothing signs. The material is fetched and unsealed per
call — never cached between calls, never written unsealed, never
logged. Localhost only. Stdlib + `cryptography` + the SKAP suite
package (read-only import from the production sitting tree).
"""
import hashlib, hmac, json, os, sys, threading, uuid
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

BASE = os.path.dirname(os.path.abspath(__file__))
CONFIG = json.load(open(os.path.join(BASE, "config.json")))
sys.path.insert(0, CONFIG["custody"]["skap_suite_path"])
from skap import retrieval, vault  # noqa: E402
from skap.authority import Authority  # noqa: E402
from skap.receipts import ReceiptChain as SkapChain  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
from cryptography.hazmat.primitives.hashes import SHA256  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed  # noqa: E402

SEG_DIR = os.path.join(BASE, "receipts")
PORT = int(os.environ.get("SKAP_SIGNING_PORT", str(CONFIG.get("port", 8795))))
SEGMENT_MAX = 500
os.makedirs(SEG_DIR, exist_ok=True)

IDENTITY = CONFIG["identity"]["designation"]
SPECIMEN = CONFIG["identity"]["specimen_id"]
ADDRESS = CONFIG["identity"]["public_address"]
ADMITTED_REF = CONFIG["authorization"]["admitted_ref"]
TREE = CONFIG["custody"]["skap_tree"]
OWNING_GOAL = "MACHINE-ECONOMY-ENTRY-01 / BUILD-Q-14"
SIGN_LOCK = threading.Lock()

AUTHORITY = Authority(CONFIG["custody"]["authority_store"])
SKAP_CHAIN = SkapChain(os.path.join(TREE, "Receipts"))

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

# ---------------- own receipt chain (mirrors the endpoint's form) ----------------
class ReceiptChain:
    """Each receipt: {i, prev, content, hash}; hash = SHA256(prev ||
    canonical(content)) — patent spec S4 tuple form. Pairs occupy two
    consecutive entries."""
    def __init__(self, seg_dir):
        self.dir = seg_dir
        self.lock = threading.Lock()
        self.i = 0
        self.prev = "GENESIS"
        self.pairs = 0
        self.pair_seq = 0
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
                          "recorded_by": "skap-signing (StegVerse LLC)"})
        self._append({**base_c, "kind": "RECOVERY_ANCHOR",
                      "index_in_pair": 1, "side": "chain",
                      "recorded_by": "skap-signing (StegVerse LLC)",
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

    def issue_pair(self, kind, base_content, disposition, disposition_detail=None):
        """kind: 'SIGNING' (ALLOW) or 'REFUSAL' (non-ALLOW). Returns
        (pair_id, [rec_a, rec_b])."""
        with self.lock:
            self.pair_seq += 1
            pair_id = f"PAIR-{self.pair_seq:06d}"
            base = {**base_content, "pair_id": pair_id,
                    "disposition": disposition, "ts": now()}
            if kind == "SIGNING":
                a = self._append({**base, "kind": "SIGNING_OPERATION_SIDE",
                                  "index_in_pair": 0, "side": "operation",
                                  "recorded_by": "skap-signing (StegVerse LLC)"})
                b = self._append({**base, "kind": "SIGNING_REQUESTER_SIDE",
                                  "index_in_pair": 1, "side": "requester",
                                  "recorded_by": base_content.get("requester"),
                                  "pair_anchor": a["hash"]})
            else:
                a = self._append({**base, "kind": "REFUSAL_ATTEMPT",
                                  "index_in_pair": 0, "side": "attempt",
                                  "recorded_by": "skap-signing (StegVerse LLC)",
                                  "executed": False})
                b = self._append({**base, "kind": "REFUSAL_DISPOSITION",
                                  "index_in_pair": 1, "side": "disposition",
                                  "recorded_by": "skap-signing (StegVerse LLC)",
                                  "pair_anchor": a["hash"], "executed": False,
                                  "disposition_detail": disposition_detail or {}})
            self.pairs += 1
            if disposition in self.by_disp:
                self.by_disp[disposition] += 1
            return pair_id, [a, b]

    def totals(self):
        return {"receipt_pairs": self.pairs,
                "by_disposition": dict(self.by_disp),
                "chain_entries": self.i,
                "terminal_anchor": self.prev}

CHAIN = ReceiptChain(SEG_DIR)

def replay(seg_dir=SEG_DIR):
    """Recompute the chain and verify linkage, hashes, and pair matching.

    Torn tail (BUILD-Q-16): a segment file whose final line is incomplete
    verifies up to its last complete entry; an unrecovered tear at the
    chain's active tail yields MATCH_WITH_TORN_TAIL (torn byte count +
    last complete anchor named); a tear already sealed by a RECOVERY pair
    is reported under recovered_tails and the verdict stays MATCH; a torn
    line anywhere else is a hard MISMATCH."""
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
    # tail is explained BY the tear (its second member never committed).
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
        elif sorted(members, key=lambda c: c["index_in_pair"])[1].get("pair_anchor") is None:
            problems.append(f"{pid}: second member carries no pair anchor")
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

# ---------------- disposition grammar ----------------
def six_field(failure_code, failed_predicate, repair, retry, next_attempt):
    return {"failure_code": failure_code, "failed_predicate": failed_predicate,
            "required_evidence_or_repair": repair, "retry_entrypoint": retry,
            "owning_goal": OWNING_GOAL, "next_attempt": next_attempt}

def skap_tail_seq():
    files = [f for f in os.listdir(os.path.join(TREE, "Receipts")) if f.endswith(".json")]
    return len(files)

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
    def _body(self):
        n = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(n) if n else b"{}"
        return json.loads(raw or b"{}")
    def do_GET(self):
        if self.path == "/health":
            entry = vault.registry_entry(TREE, SPECIMEN)
            self._json(200, {"status": "ok", "service": CONFIG["service"],
                             "port": PORT, "project_id": CONFIG["project_id"],
                             "queue_item": CONFIG["queue_item"],
                             "identity": {"designation": IDENTITY,
                                          "form": CONFIG["identity"]["form"],
                                          "specimen_id": SPECIMEN,
                                          "public_address": ADDRESS,
                                          "key_fingerprint": CONFIG["identity"]["key_fingerprint"]},
                             "custody": {"specimen_status": entry["status"] if entry else "UNKNOWN",
                                         "deposit_seq": entry["deposit_seq"] if entry else None,
                                         "skap_chain_receipts": skap_tail_seq(),
                                         "material_policy": CONFIG["custody"]["material_policy"]},
                             "chain": CHAIN.totals()})
        elif self.path == "/replay":
            self._json(200, replay())
        else:
            self._json(404, {"error": "not found"})
    def do_POST(self):
        try:
            if self.path == "/sign":
                self._sign()
            else:
                self._json(404, {"error": "not found"})
        except Exception as e:
            self._json(500, {"error": f"{type(e).__name__}: {e}"})
    def _refuse(self, base, detail, http_code=422):
        pair_id, recs = CHAIN.issue_pair("REFUSAL", base, "FAIL_CLOSED", detail)
        self._json(http_code, {"disposition": "FAIL_CLOSED", "executed": False,
                               "signed": False, **detail,
                               "refusal_pair_id": pair_id,
                               "refusal_record_pair": recs})
    def _sign(self):
        req = self._body()
        request_id = uuid.uuid4().hex[:16]
        base = {"request_id": request_id,
                "requester": req.get("requester") or "machine-economy-endpoint",
                "identity": req.get("identity"),
                "payload_digest": req.get("payload_digest")}
        # --- admission (precedes any custody contact) ---
        if req.get("identity") != IDENTITY:
            self._refuse(base, six_field(
                "IDENTITY_NOT_ADMITTED",
                "the signing identity is the designated machine-economy identity 8374",
                "present identity '8374'; signing keys are held per designated identity and no other identity is admitted by this operation",
                "POST /sign with identity 8374", "caller correction"))
            return
        pd = req.get("payload_digest")
        ok_digest = isinstance(pd, str) and len(pd) == 64
        if ok_digest:
            try:
                bytes.fromhex(pd)
            except ValueError:
                ok_digest = False
        if not ok_digest:
            self._refuse(base, six_field(
                "PAYLOAD_DIGEST_MALFORMED",
                "payload_digest is a well-formed SHA-256 digest (64 hex characters)",
                "present payload_digest as the 64-hex SHA-256 of the payload to sign",
                "POST /sign with a well-formed payload_digest", "caller correction"))
            return
        ref = req.get("authorization_ref")
        if not isinstance(ref, str) or not hmac.compare_digest(ref, ADMITTED_REF):
            self._refuse(base, six_field(
                "AUTHORIZATION_NOT_ADMITTED",
                "authorization_ref equals the admitted BUILD-Q-14 authorization artifact digest (AUTH-BUILD-Q-14-SIGN-UNDER-SEAL-01)",
                "present the authorization_ref of the admitted authorization record filed with the key birth record (Drive 182btznFcJ9FjWJi6jFmhWh20Sz7UqYY3)",
                "POST /sign with the admitted authorization_ref", "caller correction"))
            return
        # --- governed retrieval + sign, serialized (SKAP chain is append-only) ---
        with SIGN_LOCK:
            purpose = "sign-under-seal (BUILD-Q-14)"
            ctx = f"skap-signing /sign req {request_id}"
            try:
                grant = retrieval.issue_grant(TREE, AUTHORITY, SKAP_CHAIN,
                                              SPECIMEN, purpose, ctx, 120)
                material = retrieval.retrieve(TREE, AUTHORITY, SKAP_CHAIN,
                                              grant, purpose, ctx)
            except retrieval.FailClosed as e:
                self._refuse(base, six_field(
                    "SKAP_RETRIEVAL_DENIED",
                    f"governed SKAP retrieval admits specimen {SPECIMEN} for this call (C-02 denial: {e.reason})",
                    "the specimen must be SEALED (not revoked) and the Authority grant valid; see the SKAP chain RETRIEVAL_DENIED receipt for this call",
                    "POST /sign after the custody state is repaired", "custody repair"))
                return
            ba = bytearray(material)
            material = None
            try:
                n = int.from_bytes(ba, "big")
            finally:
                for i in range(len(ba)):
                    ba[i] = 0
            priv = ec.derive_private_key(n, ec.SECP256K1())
            n = 0
            sig = priv.sign(bytes.fromhex(pd), ec.ECDSA(Prehashed(SHA256())))
            del priv
            sig_hex = sig.hex()
            base.update({"signature_sha256": hashlib.sha256(sig).hexdigest(),
                         "public_address": ADDRESS,
                         "skap_grant_id": grant["grant_id"],
                         "skap_retrieval_seq": skap_tail_seq()})
            pair_id, recs = CHAIN.issue_pair("SIGNING", base, "ALLOW")
            self._json(200, {"disposition": "ALLOW", "executed": True, "signed": True,
                             "signature": sig_hex,
                             "signature_format": CONFIG["signing"]["signature_format"],
                             "scheme": CONFIG["signing"]["scheme"],
                             "public_address": ADDRESS,
                             "payload_digest": pd,
                             "pair_id": pair_id,
                             "receipt_pair": recs,
                             "skap": {"grant_id": grant["grant_id"],
                                      "retrieval_seq": base["skap_retrieval_seq"],
                                      "specimen_id": SPECIMEN}})

if __name__ == "__main__":
    print(f"skap-signing on 127.0.0.1:{PORT}, identity {IDENTITY}, specimen "
          f"{SPECIMEN}, chain: {CHAIN.totals()}")
    ThreadingHTTPServer(("127.0.0.1", PORT), H).serve_forever()
