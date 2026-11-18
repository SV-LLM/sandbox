#!/usr/bin/env python3
"""Lane-form custody signing service (BUILD-Q-33 production form).

The lane-site form of the 8374 sign-under-seal operation. It differs
from the coordinator node's proving form in exactly the way
BUILD-Q-33 requires: admission no longer rests on a scope-less,
expiry-less bearer digest. Per signing call this service:

  1. admits the request — identity, well-formed SHA-256 payload
     digest, and an AUTHORITY GRANT presented as authorization_ref.
     The grant is issued by the site's own Authority store
     (authority.py) and must name the admitted signing scope triple
     (scope_ref / action / resource from this service's config),
     be unexpired, unrevoked, and unused. The grant is consumed by
     the admitted call (single-use). Every refusal is FAIL_CLOSED
     with the six-field disposition and a refusal pair on this
     service's own chain;
  2. loads the site's own signing specimen from the site SKAP tree
     (custody slot: specimen_key.json, mode 0600, born at the site
     by the host bootstrap — never copied from another site),
     signs the payload digest in memory (ECDSA / secp256k1,
     Prehashed, DER), and zeroizes the material;
  3. returns {signature, public_address, receipt_pair} — the pair
     being dual records on this service's hash-chained chain.

If the custody slot is unfilled (no specimen / no Authority store),
every signing request fails closed with failure_code
SIGNING_CUSTODY_SLOTS_UNFILLED. Localhost only. Stdlib only; the
secp256k1 arithmetic is the operation's own pure-Python form
(../operation/x402_specimen.py).
"""
import hashlib, json, os, sys, threading, uuid
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

BASE = os.path.dirname(os.path.abspath(__file__))
CONFIG = json.load(open(os.path.join(BASE, "config.json")))
sys.path.insert(0, os.path.join(BASE, "..", "operation"))
sys.path.insert(0, BASE)
from x402_specimen import _mul, G, N, P as _P  # noqa: E402
from authority import AuthorityStore  # noqa: E402

SEG_DIR = os.path.join(BASE, "receipts")
PORT = int(os.environ.get("SKAP_SIGNING_PORT", str(CONFIG.get("port", 8795))))
SEGMENT_MAX = 500
os.makedirs(SEG_DIR, exist_ok=True)

IDENTITY = CONFIG["identity"]["designation"]
SPECIMEN = CONFIG["identity"]["specimen_id"]
ADDRESS = CONFIG["identity"]["public_address"]
ADMITTED_SCOPE = CONFIG["admitted_scope"]
TREE = CONFIG["custody"]["skap_tree"]
STORE_PATH = CONFIG["custody"]["authority_store"]
SPECIMEN_FILE = os.path.join(TREE, "specimen_key.json")
OWNING_GOAL = "MACHINE-ECONOMY-ENTRY-01 / BUILD-Q-33"
SIGN_LOCK = threading.Lock()

def now():
    return datetime.now(timezone.utc).isoformat()

def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()

def digest(prev, content):
    return hashlib.sha256(prev.encode() + canonical(content)).hexdigest()

def _fsync_dir(d):
    fd = os.open(d, os.O_RDONLY)
    try: os.fsync(fd)
    finally: os.close(fd)

def _scan_segment(path):
    with open(path, "rb") as f:
        data = f.read()
    entries, pos, n, torn = [], 0, len(data), 0
    while pos < n:
        nl = data.find(b"\n", pos)
        if nl == -1:
            torn = n - pos; break
        raw = data[pos:nl]
        if raw.strip():
            try: entries.append(json.loads(raw))
            except ValueError:
                if nl == n - 1: torn = n - pos
                else: raise ValueError(f"{os.path.basename(path)}: "
                                       "undecodable line inside sealed span")
                break
        pos = nl + 1
    return entries, torn

class ReceiptChain:
    def __init__(self, seg_dir):
        self.dir = seg_dir; self.lock = threading.Lock()
        self.i = 0; self.prev = "GENESIS"; self.pairs = 0; self.pair_seq = 0
        self.by_disp = {"ALLOW": 0, "DENY": 0, "FAIL_CLOSED": 0}
        self.seg_no = 1; self.seg_count = 0; self._load()
    def _segments(self):
        return [os.path.join(self.dir, n) for n in sorted(os.listdir(self.dir))
                if n.startswith("segment-") and n.endswith(".jsonl")]
    def _load(self):
        for path in self._segments():
            self.seg_no = int(os.path.basename(path)[8:12]); self.seg_count = 0
            entries, _torn = _scan_segment(path)
            for r in entries:
                self.i = r["i"]; self.prev = r["hash"]; self.seg_count += 1
                c = r["content"]; pid = c.get("pair_id", "")
                if pid.startswith("PAIR-"):
                    self.pair_seq = max(self.pair_seq, int(pid[5:]))
                if c.get("index_in_pair") == 1:
                    self.pairs += 1
                    d = c.get("disposition")
                    if d in self.by_disp: self.by_disp[d] += 1
    def _append(self, content):
        if self.seg_count >= SEGMENT_MAX:
            self.seg_no += 1; self.seg_count = 0
        self.i += 1
        rec = {"i": self.i, "prev": self.prev, "content": content}
        rec["hash"] = digest(self.prev, content)
        path = os.path.join(self.dir, f"segment-{self.seg_no:04d}.jsonl")
        created = not os.path.exists(path)
        with open(path, "a") as f:
            f.write(json.dumps(rec, sort_keys=True) + "\n")
            f.flush(); os.fsync(f.fileno())
        if created: _fsync_dir(self.dir)
        self.prev = rec["hash"]; self.seg_count += 1
        return rec
    def issue_pair(self, kind, base_content, disposition, detail=None):
        with self.lock:
            self.pair_seq += 1
            pair_id = f"PAIR-{self.pair_seq:06d}"
            base = {**base_content, "pair_id": pair_id,
                    "disposition": disposition, "ts": now()}
            if kind == "SIGNING":
                a = self._append({**base, "kind": "SIGNING_OPERATION_SIDE",
                                  "index_in_pair": 0, "side": "operation",
                                  "recorded_by": "lane-signing (StegVerse LLC)"})
                b = self._append({**base, "kind": "SIGNING_REQUESTER_SIDE",
                                  "index_in_pair": 1, "side": "requester",
                                  "recorded_by": base_content.get("requester"),
                                  "pair_anchor": a["hash"]})
            else:
                a = self._append({**base, "kind": "REFUSAL_ATTEMPT",
                                  "index_in_pair": 0, "side": "attempt",
                                  "recorded_by": "lane-signing (StegVerse LLC)",
                                  "executed": False})
                b = self._append({**base, "kind": "REFUSAL_DISPOSITION",
                                  "index_in_pair": 1, "side": "disposition",
                                  "recorded_by": "lane-signing (StegVerse LLC)",
                                  "pair_anchor": a["hash"], "executed": False,
                                  "disposition_detail": detail or {}})
            self.pairs += 1
            if disposition in self.by_disp: self.by_disp[disposition] += 1
            return pair_id, [a, b]
    def totals(self):
        return {"receipt_pairs": self.pairs, "by_disposition": dict(self.by_disp),
                "chain_entries": self.i, "terminal_anchor": self.prev}

CHAIN = ReceiptChain(SEG_DIR)

def replay(seg_dir=SEG_DIR):
    prev = "GENESIS"; i = 0; pairs = {}; problems = []
    names = [n for n in sorted(os.listdir(seg_dir))
             if n.startswith("segment-") and n.endswith(".jsonl")]
    for n in names:
        try: entries, _t = _scan_segment(os.path.join(seg_dir, n))
        except ValueError as e:
            problems.append(str(e)); entries = []
        for r in entries:
            i += 1
            if r["i"] != i: problems.append(f"entry {i}: index gap")
            if r["prev"] != prev: problems.append(f"entry {i}: prev broken")
            if digest(r["prev"], r["content"]) != r["hash"]:
                problems.append(f"entry {i}: hash does not recompute")
            prev = r["hash"]
            pairs.setdefault(r["content"]["pair_id"], []).append(r["content"])
    for pid, members in pairs.items():
        if len(members) != 2:
            problems.append(f"{pid}: {len(members)} members, pair unmatched")
    return {"verdict": "MISMATCH" if problems else "MATCH",
            "entries": i, "pairs": len(pairs), "terminal_anchor": prev,
            "problems": problems}

def six_field(failure_code, failed_predicate, repair, retry, next_attempt):
    return {"failure_code": failure_code, "failed_predicate": failed_predicate,
            "required_evidence_or_repair": repair, "retry_entrypoint": retry,
            "owning_goal": OWNING_GOAL, "next_attempt": next_attempt}

def _der_int(x):
    b = x.to_bytes((x.bit_length() + 7) // 8 or 1, "big")
    if b[0] & 0x80: b = b"\x00" + b
    return b"\x02" + bytes([len(b)]) + b

def sign_digest_der(priv, digest_bytes):
    """ECDSA over secp256k1 of a prehashed 32-byte digest; DER out."""
    import secrets as _s
    z = int.from_bytes(digest_bytes, "big")
    while True:
        k = _s.randbelow(N - 1) + 1
        kg = _mul(k, G)
        r = kg[0] % N
        if r == 0: continue
        s = (pow(k, -1, N) * (z + r * priv)) % N
        if s == 0: continue
        if s > N // 2: s = N - s
        body = _der_int(r) + _der_int(s)
        return b"\x30" + bytes([len(body)]) + body

def custody_ready():
    return os.path.exists(SPECIMEN_FILE) and os.path.exists(STORE_PATH)

class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def _json(self, code, obj):
        b = json.dumps(obj, indent=1).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers(); self.wfile.write(b)
    def _body(self):
        n = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(n) if n else b"{}"
        return json.loads(raw or b"{}")
    def do_GET(self):
        if self.path == "/health":
            store_state = {"present": os.path.exists(STORE_PATH)}
            if store_state["present"]:
                store_state["log"] = AuthorityStore(STORE_PATH).verify_log()
            self._json(200, {"status": "ok", "service": CONFIG["service"],
                             "form": "lane (BUILD-Q-33 Authority grants)",
                             "port": PORT, "project_id": CONFIG["project_id"],
                             "queue_item": CONFIG["queue_item"],
                             "identity": {"designation": IDENTITY,
                                          "specimen_id": SPECIMEN,
                                          "public_address": ADDRESS,
                                          "key_fingerprint":
                                              CONFIG["identity"]["key_fingerprint"]},
                             "custody": {"ready": custody_ready(),
                                         "specimen_present":
                                             os.path.exists(SPECIMEN_FILE),
                                         "authority_store": store_state,
                                         "material_policy":
                                             CONFIG["custody"]["material_policy"]},
                             "admitted_scope": ADMITTED_SCOPE,
                             "chain": CHAIN.totals()})
        elif self.path == "/replay":
            self._json(200, replay())
        else:
            self._json(404, {"error": "not found"})
    def do_POST(self):
        try:
            if self.path == "/sign": self._sign()
            else: self._json(404, {"error": "not found"})
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
        if req.get("identity") != IDENTITY:
            self._refuse(base, six_field(
                "IDENTITY_NOT_ADMITTED",
                "the signing identity is the designated machine-economy identity 8374",
                "present identity '8374'; signing keys are held per designated identity",
                "POST /sign with identity 8374", "caller correction"))
            return
        pd = req.get("payload_digest")
        ok_digest = isinstance(pd, str) and len(pd) == 64
        if ok_digest:
            try: bytes.fromhex(pd)
            except ValueError: ok_digest = False
        if not ok_digest:
            self._refuse(base, six_field(
                "PAYLOAD_DIGEST_MALFORMED",
                "payload_digest is a well-formed SHA-256 digest (64 hex characters)",
                "present payload_digest as the 64-hex SHA-256 of the payload to sign",
                "POST /sign with a well-formed payload_digest", "caller correction"))
            return
        if not custody_ready():
            self._refuse(base, six_field(
                "SIGNING_CUSTODY_SLOTS_UNFILLED",
                "the site SKAP tree holds its own born specimen and the Authority store exists",
                "run the host bootstrap (components/host) at the site: it births the specimen into the site SKAP tree and creates the Authority store; key material is never copied from another site",
                "POST /sign after the host bootstrap fills the custody slots",
                "site bootstrap"))
            return
        store = AuthorityStore(STORE_PATH)
        verdict, grant, code = store.check(
            req.get("authorization_ref"), ADMITTED_SCOPE["scope_ref"],
            ADMITTED_SCOPE["action"], ADMITTED_SCOPE["resource"])
        if verdict != "ALLOW":
            repairs = {
                "GRANT_NOT_PRESENTED": "present an Authority grant token as authorization_ref; grants are issued by the site Authority (signing/authority.py issue)",
                "GRANT_NOT_ADMITTED": "present the token of a grant issued by this site's Authority store; unknown tokens are not admitted",
                "GRANT_REVOKED": "the grant was revoked at the site Authority; obtain a fresh grant after the revocation cause is resolved",
                "GRANT_EXPIRED": "the grant's valid_before has passed; obtain a fresh grant from the site Authority",
                "GRANT_ALREADY_USED": "grants are single-use; obtain a fresh grant from the site Authority",
                "GRANT_SCOPE_MISMATCH": "the grant must name the admitted signing scope triple (scope_ref / action / resource in this service's config); obtain a grant for that scope",
            }
            self._refuse(base, six_field(
                "AUTHORIZATION_" + code.replace("GRANT_", ""),
                f"a live Authority grant admits this signing call ({code})",
                repairs.get(code, "obtain a conforming grant from the site Authority"),
                "POST /sign with a live, in-scope Authority grant",
                "caller correction"))
            return
        with SIGN_LOCK:
            store.consume(grant["grant_id"])
            doc = json.load(open(SPECIMEN_FILE))
            raw_key = doc["private_key"]
            if raw_key.startswith("0x"):
                raw_key = raw_key[2:]
            ba = bytearray(bytes.fromhex(raw_key))
            try:
                n = int.from_bytes(ba, "big")
            finally:
                for i in range(len(ba)): ba[i] = 0
            sig = sign_digest_der(n, bytes.fromhex(pd))
            n = 0
            sig_hex = sig.hex()
            base.update({"signature_sha256": hashlib.sha256(sig).hexdigest(),
                         "public_address": ADDRESS,
                         "authority_grant_id": grant["grant_id"],
                         "authority_scope": [grant["scope_ref"],
                                             grant["action"],
                                             grant["resource"]]})
            pair_id, recs = CHAIN.issue_pair("SIGNING", base, "ALLOW")
            self._json(200, {"disposition": "ALLOW", "executed": True,
                             "signed": True, "signature": sig_hex,
                             "signature_format": CONFIG["signing"]["signature_format"],
                             "scheme": CONFIG["signing"]["scheme"],
                             "public_address": ADDRESS, "payload_digest": pd,
                             "pair_id": pair_id, "receipt_pair": recs,
                             "authority": {"grant_id": grant["grant_id"],
                                           "scope_ref": grant["scope_ref"],
                                           "action": grant["action"],
                                           "resource": grant["resource"]}})

if __name__ == "__main__":
    print(f"lane-signing on 127.0.0.1:{PORT}, identity {IDENTITY}, specimen "
          f"{SPECIMEN}, custody_ready={custody_ready()}, chain: {CHAIN.totals()}")
    ThreadingHTTPServer(("127.0.0.1", PORT), H).serve_forever()
