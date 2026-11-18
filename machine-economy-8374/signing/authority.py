#!/usr/bin/env python3
"""Production-form Authority store for a lane site (BUILD-Q-33).

Replaces the proving form's scope-less, expiry-less bearer digest
with governed grants. A grant is:

  - SCOPED: it names exactly one (scope_ref, action, resource)
    triple; a request outside that triple is refused;
  - EXPIRING: it carries valid_before (unix seconds); a request at
    or after that instant is refused;
  - REVOCABLE: the store carries a revocation list, checked at
    admission on every call; a revoked grant is refused;
  - SINGLE-USE: a grant is consumed by the first admitted use.

Every store event (ISSUE / CONSUME / REVOKE / REFUSE) is appended to
a hash-chained log beside the store (authority_log.jsonl), so the
grant history of a site is replayable. The store itself is one JSON
file, written atomically (tmp + rename + fsync). Stdlib only.

CLI (the site operator's surface):
  authority.py --store PATH issue --scope-ref S --action A \
      --resource R --ttl SECONDS [--requester NAME]
      -> prints the grant as JSON, including the one-time token.
         The token is the authorization_ref a caller presents.
  authority.py --store PATH revoke --grant-id ID
  authority.py --store PATH list
  authority.py --store PATH verify-log
"""
import argparse, hashlib, json, os, secrets, sys, threading
from datetime import datetime, timezone

LOCK = threading.Lock()

def now_iso():
    return datetime.now(timezone.utc).isoformat()

def _canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()

class AuthorityStore:
    def __init__(self, store_path):
        self.path = store_path
        self.log_path = store_path + ".log.jsonl"
        os.makedirs(os.path.dirname(os.path.abspath(store_path)),
                    exist_ok=True)
        if not os.path.exists(self.path):
            self._save({"grants": [], "revocations": []})
        if not os.path.exists(self.log_path):
            with open(self.log_path, "a") as f:
                f.flush(); os.fsync(f.fileno())

    # ---------- persistence ----------
    def _load(self):
        with open(self.path) as f:
            return json.load(f)

    def _save(self, doc):
        tmp = self.path + ".tmp"
        with open(tmp, "w") as f:
            json.dump(doc, f, indent=1, sort_keys=True)
            f.write("\n"); f.flush(); os.fsync(f.fileno())
        os.replace(tmp, self.path)
        fd = os.open(os.path.dirname(os.path.abspath(self.path)),
                     os.O_RDONLY)
        try: os.fsync(fd)
        finally: os.close(fd)

    def _log(self, event, detail):
        prev = "GENESIS"
        try:
            with open(self.log_path, "rb") as f:
                data = f.read().decode().strip()
            if data:
                prev = json.loads(data.splitlines()[-1])["hash"]
        except (OSError, ValueError):
            prev = "GENESIS"
        rec = {"ts": now_iso(), "event": event, "detail": detail,
               "prev": prev}
        rec["hash"] = hashlib.sha256(
            prev.encode() + _canonical(
                {k: rec[k] for k in ("ts", "event", "detail")})).hexdigest()
        with open(self.log_path, "a") as f:
            f.write(json.dumps(rec, sort_keys=True) + "\n")
            f.flush(); os.fsync(f.fileno())
        return rec

    # ---------- grant lifecycle ----------
    def issue(self, scope_ref, action, resource, ttl_seconds,
              requester="site-operator"):
        import time
        with LOCK:
            doc = self._load()
            grant_id = "GRT-" + secrets.token_hex(6)
            token = secrets.token_hex(32)
            g = {"grant_id": grant_id, "token_sha256":
                 hashlib.sha256(token.encode()).hexdigest(),
                 "scope_ref": scope_ref, "action": action,
                 "resource": resource, "requester": requester,
                 "issued_at": now_iso(),
                 "valid_before": int(time.time()) + int(ttl_seconds),
                 "used": False, "revoked": False}
            doc["grants"].append(g)
            self._save(doc)
            self._log("ISSUE", {"grant_id": grant_id,
                                "scope_ref": scope_ref, "action": action,
                                "resource": resource,
                                "valid_before": g["valid_before"],
                                "requester": requester})
            out = dict(g); out["token"] = token
            return out

    def revoke(self, grant_id):
        with LOCK:
            doc = self._load()
            for g in doc["grants"]:
                if g["grant_id"] == grant_id and not g["revoked"]:
                    g["revoked"] = True
                    doc["revocations"].append(
                        {"grant_id": grant_id, "ts": now_iso()})
                    self._save(doc)
                    self._log("REVOKE", {"grant_id": grant_id})
                    return True
            return False

    def check(self, token, scope_ref, action, resource):
        """Admission check. Returns (verdict, grant_or_None, code):
        verdict ALLOW only when the token names a live grant whose
        scope triple matches exactly, unexpired, unrevoked, unused."""
        import time
        if not isinstance(token, str) or not token:
            return ("FAIL_CLOSED", None, "GRANT_NOT_PRESENTED")
        digest = hashlib.sha256(token.encode()).hexdigest()
        doc = self._load()
        grant = None
        import hmac
        for g in doc["grants"]:
            if hmac.compare_digest(g["token_sha256"], digest):
                grant = g; break
        if grant is None:
            self._log("REFUSE", {"code": "GRANT_NOT_ADMITTED",
                                 "scope_ref": scope_ref, "action": action,
                                 "resource": resource})
            return ("FAIL_CLOSED", None, "GRANT_NOT_ADMITTED")
        if grant["revoked"]:
            self._log("REFUSE", {"code": "GRANT_REVOKED",
                                 "grant_id": grant["grant_id"]})
            return ("FAIL_CLOSED", grant, "GRANT_REVOKED")
        if int(time.time()) >= grant["valid_before"]:
            self._log("REFUSE", {"code": "GRANT_EXPIRED",
                                 "grant_id": grant["grant_id"]})
            return ("FAIL_CLOSED", grant, "GRANT_EXPIRED")
        if grant["used"]:
            self._log("REFUSE", {"code": "GRANT_ALREADY_USED",
                                 "grant_id": grant["grant_id"]})
            return ("FAIL_CLOSED", grant, "GRANT_ALREADY_USED")
        if (grant["scope_ref"], grant["action"], grant["resource"]) != \
                (scope_ref, action, resource):
            self._log("REFUSE", {"code": "GRANT_SCOPE_MISMATCH",
                                 "grant_id": grant["grant_id"],
                                 "grant_scope": [grant["scope_ref"],
                                                 grant["action"],
                                                 grant["resource"]],
                                 "request_scope": [scope_ref, action,
                                                   resource]})
            return ("FAIL_CLOSED", grant, "GRANT_SCOPE_MISMATCH")
        return ("ALLOW", grant, None)

    def consume(self, grant_id):
        with LOCK:
            doc = self._load()
            for g in doc["grants"]:
                if g["grant_id"] == grant_id:
                    g["used"] = True
                    self._save(doc)
                    self._log("CONSUME", {"grant_id": grant_id})
                    return True
            return False

    def list_grants(self):
        doc = self._load()
        out = []
        for g in doc["grants"]:
            row = {k: g[k] for k in ("grant_id", "scope_ref", "action",
                                     "resource", "requester", "issued_at",
                                     "valid_before", "used", "revoked")}
            out.append(row)
        return out

    def verify_log(self):
        prev = "GENESIS"; n = 0; problems = []
        try:
            lines = open(self.log_path).read().splitlines()
        except OSError:
            lines = []
        for line in lines:
            if not line.strip():
                continue
            rec = json.loads(line)
            n += 1
            if rec["prev"] != prev:
                problems.append(f"entry {n}: prev linkage broken")
            h = hashlib.sha256(prev.encode() + _canonical(
                {k: rec[k] for k in ("ts", "event", "detail")})).hexdigest()
            if h != rec["hash"]:
                problems.append(f"entry {n}: hash does not recompute")
            prev = rec["hash"]
        return {"verdict": "MATCH" if not problems else "MISMATCH",
                "entries": n, "terminal_anchor": prev,
                "problems": problems}

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--store", required=True)
    sub = ap.add_subparsers(dest="cmd", required=True)
    pi = sub.add_parser("issue")
    pi.add_argument("--scope-ref", required=True)
    pi.add_argument("--action", required=True)
    pi.add_argument("--resource", required=True)
    pi.add_argument("--ttl", type=int, default=300)
    pi.add_argument("--requester", default="site-operator")
    pr = sub.add_parser("revoke"); pr.add_argument("--grant-id", required=True)
    sub.add_parser("list"); sub.add_parser("verify-log")
    a = ap.parse_args()
    store = AuthorityStore(a.store)
    if a.cmd == "issue":
        print(json.dumps(store.issue(a.scope_ref, a.action, a.resource,
                                     a.ttl, a.requester), indent=1))
    elif a.cmd == "revoke":
        print(json.dumps({"revoked": store.revoke(a.grant_id)}))
    elif a.cmd == "list":
        print(json.dumps(store.list_grants(), indent=1))
    elif a.cmd == "verify-log":
        print(json.dumps(store.verify_log(), indent=1))

if __name__ == "__main__":
    main()
