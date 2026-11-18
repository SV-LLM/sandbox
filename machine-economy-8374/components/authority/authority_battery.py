#!/usr/bin/env python3
"""Authority revocation drill battery (BUILD-Q-33).

    python3 authority_battery.py <instance-tree> <endpoint-base-url>

Drives the lane instance's signing service directly and through the
endpoint's /sign route, against the instance's own Authority store:

  1. in-scope grant          -> sign ALLOW, signature verifies
  2. same grant re-presented -> FAIL_CLOSED AUTHORIZATION_ALREADY_USED
  3. grant revoked, then used-> FAIL_CLOSED AUTHORIZATION_REVOKED
  4. grant expired           -> FAIL_CLOSED AUTHORIZATION_EXPIRED
  5. wrong-scope grant       -> FAIL_CLOSED AUTHORIZATION_SCOPE_MISMATCH
  6. unknown token           -> FAIL_CLOSED AUTHORIZATION_NOT_ADMITTED
  7. fresh grant via endpoint /sign -> ALLOW, signed
  8. authority log replays MATCH

Prints one line per leg and a final "authority battery: n/n".
"""
import hashlib, json, os, sys, time, urllib.request, urllib.error

TREE = os.path.abspath(sys.argv[1])
ENDPOINT = sys.argv[2].rstrip("/")
sys.path.insert(0, os.path.join(TREE, "operation"))
sys.path.insert(0, os.path.join(TREE, "signing"))
import x402_specimen as xs
from authority import AuthorityStore

SCFG = json.load(open(os.path.join(TREE, "signing", "config.json")))
SPORT = int(SCFG["port"])
SIGNING = f"http://127.0.0.1:{SPORT}"
STORE = AuthorityStore(SCFG["custody"]["authority_store"])
SCOPE = SCFG["admitted_scope"]
SPEC = json.load(open(os.path.join(
    TREE, "signing", "custody", "specimen_key.json")))

results = []
def leg(name, ok, detail=""):
    results.append(ok)
    print(f"{'PASS' if ok else 'FAIL'}  {name}  {detail}")

def post(url, obj):
    r = urllib.request.Request(url, data=json.dumps(obj).encode(),
                               headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(r, timeout=15) as resp:
            return resp.status, json.load(resp)
    except urllib.error.HTTPError as e:
        return e.code, json.load(e)

DIGEST = hashlib.sha256(b"authority drill payload").hexdigest()

def sign_req(token):
    return {"identity": "8374", "payload_digest": DIGEST,
            "authorization_ref": token,
            "requester": "authority-battery"}

def verify_der(sig_hex, digest_hex, priv):
    raw = bytes.fromhex(sig_hex)
    assert raw[0] == 0x30
    body = raw[2:]
    assert body[0] == 0x02
    ln = body[1]; r = int.from_bytes(body[2:2 + ln], "big")
    rest = body[2 + ln:]
    assert rest[0] == 0x02
    ln2 = rest[1]; s = int.from_bytes(rest[2:2 + ln2], "big")
    z = int.from_bytes(bytes.fromhex(digest_hex), "big")
    q = xs._mul(priv, xs.G)
    w = pow(s, -1, xs.N)
    pt = xs._add(xs._mul((z * w) % xs.N, xs.G), xs._mul((r * w) % xs.N, q))
    return pt is not None and pt[0] % xs.N == r

priv = int(SPEC["private_key"], 16)

# 1. in-scope grant -> ALLOW + signature verifies
g = STORE.issue(SCOPE["scope_ref"], SCOPE["action"], SCOPE["resource"],
                300, "authority-battery")
code, resp = post(SIGNING + "/sign", sign_req(g["token"]))
ok = code == 200 and resp.get("disposition") == "ALLOW" \
    and resp.get("signed") is True \
    and verify_der(resp["signature"], DIGEST, priv)
leg("grant -> sign ALLOW, signature verifies", ok,
    f"http {code}, pair {resp.get('pair_id')}")

# 2. same grant re-presented -> ALREADY_USED
code, resp = post(SIGNING + "/sign", sign_req(g["token"]))
leg("consumed grant re-presented refused",
    code == 422 and resp.get("failure_code") ==
    "AUTHORIZATION_ALREADY_USED", f"http {code}, {resp.get('failure_code')}")

# 3. revoked grant -> REVOKED
g2 = STORE.issue(SCOPE["scope_ref"], SCOPE["action"], SCOPE["resource"],
                 300, "authority-battery")
STORE.revoke(g2["grant_id"])
code, resp = post(SIGNING + "/sign", sign_req(g2["token"]))
leg("revoked grant refused",
    code == 422 and resp.get("failure_code") == "AUTHORIZATION_REVOKED",
    f"http {code}, {resp.get('failure_code')}")

# 4. expired grant -> EXPIRED
g3 = STORE.issue(SCOPE["scope_ref"], SCOPE["action"], SCOPE["resource"],
                 1, "authority-battery")
time.sleep(2)
code, resp = post(SIGNING + "/sign", sign_req(g3["token"]))
leg("expired grant refused",
    code == 422 and resp.get("failure_code") == "AUTHORIZATION_EXPIRED",
    f"http {code}, {resp.get('failure_code')}")

# 5. wrong-scope grant -> SCOPE_MISMATCH
g4 = STORE.issue(SCOPE["scope_ref"], "seal", SCOPE["resource"],
                 300, "authority-battery")
code, resp = post(SIGNING + "/sign", sign_req(g4["token"]))
leg("wrong-scope grant refused",
    code == 422 and resp.get("failure_code") ==
    "AUTHORIZATION_SCOPE_MISMATCH", f"http {code}, {resp.get('failure_code')}")

# 6. unknown token -> NOT_ADMITTED
code, resp = post(SIGNING + "/sign", sign_req("ab" * 32))
leg("unknown token refused",
    code == 422 and resp.get("failure_code") ==
    "AUTHORIZATION_NOT_ADMITTED", f"http {code}, {resp.get('failure_code')}")

# 7. fresh grant through the endpoint /sign route -> ALLOW
g5 = STORE.issue(SCOPE["scope_ref"], SCOPE["action"], SCOPE["resource"],
                 300, "authority-battery")
code, resp = post(ENDPOINT + "/sign",
                  {"identity": "8374", "payload_digest": DIGEST,
                   "authorization_ref": g5["token"],
                   "counterparty": "authority-battery"})
leg("fresh grant via endpoint /sign ALLOW",
    code == 200 and resp.get("disposition") == "ALLOW"
    and resp.get("signed") is True,
    f"http {code}, pair {resp.get('pair_id')}")

# 8. authority log replays MATCH
v = STORE.verify_log()
leg("authority log replays MATCH", v["verdict"] == "MATCH",
    f"{v['entries']} entries, anchor {v['terminal_anchor'][:12]}")

print(f"authority battery: {sum(results)}/{len(results)}")
sys.exit(0 if all(results) else 1)
