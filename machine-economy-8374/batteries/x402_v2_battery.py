#!/usr/bin/env python3
"""BUILD-Q-48 acceptance battery: x402 v2 dual-stack.

Runs against a THROWAWAY endpoint instance (its own receipts dir) —
never the live chain. Usage:
    python3 x402_v2_battery.py [base_url]   (default http://127.0.0.1:8899)

Cases: unpaid POST/GET/HEAD -> 402 carrying BOTH the v1 body and
the PAYMENT-REQUIRED header (decodes to a v2 PaymentRequired naming
the same receptor and tier amount); a valid v2 PAYMENT-SIGNATURE ->
ALLOW with v2 payment evidence in the pair and a PAYMENT-RESPONSE
header; accepted-requirements mismatch -> PAYMENT_REQUIREMENTS_
MISMATCH; wrong x402Version in the v2 envelope -> PAYMENT_VERSION_
UNSUPPORTED; tampered signature -> PAYMENT_SIGNATURE_INVALID;
replayed v2 nonce -> PAYMENT_NONCE_REUSED; full-evaluation tier
under v2 -> ALLOW. Every presented-but-invalid payment must
receipt a refusal pair; the 402 path receipts nothing.

Offer v07 (BUILD-Q-43): the challenge amount in BOTH stacks is the
TOTAL for the crossing -- governance fee + the settlement charge
quoted at challenge time. This battery reads the total from the
live challenge, asserts the v1 body and the v2 header agree on it,
and signs exactly that.
"""
import base64, json, sys, time, urllib.request, urllib.error
import os as _os
sys.path.insert(0, _os.path.join(_os.path.dirname(_os.path.abspath(__file__)), "..", "operation"))
from x402_specimen import new_keypair, make_payment_header

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8899"
PAYTO = "0x7721aB66161e60fCcA59CCe2A86817cbdd9b16Be"
USDC = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"
RESULTS = []

def check(name, ok, evidence):
    RESULTS.append((name, ok, evidence))
    print(("PASS " if ok else "FAIL ") + name + " — " + evidence)

def call(method, path, body=None, headers=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(BASE + path, data=data, method=method)
    req.add_header("Content-Type", "application/json")
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, dict(r.headers), json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        raw = e.read()
        try:
            parsed = json.loads(raw or b"{}")
        except Exception:
            parsed = {}
        return e.code, dict(e.headers), parsed

def b64dec(s):
    return json.loads(base64.b64decode(s))

def v2_header(priv, payer, tier_amount, tier="receipt-only",
              valid_before=None, tamper=False, accepted_mut=None):
    """Build a PAYMENT-SIGNATURE value: sign the EIP-3009
    authorization via the specimen signer, then wrap it in the v2
    envelope echoing the offered requirements."""
    now = int(time.time())
    hdr1, auth, _digest = make_payment_header(
        priv, payer, PAYTO, tier_amount, now - 10,
        valid_before if valid_before is not None else now + 600)
    sig = json.loads(base64.b64decode(hdr1))["payload"]["signature"]
    if tamper:
        # Corrupt the first byte of r. (Flipping the v byte is NOT a
        # tamper: v in {0, 27} both map to recovery id 0.)
        sig = sig[:2] + ("00" if sig[2:4] != "00" else "ff") + sig[4:]
    accepted = {"scheme": "exact", "network": "eip155:8453",
                "amount": str(tier_amount), "asset": USDC,
                "payTo": PAYTO, "maxTimeoutSeconds": 60,
                "extra": {"name": "USD Coin", "version": "2"}}
    if accepted_mut:
        accepted_mut(accepted)
    payload = {"x402Version": 2,
               "resource": {"url": BASE + "/crossing",
                            "mimeType": "application/json"},
               "accepted": accepted,
               "payload": {"signature": sig, "authorization": auth},
               "extensions": {}}
    return base64.b64encode(json.dumps(payload).encode()).decode()

BODY = {"counterparty": "v2-battery", "action": "evaluate",
        "scope_ref": "ME-EVAL-01", "resource": "governed-evaluation"}

# 1. Unpaid POST: dual-stack challenge. v07: the v1 body's
# maxAmountRequired and the v2 header's amount are the same TOTAL
# (governance fee 500 + settlement charge > 0).
st, hd, bd = call("POST", "/crossing", BODY)
pr = hd.get("Payment-Required") or hd.get("PAYMENT-REQUIRED")
v1_acc = (bd.get("accepts") or [{}])[0]
TOTAL = int(v1_acc.get("maxAmountRequired") or 0)
ok = st == 402 and bd.get("x402Version") == 1 and pr is not None
detail = f"status {st}, body v{bd.get('x402Version')}, header {'present' if pr else 'MISSING'}"
if pr:
    v2 = b64dec(pr)
    a0 = (v2.get("accepts") or [{}])[0]
    ok = ok and v2.get("x402Version") == 2 \
        and a0.get("amount") == str(TOTAL) \
        and TOTAL > 500 \
        and v1_acc.get("governance_fee_micro_usdc") == 500 \
        and v1_acc.get("settlement_charge_micro_usdc") == TOTAL - 500 \
        and (v2.get("pricing") or {}).get("total_micro_usdc") == TOTAL \
        and a0.get("payTo") == PAYTO \
        and a0.get("asset") == USDC \
        and a0.get("network") == "eip155:8453" \
        and (a0.get("extra") or {}).get("name") == "USD Coin" \
        and "bazaar" in (v2.get("extensions") or {})
    detail += f", v1/v2 total {TOTAL} (fee 500 + charge {TOTAL - 500}), bazaar {'yes' if 'bazaar' in (v2.get('extensions') or {}) else 'no'}"
check("unpaid POST -> 402 dual-stack (v1 body + v2 header)", ok, detail)

# 2. Unpaid GET and HEAD carry the v2 header too.
def _hdr(hd, name):
    for k, v in hd.items():
        if k.lower() == name.lower():
            return v
    return None

st_g, hd_g, _ = call("GET", "/crossing")
st_h, hd_h, _ = call("HEAD", "/crossing")
check("unpaid GET/HEAD -> 402 with PAYMENT-REQUIRED",
      st_g == 402 and st_h == 402
      and (_hdr(hd_g, "PAYMENT-REQUIRED") is not None)
      and (_hdr(hd_h, "PAYMENT-REQUIRED") is not None),
      f"GET {st_g} header {'y' if _hdr(hd_g, 'PAYMENT-REQUIRED') else 'n'}, "
      f"HEAD {st_h} header {'y' if _hdr(hd_h, 'PAYMENT-REQUIRED') else 'n'}")

# 3. Valid v2 payment -> ALLOW + evidence + PAYMENT-RESPONSE.
priv, payer = new_keypair()
hdr = v2_header(priv, payer, TOTAL)
st, hd, bd = call("POST", "/crossing", BODY,
                  {"PAYMENT-SIGNATURE": hdr})
pay = bd.get("payment") or {}
presp = _hdr(hd, "PAYMENT-RESPONSE")
ok = st == 200 and bd.get("disposition") == "ALLOW" \
    and pay.get("x402_version") == 2 \
    and pay.get("payment_header") == "PAYMENT-SIGNATURE" \
    and pay.get("governance_fee_micro_usdc") == 500 \
    and pay.get("settlement_charge_micro_usdc") == TOTAL - 500 \
    and pay.get("total_authorized_micro_usdc") == TOTAL \
    and presp is not None
detail = f"status {st}, disp {bd.get('disposition')}, evidence v{pay.get('x402_version')}, PAYMENT-RESPONSE {'present' if presp else 'MISSING'}"
if presp:
    sr = b64dec(presp)
    ok = ok and sr.get("network") == "eip155:8453" \
        and sr.get("payer", "").lower() == payer.lower() \
        and "success" in sr
    detail += f", settle-response success={sr.get('success')} payer match"
check("valid v2 payment -> ALLOW with PAYMENT-RESPONSE", ok, detail)

# 4. Same v2 payment replayed -> nonce refused.
st, hd, bd = call("POST", "/crossing", BODY,
                  {"PAYMENT-SIGNATURE": hdr})
check("replayed v2 nonce -> PAYMENT_NONCE_REUSED",
      st == 422 and bd.get("failure_code") == "PAYMENT_NONCE_REUSED",
      f"status {st}, code {bd.get('failure_code')}")

# 5. Accepted-amount mismatch -> requirements refused.
priv2, payer2 = new_keypair()
hdr_bad = v2_header(priv2, payer2, TOTAL,
                    accepted_mut=lambda a: a.update(amount=str(TOTAL + 1)))
st, hd, bd = call("POST", "/crossing", BODY,
                  {"PAYMENT-SIGNATURE": hdr_bad})
check("accepted amount mismatch -> PAYMENT_REQUIREMENTS_MISMATCH",
      st == 422 and bd.get("failure_code") == "PAYMENT_REQUIREMENTS_MISMATCH",
      f"status {st}, code {bd.get('failure_code')}")

# 6. v2 envelope with x402Version 1 -> version refused.
raw = json.loads(base64.b64decode(hdr_bad))
raw["x402Version"] = 1
hdr_ver = base64.b64encode(json.dumps(raw).encode()).decode()
st, hd, bd = call("POST", "/crossing", BODY,
                  {"PAYMENT-SIGNATURE": hdr_ver})
check("wrong envelope version -> PAYMENT_VERSION_UNSUPPORTED",
      st == 422 and bd.get("failure_code") == "PAYMENT_VERSION_UNSUPPORTED",
      f"status {st}, code {bd.get('failure_code')}")

# 7. Tampered signature -> signature refused.
priv3, payer3 = new_keypair()
hdr_sig = v2_header(priv3, payer3, TOTAL, tamper=True)
st, hd, bd = call("POST", "/crossing", BODY,
                  {"PAYMENT-SIGNATURE": hdr_sig})
check("tampered signature -> PAYMENT_SIGNATURE_INVALID",
      st == 422 and bd.get("failure_code") == "PAYMENT_SIGNATURE_INVALID",
      f"status {st}, code {bd.get('failure_code')}")

# 8. Full-evaluation tier under v2 -> ALLOW at 15000. The
# full-evaluation grammar requires the commit-time evidence object
# in the body (the v1 battery's specimen shape).
priv4, payer4 = new_keypair()
body_full = dict(BODY, tier="full-evaluation", evidence={
    "authority": "battery specimen authority (self-presented)",
    "delegation": "no delegation",
    "evidence_refs": ["x402_v2_battery.py specimen run"],
    "exclusions": [],
    "policy": "ME-POLICY-01", "validity_at_commit": True})
st_f, hd_f, bd_f = call("POST", "/crossing", body_full)
FULL_TOTAL = int(((bd_f.get("accepts") or [{}])[0]).get("maxAmountRequired") or 0)
hdr_full = v2_header(priv4, payer4, FULL_TOTAL, tier="full-evaluation")
st, hd, bd = call("POST", "/crossing", body_full,
                  {"PAYMENT-SIGNATURE": hdr_full})
pay = bd.get("payment") or {}
check("full-evaluation v2 payment -> ALLOW",
      st == 200 and bd.get("disposition") == "ALLOW"
      and pay.get("value_micro_usdc") == FULL_TOTAL
      and pay.get("governance_fee_micro_usdc") == 15000,
      f"status {st}, disp {bd.get('disposition')}, value {pay.get('value_micro_usdc')} (fee 15000 + charge {FULL_TOTAL - 15000})")

fails = [n for n, ok, _ in RESULTS if not ok]
print(f"\n{len(RESULTS) - len(fails)}/{len(RESULTS)} PASS"
      + (f" — FAILING: {fails}" if fails else ""))
sys.exit(1 if fails else 0)
