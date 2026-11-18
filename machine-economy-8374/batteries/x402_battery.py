#!/usr/bin/env python3
"""BUILD-Q-18 acceptance battery: x402 payment verification.

Runs against a THROWAWAY endpoint instance (its own receipts dir) —
never the live chain. Usage:
    python3 x402_battery.py [base_url]     (default http://127.0.0.1:8899)

Cases: no header -> 402 with requirements; valid authorization ->
ALLOW with payment evidence in the pair; replayed nonce ->
FAIL_CLOSED PAYMENT_NONCE_REUSED; underpaid -> PAYMENT_VALUE_
INSUFFICIENT; wrong payTo -> PAYMENT_PAYEE_MISMATCH; wrong asset ->
PAYMENT_REQUIREMENTS_MISMATCH; expired -> PAYMENT_AUTHORIZATION_
NOT_IN_WINDOW; garbage signature -> PAYMENT_SIGNATURE_INVALID;
full-evaluation valid -> ALLOW. Every presented-but-invalid payment
must receipt a refusal pair; the 402 path receipts nothing.

Offer v07 (BUILD-Q-43): the challenge amount is the TOTAL for the
crossing -- governance fee + the settlement charge quoted at
challenge time. This battery reads the total from the live
challenge and signs exactly that; the pair's payment evidence must
carry the fee/settlement-charge split.
"""
import json, os, sys, time, urllib.request, urllib.error
import os as _os
sys.path.insert(0, _os.path.join(_os.path.dirname(_os.path.abspath(__file__)), "..", "operation"))
from x402_specimen import new_keypair, make_payment_header, USDC_BASE

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8899"
PAYTO = "0x7721aB66161e60fCcA59CCe2A86817cbdd9b16Be"
RESULTS = []

def check(name, ok, evidence):
    RESULTS.append((name, ok, evidence))
    print(("PASS " if ok else "FAIL ") + name + " — " + evidence)

def call(method, path, body=None, headers=None):
    data = json.dumps(body).encode() if body is not None else None
    r = urllib.request.Request(BASE + path, data=data, method=method,
                               headers={"Content-Type": "application/json",
                                        **(headers or {})})
    try:
        with urllib.request.urlopen(r, timeout=30) as resp:
            return resp.status, json.load(resp)
    except urllib.error.HTTPError as e:
        return e.code, json.load(e)

def pairs_now():
    _c, h = call("GET", "/health")
    return h["metering"]["receipt_pairs"]

def crossing_body(tier="receipt-only", **kw):
    b = {"counterparty": "x402-battery", "action": "evaluate",
         "scope_ref": "ME-EVAL-01", "resource": "governed-evaluation",
         "tier": tier}
    if tier == "full-evaluation":
        b["evidence"] = {
            "authority": "battery specimen authority (self-presented)",
            "delegation": "no delegation",
            "evidence_refs": ["x402_battery.py specimen run"],
            "exclusions": [],
            "policy": "ME-POLICY-01", "validity_at_commit": True}
    b.update(kw)
    return b

def challenge(tier="receipt-only"):
    """The unpaid challenge for a tier: (total_micro, accepts[0])."""
    _code, body = call("POST", "/crossing", crossing_body(tier))
    acc = body.get("accepts", [{}])[0]
    return int(acc.get("maxAmountRequired")), acc

def main():
    priv, payer = new_keypair()
    print(f"specimen payer (throwaway, unfunded): {payer}")
    now_ts = int(time.time())
    p0 = pairs_now()

    # 1. no header -> 402 with requirements, nothing receipted.
    # v07: maxAmountRequired is the TOTAL (governance fee 500 +
    # settlement charge > 0), with the split stated in the accepts.
    code, body = call("POST", "/crossing", crossing_body())
    acc = body.get("accepts", [{}])[0]
    total, _a = challenge()
    charge = total - 500
    check("no-header 402", code == 402
          and acc.get("network") == "eip155:8453"
          and acc.get("asset") == USDC_BASE
          and acc.get("payTo") == PAYTO
          and acc.get("maxAmountRequired") == str(total)
          and total > 500
          and acc.get("governance_fee_micro_usdc") == 500
          and acc.get("settlement_charge_micro_usdc") == charge
          and acc.get("total_micro_usdc") == total
          and pairs_now() == p0,
          f"HTTP {code}, maxAmountRequired={acc.get('maxAmountRequired')} (fee 500 + charge {charge}), pairs {p0}->{pairs_now()}")

    # 2. valid authorization -> ALLOW, payment evidence in the pair
    hdr, auth, dg = make_payment_header(priv, payer, PAYTO, total,
                                        now_ts - 10, now_ts + 3600)
    code, body = call("POST", "/crossing", crossing_body(),
                      {"X-PAYMENT": hdr})
    pay = body.get("payment") or {}
    pair_pay = ((body.get("receipt_pair") or [{}, {}])[0].get("content")
                or {}).get("payment") or {}
    check("valid authorization ALLOW", code == 200
          and body.get("disposition") == "ALLOW"
          and pay.get("authorization_digest") == dg
          and pair_pay.get("authorization_digest") == dg
          and pair_pay.get("nonce") == auth["nonce"]
          and pair_pay.get("signature_verified") is True
          and pair_pay.get("governance_fee_micro_usdc") == 500
          and pair_pay.get("settlement_charge_micro_usdc") == charge
          and pair_pay.get("total_authorized_micro_usdc") == total,
          f"HTTP {code}, pair={body.get('pair_id')}, auth_digest={dg[:18]}…, split fee 500 + charge {charge} = {total}")

    # 3. replayed nonce -> FAIL_CLOSED PAYMENT_NONCE_REUSED
    code, body = call("POST", "/crossing", crossing_body(),
                      {"X-PAYMENT": hdr})
    check("replayed nonce", code == 422
          and body.get("failure_code") == "PAYMENT_NONCE_REUSED"
          and body.get("refusal_pair_id"),
          f"HTTP {code}, code={body.get('failure_code')}, refusal={body.get('refusal_pair_id')}")

    # 4. underpaid -> PAYMENT_VALUE_INSUFFICIENT
    hdr2, _a, _d = make_payment_header(priv, payer, PAYTO, total - 1,
                                       now_ts - 10, now_ts + 3600)
    code, body = call("POST", "/crossing", crossing_body(),
                      {"X-PAYMENT": hdr2})
    check("underpaid", code == 422
          and body.get("failure_code") == "PAYMENT_VALUE_INSUFFICIENT",
          f"HTTP {code}, code={body.get('failure_code')}")

    # 5. wrong payTo -> PAYMENT_PAYEE_MISMATCH
    hdr3, _a, _d = make_payment_header(
        priv, payer, "0x000000000000000000000000000000000000dEaD", total,
        now_ts - 10, now_ts + 3600)
    code, body = call("POST", "/crossing", crossing_body(),
                      {"X-PAYMENT": hdr3})
    check("wrong payTo", code == 422
          and body.get("failure_code") == "PAYMENT_PAYEE_MISMATCH",
          f"HTTP {code}, code={body.get('failure_code')}")

    # 6. wrong asset named in payload -> PAYMENT_REQUIREMENTS_MISMATCH
    hdr4, _a, _d = make_payment_header(
        priv, payer, PAYTO, total, now_ts - 10, now_ts + 3600,
        asset="0x0000000000000000000000000000000000000000")
    code, body = call("POST", "/crossing", crossing_body(),
                      {"X-PAYMENT": hdr4})
    check("wrong asset", code == 422
          and body.get("failure_code") == "PAYMENT_REQUIREMENTS_MISMATCH",
          f"HTTP {code}, code={body.get('failure_code')}")

    # 7. expired -> PAYMENT_AUTHORIZATION_NOT_IN_WINDOW
    hdr5, _a, _d = make_payment_header(priv, payer, PAYTO, total,
                                       now_ts - 7200, now_ts - 3600)
    code, body = call("POST", "/crossing", crossing_body(),
                      {"X-PAYMENT": hdr5})
    check("expired", code == 422
          and body.get("failure_code") == "PAYMENT_AUTHORIZATION_NOT_IN_WINDOW",
          f"HTTP {code}, code={body.get('failure_code')}")

    # 8. garbage signature -> PAYMENT_SIGNATURE_INVALID
    import base64 as _b64
    hdr6, _a, _d = make_payment_header(priv, payer, PAYTO, total,
                                       now_ts - 10, now_ts + 3600)
    pl = json.loads(_b64.b64decode(hdr6))
    pl["payload"]["signature"] = "0x" + "ab" * 65
    hdr6b = _b64.b64encode(json.dumps(pl).encode()).decode()
    code, body = call("POST", "/crossing", crossing_body(),
                      {"X-PAYMENT": hdr6b})
    check("garbage signature", code == 422
          and body.get("failure_code") == "PAYMENT_SIGNATURE_INVALID",
          f"HTTP {code}, code={body.get('failure_code')}")

    # 9. full-evaluation valid -> ALLOW at the tier total
    # (governance fee 15000 + the quoted settlement charge)
    full_total, _fa = challenge("full-evaluation")
    hdr7, _a7, dg7 = make_payment_header(priv, payer, PAYTO, full_total,
                                         now_ts - 10, now_ts + 3600)
    code, body = call("POST", "/crossing", crossing_body("full-evaluation"),
                      {"X-PAYMENT": hdr7})
    check("full-evaluation ALLOW", code == 200
          and body.get("disposition") == "ALLOW"
          and (body.get("payment") or {}).get("value_micro_usdc") == full_total
          and (body.get("payment") or {}).get("governance_fee_micro_usdc") == 15000,
          f"HTTP {code}, pair={body.get('pair_id')}, total={full_total}, auth_digest={dg7[:18]}…")

    # 10. replay verdict on the throwaway chain
    code, rep = call("GET", "/replay")
    check("throwaway replay MATCH", rep.get("verdict") == "MATCH",
          f"verdict={rep.get('verdict')}, pairs={rep.get('pairs')}, anchor={str(rep.get('terminal_anchor'))[:16]}…")

    fails = [r for r in RESULTS if not r[1]]
    print(f"\n{len(RESULTS) - len(fails)}/{len(RESULTS)} PASS")
    sys.exit(1 if fails else 0)

if __name__ == "__main__":
    main()
