#!/usr/bin/env python3
"""BUILD-Q-49 acceptance battery: the ME-AGREE-01 agreement scope.

Runs against a THROWAWAY endpoint instance (its own receipts dir) —
never the live chain. Usage:
    python3 agreement_battery.py [base_url]  (default http://127.0.0.1:8899)

Cases: unpaid POST -> 402 at the full-evaluation TOTAL (governance
fee 15000 + settlement charge, split declared, v1/v2 agree); a valid
ME-AGREE-01 record-agreement crossing -> ALLOW with the fee/charge
split in the pair's payment evidence; the same body WITHOUT the
commit-time evidence object -> FAIL_CLOSED KNOWN_EVIDENCE_MISSING;
wrong action under ME-AGREE-01 and record-agreement under
ME-EVAL-01 -> DENY ACTION_NOT_IN_SCOPE; a replayed nonce ->
PAYMENT_NONCE_REUSED. Every presented-but-refused crossing must
receipt a refusal pair; the 402 path receipts nothing.
"""
import base64, json, sys, time, urllib.request, urllib.error
import os as _os
sys.path.insert(0, _os.path.join(_os.path.dirname(_os.path.abspath(__file__)), "..", "operation"))
from x402_specimen import new_keypair, make_payment_header

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8899"
PAYTO = "0x7721aB66161e60fCcA59CCe2A86817cbdd9b16Be"
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
        with urllib.request.urlopen(req, timeout=60) as r:
            return r.status, dict(r.headers), json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        raw = e.read()
        try:
            parsed = json.loads(raw or b"{}")
        except Exception:
            parsed = {}
        return e.code, dict(e.headers), parsed

def hdr_of(hd, name):
    for k, v in hd.items():
        if k.lower() == name.lower():
            return v
    return None

EVIDENCE = {
    "authority": "battery specimen authority (self-presented)",
    "delegation": "no delegation",
    "evidence_refs": ["agreement_battery.py specimen agreement terms"],
    "exclusions": [],
    "policy": "ME-POLICY-01", "validity_at_commit": True}

BODY = {"counterparty": "agree-battery", "action": "record-agreement",
        "scope_ref": "ME-AGREE-01",
        "resource": "agreement-record:battery-specimen-01",
        "tier": "full-evaluation", "evidence": EVIDENCE}

def challenge_total(body):
    st, hd, bd = call("POST", "/crossing", body)
    acc = (bd.get("accepts") or [{}])[0]
    return st, hd, bd, acc, int(acc.get("maxAmountRequired") or 0)

def pay_header(priv, payer, total):
    now = int(time.time())
    hdr, _auth, _digest = make_payment_header(
        priv, payer, PAYTO, total, now - 10, now + 600)
    return hdr

# 1. Unpaid POST -> 402 at the full-evaluation total, split declared,
# v1 body and v2 header agree.
st, hd, bd, acc, TOTAL = challenge_total(BODY)
pr = hdr_of(hd, "PAYMENT-REQUIRED")
ok = st == 402 and TOTAL > 15000 \
    and acc.get("governance_fee_micro_usdc") == 15000 \
    and acc.get("settlement_charge_micro_usdc") == TOTAL - 15000 \
    and acc.get("tier") == "full-evaluation" and pr is not None
detail = f"status {st}, total {TOTAL} (fee 15000 + charge {TOTAL - 15000})"
if pr:
    v2 = json.loads(base64.b64decode(pr))
    a0 = (v2.get("accepts") or [{}])[0]
    ok = ok and a0.get("amount") == str(TOTAL) \
        and a0.get("payTo") == PAYTO
    detail += f", v2 amount {a0.get('amount')}"
check("unpaid POST -> 402 full-evaluation total with fee/charge split",
      ok, detail)

# 2. Valid ME-AGREE-01 crossing -> ALLOW, split in pair evidence,
# settlement attempted (throwaway relayer is unfunded: its named
# failure is the expected settlement record, not a refusal).
priv, payer = new_keypair()
body2 = dict(BODY, counterparty=payer)
hdr = pay_header(priv, payer, TOTAL)
st, hd, bd = call("POST", "/crossing", body2, {"X-PAYMENT": hdr})
pay = bd.get("payment") or {}
settle = bd.get("settlement") or {}
check("valid record-agreement -> ALLOW with split in evidence",
      st == 200 and bd.get("disposition") == "ALLOW"
      and bd.get("pair_id")
      and pay.get("governance_fee_micro_usdc") == 15000
      and pay.get("settlement_charge_micro_usdc") == TOTAL - 15000
      and pay.get("total_authorized_micro_usdc") == TOTAL
      and pay.get("value_micro_usdc") == TOTAL
      and settle.get("status") is not None,
      f"status {st}, disp {bd.get('disposition')}, pair {bd.get('pair_id')}, "
      f"fee {pay.get('governance_fee_micro_usdc')} + charge "
      f"{pay.get('settlement_charge_micro_usdc')} = "
      f"{pay.get('total_authorized_micro_usdc')}, settlement "
      f"{settle.get('status')}")

# 3. Missing evidence object -> FAIL_CLOSED KNOWN_EVIDENCE_MISSING.
priv3, payer3 = new_keypair()
body3 = {k: v for k, v in BODY.items() if k != "evidence"}
body3["counterparty"] = payer3
hdr3 = pay_header(priv3, payer3, TOTAL)
st, hd, bd = call("POST", "/crossing", body3, {"X-PAYMENT": hdr3})
check("missing evidence object -> FAIL_CLOSED KNOWN_EVIDENCE_MISSING",
      st == 422 and bd.get("disposition") == "FAIL_CLOSED"
      and bd.get("failure_code") == "KNOWN_EVIDENCE_MISSING"
      and bd.get("refusal_pair_id"),
      f"status {st}, code {bd.get('failure_code')}, "
      f"refusal pair {bd.get('refusal_pair_id')}")

# 4. Wrong scope/action -> DENY ACTION_NOT_IN_SCOPE, both directions.
priv4, payer4 = new_keypair()
body4 = dict(BODY, counterparty=payer4, action="evaluate")
hdr4 = pay_header(priv4, payer4, TOTAL)
st_a, _h, bd_a = call("POST", "/crossing", body4, {"X-PAYMENT": hdr4})
priv5, payer5 = new_keypair()
body5 = dict(BODY, counterparty=payer5, scope_ref="ME-EVAL-01")
hdr5 = pay_header(priv5, payer5, TOTAL)
st_b, _h, bd_b = call("POST", "/crossing", body5, {"X-PAYMENT": hdr5})
check("wrong scope/action -> DENY ACTION_NOT_IN_SCOPE",
      st_a == 422 and bd_a.get("disposition") == "DENY"
      and bd_a.get("failure_code") == "ACTION_NOT_IN_SCOPE"
      and st_b == 422 and bd_b.get("disposition") == "DENY"
      and bd_b.get("failure_code") == "ACTION_NOT_IN_SCOPE",
      f"evaluate@ME-AGREE-01: {st_a}/{bd_a.get('failure_code')}; "
      f"record-agreement@ME-EVAL-01: {st_b}/{bd_b.get('failure_code')}")

# 5. Replayed nonce (case 2's exact payment) -> PAYMENT_NONCE_REUSED.
st, hd, bd = call("POST", "/crossing", body2, {"X-PAYMENT": hdr})
check("replayed nonce -> PAYMENT_NONCE_REUSED",
      st == 422 and bd.get("failure_code") == "PAYMENT_NONCE_REUSED",
      f"status {st}, code {bd.get('failure_code')}")

fails = [n for n, ok, _ in RESULTS if not ok]
print(f"\n{len(RESULTS) - len(fails)}/{len(RESULTS)} PASS"
      + (f" — FAILING: {fails}" if fails else ""))
sys.exit(1 if fails else 0)
