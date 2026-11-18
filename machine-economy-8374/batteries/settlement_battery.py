#!/usr/bin/env python3
"""Gate 2 acceptance battery: settlement submission leg.

Runs against a THROWAWAY endpoint instance (its own receipts dir and
its own unfunded relayer) -- never the live chain. Usage:
    python3 settlement_battery.py [base_url] [instance_dir] [relayer]

Cases:
 1. verified authorization + unfunded relayer -> crossing ALLOW,
    pair carries settlement FAIL_CLOSED / SETTLEMENT_RELAYER_UNFUNDED,
    relayer named in the record.
 2. garbage signature -> PAYMENT_SIGNATURE_INVALID refusal pair with
    NO settlement record (settlement is never attempted when
    verification fails -- BUILD-Q-18 behavior unchanged).
 3. broadcast code path exercised against the live RPC: calldata for
    a fresh, validly signed authorization is built (selector + 9
    words, locally asserted) and dispatched via read-only eth_call;
    the live contract's answer (here: a revert at the payer-balance
    step, downstream of signature validation, because the specimen
    payer is unfunded) proves the calldata decodes and executes.
 4. throwaway chain replays MATCH with the settlement records in it.
"""
import json, os, sys, time, urllib.request, urllib.error
sys.path.insert(0, sys.argv[2] if len(sys.argv) > 2 else os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "operation"))
from x402_specimen import new_keypair, make_payment_header, USDC_BASE
import settlement as settle_mod

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8899"
RELAYER = sys.argv[3] if len(sys.argv) > 3 else None
PAYTO = "0x7721aB66161e60fCcA59CCe2A86817cbdd9b16Be"
RESULTS = []

def check(name, ok, evidence):
    RESULTS.append((name, ok, evidence))
    print(("PASS " if ok else "FAIL ") + name + " -- " + evidence)

def call(method, path, body=None, headers=None):
    data = json.dumps(body).encode() if body is not None else None
    r = urllib.request.Request(BASE + path, data=data, method=method,
                               headers={"Content-Type": "application/json",
                                        **(headers or {})})
    try:
        with urllib.request.urlopen(r, timeout=60) as resp:
            return resp.status, json.load(resp)
    except urllib.error.HTTPError as e:
        return e.code, json.load(e)

def crossing_body():
    return {"counterparty": "settlement-battery", "action": "evaluate",
            "scope_ref": "ME-EVAL-01", "resource": "governed-evaluation",
            "tier": "receipt-only"}

def main():
    priv, payer = new_keypair()
    print(f"specimen payer (throwaway, unfunded): {payer}")
    now_ts = int(time.time())

    code, health = call("GET", "/health")
    ss = health.get("settlement_submission") or {}
    check("health exposes relayer", ss.get("relayer") == RELAYER
          and ss.get("enabled") is True,
          f"relayer={ss.get('relayer')}, enabled={ss.get('enabled')}")

    # 1. verified authorization, unfunded relayer -> NO_GAS settlement.
    # Offer v07 (BUILD-Q-43): the authorization must be for the
    # challenge TOTAL (governance fee + quoted settlement charge),
    # read from the live challenge.
    _c, chal = call("POST", "/crossing", crossing_body())
    total = int(chal["accepts"][0]["maxAmountRequired"])
    hdr, auth, dg = make_payment_header(priv, payer, PAYTO, total,
                                        now_ts - 10, now_ts + 3600)
    code, body = call("POST", "/crossing", crossing_body(),
                      {"X-PAYMENT": hdr})
    srec = body.get("settlement") or {}
    pair_srec = ((body.get("receipt_pair") or [{}, {}])[0].get("content")
                 or {}).get("settlement") or {}
    check("verified auth + unfunded relayer", code == 200
          and body.get("disposition") == "ALLOW"
          and srec.get("status") == "FAIL_CLOSED"
          and srec.get("failure_code") == "SETTLEMENT_RELAYER_UNFUNDED"
          and srec.get("relayer") == RELAYER
          and pair_srec.get("failure_code")
              == "SETTLEMENT_RELAYER_UNFUNDED"
          and (body.get("payment") or {}).get(
              "governance_fee_micro_usdc") == 500
          and (body.get("payment") or {}).get(
              "total_authorized_micro_usdc") == total,
          f"HTTP {code}, pair={body.get('pair_id')}, "
          f"settlement={srec.get('failure_code')}, total={total}")

    # 2. garbage signature -> verification failure, no settlement
    import base64 as _b64
    hdr2, _a, _d = make_payment_header(priv, payer, PAYTO, total,
                                       now_ts - 10, now_ts + 3600)
    pl = json.loads(_b64.b64decode(hdr2))
    pl["payload"]["signature"] = "0x" + "ab" * 65
    hdr2b = _b64.b64encode(json.dumps(pl).encode()).decode()
    code, body = call("POST", "/crossing", crossing_body(),
                      {"X-PAYMENT": hdr2b})
    pair_content = ((body.get("refusal_record_pair") or [{}, {}])[0]
                    .get("content") or {})
    check("garbage signature unchanged", code == 422
          and body.get("failure_code") == "PAYMENT_SIGNATURE_INVALID"
          and body.get("settlement") is None
          and "settlement" not in pair_content,
          f"HTTP {code}, code={body.get('failure_code')}, "
          f"settlement_in_pair={'settlement' in pair_content}")

    # 3. broadcast path vs live RPC via eth_call simulation
    hdr3, auth3, _d3 = make_payment_header(priv, payer, PAYTO, 500,
                                           now_ts - 10, now_ts + 3600)
    payload3 = json.loads(_b64.b64decode(hdr3))
    payment3 = {"from": auth3["from"], "to": auth3["to"],
                "value_micro_usdc": int(auth3["value"]),
                "valid_after": int(auth3["validAfter"]),
                "valid_before": int(auth3["validBefore"]),
                "nonce": auth3["nonce"],
                "signature": payload3["payload"]["signature"],
                "asset": USDC_BASE}
    cfg = {"enabled": True, "rpc_primary": "https://mainnet.base.org",
           "rpc_fallback": "https://base-rpc.publicnode.com",
           "relayer_key_file": "settlement_relayer.json"}
    sim = settle_mod.simulate(payment3, cfg,
                              sys.argv[2] if len(sys.argv) > 2
                              else "/tmp/me-settle")
    check("live eth_call simulation", sim.get("dispatched") is True
          and sim.get("selector") == "0xe3ee160e"
          and sim.get("calldata_bytes") == 292
          and sim.get("outcome") in ("success", "reverted"),
          f"selector={sim.get('selector')}, bytes="
          f"{sim.get('calldata_bytes')}, outcome={sim.get('outcome')}, "
          f"detail={str(sim.get('error') or sim.get('result'))[:120]}")

    # 4. throwaway replay MATCH
    code, rep = call("GET", "/replay")
    check("throwaway replay MATCH", rep.get("verdict") == "MATCH",
          f"verdict={rep.get('verdict')}, pairs={rep.get('pairs')}, "
          f"anchor={str(rep.get('terminal_anchor'))[:16]}...")

    fails = [r for r in RESULTS if not r[1]]
    print(f"\n{len(RESULTS) - len(fails)}/{len(RESULTS)} PASS")
    sys.exit(1 if fails else 0)

if __name__ == "__main__":
    main()
