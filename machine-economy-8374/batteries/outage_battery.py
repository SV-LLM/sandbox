#!/usr/bin/env python3
"""BUILD-Q-45 pair-first migration: the outage battery.

Runs against a THROWAWAY instance this script builds and drives
itself (its own tree, own genesis chain, port 8898) -- never the
live chain. The instance's RPC routes are toggled between the live
Base RPCs and a blackhole (127.0.0.1:9) by rewriting its config and
restarting it, which is what an egress outage is from the
endpoint's seat. Usage:
    python3 outage_battery.py [instance_dir]

Cases:
 0. no quote ever obtained + RPC blackholed -> the charge leg
    fails closed (503 SETTLEMENT_CHARGE_QUOTE_UNAVAILABLE): the
    ONLY pair-first fail-closed that remains at crossing time.
 1. network up -> a live settlement-charge quote is obtained and
    persisted (quote-cache.json).
 a. RPC blackholed (stale quote served) -> a full-evaluation
    crossing returns ALLOW with its pair written, the pair's
    settlement_state PENDING, the response naming the failed
    attempt (SETTLEMENT_RPC_UNREACHABLE).
 b. the same nonce re-presented during the outage -> refused
    locally (PAYMENT_NONCE_REUSED) from the chain registry.
 c. RPC restored -> POST /settle-pair {"sweep": true} completes
    the pending settlement on-chain; amounts exact (payTo balance
    delta == the crossing total; receipt status 0x1).
 d. the chain replays MATCH including the outage pairs (checked
    after the sweep and again at the end).
 e. terminal failure: an authorization whose nonce was consumed
    by an out-of-band settlement is presented -> ALLOW pair
    PENDING, then the settlement leg's on-chain simulation
    reverts and the terminal failure is receipted as an appended
    SETTLEMENT-FAILURE pair (SETTLEMENT_SIMULATION_REVERTED);
    the crossing pair's disposition does not change.

Funding (insider specimens, stated as such): the payer is the
production specimen payer (key retained); the instance relayer is
a previously-funded ecosystem proof relayer whose key file is
copied into the throwaway tree. Nothing here is an external
crossing.
"""
import json, os, shutil, subprocess, sys, time
import urllib.request, urllib.error

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from x402_specimen import make_payment_header, USDC_BASE
import settlement as settle_mod

WORK = sys.argv[1] if len(sys.argv) > 1 else os.path.expanduser(
    "~/workspace/me-test/pf-outage")
PORT = 8898
BASE_URL = f"http://127.0.0.1:{PORT}"
PAYTO = "0x7721aB66161e60fCcA59CCe2A86817cbdd9b16Be"
GOOD_RPC = ("https://mainnet.base.org",
            "https://base-rpc.publicnode.com")
DEAD_RPC = ("http://127.0.0.1:9/dead", "http://127.0.0.1:9/dead2")
RELAYER_SRC = os.path.expanduser(
    "~/workspace/machine-economy-transfer/proof-instance/operation/"
    "settlement_relayer.json")
RESULTS = []
PROC = None


def check(name, ok, evidence):
    RESULTS.append((name, ok, evidence))
    print(("PASS " if ok else "FAIL ") + name + " -- " + evidence)


def call(method, path, body=None, headers=None, timeout=90):
    data = json.dumps(body).encode() if body is not None else None
    r = urllib.request.Request(BASE_URL + path, data=data, method=method,
                               headers={"Content-Type":
                                        "application/json",
                                        **(headers or {})})
    try:
        with urllib.request.urlopen(r, timeout=timeout) as resp:
            return resp.status, json.load(resp)
    except urllib.error.HTTPError as e:
        return e.code, json.load(e)


def set_rpc(mode):
    cfg_path = os.path.join(WORK, "config.json")
    cfg = json.load(open(cfg_path))
    sub = cfg["settlement"]["submission"]
    sub["rpc_primary"], sub["rpc_fallback"] = \
        GOOD_RPC if mode == "good" else DEAD_RPC
    sub["sweep_interval_seconds"] = 3600  # the manual sweep acts
    json.dump(cfg, open(cfg_path, "w"), indent=1)


def build_instance():
    if os.path.isdir(WORK):
        shutil.rmtree(WORK)
    ignore = shutil.ignore_patterns(
        "receipts", "__pycache__", "cf-tunnel-token.txt",
        "specimen_payer.json", "settlement_relayer.json",
        "quote-cache.json", "*.pyc")
    shutil.copytree(HERE, WORK, ignore=ignore)
    os.makedirs(os.path.join(WORK, "receipts"), exist_ok=True)
    shutil.copy(RELAYER_SRC,
                os.path.join(WORK, "settlement_relayer.json"))


def start():
    global PROC
    env = dict(os.environ, ME_ENDPOINT_PORT=str(PORT))
    PROC = subprocess.Popen(
        [sys.executable, "endpoint.py"], cwd=WORK, env=env,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(60):
        try:
            code, _h = call("GET", "/health", timeout=5)
            if code == 200:
                return True
        except Exception:
            pass
        time.sleep(1)
    return False


def stop():
    global PROC
    if PROC is not None:
        PROC.terminate()
        try:
            PROC.wait(timeout=10)
        except Exception:
            PROC.kill()
        PROC = None


def chain_entries():
    out = []
    rdir = os.path.join(WORK, "receipts")
    for n in sorted(os.listdir(rdir)):
        if n.startswith("segment-") and n.endswith(".jsonl"):
            with open(os.path.join(rdir, n)) as f:
                out += [json.loads(line) for line in f if line.strip()]
    return out


def pair_content(pair_id):
    return [r["content"] for r in chain_entries()
            if r["content"].get("pair_id") == pair_id]


def payto_balance():
    rpc = settle_mod.Rpc(list(GOOD_RPC))
    data = "0x70a08231" + "0" * 24 + PAYTO[2:].lower()
    return int(rpc.call("eth_call",
                        [{"to": USDC_BASE, "data": data}, "latest"]), 16)


def full_eval_body(payer):
    return {"counterparty": payer, "action": "evaluate",
            "scope_ref": "ME-EVAL-01", "resource": "governed-evaluation",
            "tier": "full-evaluation",
            "evidence": {
                "authority": "outage battery specimen authority",
                "delegation": "no delegation",
                "evidence_refs": ["outage_battery.py specimen run"],
                "exclusions": [], "policy": "ME-POLICY-01",
                "validity_at_commit": True}}


def challenge_total(payer):
    _c, chal = call("POST", "/crossing", full_eval_body(payer))
    return int(chal["accepts"][0]["maxAmountRequired"])


def main():
    payer_doc = json.load(open(os.path.join(HERE, "specimen_payer.json")))
    priv = int(payer_doc["priv_hex"], 16)
    payer = payer_doc["address"]
    print(f"specimen payer (insider, funded): {payer}")

    build_instance()

    # 0. No quote ever + blackholed RPC -> charge leg fails closed.
    set_rpc("dead")
    if not start():
        check("instance start (dead RPC)", False, "endpoint did not answer")
        return finish()
    code, body = call("POST", "/crossing", full_eval_body(payer))
    check("0. no quote ever -> SETTLEMENT_CHARGE_QUOTE_UNAVAILABLE",
          code == 503
          and body.get("failure_code")
          == "SETTLEMENT_CHARGE_QUOTE_UNAVAILABLE",
          f"HTTP {code}, code={body.get('failure_code')}")
    stop()

    # 1. Network up -> live quote obtained and persisted.
    set_rpc("good")
    if not start():
        check("instance start (good RPC)", False, "endpoint did not answer")
        return finish()
    code, offer = call("GET", "/offer")
    total1 = challenge_total(payer)
    qfile = os.path.join(WORK, "quote-cache.json")
    check("1. live quote obtained + persisted",
          code == 200 and os.path.exists(qfile) and total1 > 15000,
          f"offer HTTP {code}, full-eval total={total1}, "
          f"quote-cache {'present' if os.path.exists(qfile) else 'MISSING'}")
    stop()

    # a. Outage: crossing ALLOW + pair written, settlement PENDING.
    set_rpc("dead")
    if not start():
        check("instance start (outage)", False, "endpoint did not answer")
        return finish()
    now_ts = int(time.time())
    hdr, auth, _dg = make_payment_header(priv, payer, PAYTO, total1,
                                         now_ts - 10, now_ts + 3600)
    code, body = call("POST", "/crossing", full_eval_body(payer),
                      {"X-PAYMENT": hdr})
    pair_id_a = body.get("pair_id")
    members = pair_content(pair_id_a) if pair_id_a else []
    pair_settle = (members[0].get("settlement") or {}) if members else {}
    pair_quote = ((members[0].get("payment") or {})
                  .get("settlement_charge_quote") or {}) if members else {}
    check("a. outage crossing ALLOW, pair PENDING",
          code == 200 and body.get("disposition") == "ALLOW"
          and body.get("settlement_state") == "PENDING"
          and (body.get("settlement") or {}).get("failure_code")
          == "SETTLEMENT_RPC_UNREACHABLE"
          and pair_settle.get("status") == "PENDING"
          and pair_settle.get("settlement_state") == "PENDING"
          and pair_quote.get("quote_stale") is True,
          f"HTTP {code}, pair={pair_id_a}, "
          f"attempt={(body.get('settlement') or {}).get('failure_code')}, "
          f"pair_state={pair_settle.get('settlement_state')}, "
          f"quote_stale={pair_quote.get('quote_stale')}")

    # b. Same nonce during the outage -> refused locally.
    code, body = call("POST", "/crossing", full_eval_body(payer),
                      {"X-PAYMENT": hdr})
    check("b. nonce re-presented in outage -> PAYMENT_NONCE_REUSED",
          code == 422
          and body.get("failure_code") == "PAYMENT_NONCE_REUSED",
          f"HTTP {code}, code={body.get('failure_code')}")
    stop()

    # c. RPC restored -> sweep completes the settlement on-chain.
    set_rpc("good")
    if not start():
        check("instance start (restored)", False, "endpoint did not answer")
        return finish()
    bal_before = payto_balance()
    code, sweep = call("POST", "/settle-pair", {"sweep": True})
    mine = [r for r in sweep.get("results", [])
            if r.get("pair_id") == pair_id_a]
    tx_hash = mine[0].get("tx_hash") if mine else None
    rpc = settle_mod.Rpc(list(GOOD_RPC))
    receipt = None
    if tx_hash:
        for _ in range(10):
            receipt = rpc.call("eth_getTransactionReceipt", [tx_hash])
            if receipt:
                break
            time.sleep(2)
    bal_after = payto_balance()
    check("c. sweep settles the outage pair on-chain, exact",
          code == 200 and len(mine) == 1
          and mine[0].get("settlement_state") == "SETTLED"
          and receipt is not None
          and receipt.get("status") == "0x1"
          and bal_after - bal_before == total1,
          f"sweep HTTP {code}, state="
          f"{mine[0].get('settlement_state') if mine else None}, "
          f"tx={tx_hash}, receipt="
          f"{receipt.get('status') if receipt else None}, "
          f"payTo delta={bal_after - bal_before} (expected {total1})")

    # d. Replay MATCH including the outage pairs.
    code, rep = call("GET", "/replay")
    check("d. replay MATCH incl. outage pairs",
          rep.get("verdict") == "MATCH",
          f"verdict={rep.get('verdict')}, pairs={rep.get('pairs')}")

    # e. Terminal failure: nonce consumed out-of-band first.
    total2 = challenge_total(payer)
    now_ts = int(time.time())
    hdr2, auth2, _d2 = make_payment_header(priv, payer, PAYTO, total2,
                                           now_ts - 10, now_ts + 3600)
    import base64 as _b64
    sig2 = json.loads(_b64.b64decode(hdr2))["payload"]["signature"]
    payment2 = {"from": auth2["from"], "to": auth2["to"],
                "value_micro_usdc": int(auth2["value"]),
                "valid_after": int(auth2["validAfter"]),
                "valid_before": int(auth2["validBefore"]),
                "nonce": auth2["nonce"], "signature": sig2,
                "asset": USDC_BASE, "payTo": PAYTO}
    cfg = {"enabled": True, "mode": "self-relayer",
           "rpc_primary": GOOD_RPC[0], "rpc_fallback": GOOD_RPC[1],
           "relayer_key_file": "settlement_relayer.json"}
    direct = settle_mod.attempt_settlement(payment2, cfg, WORK)
    code, body = call("POST", "/crossing", full_eval_body(payer),
                      {"X-PAYMENT": hdr2})
    pair_id_e = body.get("pair_id")
    fail_members = [c for c in (pair_content(
        body.get("settlement_pair_id") or ""))
        ] if body.get("settlement_pair_id") else []
    fail_rec = (fail_members[0].get("settlement") or {}) \
        if fail_members else {}
    check("e. terminal failure receipted as appended record",
          direct.get("status") == "SETTLED"
          and code == 200 and body.get("disposition") == "ALLOW"
          and body.get("settlement_state") == "FAILED_TERMINAL"
          and fail_members
          and fail_members[0].get("settles_pair_id") == pair_id_e
          and fail_rec.get("failure_code")
          == "SETTLEMENT_SIMULATION_REVERTED",
          f"direct={direct.get('status')}, HTTP {code}, "
          f"pair={pair_id_e}, state={body.get('settlement_state')}, "
          f"failure_pair={body.get('settlement_pair_id')}, "
          f"code={fail_rec.get('failure_code')}")
    code, rep = call("GET", "/replay")
    check("d2. replay MATCH after terminal-failure pair",
          rep.get("verdict") == "MATCH",
          f"verdict={rep.get('verdict')}, pairs={rep.get('pairs')}")
    stop()
    return finish()


def finish():
    stop()
    fails = [r for r in RESULTS if not r[1]]
    print(f"\n{len(RESULTS) - len(fails)}/{len(RESULTS)} PASS")
    sys.exit(1 if fails else 0)


if __name__ == "__main__":
    main()
