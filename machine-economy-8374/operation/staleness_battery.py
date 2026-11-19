#!/usr/bin/env python3
"""Quote-staleness bound battery (cure of 2026-11-19 for Gemini
finding F-8374-02).

Runs against a THROWAWAY instance this script builds and drives
itself (its own tree, own genesis chain, port 8899) -- never the
live chain. The instance's RPC routes are toggled between the live
Base RPCs and a blackhole (127.0.0.1:9) by rewriting its config and
restarting it, and the persisted quote cache's quoted_at_unix is
rewritten to place the last successful quote at a chosen age --
which is what a public-RPC outage of that duration is from the
endpoint's seat.

Cases:
 1. fresh quote path unchanged: RPC live, no cache -> unpaid
    POST /crossing returns 402 with an accepts array and
    quote_stale: false.
 2. stale within bound: RPC blackholed, last quote 120s old
    (bound 300s) -> 402 served flagged quote_stale: true with a
    stale_reason and stale_age_seconds <= 300.
 3. stale beyond bound: RPC blackholed, last quote 400s old ->
    503, disposition FAIL_CLOSED, failure_code
    SETTLEMENT_QUOTE_STALE_BEYOND_BOUND, retry guidance present,
    and NO accepts array (no challenge is issued on the quote).
 4. recovery: RPC restored -> 402 with quote_stale: false again.

No payments are made; the battery only ever requests unpaid
challenges, so the throwaway chain stays at genesis.
Usage: python3 staleness_battery.py [instance_dir]
"""
import json, os, shutil, subprocess, sys, time
import urllib.request, urllib.error

HERE = os.path.dirname(os.path.abspath(__file__))
WORK = sys.argv[1] if len(sys.argv) > 1 else os.path.expanduser(
    "~/workspace/me-test/staleness-bound")
PORT = 8899
BASE_URL = f"http://127.0.0.1:{PORT}"
GOOD_RPC = ("https://mainnet.base.org",
            "https://base-rpc.publicnode.com")
DEAD_RPC = ("http://127.0.0.1:9/dead", "http://127.0.0.1:9/dead2")
RESULTS = []
PROC = None


def check(name, ok, evidence):
    RESULTS.append((name, ok, evidence))
    print(("PASS " if ok else "FAIL ") + name + " -- " + evidence)


def call(method, path, body=None, timeout=90):
    data = json.dumps(body).encode() if body is not None else None
    r = urllib.request.Request(BASE_URL + path, data=data, method=method,
                               headers={"Content-Type": "application/json"})
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
    sub["sweep_interval_seconds"] = 3600
    json.dump(cfg, open(cfg_path, "w"), indent=1)


def set_quote_age(seconds):
    cache_path = os.path.join(WORK, "quote-cache.json")
    q = json.load(open(cache_path))
    q["quoted_at_unix"] = int(time.time()) - seconds
    json.dump(q, open(cache_path, "w"), indent=1, sort_keys=True)


def build_instance():
    if os.path.isdir(WORK):
        shutil.rmtree(WORK)
    ignore = shutil.ignore_patterns(
        "receipts", "__pycache__", "cf-tunnel-token.txt",
        "specimen_payer.json", "settlement_relayer.json",
        "quote-cache.json", "*.pyc")
    shutil.copytree(HERE, WORK, ignore=ignore)
    os.makedirs(os.path.join(WORK, "receipts"), exist_ok=True)


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


def challenge():
    body = {"counterparty": "0x0000000000000000000000000000000000000001",
            "action": "evaluate", "scope_ref": "ME-EVAL-01",
            "resource": "governed-evaluation", "tier": "receipt-only"}
    return call("POST", "/crossing", body)


def quote_of(chal):
    acc = (chal.get("accepts") or [{}])[0]
    return acc.get("settlement_charge_quote") or {}


def main():
    build_instance()
    try:
        # 1. fresh quote path unchanged
        set_rpc("good")
        if not start():
            check("instance starts", False, "no /health within 60s")
            return 1
        code, chal = challenge()
        q = quote_of(chal)
        check("1 fresh: 402 with accepts, quote_stale false",
              code == 402 and bool(chal.get("accepts"))
              and q.get("quote_stale") is False,
              f"status={code} quote_stale={q.get('quote_stale')} "
              f"charge={q.get('settlement_charge_micro_usdc')}")
        stop()

        # 2. stale within bound (120s <= 300s), RPC blackholed
        set_rpc("dead")
        set_quote_age(120)
        if not start():
            check("instance restarts (dead RPC)", False, "no /health")
            return 1
        code, chal = challenge()
        q = quote_of(chal)
        check("2 stale-within-bound: 402 served flagged",
              code == 402 and bool(chal.get("accepts"))
              and q.get("quote_stale") is True
              and bool(q.get("stale_reason"))
              and (q.get("stale_age_seconds") or 999) <= 300,
              f"status={code} quote_stale={q.get('quote_stale')} "
              f"age={q.get('stale_age_seconds')}")
        stop()

        # 3. stale beyond bound (400s > 300s), RPC blackholed
        set_quote_age(400)
        if not start():
            check("instance restarts (beyond bound)", False, "no /health")
            return 1
        code, chal = challenge()
        check("3 stale-beyond-bound: 503 SETTLEMENT_QUOTE_STALE_BEYOND_BOUND, no accepts",
              code == 503
              and chal.get("disposition") == "FAIL_CLOSED"
              and chal.get("failure_code")
              == "SETTLEMENT_QUOTE_STALE_BEYOND_BOUND"
              and "accepts" not in chal
              and bool(chal.get("required_evidence_or_repair"))
              and bool(chal.get("retry_entrypoint")),
              f"status={code} failure_code={chal.get('failure_code')} "
              f"accepts={'accepts' in chal}")
        stop()

        # 4. recovery to fresh on RPC restore
        set_rpc("good")
        if not start():
            check("instance restarts (recovery)", False, "no /health")
            return 1
        code, chal = challenge()
        q = quote_of(chal)
        check("4 recovery: fresh 402, quote_stale false",
              code == 402 and bool(chal.get("accepts"))
              and q.get("quote_stale") is False,
              f"status={code} quote_stale={q.get('quote_stale')}")
        stop()
    finally:
        stop()
    passed = sum(1 for _n, ok, _e in RESULTS if ok)
    print(f"staleness battery: {passed}/{len(RESULTS)}")
    return 0 if passed == len(RESULTS) else 1


if __name__ == "__main__":
    sys.exit(main())
