#!/usr/bin/env python3
"""Lane-form funds projection + relayer monitoring (BUILD-Q-27/Q-35).

    python3 funds_projection.py <instance-tree> \
        [--runway-threshold 500]

Reads the instance's OWN address set (from HOST__RECORD__01.json)
live on Base, using the instance operation's own RPC transport, and
reconciles against the instance's supply accounting
(<tree>/continuity/funds_accounting.json — written by the operator
act that funds the instance; see OPERATOR__SLOTS.md):

  USDC: supplied(to payer) - settled_out(instance chain settlement
        records) == payer on hand; remainder must be 0.
  ETH:  provided(to relayer) - burned(actual gas of the instance's
        settled txs, from their on-chain receipts) == relayer on
        hand; remainder must be 0.

Reports per-address balances, both reconciliations, and the relayer
RUNWAY (balance / mean actual settlement cost) with a LOW_RUNWAY
flag below the named threshold. Exit 0 iff RECONCILED.
"""
import json, os, sys, time

TREE = os.path.abspath(sys.argv[1])
THRESHOLD = 500
if "--runway-threshold" in sys.argv:
    THRESHOLD = int(sys.argv[sys.argv.index("--runway-threshold") + 1])
sys.path.insert(0, os.path.join(TREE, "operation"))
import settlement as settle_mod

RPC_URLS = ["https://mainnet.base.org", "https://base-rpc.publicnode.com"]
USDC = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"

def call(method, params, attempts=4):
    last = None
    for i in range(attempts):
        try:
            return settle_mod.Rpc(RPC_URLS).call(method, params)
        except Exception as e:
            last = e
            if i + 1 < attempts:
                time.sleep(1.5 * (i + 1))
    raise last

def usdc(addr):
    data = "0x70a08231" + "0" * 24 + addr[2:].lower()
    return int(call("eth_call", [{"to": USDC, "data": data}, "latest"]), 16)

def eth(addr):
    return int(call("eth_getBalance", [addr, "latest"]), 16)

host = json.load(open(os.path.join(TREE, "HOST__RECORD__01.json")))
acct_path = os.path.join(TREE, "continuity", "funds_accounting.json")
acct = json.load(open(acct_path)) if os.path.exists(acct_path) else {}

addrs = host["addresses"]
rows = []
for name, addr in (("relayer (gas tank)", addrs["relayer"]),
                   ("specimen payer (float)", addrs["specimen_payer"]),
                   ("signing specimen", addrs["signing_specimen"]["address"]),
                   ("payTo (operation receptor)", addrs["payTo"])):
    rows.append({"name": name, "address": addr,
                 "usdc_micro": usdc(addr), "eth_wei": eth(addr)})

# instance chain settlement records
settled = []
seg_dir = os.path.join(TREE, "operation", "receipts")
for n in sorted(os.listdir(seg_dir)):
    if n.startswith("segment-") and n.endswith(".jsonl"):
        for line in open(os.path.join(seg_dir, n)):
            c = json.loads(line)["content"]
            s = c.get("settlement") or {}
            if s.get("status") == "SETTLED" and s.get("tx_hash"):
                settled.append(s)
settled_out = sum(s["value_micro_usdc"] for s in settled)
burned = 0
costs = []
for s in settled:
    rcpt = call("eth_getTransactionReceipt", [s["tx_hash"]])
    cost = int(rcpt["gasUsed"], 16) * int(rcpt["effectiveGasPrice"], 16)
    costs.append(cost)
    if s.get("relayer", "").lower() == addrs["relayer"].lower():
        burned += cost

payer_row = rows[1]; relayer_row = rows[0]
recon = {}
if "usdc_supplied_micro" in acct:
    expected = acct["usdc_supplied_micro"] - settled_out
    recon["usdc"] = {"supplied_micro": acct["usdc_supplied_micro"],
                     "settled_out_micro": settled_out,
                     "expected_on_hand_micro": expected,
                     "actual_on_hand_micro": payer_row["usdc_micro"],
                     "remainder_micro": payer_row["usdc_micro"] - expected}
else:
    recon["usdc"] = {"status": "NO_SUPPLY_ACCOUNTING",
                     "settled_out_micro": settled_out}
if "eth_provided_wei" in acct:
    expected_e = acct["eth_provided_wei"] - burned
    recon["eth"] = {"provided_wei": acct["eth_provided_wei"],
                    "burned_wei": burned,
                    "expected_on_hand_wei": expected_e,
                    "actual_on_hand_wei": relayer_row["eth_wei"],
                    "remainder_wei": relayer_row["eth_wei"] - expected_e}
else:
    recon["eth"] = {"status": "NO_SUPPLY_ACCOUNTING", "burned_wei": burned}

mean_cost = (sum(costs[-5:]) / len(costs[-5:])) if costs else None
runway = None
if mean_cost:
    runway = int(relayer_row["eth_wei"] / mean_cost)
flags = []
if runway is not None and runway < THRESHOLD:
    flags.append("LOW_RUNWAY")
ok = all(r.get("remainder_micro", 0) == 0 and r.get("remainder_wei", 0) == 0
         for r in recon.values())
out = {"projection": "FUNDS__PROJECTION (lane form)",
       "instance": host["instance"]["target"],
       "block": int(call("eth_blockNumber", []), 16),
       "addresses": rows, "settled_crossings": len(settled),
       "reconciliation": recon,
       "verdict": "RECONCILED" if ok else "UNRECONCILED",
       "relayer_runway": {"settlements_remaining": runway,
                          "mean_actual_cost_wei": mean_cost,
                          "threshold": THRESHOLD},
       "flags": flags}
print(json.dumps(out, indent=1))
sys.exit(0 if ok else 1)
