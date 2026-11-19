"""Complete-funds projection for the 8374 machine-economy operation.

One question — "what is the balance?" — gets one complete answer:
every ecosystem address on Base, read live, with the supplied-funds
accounting reconciled rather than assumed. The stranded demo payer
is shown separately and is never counted in accessible totals.

Stdlib only. RPC reads ride settlement.Rpc (the service's proven
proxy-discovery transport with failover). The reconciliation
constants are the supplied amounts of record (2026-11-17/18):

- USDC supplied into the set: 50.00 (Rigel -> m8374.base.eth);
  of that, 2.00 went to the stranded demo payer and 2.00 to the
  specimen payer; the rest of the set's USDC arrived only by
  internal movement and settled fees, so accessible USDC across the
  whole set must equal supplied - stranded exactly.
- ETH provided: 0.0056 (Rigel -> production relayer); every other
  ETH balance in the set arrived from the production relayer, so
  total ETH = provided - burned(gas); the burned figure is derived
  and displayed, and a negative remainder fails the check.
"""

import glob
import html
import json
import os
from datetime import datetime, timezone

import settlement as settle_mod

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SEG_DIR = os.path.join(BASE_DIR, "receipts")

USDC = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"
RPC_URLS = ["https://mainnet.base.org", "https://base-rpc.publicnode.com"]

USDC_SUPPLIED_MICRO = 50_000_000          # 50.00 USDC into the set
USDC_STRANDED_MICRO = 2_000_000           # 2.00 at the keyless demo payer
ETH_PROVIDED_WEI = 5_600_000_000_000_000  # 0.0056 ETH to the relayer

ADDRESSES = [
    {"name": "8374 payTo", "role": "earned fees",
     "address": "0x7721aB66161e60fCcA59CCe2A86817cbdd9b16Be",
     "stranded": False},
    {"name": "specimen payer", "role": "working float",
     "address": "0xCa48d33c14d8123A00Fd2Ac386b6295C7596B0E5",
     "stranded": False},
    {"name": "m8374.base.eth", "role": "supply wallet",
     "address": "0x415d2f959f70eaac57807d19ad54b0dbfaaa9d2c",
     "stranded": False},
    {"name": "production relayer", "role": "gas tank",
     "address": "0xB4a019cfd17DE2E6B00Aa2DAB159e24d9235Fb17",
     "stranded": False},
    {"name": "instance relayer", "role": "proof-instance gas tank",
     "address": "0x073BcC1d46e9DE1ae4851950344D33F2e98C9599",
     "stranded": False},
    {"name": "instance payer", "role": "proof-instance float",
     "address": "0x6c770Cd5Dc744A7FdE2d1762129276A4d26fC358",
     "stranded": False},
    {"name": "clean-room test wallet", "role": "insider test wallet — clean-room bot (Q-50)",
     "address": "0xd1e745b11ef23Ce77c14d6f3041260C8Afd90061",
     "stranded": False},
    {"name": "call-site instance payer", "role": "insider test wallet — lane call-site instance (Claude seat)",
     "address": "0xC2149B4bBBb4eFc558512e5A4bc5B8716f554245",
     "stranded": False},
    {"name": "stranded demo payer", "role": "STRANDED — key discarded 2026-11-17",
     "address": "0x28D0facFb848E742A448D8cD4ddad907bF27cD45",
     "stranded": True},
]

PRODUCTION_RELAYER = "0xB4a019cfd17DE2E6B00Aa2DAB159e24d9235Fb17"


def _call(method, params, attempts=4):
    """One RPC call, retried with a fresh Rpc (fresh proxy discovery)
    per attempt: the service-form transport on this node is
    intermittent per attempt (the settlement leg's standing finding),
    while single calls succeed on some route with high probability.
    A projection that needs ~15 calls must not fail whole on one
    attempt's transport."""
    import time
    last = None
    for i in range(attempts):
        try:
            return settle_mod.Rpc(RPC_URLS).call(method, params)
        except Exception as e:
            last = e
            if i + 1 < attempts:
                time.sleep(1.5 * (i + 1))
    raise last


def _balance_of(address):
    data = "0x70a08231" + "0" * 24 + address[2:].lower()
    out = _call("eth_call", [{"to": USDC, "data": data}, "latest"])
    return int(out, 16)


def _settled_tx_hashes(limit=5):
    """Distinct settlement tx hashes from the chain's own records,
    newest last in file order; returns up to `limit` most recent."""
    seen, hashes = set(), []
    for path in sorted(glob.glob(os.path.join(SEG_DIR, "segment-*.jsonl"))):
        try:
            with open(path) as f:
                lines = f.readlines()
        except OSError:
            continue
        for line in lines:
            try:
                content = json.loads(line)["content"]
            except Exception:
                continue
            s = content.get("settlement") or {}
            tx = s.get("tx_hash")
            if s.get("status") == "SETTLED" and tx and tx not in seen:
                seen.add(tx)
                hashes.append(tx)
    return hashes[-limit:]


def _runway(relayer_eth_wei):
    """Production-relayer runway: balance divided by the mean actual
    gas cost of the most recent settled settlements (gasUsed x
    effectiveGasPrice from their on-chain receipts)."""
    hashes = _settled_tx_hashes()
    costs = []
    for tx in hashes:
        try:
            r = _call("eth_getTransactionReceipt", [tx], attempts=2)
        except Exception:
            continue
        if r and r.get("gasUsed") and r.get("effectiveGasPrice"):
            costs.append(int(r["gasUsed"], 16) * int(r["effectiveGasPrice"], 16))
    if not costs:
        return {"settlements_remaining_estimate": None,
                "basis": "no settlement receipts readable",
                "sample_size": 0}
    mean_cost = sum(costs) // len(costs)
    return {"settlements_remaining_estimate":
            relayer_eth_wei // mean_cost if mean_cost else None,
            "mean_recent_settlement_gas_cost_wei": mean_cost,
            "sample_size": len(costs),
            "basis": "mean actual gas cost (gasUsed x effectiveGasPrice) "
                     "of the most recent settled settlements, from the "
                     "chain's settlement records"}


def funds_document():
    block = int(_call("eth_blockNumber", []), 16)
    rows = []
    for spec in ADDRESSES:
        rows.append({
            "name": spec["name"], "address": spec["address"],
            "role": spec["role"], "stranded": spec["stranded"],
            "usdc_micro": _balance_of(spec["address"]),
            "eth_wei": int(_call(
                "eth_getBalance", [spec["address"], "latest"]), 16),
        })
    accessible = [r for r in rows if not r["stranded"]]
    stranded_rows = [r for r in rows if r["stranded"]]
    tot_usdc = sum(r["usdc_micro"] for r in accessible)
    tot_eth = sum(r["eth_wei"] for r in accessible)
    stranded_usdc = sum(r["usdc_micro"] for r in stranded_rows)

    exp_usdc = USDC_SUPPLIED_MICRO - USDC_STRANDED_MICRO
    rem_usdc = tot_usdc - exp_usdc
    burned_eth = ETH_PROVIDED_WEI - tot_eth
    usdc_ok = rem_usdc == 0 and stranded_usdc == USDC_STRANDED_MICRO
    eth_ok = burned_eth >= 0
    relayer_row = next(r for r in rows
                       if r["address"] == PRODUCTION_RELAYER)
    return {
        "service": "machine-economy-endpoint",
        "document": "FUNDS__PROJECTION__01",
        "network": "Base (eip155:8453)",
        "usdc_contract": USDC,
        "block": block,
        "read_at": datetime.now(timezone.utc).isoformat(),
        "rows": rows,
        "totals": {
            "accessible_usdc_micro": tot_usdc,
            "accessible_eth_wei": tot_eth,
            "stranded_usdc_micro": stranded_usdc,
            "stranded_eth_wei": sum(r["eth_wei"] for r in stranded_rows),
        },
        "reconciliation": {
            "usdc": {
                "supplied_micro": USDC_SUPPLIED_MICRO,
                "stranded_micro": USDC_STRANDED_MICRO,
                "expected_accessible_micro": exp_usdc,
                "actual_accessible_micro": tot_usdc,
                "remainder_micro": rem_usdc,
                "verdict": "RECONCILED" if usdc_ok else "UNRECONCILED",
            },
            "eth": {
                "provided_wei": ETH_PROVIDED_WEI,
                "actual_total_wei": tot_eth,
                "burned_gas_wei": burned_eth,
                "verdict": "RECONCILED" if eth_ok else "UNRECONCILED",
            },
            "verdict": "RECONCILED" if (usdc_ok and eth_ok)
                       else "UNRECONCILED",
        },
        "runway": _runway(relayer_row["eth_wei"]),
    }


def _usdc(micro):
    return f"{micro / 1e6:,.6f}"


def _eth(wei):
    return f"{wei / 1e18:.6f}"


def render_html(doc):
    rows = []
    for r in doc["rows"]:
        style = ' style="color:#a00"' if r["stranded"] else ""
        rows.append(
            f"<tr{style}><td>{html.escape(r['name'])}</td>"
            f"<td>{html.escape(r['role'])}</td>"
            f"<td style='text-align:right'>{_usdc(r['usdc_micro'])}</td>"
            f"<td style='text-align:right'>{_eth(r['eth_wei'])}</td>"
            f"<td><small>{html.escape(r['address'])}</small></td></tr>")
    t = doc["totals"]
    rec = doc["reconciliation"]
    run = doc["runway"]
    runway_txt = (f"~{run['settlements_remaining_estimate']} settlements "
                  f"at recent cost" if run.get(
                      "settlements_remaining_estimate") is not None
                  else "unavailable")
    return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>8374 — Complete Funds</title></head>
<body style="font-family:system-ui,sans-serif;margin:1em;max-width:60em">
<h2>8374 — Complete Funds</h2>
<p>Base mainnet, block {doc['block']} · read {html.escape(doc['read_at'])}<br>
Reconciliation: <strong>{html.escape(rec['verdict'])}</strong> ·
Production relayer runway: <strong>{runway_txt}</strong></p>
<table border="1" cellspacing="0" cellpadding="6" style="border-collapse:collapse">
<tr><th>Account</th><th>Role</th><th>USDC</th><th>ETH</th><th>Address</th></tr>
{''.join(rows)}
<tr><td colspan="2"><strong>Accessible total</strong></td>
<td style="text-align:right"><strong>{_usdc(t['accessible_usdc_micro'])}</strong></td>
<td style="text-align:right"><strong>{_eth(t['accessible_eth_wei'])}</strong></td><td></td></tr>
</table>
<p>Stranded (never in totals): {_usdc(t['stranded_usdc_micro'])} USDC at the
keyless demo payer.<br>
USDC check: supplied {_usdc(rec['usdc']['supplied_micro'])} − stranded
{_usdc(rec['usdc']['stranded_micro'])} = expected
{_usdc(rec['usdc']['expected_accessible_micro'])}; actual
{_usdc(rec['usdc']['actual_accessible_micro'])}; remainder
{_usdc(rec['usdc']['remainder_micro'])} — {html.escape(rec['usdc']['verdict'])}<br>
ETH check: provided {_eth(rec['eth']['provided_wei'])}; on hand
{_eth(rec['eth']['actual_total_wei'])}; burned as gas
{_eth(rec['eth']['burned_gas_wei'])} — {html.escape(rec['eth']['verdict'])}</p>
</body></html>"""
