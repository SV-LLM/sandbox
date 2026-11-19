#!/usr/bin/env python3
"""Battery 2 — relay-mode route (ROUTER-V1).

Against a THROWAWAY router instance and the specimen seller:
a buyer-signed payment is routed in relay mode —
 1. the route resolves ALLOW and the seller's response is
    delivered back to the buyer;
 2. the router chain carries the ALLOW receipt pair with BOTH
    payment evidences (fee leg + seller leg), the seller leg's
    nonce being the buyer authorization's nonce;
 3. the seller saw exactly one paid request and served it;
 4. relay mode settles nothing on-chain (seller leg RELAYED);
 5. the router chain replays MATCH.
The buyer key is throwaway and unfunded: relay mode is
cryptographic verification + delivery, exactly the production
specimen pattern — nothing settles, so no balance is needed.
"""
import os, sys, tempfile, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import router_testkit as tk
import x402kit

B = tk.Battery("Battery 2 (relay-mode route)")


def main():
    tmp = tempfile.mkdtemp(prefix="router-b2-")
    _rp, router_payto = x402kit.new_keypair()
    relayer_priv, _ra = x402kit.new_keypair()
    proc, base, env, _rel = tk.make_router_instance(
        tmp, 8901, router_payto, relayer_priv)
    B.track(proc)
    _sp, seller_payto = x402kit.new_keypair()
    seller_proc, seller_base = tk.start_seller(8902, seller_payto,
                                               price=3000)
    B.track(seller_proc)
    tk.call(base, "POST", "/router/register", {"origin": seller_base})
    _c, stats0 = tk.call(seller_base, "GET", "/stats")

    buyer_priv, buyer = x402kit.new_keypair()
    now_ts = int(time.time())
    _c, quote = tk.call(base, "GET", "/router/quote?tier=receipt-only")
    total = quote["total_micro_usdc"]
    fee_hdr, fee_auth, _d1 = x402kit.make_payment_header(
        buyer_priv, buyer, router_payto, total, now_ts - 10,
        now_ts + 3600)
    seller_hdr, seller_auth, _d2 = x402kit.make_payment_header(
        buyer_priv, buyer, seller_payto, 3000, now_ts - 10,
        now_ts + 3600)
    code, resp = tk.call(base, "POST", "/router/route", {
        "counterparty": "battery-2-buyer", "seller_origin": seller_base,
        "resource": "/resource", "scope": "receipt-only",
        "settlement": "relay", "payment": seller_hdr,
        "fee_payment": fee_hdr, "resource_body": {"want": "specimen"}})
    route = resp.get("route") or {}
    seller_resp = route.get("seller_response") or {}
    B.check("relay route resolves ALLOW and delivers the seller "
            "response",
            code == 200 and resp.get("disposition") == "ALLOW"
            and route.get("delivery") == "DELIVERED"
            and route.get("seller_status") == 200
            and seller_resp.get("data")
            == "the specimen seller's paid payload",
            f"http={code}, disposition={resp.get('disposition')}, "
            f"delivery={route.get('delivery')}, "
            f"seller_status={route.get('seller_status')}")
    B.check("relay mode settles nothing on-chain",
            (resp.get("settlement") or {}).get("seller_leg", {})
            .get("settlement_state") == "RELAYED",
            f"seller_leg={(resp.get('settlement') or {}).get('seller_leg')}")

    members = tk.pair_contents(os.path.join(tmp, "receipts"),
                               resp.get("pair_id"))
    pay = (members[0].get("payment") or {}) if members else {}
    rpay = (members[0].get("route_payment") or {}) if members else {}
    B.check("ALLOW pair carries both payment evidences",
            len(members) == 2
            and members[0].get("disposition") == "ALLOW"
            and pay.get("nonce") == fee_auth["nonce"]
            and rpay.get("nonce") == seller_auth["nonce"]
            and rpay.get("payTo") == seller_payto
            and pay.get("payTo") == router_payto,
            f"members={len(members)}, fee nonce match="
            f"{pay.get('nonce') == fee_auth['nonce']}, seller nonce "
            f"match={rpay.get('nonce') == seller_auth['nonce']}")
    _c, stats1 = tk.call(seller_base, "GET", "/stats")
    B.check("seller saw exactly one paid request and served it",
            stats1["paid_requests"] - stats0["paid_requests"] == 1
            and stats1["served"] - stats0["served"] == 1,
            f"paid {stats0['paid_requests']}->{stats1['paid_requests']}, "
            f"served {stats0['served']}->{stats1['served']}")
    rc, rep = tk.replay_verdict(os.path.join(tmp, "receipts"), env)
    B.check("router chain replays MATCH",
            rc == 0 and rep.get("verdict") == "MATCH",
            f"verdict={rep.get('verdict')}, pairs={rep.get('pairs')}")
    return B.finish()


if __name__ == "__main__":
    sys.exit(main())
