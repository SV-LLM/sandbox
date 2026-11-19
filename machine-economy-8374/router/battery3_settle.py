#!/usr/bin/env python3
"""Battery 3 — settle-mode route, on-chain (ROUTER-V1).

Against a THROWAWAY router instance and the specimen seller,
with throwaway keys funded minimally from the coordinator
specimen payer (0xCa48d33c…B0E5) by the existing specimen
funding pattern:
 0. funding: ETH (gas) to the router's throwaway relayer from a
    key holding ETH (specimen payer preferred; the endpoint's
    gas-only relayer as fallback — either way a reported tx);
    USDC to the throwaway buyer from the specimen payer via an
    EIP-3009 authorization submitted by the router relayer.
 1. a settle-mode route resolves ALLOW, delivers the seller
    response, and the router's relayer submits the buyer→seller
    EIP-3009 authorization: the pair records the settlement and
    a SETTLEMENT pair is appended bound to it;
 2. the seller's payTo balance moves by EXACTLY the resource
    price (read back independently over the live RPC);
 3. the fee leg settles too: the router payTo balance moves by
    exactly the quoted total (governance fee + settlement
    charge);
 4. the router chain replays MATCH.
Every on-chain tx hash is printed.
"""
import os, sys, tempfile, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import router_testkit as tk
import x402kit

B = tk.Battery("Battery 3 (settle-mode route, on-chain)")
TXS = []
PRICE = 3000
BUYER_USDC = 30000
RELAYER_ETH = 20_000_000_000_000  # 0.00002 ETH — at the observed
# Base base fee (0.005 gwei) one settlement costs ~9e8 wei, so
# this funds the battery's submissions ~20,000x over; earlier
# runs drew 0.001 ETH per run from the endpoint relayer, which
# was ~1000x oversized and is not repeated.


def main():
    tmp = tempfile.mkdtemp(prefix="router-b3-")
    _rp, router_payto = x402kit.new_keypair()
    relayer_priv, relayer_addr = x402kit.new_keypair()
    proc, base, env, _rel = tk.make_router_instance(
        tmp, 8911, router_payto, relayer_priv)
    B.track(proc)
    _sp, seller_payto = x402kit.new_keypair()
    seller_proc, seller_base = tk.start_seller(8912, seller_payto,
                                               price=PRICE)
    B.track(seller_proc)
    buyer_priv, buyer = x402kit.new_keypair()
    relayer_key_path = os.path.join(tmp, "router_relayer.json")

    spec_priv, spec_addr = tk.load_json_key(
        os.path.join(tk.ENDPOINT_DIR, "specimen_payer.json"),
        "priv_hex")
    spec_usdc = tk.usdc_balance(spec_addr)
    B.check("specimen payer holds the funding USDC",
            spec_usdc >= BUYER_USDC,
            f"specimen payer {spec_addr} USDC={spec_usdc}")

    # ETH source: specimen payer if it holds enough, else the
    # endpoint's gas-only relayer (both specimen-grade wallets).
    eth_src_priv, eth_src_addr, eth_src_name = spec_priv, spec_addr, \
        "specimen payer"
    if tk.eth_balance(spec_addr) < RELAYER_ETH + 1_000_000_000_000:
        eth_src_priv, eth_src_addr = tk.load_json_key(
            os.path.join(tk.ENDPOINT_DIR, "settlement_relayer.json"),
            "private_key")
        eth_src_name = "endpoint gas-only relayer"
    eth_bal = tk.eth_balance(eth_src_addr)
    B.check("an ETH source holds the relayer gas funding",
            eth_bal >= RELAYER_ETH + 1_000_000_000_000,
            f"{eth_src_name} {eth_src_addr} ETH wei={eth_bal}")
    tx = tk.send_eth(eth_src_priv, relayer_addr, RELAYER_ETH)
    TXS.append(("ETH funding -> router relayer", tx))
    B.check("router relayer funded with gas ETH",
            tk.eth_balance(relayer_addr) >= RELAYER_ETH,
            f"tx={tx}, relayer={relayer_addr}")

    rec = tk.fund_usdc(spec_priv, spec_addr, buyer, BUYER_USDC,
                       relayer_key_path)
    if rec.get("tx_hash"):
        TXS.append(("USDC funding -> buyer", rec["tx_hash"]))
    B.check("buyer funded with USDC via EIP-3009 + router relayer",
            rec.get("status") in ("SETTLED", "SUBMITTED")
            and bool(rec.get("tx_hash"))
            and tk.tx_settled(rec["tx_hash"])
            and tk.usdc_balance(buyer) >= BUYER_USDC,
            f"status={rec.get('status')}, tx={rec.get('tx_hash')}, "
            f"buyer USDC={tk.usdc_balance(buyer)}")

    tk.call(base, "POST", "/router/register", {"origin": seller_base})
    seller_before = tk.usdc_balance(seller_payto)
    payto_before = tk.usdc_balance(router_payto)
    now_ts = int(time.time())
    _c, quote = tk.call(base, "GET", "/router/quote?tier=receipt-only")
    total = quote["total_micro_usdc"]
    fee_hdr, _fa, _d1 = x402kit.make_payment_header(
        buyer_priv, buyer, router_payto, total, now_ts - 10,
        now_ts + 3600)
    seller_hdr, _sa, _d2 = x402kit.make_payment_header(
        buyer_priv, buyer, seller_payto, PRICE, now_ts - 10,
        now_ts + 3600)
    code, resp = tk.call(base, "POST", "/router/route", {
        "counterparty": "battery-3-buyer", "seller_origin": seller_base,
        "resource": "/resource", "scope": "receipt-only",
        "settlement": "settle", "payment": seller_hdr,
        "fee_payment": fee_hdr, "resource_body": {"want": "specimen"}})
    st = resp.get("settlement") or {}
    s_leg = st.get("seller_leg") or {}
    f_leg = st.get("fee_leg") or {}
    s_settle = s_leg.get("settlement") or {}
    f_settle = f_leg.get("settlement") or {}
    if s_settle.get("tx_hash"):
        TXS.append(("settle: buyer->seller", s_settle["tx_hash"]))
    if f_settle.get("tx_hash"):
        TXS.append(("settle: buyer->8374 fee leg", f_settle["tx_hash"]))
    B.check("settle route resolves ALLOW and delivers",
            code == 200 and resp.get("disposition") == "ALLOW"
            and (resp.get("route") or {}).get("delivery")
            == "DELIVERED",
            f"http={code}, disposition={resp.get('disposition')}, "
            f"delivery={(resp.get('route') or {}).get('delivery')}")
    B.check("seller leg settled by the router relayer",
            s_leg.get("settlement_state") in ("SETTLED", "SUBMITTED")
            and bool(s_settle.get("tx_hash"))
            and tk.tx_settled(s_settle["tx_hash"]),
            f"state={s_leg.get('settlement_state')}, "
            f"tx={s_settle.get('tx_hash')}, "
            f"failure={s_settle.get('failure_code')}")
    B.check("seller payTo balance moved by exactly the price",
            tk.usdc_balance(seller_payto) == seller_before + PRICE,
            f"{seller_before} -> {tk.usdc_balance(seller_payto)} "
            f"(expected +{PRICE})")
    # Pair-first: a leg whose first attempt lands PENDING is
    # settled by the eventual leg — driven here through
    # POST /router/settle-pair (the production pattern) rather
    # than left to the 60s sweep, with the first attempt's record
    # printed either way.
    if f_leg.get("settlement_state") == "PENDING":
        print(f"  fee leg first attempt: state="
              f"{f_leg.get('settlement_state')}, failure_code="
              f"{f_settle.get('failure_code')}, error="
              f"{str(f_settle.get('error'))[:160]}")
        _c, sp = tk.call(base, "POST", "/router/settle-pair",
                         {"pair_id": resp.get("pair_id")})
        for res in sp.get("results", []):
            srec = res.get("settlement") or {}
            if srec.get("tx_hash"):
                TXS.append((f"settle-pair retry: {res.get('leg')} leg",
                            srec["tx_hash"]))
            if res.get("leg") == "fee":
                f_leg, f_settle = res, srec
        print(f"  fee leg after settle-pair: state="
              f"{f_leg.get('settlement_state')}, failure_code="
              f"{f_settle.get('failure_code')}")
    B.check("fee leg settled; router payTo moved by the quoted total",
            f_leg.get("settlement_state") in ("SETTLED", "SUBMITTED")
            and bool(f_settle.get("tx_hash"))
            and tk.tx_settled(f_settle["tx_hash"])
            and tk.usdc_balance(router_payto) == payto_before + total,
            f"state={f_leg.get('settlement_state')}, "
            f"tx={f_settle.get('tx_hash')}, payTo "
            f"{payto_before} -> {tk.usdc_balance(router_payto)} "
            f"(expected +{total})")
    entries = tk.read_chain(os.path.join(tmp, "receipts"))
    settle_pairs = [r["content"] for r in entries
                    if r["content"].get("pair_class") == "SETTLEMENT"
                    and r["content"].get("index_in_pair") == 0
                    and r["content"].get("settles_pair_id")
                    == resp.get("pair_id")]
    B.check("settlement outcome receipted as appended SETTLEMENT "
            "pair(s) bound to the route pair",
            len(settle_pairs) >= 1
            and all((c.get("settlement") or {}).get("status")
                    in ("SETTLED", "SUBMITTED")
                    and tk.tx_settled(
                        (c.get("settlement") or {}).get("tx_hash"))
                    for c in settle_pairs),
            f"settlement pairs bound to {resp.get('pair_id')}: "
            f"{len(settle_pairs)}")
    rc, rep = tk.replay_verdict(os.path.join(tmp, "receipts"), env)
    B.check("router chain replays MATCH",
            rc == 0 and rep.get("verdict") == "MATCH",
            f"verdict={rep.get('verdict')}, pairs={rep.get('pairs')}")
    print("\nOn-chain transactions (throwaway funds):")
    for label, h in TXS:
        print(f"  {label}: {h}")
    return B.finish()


if __name__ == "__main__":
    sys.exit(main())
