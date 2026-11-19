#!/usr/bin/env python3
"""Battery 6 — payment dialects + published contract + proof
as content (the route-contract cure, 2026-11-19).

Against a THROWAWAY router instance and the specimen seller:
 1. v1 seller leg presented in the X-PAYMENT header (fee leg
    base64 in the body) routes ALLOW and delivers;
 2. v2 seller leg presented in the PAYMENT-SIGNATURE header
    routes ALLOW and delivers;
 3. both legs presented as decoded JSON OBJECTS in the body
    route ALLOW and deliver;
 4. v2 fee leg + v2 seller leg (base64 body) in SETTLE mode
    settle on-chain: seller payTo +price exactly, router payTo
    +quoted total exactly (funded throwaway buyer, the battery-3
    specimen funding pattern);
 5. garbage fee payload -> FAIL_CLOSED PAYMENT_PAYLOAD_
    MALFORMED, seller never contacted;
 6. garbage seller payload (base64 of a non-payment object)
    with a valid fee leg -> FAIL_CLOSED, seller never
    contacted;
 7. GET /router and GET /router/openapi.json publish the route
    contract (legs, presentations, /router/route schema);
 8. the service document's provenance block is LIVE: pair
    count + terminal anchor equal an independent read of the
    production chain files, and the worked example's output is
    the production chain's latest settled ALLOW pair, fields
    matching the stored record;
 9. the discovery feed's 8374 items carry metadata.provenance
    with the same live fields; the specimen seller's item does
    not (absence stays absence).
"""
import base64, json, os, sys, tempfile, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import router_testkit as tk
import x402kit

B = tk.Battery("Battery 6 (dialects + contract + provenance)")
TXS = []
PRICE = 3000
BUYER_USDC = 30000
RELAYER_ETH = 20_000_000_000_000


def prod_scan():
    """Independent read of the production endpoint chain files:
    (pair_count, terminal_anchor, latest_settled_allow_pair)."""
    entries = tk.read_chain(os.path.join(tk.ENDPOINT_DIR,
                                         "receipts"))
    pairs = {}
    order = []
    anchor = None
    for r in entries:
        anchor = r["hash"]
        c = r["content"]
        pid = c.get("pair_id")
        if pid not in pairs:
            pairs[pid] = []
            order.append(pid)
        pairs[pid].append(c)
    latest = None
    for pid in reversed(order):
        ms = pairs[pid]
        if ms[0].get("disposition") != "ALLOW":
            continue
        for c in ms:
            s = c.get("settlement")
            if isinstance(s, dict) and s.get("status") == "SETTLED" \
                    and s.get("tx_hash"):
                latest = {"pair_id": pid,
                          "tx_hash": s["tx_hash"],
                          "value_micro_usdc":
                              s.get("value_micro_usdc")}
                break
        if latest:
            break
    return len(pairs), anchor, latest


def main():
    tmp = tempfile.mkdtemp(prefix="router-b6-")
    _rp, router_payto = x402kit.new_keypair()
    relayer_priv, relayer_addr = x402kit.new_keypair()
    proc, base, env, _rel = tk.make_router_instance(
        tmp, 8931, router_payto, relayer_priv)
    B.track(proc)
    _sp, seller_payto = x402kit.new_keypair()
    seller_proc, seller_base = tk.start_seller(8932, seller_payto,
                                               price=PRICE)
    B.track(seller_proc)
    tk.call(base, "POST", "/router/register", {"origin": seller_base})

    buyer_priv, buyer = x402kit.new_keypair()

    # --- funding (battery-3 pattern) for the settle check ---
    spec_priv, spec_addr = tk.load_json_key(
        os.path.join(tk.ENDPOINT_DIR, "specimen_payer.json"),
        "priv_hex")
    eth_src_priv, eth_src_addr = spec_priv, spec_addr
    if tk.eth_balance(spec_addr) < RELAYER_ETH + 1_000_000_000_000:
        eth_src_priv, eth_src_addr = tk.load_json_key(
            os.path.join(tk.ENDPOINT_DIR, "settlement_relayer.json"),
            "private_key")
    tx = tk.send_eth(eth_src_priv, relayer_addr, RELAYER_ETH)
    TXS.append(("ETH funding -> router relayer", tx))
    relayer_key_path = os.path.join(tmp, "router_relayer.json")
    rec = tk.fund_usdc(spec_priv, spec_addr, buyer, BUYER_USDC,
                       relayer_key_path)
    if rec.get("tx_hash"):
        TXS.append(("USDC funding -> buyer", rec["tx_hash"]))
    B.check("setup: buyer funded with USDC via EIP-3009 + "
            "router relayer",
            rec.get("status") in ("SETTLED", "SUBMITTED")
            and bool(rec.get("tx_hash"))
            and tk.tx_settled(rec["tx_hash"])
            and tk.usdc_balance(buyer) >= BUYER_USDC,
            f"status={rec.get('status')}, tx={rec.get('tx_hash')}, "
            f"buyer USDC={tk.usdc_balance(buyer)}")

    def quote_total():
        _c, q = tk.call(base, "GET", "/router/quote?tier=receipt-only")
        return q["total_micro_usdc"]

    def route(body, headers=None):
        return tk.call(base, "POST", "/router/route", body,
                       headers=headers)

    def base_body(**kw):
        b = {"counterparty": "battery-6-buyer",
             "seller_origin": seller_base, "resource": "/resource",
             "scope": "receipt-only", "settlement": "relay",
             "resource_body": {"want": "specimen"}}
        b.update(kw)
        return b

    def fresh_v1(to, value):
        n = int(time.time())
        hdr, _a, _d = x402kit.make_payment_header(
            buyer_priv, buyer, to, value, n - 10, n + 3600)
        return hdr

    def fresh_v2(to, value):
        n = int(time.time())
        hdr, _a, _d = x402kit.make_payment_header_v2(
            buyer_priv, buyer, to, value, n - 10, n + 3600)
        return hdr

    def delivered(resp):
        r = resp.get("route") or {}
        return resp.get("disposition") == "ALLOW" \
            and r.get("delivery") == "DELIVERED" \
            and r.get("seller_status") == 200

    # --- 1. v1 seller leg via X-PAYMENT header ---
    total = quote_total()
    code, resp = route(base_body(fee_payment=fresh_v1(router_payto,
                                                      total)),
                       headers={"X-PAYMENT": fresh_v1(seller_payto,
                                                      PRICE)})
    B.check("v1 seller leg via X-PAYMENT header routes ALLOW "
            "and delivers", code == 200 and delivered(resp),
            f"http={code}, disposition={resp.get('disposition')}, "
            f"route={resp.get('route')}")

    # --- 2. v2 seller leg via PAYMENT-SIGNATURE header ---
    total = quote_total()
    code, resp = route(base_body(fee_payment=fresh_v1(router_payto,
                                                      total)),
                       headers={"PAYMENT-SIGNATURE":
                                fresh_v2(seller_payto, PRICE)})
    B.check("v2 seller leg via PAYMENT-SIGNATURE header routes "
            "ALLOW and delivers", code == 200 and delivered(resp),
            f"http={code}, disposition={resp.get('disposition')}, "
            f"route={resp.get('route')}")

    # --- 3. both legs as JSON objects in the body ---
    total = quote_total()
    fee_obj = json.loads(base64.b64decode(fresh_v1(router_payto,
                                                   total)))
    seller_obj = json.loads(base64.b64decode(fresh_v1(seller_payto,
                                                      PRICE)))
    code, resp = route(base_body(fee_payment=fee_obj,
                                 payment=seller_obj))
    B.check("both legs as JSON objects in the body route ALLOW "
            "and deliver", code == 200 and delivered(resp),
            f"http={code}, disposition={resp.get('disposition')}, "
            f"route={resp.get('route')}")

    # --- 4. v2 + v2, settle mode, on-chain ---
    total = quote_total()
    seller_before = tk.usdc_balance(seller_payto)
    payto_before = tk.usdc_balance(router_payto)
    code, resp = route(base_body(
        settlement="settle",
        fee_payment=fresh_v2(router_payto, total),
        payment=fresh_v2(seller_payto, PRICE)))
    st = resp.get("settlement") or {}
    s_leg = st.get("seller_leg") or {}
    f_leg = st.get("fee_leg") or {}
    s_settle = s_leg.get("settlement") or {}
    f_settle = f_leg.get("settlement") or {}
    if s_settle.get("tx_hash"):
        TXS.append(("settle: buyer->seller (v2)", s_settle["tx_hash"]))
    if f_settle.get("tx_hash"):
        TXS.append(("settle: buyer->8374 fee leg (v2)",
                    f_settle["tx_hash"]))
    if f_leg.get("settlement_state") == "PENDING":
        _c, sp = tk.call(base, "POST", "/router/settle-pair",
                         {"pair_id": resp.get("pair_id")})
        for res in sp.get("results", []):
            srec = res.get("settlement") or {}
            if srec.get("tx_hash"):
                TXS.append((f"settle-pair retry: {res.get('leg')}",
                            srec["tx_hash"]))
            if res.get("leg") == "fee":
                f_leg, f_settle = res, srec
    B.check("v2 fee + v2 seller legs settle on-chain (seller "
            "+price, router payTo +total, exact)",
            code == 200 and delivered(resp)
            and s_leg.get("settlement_state") in ("SETTLED",
                                                  "SUBMITTED")
            and bool(s_settle.get("tx_hash"))
            and tk.tx_settled(s_settle["tx_hash"])
            and tk.usdc_balance(seller_payto)
            == seller_before + PRICE
            and f_leg.get("settlement_state") in ("SETTLED",
                                                  "SUBMITTED")
            and bool(f_settle.get("tx_hash"))
            and tk.tx_settled(f_settle["tx_hash"])
            and tk.usdc_balance(router_payto)
            == payto_before + total,
            f"http={code}, seller {seller_before}->"
            f"{tk.usdc_balance(seller_payto)} (expected +{PRICE}), "
            f"payTo {payto_before}->{tk.usdc_balance(router_payto)} "
            f"(expected +{total}), s_tx={s_settle.get('tx_hash')}, "
            f"f_tx={f_settle.get('tx_hash')}")

    # --- 5/6. garbage still fails closed ---
    _c, stats0 = tk.call(seller_base, "GET", "/stats")
    total = quote_total()
    code, resp = route(base_body(fee_payment="!!!garbage!!!",
                                 payment=fresh_v1(seller_payto,
                                                  PRICE)))
    det = resp.get("detail") or {}
    B.check("garbage fee payload -> FAIL_CLOSED "
            "PAYMENT_PAYLOAD_MALFORMED",
            resp.get("disposition") == "FAIL_CLOSED"
            and det.get("failure_code")
            == "PAYMENT_PAYLOAD_MALFORMED",
            f"http={code}, code={det.get('failure_code')}")
    junk = base64.b64encode(json.dumps({"foo": 1}).encode()).decode()
    code, resp = route(base_body(
        fee_payment=fresh_v1(router_payto, total), payment=junk))
    det = resp.get("detail") or {}
    _c, stats1 = tk.call(seller_base, "GET", "/stats")
    B.check("garbage seller payload -> FAIL_CLOSED, seller "
            "never contacted",
            resp.get("disposition") == "FAIL_CLOSED"
            and det.get("failure_code") in (
                "PAYMENT_PAYLOAD_MALFORMED",
                "PAYMENT_REQUIREMENTS_MISMATCH")
            and stats1["paid_requests"] == stats0["paid_requests"],
            f"http={code}, code={det.get('failure_code')}, seller "
            f"paid_requests {stats0['paid_requests']}->"
            f"{stats1['paid_requests']}")

    # --- 7. published contract surfaces ---
    code_r, doc = tk.call(base, "GET", "/router")
    rc = doc.get("route_contract") or {}
    legs = rc.get("legs") or {}
    code_o, oa = tk.call(base, "GET", "/router/openapi.json")
    route_op = ((oa.get("paths") or {}).get("/router/route") or {})
    B.check("GET /router + /router/openapi.json publish the "
            "route contract",
            code_r == 200 and code_o == 200
            and (legs.get("fee_leg") or {}).get("body_field")
            == "fee_payment"
            and (legs.get("seller_leg") or {}).get("body_field")
            == "payment"
            and "worked_example" in rc
            and route_op.get("post") is not None,
            f"/router http={code_r}, openapi http={code_o}, legs="
            f"{sorted(legs)}, openapi paths="
            f"{sorted((oa.get('paths') or {}).keys())}")

    # --- 8. provenance: the proof is the content ---
    code_r2, doc = tk.call(base, "GET", "/router")
    rc = doc.get("route_contract") or {}
    pairs_n, anchor, latest = prod_scan()
    prov = doc.get("provenance") or {}
    out = (rc.get("worked_example") or {}).get("output") or {}
    B.check("service document provenance is live (pairs + "
            "anchor equal the independent production read)",
            prov.get("pairs") == pairs_n
            and prov.get("terminal_anchor") == anchor
            and bool(prov.get("provenance_url"))
            and bool(prov.get("replay_url")),
            f"doc pairs={prov.get('pairs')} vs scan {pairs_n}; "
            f"anchor match={prov.get('terminal_anchor') == anchor}")
    B.check("worked example output is the production chain's "
            "latest settled ALLOW pair (real fields)",
            latest is not None
            and out.get("pair_id") == latest["pair_id"]
            and (out.get("settlement") or {}).get("tx_hash")
            == latest["tx_hash"]
            and out.get("disposition") == "ALLOW",
            f"doc output pair={out.get('pair_id')} vs scan "
            f"{latest and latest['pair_id']}; tx match="
            f"{(out.get('settlement') or {}).get('tx_hash') == (latest or {}).get('tx_hash')}")

    # --- 9. discovery feed provenance on 8374's row only ---
    code_f, feed_doc = tk.call(base, "GET",
                               "/router/discovery/resources?limit=100")
    items = feed_doc.get("items") or []
    self_items = [i for i in items if str(i.get("resource", ""))
                  .startswith("https://8374.stegverse.org")]
    seller_items = [i for i in items if str(i.get("resource", ""))
                    .startswith(seller_base)]
    def prov_of(i):
        return (i.get("metadata") or {}).get("provenance") or {}
    B.check("discovery feed: 8374 items carry live "
            "metadata.provenance; seller items carry none",
            code_f == 200 and len(self_items) >= 1
            and all(prov_of(i).get("pairs") == pairs_n
                    and prov_of(i).get("terminal_anchor") == anchor
                    and prov_of(i).get("replay_url")
                    and prov_of(i).get("provenance_url")
                    for i in self_items)
            and len(seller_items) >= 1
            and all("provenance" not in (i.get("metadata") or {})
                    for i in seller_items),
            f"self items={len(self_items)}, seller items="
            f"{len(seller_items)}, self prov pairs="
            f"{[prov_of(i).get('pairs') for i in self_items]}")

    rc2, rep = tk.replay_verdict(os.path.join(tmp, "receipts"), env)
    B.check("router chain replays MATCH",
            rc2 == 0 and rep.get("verdict") == "MATCH",
            f"verdict={rep.get('verdict')}, pairs={rep.get('pairs')}")
    for label, h in TXS:
        print(f"  tx[{label}]: {h}")
    return B.finish()


if __name__ == "__main__":
    sys.exit(main())
