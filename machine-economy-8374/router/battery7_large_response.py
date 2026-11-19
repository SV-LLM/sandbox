#!/usr/bin/env python3
"""Battery 7 — large seller responses (the relay-read cure,
2026-11-19).

The clean-room acceptance run's routed settlement completed
on-chain but receipted AMBIGUOUS: the seller's ~241 KB response
EOF'd at 177,152 of 241,350 promised bytes in the serving
segment, and the relay's single .read() converted the short
stream into a false delivery failure. The cure: the relay reads
with an explicit completion loop (_read_full_body), the serving
stack writes completely (_write_all in the public proxy and in
this router's own responses), and genuine truncation still
receipts AMBIGUOUS — the honesty rule is unchanged.

Against a THROWAWAY router instance and specimen sellers:
 A. big seller — a paid response of exactly 241,350 bytes —
    routes DELIVERED; the ROUTE pair's recorded seller_response
    carries the pad whose SHA-256 equals the hash the seller
    stated inside the body (the body hashed both sides); the
    seller served exactly one paid request;
 B. dropmid seller — response headers promise the full big
    body, the connection dies after 100,000 bytes — routes
    AMBIGUOUS (ROUTE_AMBIGUOUS pair), with exactly ONE paid
    relay attempt at the seller and the seller settlement leg
    NOT_ATTEMPTED: genuine truncation stays ambiguous;
 C. big seller behind the public proxy (the production serving
    pattern for 8374's own origin: the proxy re-originates the
    seller's body) routes DELIVERED with the pad hash intact;
 D. the throwaway router chain replays MATCH.
"""
import hashlib, json, os, sys, tempfile, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import router_testkit as tk
import x402kit

B = tk.Battery("Battery 7 (large seller responses)")
PRICE = 3000
BIG_TARGET = 241350
DROP_AFTER = 100000
PROXY_PY = os.path.join(tk.ENDPOINT_DIR, "public_proxy.py")


def route_records(receipts_dir, pair_id):
    return [r["content"] for r in tk.read_chain(receipts_dir)
            if r["content"].get("route_for_pair_id") == pair_id]


def main():
    tmp = tempfile.mkdtemp(prefix="router-b7-")
    _rp, router_payto = x402kit.new_keypair()
    relayer_priv, _ra = x402kit.new_keypair()
    proc, base, env, _rel = tk.make_router_instance(
        tmp, 8941, router_payto, relayer_priv)
    B.track(proc)
    receipts_dir = os.path.join(tmp, "receipts")

    _sp, seller_payto = x402kit.new_keypair()
    big_proc, big_base = tk.start_seller(8942, seller_payto,
                                         price=PRICE, mode="big")
    B.track(big_proc)
    drop_proc, drop_base = tk.start_seller(8943, seller_payto,
                                           price=PRICE,
                                           mode="dropmid")
    B.track(drop_proc)
    # Case C stack: big seller (8944) behind a replica of the
    # production public proxy (8945), advertised under the
    # proxy's origin — the production serving pattern.
    c_proc, _c_base = tk.start_seller(
        8944, seller_payto, price=PRICE, mode="big",
        public_origin="http://127.0.0.1:8945",
        resource_path="/crossing")
    B.track(c_proc)
    proxy_proc = tk.start_proc(
        [PROXY_PY],
        {"ME_UPSTREAM_PORT": "8944", "ME_PROXY_PORT": "8945",
         "ME_ROUTER_UPSTREAM_PORT": "8944"},
        cwd=tk.ENDPOINT_DIR)
    B.track(proxy_proc)
    proxy_base = "http://127.0.0.1:8945"
    if not tk.wait_health(proxy_base):
        raise RuntimeError("public proxy replica never healthy")

    for origin in (big_base, drop_base, proxy_base):
        tk.call(base, "POST", "/router/register",
                {"origin": origin})

    buyer_priv, buyer = x402kit.new_keypair()

    def quote_total():
        _c, q = tk.call(base, "GET", "/router/quote?tier=receipt-only")
        return q["total_micro_usdc"]

    def fresh_v1(to, value):
        n = int(time.time())
        hdr, _a, _d = x402kit.make_payment_header(
            buyer_priv, buyer, to, value, n - 10, n + 3600)
        return hdr

    def route(origin, resource, mode):
        return tk.call(base, "POST", "/router/route", {
            "counterparty": "battery-7-buyer",
            "seller_origin": origin, "resource": resource,
            "scope": "receipt-only", "settlement": mode,
            "resource_body": {"want": "specimen"},
            "fee_payment": fresh_v1(router_payto, quote_total()),
            "payment": fresh_v1(seller_payto, PRICE)})

    def pad_ok(resp, pair_id, stats):
        recs = route_records(receipts_dir, pair_id)
        if not recs:
            return False, "no ROUTE pair recorded"
        sr = recs[0].get("route", {}).get("seller_response") or {}
        pad = sr.get("pad") or ""
        digest = hashlib.sha256(pad.encode()).hexdigest()
        return (sr.get("pad_sha256") == stats.get("big_pad_sha256")
                and digest == stats.get("big_pad_sha256")
                and stats.get("big_body_len") == BIG_TARGET), \
            f"chain pad sha={digest[:16]} vs seller stated " \
            f"{(stats.get('big_pad_sha256') or '')[:16]}, body " \
            f"len={stats.get('big_body_len')}"

    # --- A. big seller, direct: DELIVERED, body intact ---
    _c, st0 = tk.call(big_base, "GET", "/stats")
    code, resp = route(big_base, "/resource", "relay")
    _c, st1 = tk.call(big_base, "GET", "/stats")
    ok_pad, ev_pad = pad_ok(resp, resp.get("pair_id"), st1)
    B.check("big seller (241,350-byte body) routes DELIVERED "
            "with the body intact (pad hash both sides)",
            code == 200
            and resp.get("disposition") == "ALLOW"
            and (resp.get("route") or {}).get("delivery")
            == "DELIVERED"
            and (resp.get("route") or {}).get("seller_status")
            == 200
            and resp.get("outcome") != "AMBIGUOUS"
            and ok_pad
            and st1["served"] == st0["served"] + 1
            and st1["paid_requests"] == st0["paid_requests"] + 1,
            f"http={code}, delivery="
            f"{(resp.get('route') or {}).get('delivery')}, "
            f"outcome={resp.get('outcome')}, {ev_pad}, served "
            f"{st0['served']}->{st1['served']}")

    # --- B. dropmid seller: genuine truncation stays AMBIGUOUS ---
    _c, st0 = tk.call(drop_base, "GET", "/stats")
    code, resp = route(drop_base, "/resource", "settle")
    _c, st1 = tk.call(drop_base, "GET", "/stats")
    recs = route_records(receipts_dir, resp.get("pair_id"))
    s_leg = (resp.get("settlement") or {}).get("seller_leg") or {}
    B.check("dropmid seller (dies at 100,000 of 241,350 bytes) "
            "routes AMBIGUOUS, exactly one relay attempt, "
            "seller leg NOT_ATTEMPTED",
            code == 200
            and resp.get("outcome") == "AMBIGUOUS"
            and (resp.get("route") or {}).get("delivery")
            == "AMBIGUOUS"
            and any(r.get("disposition") == "ROUTE_AMBIGUOUS"
                    for r in recs)
            and st1["paid_requests"] == st0["paid_requests"] + 1
            and st1["dropped_mid_after"] == DROP_AFTER
            and s_leg.get("settlement_state") == "NOT_ATTEMPTED",
            f"http={code}, outcome={resp.get('outcome')}, "
            f"route pair dispositions="
            f"{[r.get('disposition') for r in recs]}, seller paid "
            f"{st0['paid_requests']}->{st1['paid_requests']}, "
            f"dropped after {st1['dropped_mid_after']}, seller "
            f"leg={s_leg.get('settlement_state')}")

    # --- C. big seller behind the public proxy: DELIVERED ---
    _c, st0 = tk.call("http://127.0.0.1:8944", "GET", "/stats")
    code, resp = route(proxy_base, "/crossing", "relay")
    _c, st1 = tk.call("http://127.0.0.1:8944", "GET", "/stats")
    ok_pad, ev_pad = pad_ok(resp, resp.get("pair_id"), st1)
    B.check("big seller behind the public proxy (production "
            "serving pattern) routes DELIVERED, body intact",
            code == 200
            and resp.get("disposition") == "ALLOW"
            and (resp.get("route") or {}).get("delivery")
            == "DELIVERED"
            and (resp.get("route") or {}).get("seller_status")
            == 200
            and resp.get("outcome") != "AMBIGUOUS"
            and ok_pad
            and st1["served"] == st0["served"] + 1,
            f"http={code}, delivery="
            f"{(resp.get('route') or {}).get('delivery')}, "
            f"outcome={resp.get('outcome')}, {ev_pad}, served "
            f"{st0['served']}->{st1['served']}")

    rc, rep = tk.replay_verdict(receipts_dir, env)
    B.check("router chain replays MATCH",
            rc == 0 and rep.get("verdict") == "MATCH",
            f"verdict={rep.get('verdict')}, pairs={rep.get('pairs')}")
    return B.finish()


if __name__ == "__main__":
    sys.exit(main())
