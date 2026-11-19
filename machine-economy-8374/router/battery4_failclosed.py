#!/usr/bin/env python3
"""Battery 4 — the fail-closed set (ROUTER-V1).

Against a THROWAWAY router instance and specimen sellers:
 A. garbled fee payment -> FAIL_CLOSED pair
    (PAYMENT_PAYLOAD_MALFORMED); the seller is never contacted.
 B. full-evaluation scope (ME-EVAL-01) without the commit-time
    evidence object -> FAIL_CLOSED KNOWN_EVIDENCE_MISSING; the
    seller is never contacted; no settlement attempted.
 C. replayed seller-leg nonce -> the first route ALLOWs; the
    re-presentation (fresh fee leg, SAME seller authorization)
    resolves DENY / PAYMENT_NONCE_REUSED, the seller is not paid
    twice, and no settlement pair is appended for the refusal.
 D. seller drops the connection mid-route AFTER receiving the
    payment -> the router surfaces AmbiguousOutcome, makes
    exactly ONE relay attempt, appends a ROUTE_AMBIGUOUS outcome
    pair, and settles nothing.
 The chain replays MATCH after all of it.
"""
import os, sys, tempfile, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import router_testkit as tk
import x402kit

B = tk.Battery("Battery 4 (fail-closed set)")
RECEIPTS = None


def headers(buyer_priv, buyer, router_payto, seller_payto, total,
            price=3000):
    now_ts = int(time.time())
    fee_hdr, _fa, _d1 = x402kit.make_payment_header(
        buyer_priv, buyer, router_payto, total, now_ts - 10,
        now_ts + 3600)
    seller_hdr, seller_auth, _d2 = x402kit.make_payment_header(
        buyer_priv, buyer, seller_payto, price, now_ts - 10,
        now_ts + 3600)
    return fee_hdr, seller_hdr, seller_auth


def route(base, buyer, origin, fee_hdr, seller_hdr, scope="receipt-only",
          mode="relay"):
    return tk.call(base, "POST", "/router/route", {
        "counterparty": buyer, "seller_origin": origin,
        "resource": "/resource", "scope": scope, "settlement": mode,
        "payment": seller_hdr, "fee_payment": fee_hdr,
        "resource_body": {"want": "specimen"}})


def main():
    global RECEIPTS
    tmp = tempfile.mkdtemp(prefix="router-b4-")
    RECEIPTS = os.path.join(tmp, "receipts")
    _rp, router_payto = x402kit.new_keypair()
    relayer_priv, _ra = x402kit.new_keypair()
    proc, base, env, _rel = tk.make_router_instance(
        tmp, 8921, router_payto, relayer_priv)
    B.track(proc)
    _sp, seller_payto = x402kit.new_keypair()
    seller_proc, seller_base = tk.start_seller(8922, seller_payto)
    B.track(seller_proc)
    _dp, drop_payto = x402kit.new_keypair()
    drop_proc, drop_base = tk.start_seller(8923, drop_payto,
                                           mode="drop")
    B.track(drop_proc)
    tk.call(base, "POST", "/router/register", {"origin": seller_base})
    tk.call(base, "POST", "/router/register", {"origin": drop_base})
    _c, quote = tk.call(base, "GET", "/router/quote?tier=receipt-only")
    total = quote["total_micro_usdc"]
    buyer_priv, buyer = x402kit.new_keypair()

    # A. garbled fee payment.
    _c, s0 = tk.call(seller_base, "GET", "/stats")
    fee_hdr, seller_hdr, _a = headers(buyer_priv, buyer, router_payto,
                                      seller_payto, total)
    code, resp = route(base, "battery-4-A", seller_base,
                       "!!!not-base64!!!", seller_hdr)
    members = tk.pair_contents(RECEIPTS, resp.get("pair_id"))
    _c, s1 = tk.call(seller_base, "GET", "/stats")
    B.check("A: garbled payment -> FAIL_CLOSED pair, no relay",
            code == 422 and resp.get("disposition") == "FAIL_CLOSED"
            and (resp.get("detail") or {}).get("failure_code")
            == "PAYMENT_PAYLOAD_MALFORMED"
            and len(members) == 2
            and members[0].get("disposition") == "FAIL_CLOSED"
            and s1["requests"] == s0["requests"],
            f"http={code}, code={(resp.get('detail') or {}).get('failure_code')}, "
            f"pair members={len(members)}, seller requests "
            f"{s0['requests']}->{s1['requests']}")

    # B. full evaluation without the evidence object. The fee leg
    # is signed for the FULL-evaluation total (read from the live
    # quote) so verification passes and the evidence predicate is
    # the one that resolves the crossing.
    _c, quote_full = tk.call(base, "GET",
                             "/router/quote?tier=full-evaluation")
    fee_hdr, seller_hdr, _a = headers(
        buyer_priv, buyer, router_payto, seller_payto,
        quote_full["total_micro_usdc"])
    code, resp = route(base, "battery-4-B", seller_base, fee_hdr,
                       seller_hdr, scope="ME-EVAL-01")
    _c, s2 = tk.call(seller_base, "GET", "/stats")
    B.check("B: full evaluation without evidence -> FAIL_CLOSED "
            "KNOWN_EVIDENCE_MISSING, no relay, no settlement",
            code == 422 and resp.get("disposition") == "FAIL_CLOSED"
            and (resp.get("detail") or {}).get("failure_code")
            == "KNOWN_EVIDENCE_MISSING"
            and s2["requests"] == s1["requests"]
            and (resp.get("settlement") or {}).get("state")
            == "NOT_SUBMITTED",
            f"http={code}, code={(resp.get('detail') or {}).get('failure_code')}, "
            f"seller requests {s1['requests']}->{s2['requests']}")

    # C. replayed seller-leg nonce.
    fee_hdr, seller_hdr, _a = headers(buyer_priv, buyer, router_payto,
                                      seller_payto, total)
    code1, resp1 = route(base, "battery-4-C", seller_base, fee_hdr,
                         seller_hdr)
    fee_hdr2, _unused, _a2 = headers(buyer_priv, buyer, router_payto,
                                     seller_payto, total)
    code2, resp2 = route(base, "battery-4-C", seller_base, fee_hdr2,
                         seller_hdr)
    _c, s3 = tk.call(seller_base, "GET", "/stats")
    entries = tk.read_chain(RECEIPTS)
    settle_for_resp2 = [r for r in entries
                        if r["content"].get("settles_pair_id")
                        == resp2.get("pair_id")]
    B.check("C: replayed nonce -> DENY, no double payment, no "
            "settlement for the refusal",
            code1 == 200 and resp1.get("disposition") == "ALLOW"
            and code2 == 403 and resp2.get("disposition") == "DENY"
            and (resp2.get("detail") or {}).get("failure_code")
            == "PAYMENT_NONCE_REUSED"
            and s3["paid_requests"] - s2["paid_requests"] == 1
            and len(settle_for_resp2) == 0,
            f"first={resp1.get('disposition')}, second http={code2} "
            f"{resp2.get('disposition')}/"
            f"{(resp2.get('detail') or {}).get('failure_code')}, "
            f"seller paid {s2['paid_requests']}->{s3['paid_requests']}")

    # D. seller drops mid-route after receiving the payment.
    fee_hdr, seller_hdr, _a = headers(buyer_priv, buyer, router_payto,
                                      drop_payto, total)
    code, resp = route(base, "battery-4-D", drop_base, fee_hdr,
                       seller_hdr)
    _c, dstats = tk.call(drop_base, "GET", "/stats")
    entries = tk.read_chain(RECEIPTS)
    route_pairs = [r["content"] for r in entries
                   if r["content"].get("pair_class") == "ROUTE"
                   and r["content"].get("route_for_pair_id")
                   == resp.get("pair_id")]
    settle_for_resp = [r for r in entries
                       if r["content"].get("settles_pair_id")
                       == resp.get("pair_id")]
    B.check("D: mid-route drop -> AmbiguousOutcome surfaced, one "
            "attempt, ROUTE_AMBIGUOUS pair, no settlement",
            code == 200 and resp.get("disposition") == "ALLOW"
            and resp.get("outcome") == "AMBIGUOUS"
            and (resp.get("route") or {}).get("delivery")
            == "AMBIGUOUS"
            and dstats["paid_requests"] == 1
            and len(route_pairs) == 2
            and route_pairs[0].get("disposition")
            == "ROUTE_AMBIGUOUS"
            and len(settle_for_resp) == 0,
            f"outcome={resp.get('outcome')}, drop seller paid "
            f"requests={dstats['paid_requests']}, route pair "
            f"members={len(route_pairs)}, settlement pairs="
            f"{len(settle_for_resp)}")

    rc, rep = tk.replay_verdict(RECEIPTS, env)
    B.check("router chain replays MATCH after the fail-closed set",
            rc == 0 and rep.get("verdict") == "MATCH",
            f"verdict={rep.get('verdict')}, pairs={rep.get('pairs')}, "
            f"problems={rep.get('problems')}")
    return B.finish()


if __name__ == "__main__":
    sys.exit(main())
