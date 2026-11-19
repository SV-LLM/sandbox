#!/usr/bin/env python3
"""Battery 1 — registry, crawl, catalog, provenance (ROUTER-V1).

Against a THROWAWAY router instance (own temp dir / receipts /
registry) and a specimen seller on its own port:
 1. POST /router/register crawls the seller's /.well-known/x402
    and /openapi.json and probes the live 402 challenge — the
    catalog entry carries the correct probed terms (payTo,
    amount, scheme, network, asset).
 2. GET /router/catalog lists the specimen seller with those
    terms, and lists 8374 itself (self-registered at startup)
    with LIVE provenance: pair count + terminal anchor + replay
    verdict recomputed read-only from the production chain files
    — checked here against an independent read of those files.
 3. Re-registration refreshes in place (still exactly one entry).
 4. GET /router/provenance: third party = registered terms +
    "routable — provenance not yet established" (never a block);
    8374 = the replayable chain facts.
 5. The throwaway router chain replays MATCH.
"""
import json, os, sys, tempfile, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import router_testkit as tk
import x402kit

B = tk.Battery("Battery 1 (registry/catalog/provenance)")


def main():
    tmp = tempfile.mkdtemp(prefix="router-b1-")
    _rp, router_payto = x402kit.new_keypair()
    relayer_priv, _ra = x402kit.new_keypair()
    proc, base, env, _rel = tk.make_router_instance(
        tmp, 8897, router_payto, relayer_priv)
    B.track(proc)
    _sp, seller_payto = x402kit.new_keypair()
    seller_proc, seller_base = tk.start_seller(8898, seller_payto,
                                               price=3000)
    B.track(seller_proc)
    origin = seller_base

    code, reg = tk.call(base, "POST", "/router/register",
                        {"origin": origin})
    entry = reg.get("entry") or {}
    res = [r for r in entry.get("resources", [])
           if r.get("path") == "/resource"]
    terms = (res[0].get("terms") or {}) if res else {}
    B.check("register crawls + probes the specimen seller",
            code == 200 and reg.get("registered") is True
            and len(res) == 1,
            f"http={code}, resources={len(entry.get('resources', []))}, "
            f"sources={entry.get('sources')}")
    B.check("probed terms are the seller's live 402 terms",
            terms.get("payTo") == seller_payto
            and terms.get("amount_micro_usdc") == 3000
            and terms.get("scheme") == "exact"
            and terms.get("network") == "eip155:8453"
            and terms.get("asset") == x402kit.USDC_BASE,
            f"terms={terms}")

    # Independent read of the production chain files.
    prod_entries = tk.read_chain(os.path.join(tk.ENDPOINT_DIR,
                                              "receipts"))
    prod_pairs = {r["content"].get("pair_id") for r in prod_entries}
    prod_anchor = prod_entries[-1]["hash"] if prod_entries else None

    cat = None
    t0 = time.time()
    while time.time() - t0 < 60:
        _c, cat = tk.call(base, "GET", "/router/catalog")
        origins = [s.get("origin") for s in cat.get("sellers", [])]
        if "https://8374.stegverse.org" in origins and origin in origins:
            break
        time.sleep(1)
    sellers = {s["origin"]: s for s in (cat or {}).get("sellers", [])}
    B.check("catalog lists the specimen seller with probed terms",
            origin in sellers
            and (sellers[origin]["resources"][0].get("terms") or {})
            .get("payTo") == seller_payto,
            f"catalog sellers={sorted(sellers)}")
    self_entry = sellers.get("https://8374.stegverse.org") or {}
    prov = self_entry.get("provenance") or {}
    B.check("8374 self-listed with live chain provenance",
            prov.get("replay_verdict") == "MATCH"
            and prov.get("pairs") == len(prod_pairs)
            and prov.get("terminal_anchor") == prod_anchor,
            f"provenance pairs={prov.get('pairs')} (independent "
            f"{len(prod_pairs)}), verdict={prov.get('replay_verdict')}, "
            f"anchor match={prov.get('terminal_anchor') == prod_anchor}")

    code, reg2 = tk.call(base, "POST", "/router/register",
                         {"origin": origin})
    _c, cat2 = tk.call(base, "GET", "/router/catalog")
    count = sum(1 for s in cat2.get("sellers", [])
                if s.get("origin") == origin)
    B.check("re-registration refreshes in place",
            code == 200 and count == 1,
            f"http={code}, entries for origin={count}")

    code, pv = tk.call(base, "GET",
                       "/router/provenance?origin=" + origin)
    B.check("third-party provenance: routable, not yet established",
            code == 200 and pv.get("registered") is True
            and "not yet established" in
            (pv.get("provenance") or {}).get("status", ""),
            f"status={(pv.get('provenance') or {}).get('status')}")
    code, pv2 = tk.call(
        base, "GET",
        "/router/provenance?origin=https://8374.stegverse.org")
    prov2 = pv2.get("provenance") or {}
    B.check("8374 provenance endpoint returns the chain facts",
            code == 200 and prov2.get("pairs") == len(prod_pairs)
            and prov2.get("terminal_anchor") == prod_anchor
            and prov2.get("replay_verdict") == "MATCH",
            f"pairs={prov2.get('pairs')}, "
            f"verdict={prov2.get('replay_verdict')}")

    rc, rep = tk.replay_verdict(os.path.join(tmp, "receipts"), env)
    B.check("throwaway router chain replays MATCH",
            rc == 0 and rep.get("verdict") == "MATCH",
            f"verdict={rep.get('verdict')}, pairs={rep.get('pairs')}")
    return B.finish()


if __name__ == "__main__":
    sys.exit(main())
