#!/usr/bin/env python3
"""Battery 5 — Bazaar discovery feed (ROUTER-V1 extension).

Against a THROWAWAY router instance (own temp dir / receipts /
registry) and a specimen seller on its own port:
 B1. GET /router/discovery/resources lists the registered
     specimen seller with schema-exact fields and its probed
     terms (amount as a string, the CDP v2 representation), plus
     the description / mimeType its own challenge declares.
 B2. Schema diff against the grounded feeds (CDP + PayAI,
     fetched live 2026-11-19): every item carries the core keys,
     every accepts the core payment fields, and NO key appears
     that neither grounded feed carries (no invented schema);
     pagination behaves (limit / offset / total).
 B3. 8374's self items (one per tier resource of the declared
     receptor configuration) carry its real accepts — exact /
     eip155:8453 / USDC / the production payTo — with amounts
     equal to the live crossing totals (tier fee + the same
     settlement charge), and the extensions.bazaar block
     harvested verbatim from the endpoint's own 402 challenge.
 B4. Freshness: the seller restarts at a new price, the origin
     re-registers, and the feed reflects the new terms with the
     router never restarted.
"""
import json, os, sys, tempfile, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import router_testkit as tk
import x402kit

B = tk.Battery("Battery 5 (Bazaar discovery feed)")

# Key sets observed in the grounded feeds (CDP discovery +
# PayAI discovery, live 2026-11-19). The feed may use only keys
# from this union, and must always carry the core.
ITEM_KEYS_KNOWN = {
    "accepts", "description", "extensions", "lastUpdated",
    "resource", "type", "x402Version", "serviceName", "tags",
    "iconUrl", "bundleSlugs", "curated", "quality", "metadata",
    "mimeType", "method", "toolName", "inputSchema",
    "outputSchema"}
ACCEPTS_KEYS_KNOWN = {
    "amount", "asset", "extra", "maxTimeoutSeconds", "network",
    "payTo", "scheme", "resource", "currency",
    "maxAmountRequired", "recipient", "mimeType", "description"}
ITEM_CORE = {"resource", "type", "x402Version", "lastUpdated",
             "accepts"}
ACCEPTS_CORE = {"scheme", "network", "asset", "payTo", "amount"}

ROUTER_PORT, SELLER_PORT = 8891, 8892
SELF_RESOURCE = "https://8374.stegverse.org/crossing"


def feed(base, qs=""):
    code, doc = tk.call(base, "GET",
                        "/router/discovery/resources" + qs)
    return code, doc


def items_for(doc, resource):
    return [it for it in doc.get("items", [])
            if it.get("resource") == resource]


def main():
    tmp = tempfile.mkdtemp(prefix="router-b5-")
    _rp, router_payto = x402kit.new_keypair()
    relayer_priv, _ra = x402kit.new_keypair()
    proc, base, env, _rel = tk.make_router_instance(
        tmp, ROUTER_PORT, router_payto, relayer_priv)
    B.track(proc)
    _sp, seller_payto = x402kit.new_keypair()
    seller_proc, seller_base = tk.start_seller(SELLER_PORT,
                                               seller_payto,
                                               price=3000)
    B.track(seller_proc)
    origin = seller_base
    resource_url = origin + "/resource"

    code, reg = tk.call(base, "POST", "/router/register",
                        {"origin": origin})
    B.check("setup: specimen seller registered",
            code == 200 and reg.get("registered") is True,
            f"http={code}")

    # ---- B1: the specimen seller in the feed ----------------
    code, doc = feed(base)
    B.check("B1 feed answers in the CDP top-level shape",
            code == 200 and doc.get("x402Version") == 2
            and isinstance(doc.get("items"), list)
            and set((doc.get("pagination") or {}).keys())
            == {"limit", "offset", "total"},
            f"http={code}, top-level keys={sorted(doc.keys())}, "
            f"pagination={doc.get('pagination')}")
    mine = items_for(doc, resource_url)
    it = mine[0] if mine else {}
    acc = (it.get("accepts") or [{}])[0]
    B.check("B1 specimen item carries its probed terms",
            len(mine) == 1
            and acc.get("scheme") == "exact"
            and acc.get("network") == "eip155:8453"
            and acc.get("asset") == x402kit.USDC_BASE
            and acc.get("payTo") == seller_payto
            and acc.get("amount") == "3000",
            f"accepts={acc}")
    B.check("B1 specimen item mirrors its challenge's declared "
            "description + mimeType",
            it.get("description") == "specimen paid resource "
            "(ROUTER-V1 battery seller)"
            and it.get("mimeType") == "application/json",
            f"description={it.get('description')!r}, "
            f"mimeType={it.get('mimeType')!r}")

    # ---- B2: schema diff ------------------------------------
    all_items = doc.get("items", [])
    core_ok = all(
        ITEM_CORE <= set(i.keys())
        and all(ACCEPTS_CORE <= set(a.keys())
                for a in i.get("accepts", []))
        for i in all_items) and bool(all_items)
    B.check("B2 every item/accepts carries the core keys",
            core_ok, f"items={len(all_items)}")
    invented = [k for i in all_items for k in i.keys()
                if k not in ITEM_KEYS_KNOWN] + \
               [k for i in all_items for a in i.get("accepts", [])
                for k in a.keys() if k not in ACCEPTS_KEYS_KNOWN]
    B.check("B2 no invented keys (item + accepts key sets within "
            "the grounded union)", not invented,
            f"invented={invented}")
    total = (doc.get("pagination") or {}).get("total")
    _c1, page1 = feed(base, "?limit=1&offset=0")
    _c2, page2 = feed(base, f"?limit=1&offset={total}")
    B.check("B2 pagination: limit slices, offset past end is "
            "empty, total is stable",
            len(page1.get("items", [])) == 1
            and page1.get("pagination", {}).get("total") == total
            and page2.get("items") == []
            and page2.get("pagination", {}).get("total") == total,
            f"total={total}, page1={len(page1.get('items', []))}, "
            f"page2={len(page2.get('items', []))}")

    # ---- B3: 8374's own items -------------------------------
    pcfg = json.load(open(os.path.join(tk.ENDPOINT_DIR,
                                       "config.json")))
    prod_payto = pcfg["settlement"]["payTo"]
    self_items = items_for(doc, SELF_RESOURCE)
    B.check("B3 8374 lists one feed item per tier resource",
            len(self_items) == 2,
            f"self items={len(self_items)}")
    accs = [(i.get("accepts") or [{}])[0] for i in self_items]
    B.check("B3 self accepts are 8374's real terms (exact / "
            "Base / USDC / production payTo)",
            all(a.get("scheme") == "exact"
                and a.get("network") == "eip155:8453"
                and a.get("asset") == x402kit.USDC_BASE
                and a.get("payTo") == prod_payto for a in accs),
            f"payTo={[a.get('payTo') for a in accs]}, "
            f"expected={prod_payto}")
    amounts = sorted(int(a["amount"]) for a in accs
                     if a.get("amount"))
    charges = [amounts[0] - 500, amounts[1] - 15000] \
        if len(amounts) == 2 else []
    B.check("B3 self amounts are the live tier totals (fee + "
            "one settlement charge)",
            len(amounts) == 2 and amounts[0] > 500
            and amounts[1] > 15000
            and abs(charges[0] - charges[1]) <= 100,
            f"amounts={amounts}, implied charges={charges}")
    bz_ok = all(
        ((i.get("extensions") or {}).get("bazaar") or {})
        .get("info", {}).get("input", {}).get("method") == "POST"
        and "schema" in ((i.get("extensions") or {})
                         .get("bazaar") or {})
        for i in self_items) and len(self_items) == 2
    B.check("B3 self items carry the extensions.bazaar block "
            "harvested from the endpoint's challenge", bz_ok,
            f"bazaar inputs="
            f"{[(((i.get('extensions') or {}).get('bazaar') or {}).get('info') or {}).get('input', {}).get('method') for i in self_items]}")

    # ---- B4: freshness without a router restart -------------
    seller_proc.terminate()
    seller_proc.wait(timeout=5)
    seller2, _b2 = tk.start_seller(SELLER_PORT, seller_payto,
                                   price=4500)
    B.track(seller2)
    code, _reg2 = tk.call(base, "POST", "/router/register",
                          {"origin": origin})
    _c, doc2 = feed(base)
    mine2 = items_for(doc2, resource_url)
    acc2 = ((mine2[0].get("accepts") or [{}])[0]) if mine2 else {}
    B.check("B4 re-registration refreshes the feed in place "
            "(router never restarted)",
            code == 200 and len(mine2) == 1
            and acc2.get("amount") == "4500",
            f"amount after refresh={acc2.get('amount')!r} "
            f"(was '3000')")
    return B.finish()


if __name__ == "__main__":
    sys.exit(main())
