# Router Discovery Feed — Build + Carry Record 01

ProjectID: MACHINE-ECONOMY-ENTRY-01
Component: 8374 router (`8374.@router`) — Bazaar-format discovery feed
Date: 2026-11-19
Carry: BUILD-Q-54 version step (built + battery-proven off-production
first, then carried to all three systems).

## What was built

`GET /router/discovery/resources` on the router service: the router
publishes its registry in the **CDP Bazaar discovery schema**, so
aggregators that ingest facilitator discovery endpoints can pull
8374's sellers without anyone's admission. Until this build, 8374
appeared in no facilitator's discovery feed, and every aggregator
surface traced back to that absence. The router is itself a
facilitator (relay + settle, GEN 10) — so it now publishes its own
feed.

Response shape (mirrored field-for-field from the grounded feeds):
`{x402Version: 2, items: [...], pagination: {limit, offset, total}}`
with `?limit=` (default 20, max 100) and `?offset=` pagination. Item
core: `resource`, `type: "http"`, `x402Version`, `lastUpdated`,
`accepts[{scheme, network, asset, payTo, amount, maxTimeoutSeconds?,
extra?}]`, plus `description` / `mimeType` / `extensions.bazaar`
when the seller's own 402 challenge declares them. Accepts are
emitted in the v2 representation (`amount` as a string). The feed is
generated **live from the registry** on every call.

## Schema grounding (live fetches, 2026-11-19)

- **CDP** — `GET https://api.cdp.coinbase.com/platform/v2/x402/discovery/resources`:
  top-level `{items, pagination{limit, offset, total}, x402Version: 2}`
  (36,976 resources). Item keys in 20/20 sampled items: `accepts`,
  `description`, `extensions`, `lastUpdated`, `resource`, `type`
  ("http"), `x402Version` (2); accepts core: `amount`, `asset`,
  `extra{name, version}`, `maxTimeoutSeconds`, `network`, `payTo`,
  `scheme`. `extensions.bazaar = {info{input{method, queryParams|body,
  type: "http"}, output{example, type}}, schema{JSON Schema}}` is
  carried per item, extracted from the seller's 402 response.
  Aggregator-computed fields (`quality`, `serviceName`, `tags`,
  `iconUrl`, `curated`) are the aggregator's, not the publisher's.
- **PayAI** — `GET https://facilitator.payai.network/discovery/resources`:
  same top-level shape (top-level x402Version 1, items carry 2);
  EVM accepts carry the identical core fields; items additionally
  carry `mimeType`, `metadata`, `method`, `toolName`, schemas.
- **8374's own 402** (production endpoint, `POST /crossing`) already
  carries `extensions.bazaar` in exactly the observed format
  (`info{input{type: "http", method: "POST", bodyType: "json",
  body{...}}, output{type: "json", example{...}}}` + a full JSON
  `schema`), alongside `outputSchema`. The feed harvests that block
  verbatim for 8374's items.

Field rule: the feed mirrors the schema for the fields the registry
actually knows; unknown fields are **omitted, never fabricated** (no
`quality`, no invented schemas or service names).

## Design points

- **Third-party items** come from their registry entries: the probed
  terms (probe now also records the challenge's declared
  `description`, `maxTimeoutSeconds`, asset-domain `extra`, and
  `extensions.bazaar` verbatim).
- **8374's own items** are built from the declared receptor
  configuration — one per tier resource (receipt-only 500 µUSDC,
  full evaluation 15,000 µUSDC) — with `amount` equal to the **live
  crossing total** for the tier (fee + the live settlement charge):
  harvested from the endpoint's own 402 challenge when reachable
  (local listener first — the public origin's CDN refuses this
  service's user agent, the same reason self-registration falls
  back to the local record), else priced by the router's own
  BUILD-Q-43 quote. A tier whose total cannot be stated whole is
  omitted rather than understated.
- **Item 3 disposition (bazaar extension on 402 responses):** the
  router issues no 402 challenges of its own (its refusals are
  governed 403/422 responses, GEN 10 design); 8374's resource 402s
  are served by the production endpoint, whose behavior is never
  edited — and which already carries `extensions.bazaar` in the
  grounded format. The bazaar block therefore travels in the feed
  items, harvested verbatim from the challenges that declare it.

## Proof — battery 5 (throwaway instances, endpoint idiom)

**12/12 checks passed** (`ROUTER__battery5_discovery.py`):
B1 feed shape + specimen item with schema-exact probed terms +
mirrored description/mimeType (3/3); B2 schema diff against the
grounded key union — core keys everywhere, zero invented keys,
pagination slices/offsets/totals (3/3); B3 8374 self items — one per
tier, real accepts (exact / eip155:8453 / USDC / production payTo
`0x7721aB66161e60fCcA59CCe2A86817cbdd9b16Be`), amounts = live tier
totals (2,201 and 16,701 µUSDC at battery time; implied settlement
charge identical at 1,701), bazaar block harvested with
`info.input.method = POST` + schema (4/4); B4 freshness —
seller restarted at a new price (3,000 → 4,500), re-registered, feed
reflected the new terms with the router never restarted (1/1);
plus the registration setup check (1/1).

## Production carry (coordinator node)

- Deployed additively through the existing proxy mount:
  `("GET", "/router/discovery/resources")` added to the proxy's
  route allowlist and query-route set (pre-edit proxy backed up at
  `router-8374-prod/public_proxy.py.pre-discovery-carry`); only the
  router and proxy units were restarted.
- **Endpoint untouched**: MainPID **2277** and
  ActiveEnterTimestamp 2026-11-19 17:33:11 UTC identical before and
  after; `/replay` before and after: **55 pairs, 110 entries,
  verdict MATCH, terminal anchor
  `3a8046e39b000d708b83a0b41a5ba6ee3d333761a8c1c5f9c5a40914e133b46d`**.
- Public verification (live fetch-back):
  `https://8374.stegverse.org/router/discovery/resources` answers
  `x402Version: 2`, `pagination.total: 2` — 8374's two tier items
  with live totals (16,702 / 2,202 µUSDC at carry readback),
  production payTo, `extra{name: "USD Coin", version: "2"}`,
  `maxTimeoutSeconds: 60`, description, and the harvested
  `extensions.bazaar` block. `/router/settle-pair` still returns
  404 publicly.

## Lane carriage

Changed router source pushed to **SV-LLM/sandbox**, branch
`machine-economy-8374`, under `machine-economy-8374/router/`
(`router.py`, `README.md`, `battery5_discovery.py`): new branch
head **`5e4d5fdf4dfa1b662d5fef1b71d048875270cb9f`**. Readback of
`router.py` via the connector: SHA-256
`ce7d7fe33a6b7dbc1a35e6bdd5bfb9a2680d0f6c2d06a839cb6c842a741faa4d`
(94,075 B) — **MATCH** against the carried bytes. No key material,
no runtime state carried.

## Aggregator-ingestion finding (ScriptMasterLabs)

- Their machine feed (`scriptmasterlabs.com/x402-directory.json`,
  51,341 resources at check time) names its sources: a **fixed,
  curated facilitator set** — `cdp` (36,944), `payai` (16,790),
  `dexter` (3,034), `omnigate` (247, their own), `402proof-sidecar`
  (4), `sml-payment-offers` (45). **No self-serve submission of a
  discovery-feed URL exists** in their public materials; new
  facilitator ingestion is curated/closed. Recorded exactly: the
  feed does not fail on their gate — it serves every other present
  and future ingester (its URL is the standard
  `/discovery/resources` shape the curated set itself uses).
- The free self-serve route that **does** exist — their per-service
  probe submission (`POST /x402-directory/submit`, one `url`
  field) — was used after the production carry for
  `https://8374.stegverse.org/crossing`: **HTTP 201, "Listed —
  probe-verified. The live challenge answered via
  challenge-header-or-body on Base. The row is in the feed now"**;
  fetch-back through their feed query returns the row: slug
  `8374-stegverse-org-crossing-r58t0w`, `sources: ["submission"]`,
  networks `["Base"]`, accepts naming the production payTo and the
  live total at probe time; `reporting_facilitators: []` (no
  facilitator reports 8374 yet — the honest state this feed build
  exists to change).

## Remainder carried forward

The GEN 10 remainder stands unchanged: the router relayer holds
0.0001 ETH of the ordered 0.001 ETH (specimen-payer balance was the
constraint); top-up entrypoint is any specimen-payer refill. The
router chain remains at genesis; its first production pair is a
real third-party routed crossing.
