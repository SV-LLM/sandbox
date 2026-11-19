# 8374 Router Layer v1 — relay + settle (ROUTER-V1)

An off-production, battery-proven candidate for the router/index
layer of the x402 machine economy, built 2026-11-19 under the
principal's direction ("Build it — relay + settle third-party
crossings"). **Production v1 is untouched**: no production code
was edited, no production service restarted, and the router
writes only to its own receipts/registry in this directory.

**Discovery feed (added 2026-11-19, battery 5 — 12/12):** the
router publishes its registry as a Bazaar-format discovery feed
at `GET /router/discovery/resources` — the CDP Bazaar discovery
schema (`{x402Version: 2, items, pagination{limit, offset,
total}}`), grounded live against the CDP and PayAI discovery
endpoints. Every registered seller's resources appear with their
probed terms (accepts in the v2 representation: scheme /
network / asset / payTo / amount, plus maxTimeoutSeconds and the
asset-domain extra when the seller's challenge declares them);
a seller's `extensions.bazaar` block is mirrored verbatim from
its own 402 challenge when it declares one. 8374's own items are
built from the declared receptor configuration — one per tier
resource — with amounts equal to the live crossing totals,
harvested from the endpoint's own challenge (which itself
carries `extensions.bazaar` in the observed format) or priced by
the router's BUILD-Q-43 quote. Fields the registry does not
know are omitted, never fabricated (no aggregator-computed
`quality`, no invented schemas). As a facilitator (relay +
settle), the router is a source aggregators ingest, not only a
service they admit. Ingestion finding: ScriptMasterLabs'
directory ingests a fixed, curated facilitator set (cdp /
payai / dexter / omnigate / 402proof-sidecar) — no self-serve
discovery-feed submission exists; their free self-serve route
is a per-service probe submission, used for 8374's /crossing
resource. The feed serves every other present and future
ingester regardless.

## What it is

A router for machine-economy crossings with **no middleman
pricing**:

- **Free self-serve seller registration** (`POST /router/register
  {origin}`): the router crawls the origin's `/.well-known/x402`
  and `/openapi.json`, enumerates its paid resources, and probes
  each resource's live 402 challenge to record its terms
  (scheme / network / asset / payTo / amount). No listing fee,
  no account, no review queue.
- **No "proven seller" gate.** Provenance is the replayable
  receipt chain, recomputed, never granted. A third-party seller
  is routable on its registered terms from the moment it
  registers; its provenance establishes itself in replayable
  records as routed crossings settle. 8374's own origin is
  self-registered at startup (listed by construction) and its
  catalog provenance carries the live pair count, terminal
  anchor, and replay verdict recomputed **read-only** from the
  production chain files.
- **Every routed call is a governed crossing** under 8374
  (`POST /router/route`): production evaluation + evidence rules
  (scope ME-EVAL-01; `receipt-only` tier $0.0005, full
  evaluation $0.015; full evaluation requires the commit-time
  evidence object, else `KNOWN_EVIDENCE_MISSING`). The
  disposition resolves **first**, from locally-decidable
  predicates only; only on ALLOW is anything relayed or settled.
  On DENY / FAIL_CLOSED the pair issues and nothing moves — the
  ordering defect found and cured in production is preserved as
  cured.
- **Relay + settle, non-custodial.** The router relays the
  buyer's own signed EIP-3009 authorization to the seller — it
  never accepts, stores, or generates buyer/seller keys. In
  `settle` mode the router's gas-only relayer also submits the
  buyer→seller `transferWithAuthorization` on-chain, and the
  8374 fee leg (governance fee + live-quoted settlement charge,
  BUILD-Q-43 formula — charged, never absorbed) to 8374's payTo.
- **Pair-first** (BUILD-Q-45 semantics): pairs are born with
  `settlement_state: PENDING`; settlement is an eventual leg
  (immediate attempt + 60s sweep + `POST /router/settle-pair`),
  its outcome receipted as an appended SETTLEMENT pair (or
  SETTLEMENT-FAILURE pair on terminal on-chain failure); the
  pair's disposition never changes. A mid-route transport
  ambiguity surfaces as AmbiguousOutcome — the authorization is
  never re-presented and never settled by the router; a
  ROUTE_AMBIGUOUS outcome pair receipts the event.
- **8374's only take is the posted crossing fee.** No
  percentage skim. Routing name `8374.@router` — a routing
  name, not an identity; signing resolves to 8374's one SKAP
  specimen via the production signing-service pattern. The
  router's only key is a gas-only relayer key (dust ETH, no
  USDC), the production Gate 2 pattern.

## Route contract (published; cured 2026-11-19)

A clean-room sufficiency test found the original route path
accepted payments **only** as two base64 payloads in JSON body
fields — a contract published nowhere — and rejected every
standard header-presented x402 payload as
`PAYMENT_PAYLOAD_MALFORMED`. The cured contract, published at
`GET /router` (service document, with a worked example) and
`GET /router/openapi.json`:

- A routed crossing carries **two** buyer-signed EIP-3009
  authorizations: the **fee leg** (`fee_payment`: to the
  router's payTo, exactly the `GET /router/quote` total =
  governance fee + live settlement charge) and the **seller
  leg** (`payment`: to the resource's catalog `terms.payTo`,
  exactly its amount — a probed fixed amount, or, for
  live-priced terms such as 8374's own `/crossing`, the tier
  governance fee + the same quote's settlement charge).
- Each leg accepts the dialects the governed endpoint
  accepts: **x402 v1** (`{x402Version: 1, scheme, network,
  payload:{signature, authorization}}`) and **v2**
  (`{x402Version: 2, accepted:{...}, payload:{...}}`, with the
  `accepted` object checked against the leg's declared
  requirements), presented as a base64 string or the decoded
  JSON object in its body field, **or** in the `X-PAYMENT` /
  `PAYMENT-SIGNATURE` HTTP header. A header fills the seller
  leg first (the standard presentation pays the resource);
  when the seller leg already rides in the body, a header
  fills the fee leg. Verification strictness is unchanged —
  garbage still fails closed.
- **The proof is the content of 8374's published row.** The
  service document carries a live `provenance` block (pair
  count, terminal anchor, replay verdict — recomputed from
  the production chain at request time) and its worked
  example's **output is a real settled receipt pair** (the
  production chain's latest settled ALLOW pair, fields read
  live). The discovery feed's 8374 items carry the same live
  fields as `metadata.provenance`; other sellers' items are
  unchanged.
- Resource selection prefers the registry entry whose terms
  carry the requested tier (8374 lists `/crossing` per tier),
  and live-priced terms (`amount_micro_usdc: null`) are priced
  from the route's own quote — previously that path evaluated
  `int(None)` after the fee leg verified.

## Files

| file | role |
|---|---|
| `router.py` | the service: registry, catalog, provenance, quote, route, settle-pair, sweep; vendored chain/replay/evaluation/quote constructions from the production endpoint |
| `x402kit.py` | x402 exact-scheme toolkit: EIP-712/EIP-3009 digests, signing, recovery, header construction, the shared verification core |
| `settlement.py` | vendored production settlement leg (Gate 2): gas-only relayer submission of verified authorizations, RPC failover |
| `keccak_pure.py` | vendored pure-Python Keccak-256 |
| `seller.py` | specimen third-party x402 seller (battery support; normal, connection-drop, big-body, and drop-mid-body modes) |
| `router_testkit.py` | battery support: throwaway instances, chain reads, replay runs, on-chain funding helpers |
| `battery1_registry.py` | registry / crawl / catalog / provenance — 8 checks |
| `battery2_relay.py` | relay-mode route — 5 checks |
| `battery3_settle.py` | settle-mode route, on-chain, exact balance movement — 10 checks |
| `battery4_failclosed.py` | garbled payment / missing evidence / replayed nonce / mid-route drop — 5 checks |
| `battery5_discovery.py` | Bazaar discovery feed: registry→feed schema fidelity, self-entry real accepts + harvested bazaar block, freshness — 12 checks |
| `battery6_dialects.py` | payment dialects (v1/v2 × header/body/object), v2 settle on-chain, garbage fail-closed, published contract + live provenance assertions — 12 checks |
| `battery7_large_response.py` | large seller responses: 241,350-byte body DELIVERED intact (pad hash both sides), drop-mid-body AMBIGUOUS with one relay attempt, big body behind the public proxy — 4 checks |
| `replay_router.py` | chain replay CLI (production replay.py pattern) |
| `setup_dev.py` | generates the dev instance's throwaway relayer key + config |
| `router_config.json` | dev config (throwaway payTo — see carry checklist) |
| `router_relayer.json` | dev gas-only relayer key, mode 0600 (throwaway) |
| `registry.json`, `receipts/`, `router-quote-cache.json`, `router-dev.log` | dev instance runtime state |

Battery result at build time (2026-11-19, final code):
**28/28 checks passed** (B1 8/8, B2 5/5, B3 10/10, B4 5/5),
including on-chain settlement of both legs with exact balance
movement and chain replay MATCH on every battery chain.
Route-contract cure re-run (2026-11-19): **B1–B4 28/28,
B5 12/12, B6 12/12** on the cured code.
Relay-read cure re-run (2026-11-19): **B1–B4 28/28, B5 12/12,
B6 12/12, B7 4/4** on the cured code. The cure: the relay reads
seller responses with an explicit completion loop
(`_read_full_body` — a single .read() mistook a short stream
return for EOF and receipted a settled routed call AMBIGUOUS),
and every large-body write in the serving stack loops until
complete (`_write_all` — a single write() on a timeout socket
may silently drop a body's remainder while its Content-Length
still promises it). Genuine truncation still receipts
AMBIGUOUS (battery 7, dropmid case).

## Run the dev instance

```
python3 setup_dev.py          # once: throwaway relayer + config
python3 router.py             # 127.0.0.1:8797 (ROUTER_PORT to move)
```

State lives in the router dir; `ROUTER_DIR`, `ROUTER_CONFIG_PATH`,
`ROUTER_RECEIPTS_DIR`, `ROUTER_REGISTRY_PATH` override locations
(the batteries run fully throwaway instances this way, on their
own ports, and never touch this state).

Routes: `GET /` (service document), `GET /health`,
`POST /router/register`, `GET /router/catalog`,
`GET /router/discovery/resources` (Bazaar-format discovery
feed; `?limit=` / `?offset=` pagination),
`GET /router/provenance?origin=`, `GET /router/quote?tier=`,
`POST /router/route`, `POST /router/settle-pair`,
`GET /router/replay`.

## Production-carry checklist (NOT executed)

1. **Config**: set `payTo` to 8374's declared receptor
   (`0x7721aB66161e60fCcA59CCe2A86817cbdd9b16Be`); point
   `settlement.relayer_key_file` at the production settlement
   configuration (the endpoint's gas-only relayer arrangement —
   note the endpoint relayer's dust balance when scheduling);
   keep tiers at offer v07 values.
2. **Origin routes**: mount the router's routes on the
   production origin (either as the endpoint's own new routes —
   `/router/register`, `/router/catalog`, `/router/provenance`,
   `/router/quote`, `/router/route`, `/router/settle-pair` — or
   as a sibling service behind the public proxy on the same
   origin). Add the routes to the public proxy's public set;
   `/router/settle-pair` stays operator-only, as `/settle-pair`
   is today.
3. **Service wiring**: a systemd unit for the router beside the
   endpoint's (same watchdog/restore pattern), binding
   localhost behind the proxy; the settlement sweeper thread
   runs in-process.
4. **Persistence**: registry + receipts on the production
   node's durable state path, with the receipts dir added to
   the chain-carriage set (the router chain is a second,
   independent chain — it never writes to the endpoint's).
5. **Discovery**: add the router's catalog to the origin's
   discovery documents (`/.well-known/x402` resources and the
   OpenAPI `x-payment-info` for the route), and register the
   production origin with the router itself (self-registration
   already does this at startup).
6. **Version step**: carry as the next 8374 version step under
   the BUILD-Q-54 rule — the candidate is battery-proven
   off-production; the carry is a separate act, and production
   v1 is not edited in place before it.


## Scope-shape refusal repair candidate

Non-string `scope` values now produce a six-field `SCOPE_TYPE_INVALID` refusal with a receipt pair; missing scope still defaults to `receipt-only`. This closes R-GEN12-SCOPE-TYPE-01's unreceipted TypeError. Run `python3 test_scope_type_refusal.py` and `python3 -O test_scope_type_refusal.py` for isolated local HTTP/function/replay controls. No payment, pricing, scope-admission or settlement policy changes. See `ROUTER_SCOPE_INPUT_MIRROR_HANDOFF.md` for pending owner integration and independent acceptance.
