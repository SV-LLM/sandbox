# Router Production Carry Record — 8374.@router (ROUTER-V1)

ProjectID: MACHINE-ECONOMY-ENTRY-01
Suite: MACHINE__ECONOMY__ENTRY__SUITE — GEN 10
Carry date: 2026-11-19. Carry rule: BUILD-Q-54 version step —
built and battery-proven off-production first; production v1 was
not edited in place. This record states only what was verified
by live readback at carry time.

## Carried form

- Service: sibling service behind the production public proxy on
  the same origin; systemd unit `machine-economy-router.service`
  (source carried in-suite as ROUTER__SYSTEMD__UNIT__01.service;
  idempotent install/restore script as ROUTER__INSTALL__01.sh).
  The unit is on the node supervisor's restore manifest — a
  restore dry run after the carry re-verified the unit set
  including the router (VM replacements delete unit files; the
  restore path is the cure).
- State: the router's registry and receipts live in its own
  production state dir on the coordinator node, separate from
  the endpoint's. The router chain is a second, independent
  chain — it never writes to the endpoint's chain.
- Custody: the router's only key is its own gas-only relayer key,
  born in its production state, held outside this suite. The
  router never accepts, stores, or generates buyer/seller keys;
  it relays buyer-signed EIP-3009 authorizations only.
- Config: production configuration is carried in-suite as
  ROUTER__PRODUCTION__CONFIG__TEMPLATE__01.json (payTo
  `0x7721aB66161e60fCcA59CCe2A86817cbdd9b16Be` and the offer v07
  tiers are public record; custody-bearing values are slots).

## Public surface (verified live)

- `GET https://8374.stegverse.org/router/catalog` — answers
  publicly; 8374 self-listed by construction (2 resources) with
  provenance recomputed read-only from the production chain
  files (55 pairs, replay MATCH, terminal anchor below).
- `GET https://8374.stegverse.org/router/provenance` — live
  recompute at read time.
- `GET https://8374.stegverse.org/router/quote` — live quote at
  carry readback: 2,195 µUSDC total (500 receipt-only fee +
  1,695 live-quoted settlement charge), `quote_stale: false`.
- `POST https://8374.stegverse.org/router/register` — exercised
  publicly at carry: the production origin registered with
  itself (routable, 2 resources).
- `POST https://8374.stegverse.org/router/route` — in the public
  proxy set. No paid public route was exercised in the carry
  step; the settle path was proven in batteries, and its first
  production use is a real crossing.
- `POST https://8374.stegverse.org/router/settle-pair` —
  operator-only: returns 404 publicly, as `/settle-pair` does.
- Discovery: `/.well-known/x402` on the production origin now
  lists two resources — `/crossing` and `/router/catalog`
  (additive change only).

## Verification readbacks at carry

- Endpoint untouched: `GET /health` OK; `GET /inspect` — 55
  pairs, replay MATCH, terminal anchor
  `3a8046e39b000d708b83a0b41a5ba6ee3d333761a8c1c5f9c5a40914e133b46d`
  — identical to the pre-build record. The endpoint service was
  not restarted; only the public proxy and the router unit were.
- Router chain: genesis — 0 pairs, GENESIS anchor, own receipts
  dir.
- Restart survival: the router unit was restarted under systemd;
  on readback it was active, health OK, catalog self-listed,
  provenance MATCH.

## Battery record (off-production, throwaway instances, final code)

- **Battery 1 — registry / catalog / provenance: 8/8.**
  Registration crawled both discovery documents and probed the
  specimen seller's exact terms (payTo, 3,000 µUSDC,
  exact / eip155:8453 / USDC); catalog lists the seller and 8374
  itself with provenance matching an independent read of the
  production files (55 pairs, anchor match, MATCH);
  re-registration refreshes in place; third-party provenance
  returns "routable — provenance not yet established" (never a
  block).
- **Battery 2 — relay mode: 5/5.** ALLOW; seller response
  delivered; the ALLOW pair carries both payment evidences with
  matching nonces; the seller saw exactly one paid request;
  relay settled nothing on-chain; chain replays MATCH.
- **Battery 3 — settle mode, on-chain: 10/10.** Route ALLOW and
  delivered; seller leg settled by the router's throwaway
  relayer; seller payTo 0 → 3,000 µUSDC exactly; fee leg settled,
  router payTo 0 → 2,194 µUSDC exactly (500 fee + 1,694 quoted
  charge); two SETTLEMENT pairs appended, bound to the route
  pair; chain replays MATCH; settlement records confirmed by
  independent mined-receipt reads.
- **Battery 4 — fail-closed set: 5/5.** Garbled payment →
  FAIL_CLOSED `PAYMENT_PAYLOAD_MALFORMED`, seller never
  contacted; ME-EVAL-01 without the evidence object →
  FAIL_CLOSED `KNOWN_EVIDENCE_MISSING`, no relay, no settlement;
  replayed seller nonce → DENY `PAYMENT_NONCE_REUSED`, seller
  paid exactly once, no settlement pair for the refusal;
  drop-mode seller → AmbiguousOutcome surfaced, exactly one
  relay attempt, ROUTE_AMBIGUOUS pair, zero settlement; chain
  replays MATCH after all of it.
- **Total: 28/28.** Total on-chain specimen spend across the
  build: 150,000 µUSDC ($0.15) from the specimen payer to
  throwaway buyers, plus a few thousandths of an ETH in gas.

## Source mapping (suite member → lane path)

Lane form: SV-LLM/sandbox, branch `machine-economy-8374`, head
`b3077c7e`, directory `machine-economy-8374/router/`. Suite
members carry the identical bytes; the suite manifest binds each
member's size + SHA-256.

| Suite member | Lane path |
|---|---|
| ROUTER__router.py | router/router.py |
| ROUTER__x402kit.py | router/x402kit.py |
| ROUTER__settlement.py | router/settlement.py |
| ROUTER__keccak_pure.py | router/keccak_pure.py |
| ROUTER__seller.py | router/seller.py |
| ROUTER__router_testkit.py | router/router_testkit.py |
| ROUTER__battery1_registry.py | router/battery1_registry.py |
| ROUTER__battery2_relay.py | router/battery2_relay.py |
| ROUTER__battery3_settle.py | router/battery3_settle.py |
| ROUTER__battery4_failclosed.py | router/battery4_failclosed.py |
| ROUTER__replay_router.py | router/replay_router.py |
| ROUTER__setup_dev.py | router/setup_dev.py |
| ROUTER__README__01.md | router/README.md |
| ROUTER__INSTALL__01.sh | router/install.sh |
| ROUTER__SYSTEMD__UNIT__01.service | router/systemd/machine-economy-router.service |

## Open remainder (one)

The router relayer was funded 0.0001 ETH of the ordered
0.001 ETH. Failure grammar: the specimen payer's balance was
the binding constraint at funding time (not a technical
failure, not a refusal). Top-up entrypoint: any specimen-payer
refill, then fund the remaining 0.0009 ETH to the router
relayer. At observed Base fees the funded amount covers on the
order of 200 settlements, so this remainder does not gate
operation; it is recorded so it is never silently absorbed.
