# PAIR-FIRST MIGRATION — BUILD RECORD 01 (BUILD-Q-45 discharged)

ProjectID: MACHINE-ECONOMY-ENTRY-01 · Suite: MACHINE__ECONOMY__ENTRY__SUITE GEN 09
Built 2026-11-18 (America/Chicago) at the principal's direction of
2026-11-18 18:54 CST. Coordinator-grade execution; the operation
resides in the Build Lane home (SV-LLM/sandbox, branch
machine-economy-8374) as before.

## What was built

The 8374 production endpoint's crossing is now PAIR-FIRST. Before
this build, POST /crossing verified the x402 payment with network
reads and attempted settlement BEFORE writing the receipt pair, so
a total egress outage at crossing time deferred the crossing
itself. Now:

1. At crossing, only locally-decidable predicates are evaluated:
   EIP-712/EIP-3009 signature recovery and typed-data match;
   receptor match (network, asset, payTo, scheme) against the
   offer; value == quoted total; validity window; commit-time
   evidence rules (unchanged); and the nonce checked against the
   registry the receipt chain itself is (every presented
   authorization's nonce stands in its pair; the registry is the
   chain replay — no second store).
2. The receipt pair is written FIRST (fsync, existing durability
   discipline) with `settlement_state: PENDING`, before any
   settlement RPC. A crossing during a total RPC outage returns
   its disposition + pair exactly as in normal operation.
3. Settlement is an eventual leg: attempted immediately when the
   RPC answers; while PENDING it is retried by a background sweep
   (60 s) and by POST /settle-pair (extended: `{"sweep": true}`
   sweeps every PENDING pair on every chain; the single-pair form
   is unchanged in shape). The outcome is receipted as an appended
   record bound to the pair — a SETTLEMENT pair on success, a
   SETTLEMENT-FAILURE pair on terminal on-chain failure — never a
   rewrite, never a silent drop; the pair's disposition never
   changes.
4. Terminal classification is confirmed against chain state, not
   taken from an RPC response (cure built during this build's own
   production proof, see below): a mined status-0 receipt is
   terminal as it stands; a simulation revert is terminal only
   when an on-chain read shows the nonce consumed or the payer's
   balance below the authorized value (`terminal_confirmed: true`
   + `terminal_evidence` in the failure record). An unconfirmed
   revert leaves the pair PENDING, and an unconfirmed failure
   record does not bar a later settlement.
5. Settlement charge under outage: the quote cache serves its
   last successful quote with `quote_stale: true` recorded in the
   pair (persisted across restarts in quote-cache.json); the
   charge leg fails closed with SETTLEMENT_CHARGE_QUOTE_UNAVAILABLE
   only when no quote has ever been obtained. Actual gas
   reconciles in the settlement record, as before.
6. Addition (principal, 2026-11-18 18:56 CST): GET /inspect — the
   one-link public inspection surface at
   https://8374.stegverse.org/inspect (HTML; JSON twin at
   /inspect?format=json), added to the public proxy allowlist. One
   response carries live service state (health, offer version,
   tiers + settlement-charge basis), receipt-chain state (pair
   count, live replay verdict, terminal anchor), settlement
   evidence (settled pairs with on-chain tx hashes and block
   numbers; payTo address + live on-chain balance), resolving
   pointers (this suite's conformance proof location, the
   retention verifier, the lane home), and a compact determination
   block stating which claims the evidence supports (functional,
   settled-on-chain, chain-integrity) and which it does not
   (external demand, profitability), each tied to its deciding
   check.

Backward compatibility: chain grammar additions are additive
fields only. The 44 pre-existing production pairs replay
byte-identical under the migrated code (proof below).

## Migrated code (SHA-256)

- operation/endpoint.py `25694f55a603db23e7faf13a3ce401b465225bc08dee2450848fc0e3207a5561`
  (pre-migration `395969e8…`)
- operation/public_proxy.py `018a844f162fa08181ad5a7f75b1dd0e89303fadae34a963ec7ea0faa9124c1c`
  (/inspect allowlist + content-type forwarding)
- operation/settlement.py `b0c78d08a224ed9a91fe7949972af6e1ae9e299a45c9279ce041d9c81918ad28`
  (unchanged; the 2026-11-18 broadcast-failover cure)
- operation/funds.py `274ec65f04669aeec7a67fdf7a87fef6a23e59bb3ebee6ba26a0378dd64f7a51` (unchanged)
- batteries/settlement_battery.py `544537212e9eea83a84b87d37a4d3d0ba940d1d29b6a3571fdec2675fc848bc1`
  (case 1 amended to the pair-first grammar: the pair is born
  PENDING; the response carries the attempt record)
- batteries/outage_battery.py `d55e208d50d3c9d65cb012f70a8144da86a4722462225e5123dee59293da5396` (new)

## Proof

Standing batteries against a throwaway migrated instance
(unfunded throwaway relayer): x402 10/10 · x402 v2 8/8 ·
settlement 5/5 (amended grammar) · agreement 5/5.

Outage battery (new; throwaway instance, RPC toggled between the
live Base RPCs and a blackhole at 127.0.0.1:9) — 8/8 PASS, run
twice (before and after the terminal-confirmation cure):
- 0. no quote ever obtained + RPC blackholed → the charge leg
  fails closed, 503 SETTLEMENT_CHARGE_QUOTE_UNAVAILABLE.
- 1. network up → live quote obtained and persisted.
- a. RPC blackholed → full-evaluation crossing returns ALLOW with
  its pair written, settlement_state PENDING, the response naming
  the failed attempt (SETTLEMENT_RPC_UNREACHABLE), the stale quote
  flagged in the pair.
- b. the same nonce re-presented during the outage → refused
  locally, 422 PAYMENT_NONCE_REUSED.
- c. RPC restored → POST /settle-pair {"sweep": true} completes
  the pending settlement on-chain: run 1 tx
  `0xd68d49f7c969397903f3508cfd1c29dac3ed834da09fac4f87ad4d4f040804c0`,
  run 2 tx
  `0x5a0b586e8624290e0599a1c74dc2f6455852bb188cf6aaa24516c9002d7e3112`
  (block 59301533); receipt status 0x1; payTo balance delta ==
  the crossing total, exact.
- d. chain replay MATCH including the outage pairs.
- e. terminal failure: an authorization whose nonce was consumed
  by an out-of-band settlement receipts its appended
  SETTLEMENT-FAILURE pair (SETTLEMENT_SIMULATION_REVERTED,
  terminal_confirmed against chain state); replay still MATCH.

Production deployment (explicit systemctl restart of
machine-economy-endpoint and machine-economy-public-proxy):
- Backward compatibility: the anchor at pair 44 under the
  migrated code is
  `a7e127d3983c031f010f2f60178b9bbf2863b1d09d971c124db36a28c3ee5c21`
  — the pre-migration anchor, unchanged. (The chain stood at 47
  pairs at deployment: pairs 45–47 are the entry push's clean-room
  crossings, appended after the 44-pair checkpoint.)
- /offer v07 live; public origin https://8374.stegverse.org/health 200.
- Relayer top-up before the specimen: 0.0012 ETH from the lane
  proof relayer to the production relayer, tx
  `0xc2271fa224098fb2055703e0b68da452973e9f5bec2440f9104780266d2b6e52`,
  block 59299875 (production relayer 0.000997 → 0.002197 ETH,
  above the worst-case settlement gas gate).
- Live specimen crossing 1 (insider, specimen payer,
  full-evaluation): PAIR-000049 ALLOW, born with settlement
  PENDING. Its settlement history is the outage grammar exercised
  live, and it is recorded here in full: the inline and sweep
  attempts met the night's egress interference (SETTLEMENT_RPC_
  UNREACHABLE); one sweep attempt classified a degraded-route
  simulation revert as terminal and appended PAIR-000050
  (SETTLEMENT-FAILURE, unconfirmed) — the defect the
  terminal-confirmation cure above repairs; a later sweep
  broadcast in fact landed on-chain (tx
  `0x6fac4964f1a4d0e44e5189d6f8a6ac50eabd46b516d463da0d5eb07d00bd9b77`,
  block 59302294, 16,702 µUSDC exact) while its response was lost
  to the same interference; the next attempt's revert was then
  confirmed against chain state (authorizationState: consumed)
  and receipted as PAIR-000051 (SETTLEMENT-FAILURE,
  terminal_confirmed: true). The pair's disposition never
  changed; the funds moved; every step stands on the chain.
- Live specimen crossing 2 (insider, specimen payer,
  full-evaluation): PAIR-000054 ALLOW, born PENDING on both pair
  members, settlement completed inline — settlement pair
  PAIR-000055 SETTLED, tx
  `0x9fda13264a261f00d5fe2aed00af86e15def11c4f3a13b06831575d91c445f40`,
  block 59304079, total 16,697 µUSDC. Replay after: MATCH, 55
  pairs, anchor
  `3a8046e39b000d708b83a0b41a5ba6ee3d333761a8c1c5f9c5a40914e133b46d`.
- /inspect verified from the public origin after deployment:
  200 through the proxy; stated pair count, anchor, and payTo
  balance match independent reads; every named pointer resolves.

## Q-45 state

DISCHARGED by this build: the charging half (offer v07, landed
earlier) and the pair-first migration (this record). REMAINDER,
unchanged and still open: the Q-45 terms-publication remainder
(published terms carrying the pair-first settlement grammar), and
two observations from this build's proof, named for the record:
(1) the /funds projection reads UNRECONCILED with a −6,602 µUSDC
remainder that arose in the entry-push window, before any
migrated-code production crossing (3,298 µUSDC of it verified at
the clean-room wallet 0xd1e745b11ef23Ce77c14d6f3041260C8Afd90061,
which the projection's seven-address set does not cover; the
balance is unattributed from this seat) — a projection-scope
reconciliation, not a migration defect: the 44-pair chain prefix
is byte-identical under the migrated code; (2) challenge and
crossing quotes can drift by micro-USDC amounts when one side
serves a stale quote and the other a live one under egress
interference (refusals PAIR-000048/52/53), a pre-existing
challenge/crossing coherence property the pair-first grammar does
not worsen and a future quote-binding refinement can close.

## Supersession note

COMPONENT__INSTRUCTIONS__01.md (capability component zip GEN 02,
KV `16AKOJmZzOFBH6oxf11_iicTKA1ZgOtqc`) published the
outage-property statement with the bound worded "pair-first
migration is filed, not yet built". That bound is superseded by
this build: pair-first is built and live in production, proven
above. The component instructions' bound sentence is updated at
its lane source in this build's carriage; the GEN 02 zip stands
as filed, with this record as the superseding evidence.
