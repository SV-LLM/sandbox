# ENDPOINT__SPEC__01 — The Governed Endpoint

Suite: MACHINE__ECONOMY__ENTRY__SUITE GEN 06
ProjectID: MACHINE-ECONOMY-ENTRY-01
Status: SPECIFICATION + ACTIVATION RECORD. This document
specifies the endpoint built under queue item BUILD-Q-13 and,
as of GEN 06, records its activation: the endpoint is built,
the gate of §6 stands discharged, the receptor is declared,
fee verification and settlement submission are live, and the
first settling crossing settled on-chain on 2026-11-17 (see
§6, DISCHARGED, and GEN__06__CHANGES__01.md).
Generation: GEN 06 — the record of activation (BUILD-Q-17/18/19,
Gates 1–3). GEN 05 stands unedited; the conformances of this
generation are recorded in GEN__06__CHANGES__01.md.

## 1. What the endpoint is

A governed endpoint operated by StegVerse LLC that sells
admissibility evaluation and receipting as a service over
machine-economy transactions already flowing on existing rails.
It is not a marketplace and not a payment rail: the rail carries
the money; this endpoint decides, at the signing boundary,
whether a proposed crossing is admissible, and issues the
dual-recorded receipt pair that proves the crossing afterward.

## 2. Protocol dialects

- Primary: **x402** (HTTP 402 Payment Required). The endpoint
  answers an unpaid request for a governed resource with a 402
  carrying x402 payment requirements (the `accepts[]` shape of
  OFFER__MACHINE__READABLE__01.json), and serves the resource
  when the client returns a valid payment authorization.
- Alternate: **MPP**, noted as an alternate dialect for a later
  generation; GEN 04 builds x402 only.

## 3. The flow

1. A machine client requests a governed resource (evaluation,
   receipt-pair issuance, or a governed service behind them).
2. The endpoint evaluates the proposed crossing — the
   transition the client proposes — for admissibility **at the
   signing boundary** — before any signature is solicited or
   accepted — against the contemporaneous record: known
   evidence, exclusions and their reasons, governing
   boundaries, current policy, authority, delegation, refusal
   reachability, and validity at commit time.
3. The evaluation resolves to exactly one disposition:
   - **ALLOW** — the crossing may proceed. The client
     completes payment authorization under x402; the endpoint
     verifies the authorization cryptographically (EIP-3009,
     BUILD-Q-18); execution proceeds; and the endpoint's
     gas-only self-relayer submits the settlement transfer on
     Base, with the settlement outcome receipted in the
     crossing pair (Gate 2; fee unit and pricing mode: §4).
   - **DENY** — the crossing is inadmissible on the record
     as presented.
   - **FAIL_CLOSED** — the record is incomplete or the
     predicate unevaluable; nothing commits.
   A non-ALLOW response carries the disposition in the ecosystem
   six-field grammar: `failure_code`, `failed_predicate`,
   `required_evidence_or_repair`, `retry_entrypoint`,
   `owning goal`, `next_attempt`. A label-only refusal is never
   returned; refusal is a stated reason, not silence.
   A non-ALLOW outcome is also **receipted**: the refused or
   fail-closed attempt produces a receipt — the refusal
   record — recording the attempt and its disposition, while
   nothing executes and nothing moves. The specimen is the
   W-1 run (2026-11-13; ENTRY__BASIS__01.md §3): its admitted
   crossings produced matched receipt pairs, and its
   out-of-scope control crossing and its post-dissolution
   attempt each produced refusal receipts (failed predicates
   MANIFEST_MISMATCH and NO_STANDING_RECEIVER) while moving
   nothing.
   A non-ALLOW outcome is **fee-bearing** under the pricing
   mode of §4: the fee is paid either way.
4. Receipts attach to **transitions, not transactions**. On
   ALLOW and execution, one boundary crossing yields exactly
   one **dual-recorded receipt pair**: matched receipts
   recorded on both sides of the crossing, hash-chained to the
   predecessor chain, together constituting a **portable
   settlement proof** — the crossing is provable from the
   pair, independent of either party's internal log. A
   one-sided copy proves nothing about the other side.

**Metering.** The endpoint's metering counts **receipt
pairs**: 1 receipt pair is a unit of compute, ALLOW or
NON-ALLOW (the principal's landing of 2026-11-16 —
compute-assignment SLOT A). An ALLOW crossing's matched pair
is exactly one unit; a NON-ALLOW attempt's refusal record pair
is likewise exactly one unit. The unit is
disposition-independent: a refusal consumes the same unit of
compute as an allow, and the metering never counts a raw
transaction — it counts the receipt pairs the evaluation
produced.

## 4. Fee structure — tiered by evaluation depth; paid either way

The fee unit is the **governed crossing / evaluation** — not
the raw transaction. The fee is collected as service provider
over existing rails and is tiered by evaluation depth, because
full production evaluation (analysis cost basis $0.007–0.024
per evaluated outcome, 2026-11-08 sizing analysis) cannot ride
the median ~$0.01 machine-economy call:

- **Receipt-only tier** — receipt-pair issuance and record,
  without full evaluation. Fee unit: per governed crossing.
- **Full-evaluation tier** — complete admissibility evaluation
  at the signing boundary, for higher-value flows whose value
  supports the evaluation cost. Fee unit: per evaluated
  outcome.

**The fee is paid either way.** The pricing structure is a
selectable cost-optimization option with two modes:

- **Mode (a) — the fee follows all dispositions.** The fee is
  charged per evaluation regardless of outcome: an ALLOW, a
  DENY, and a FAIL_CLOSED each bear the fee for the unit of
  compute they consumed.
- **Mode (b) — the ALLOW disposition price covers all
  dispositions.** The cost of refused evaluations is amortized
  into the ALLOW price; a refusal draws no separate charge,
  and its compute is paid for through the ALLOW price.

Refusal compute is fee-bearing under either mode: a NON-ALLOW
attempt consumes exactly one unit of compute (§3, metering),
and that unit is paid for under mode (a) directly or under
mode (b) through the ALLOW price. The mode is a
cost-optimization option for the consumer of the service; it
changes the shape of the charge, never whether the compute is
paid.

The tiers derive from the compute cost estimate derived
2026-11-08 — receipt-only well under $0.001 per governed
crossing; full evaluation on the $0.007–0.024
per-evaluated-outcome basis — and the principal confirmed on
2026-11-16 that this compute-cost derivation is the tiers'
source. The tier prices stood **proposed, pending the
principal's ratification**, through GEN 04, recorded as such
in GEN 04's offer (class `proposed_pending_ratification`).
**The principal ratified them on 2026-11-17 (00:42 CST) —
"Ratified."** The tiers therefore stand in this generation
under class `ratified` in OFFER__MACHINE__READABLE__01.json:
they are prices of StegVerse LLC. Every tier figure is
unchanged from the analysis-derived proposal — ratification
changed the tiers' class, not their figures. The ratified
PRICE SCHEDULE 01 lines relevant to machine consumption are
recorded in the same offer, likewise under class `ratified`.
A figure that remains analysis-derived and unratified is not
a price; no such figure is offered here.

**The fee is a posted, non-negotiable toll — "the fee is the
fee"** (principal, 2026-11-16 23:52 CST). Negotiation in the
machine economy concerns the work and the terms of the
crossing, never the governance fee: the fee is not a subject
of negotiation, counter-offer, or per-transaction bargaining.
The mode (a)/(b) structure above stands as **standing pricing
structure** — set as policy — expressly not per-transaction
bargaining: a consumer selects under the standing structure;
neither side haggles the fee for a crossing.

**Revisability.** This fee position, like the intent-signing
ruling of §6, is landed as **current posture**: it is capable
of being changed in the near future if the market sees things
differently, and it is supersedeable only by a later principal
determination — which would arrive as a new generation of
this suite. Neither posture is an invariant of the endpoint's
design, and this specification does not hard-code either as
immutable structure.

## 5. What this endpoint provides that the rails do not

Per the 2026-11-11 inventory of Coinbase / Stripe / PayPal
surfaces:

- **Admissibility evaluation at the signing boundary.** The
  rails move value; none evaluates whether the crossing
  should be signed at all against authority, delegation, and
  commit-time validity.
- **Negotiation, not fixed-price-only.** 402/MPP flows are
  fixed-price; refusal exists on the rails only as silence.
  This endpoint returns governed counter-positions and stated
  refusals in the six-field grammar — the precondition for
  machine-to-machine negotiation rather than machine-to-machine
  vending. (The counter-positions concern the work and the
  terms of the crossing; the governance fee itself is never a
  subject of that negotiation — §4.)
- **The sovereign matched-pair record.** The rails keep their
  own ledgers; neither party holds a dual-recorded,
  hash-chained receipt pair that proves the crossing without
  trusting the counterparty's or the rail's internal log.
  (PayPal additionally lacks a machine layer entirely.)

## 6. THE GATE — ANSWERED: THE INTENT-SIGNING RULING

> The interim ruling has **landed** (principal, 2026-11-16
> 23:52 CST), and it is negative: **"Intent signing should not
> be a lesser act at this time."** Intent signing is
> custody-grade — identical in grade to custody signing.
> There is **no** lesser policy-key path for negotiation.
> Activation of live negotiation therefore requires the
> **production SKAP custody signing path** to be settled:
> negotiation waits on that path, not on a further ruling.

Concretely:

- The endpoint build, the offer publication, and every
  non-signing part of this package proceed without waiting.
- No live negotiation occurred, no offer was signed, and no
  payment authorization was solicited or accepted until the
  production SKAP custody signing path was settled — because,
  under the ruling, any signing in the course of negotiation
  is custody-grade signing, and no lesser policy-key
  substitute exists. That path stands SETTLED (BUILD-Q-14)
  and live negotiation is activated; see DISCHARGED below.
- The **negotiating identity** that receipts the handshake
  pair is a **dedicated identity specifically for the machine
  economy**, distinct from the suite-side identity —
  identities are per profit center (the principal's
  determination, 2026-11-16). Its designation has since
  landed (principal, 2026-11-16 23:56–23:57 CST): the
  operative designation is the digits **8374** — the digits
  represent BETA (8=B, 3=E, 7=T, 4=A) as meaning/expansion,
  and identity form follows the economy: digits for the
  machine economy, letters for the suite economy. The
  designation was carried as designation only through
  GEN 05. The identity now **exists as a declared receptor**:
  it was registered as 8374@StegVerse.ai (BUILD-Q-17;
  SV-LLM/.github PR #73, merge
  ce7a75d820ef6d2b7072be67bc3f8b2f986ce2e7; DEFINITION body
  SHA-256
  5480233521c69b5119901b6f97a19496fedf42e7fe307fda74a3ed0ed99da914)
  and the receptor declared under the 2026-11-17 operating
  configuration, so the offer's settlement fields (`payTo`,
  `network`, `asset`) stand declared — x402 exact / Base
  (eip155:8453) / USDC
  0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913 / payTo
  0x7721aB66161e60fCcA59CCe2A86817cbdd9b16Be (8374's own
  address; revisable by a later principal determination).
- Custody and settlement steps were excluded from the build's
  claimable scope until the production SKAP custody signing
  path was settled (see the eligibility scope of queue item
  BUILD-Q-13); that exclusion is spent — the path is settled
  and the settlement leg is built (Gate 2, below).

**DISCHARGED — 2026-11-17.** The gate this section answered
is discharged on the record, in four discharges and two gate
closings:

- **Signing path SETTLED (BUILD-Q-14).** The SKAP custody
  signing path — the sign-under-seal operation holding
  specimen SKI-SIGNING_KEY-31c77c60 — stands SETTLED (gate
  settled on acceptance replay). Intent signing proceeds at
  custody grade through that operation, as the ruling
  requires; no lesser path was built.
- **Identity REGISTERED, receptor DECLARED (BUILD-Q-17).**
  8374@StegVerse.ai is registered in the SV-LLM/.github
  namespace directory (PR #73, merged
  ce7a75d820ef6d2b7072be67bc3f8b2f986ce2e7), and the receptor
  is declared as above. The activation demonstration crossed
  unpaid (402, maxAmountRequired 15000) to ALLOW
  PAIR-000014, custody-signed over its anchor by PAIR-000015
  (transcript: the endpoint workspace,
  demo/DEMO__ACTIVATION__2026-11-17.json).
- **Fee verification LIVE (BUILD-Q-18).** POST /crossing
  verifies x402 exact-scheme EIP-3009 authorizations
  cryptographically against the declared receptor — scheme,
  network, asset, payTo, tier value, validity window, and a
  single-use nonce enforced by replay itself. Verification
  failures fail closed on the payment predicate, distinct
  from a governed DENY, and are refusal-paired.
- **Public surface BUILT and REACHABLE (BUILD-Q-19 + Gate 1).**
  The path-filtered public proxy (127.0.0.1:8796) exposes
  only /health, /offer, and POST /crossing; the bore.pub
  tunnel carried over the node's egress CONNECT proxy makes
  the surface publicly reachable, and public-url.txt in the
  endpoint workspace is the live pointer (the port is
  volatile per tunnel restart). The HTTPS/stable-domain leg
  remains open as a named remainder
  (GEN__06__CHANGES__01.md, six-field record).
- **Settlement LIVE (Gate 2).** Verified authorizations are
  submitted as EIP-3009 transfers on Base by the endpoint's
  gas-only self-relayer (relayer
  0xB4a019cfd17DE2E6B00Aa2DAB159e24d9235Fb17, funded by the
  principal); the outcome rides the crossing pair under
  `settlement` (SETTLED / SUBMITTED, or a SETTLEMENT_*
  fail-closed code). A failed settlement never changes the
  crossing's disposition and never consumes the nonce; the
  resubmission grammar (ReceiptChain.issue_settlement_pair,
  POST /settle-pair; pair_class SETTLEMENT, structural — not
  a unit of compute) collects it. A public facilitator was
  evaluated and set aside as primary: it would hold API
  credentials on the node, against the ecosystem's
  zero-credential custody posture (SETTLEMENT__FACILITATOR__
  NOTE.md, endpoint workspace).
- **First settling crossing SETTLED (2026-11-17).**
  PAIR-000016 (full-evaluation, ALLOW) settled by
  PAIR-000020: tx
  0x4b1dce827c08f19b3ea6aae606d5f6b473f8dcd1b055502f7c46a926e38f80b4,
  block 58730763; 8374's balance 15,000 micro-USDC
  afterward, verified on-chain. Classification: a settling
  specimen (the payer was principal-funded) — NOT an
  external conversion and NOT P1. The full record, including
  the settlement leg's initial SETTLEMENT_RPC_UNREACHABLE
  failure and its cure, is GEN__06__CHANGES__01.md §5.

**Revisability.** The ruling carries its temporal qualifier —
"at this time." It is landed as **current posture**: changeable
policy, capable of being changed in the near future if the
market sees things differently, supersedeable only by a later
principal determination — which would arrive as a new
generation of this suite. It is not an invariant of the
endpoint's design, and this specification does not hard-code
it as immutable structure.

## 7. Custody discipline

The endpoint holds no credentials and stores no keys. Any
signing capability operates under the principal's own SKAP
custody doctrine; components hold at most
provider-observation / evidence references, never stored keys.
