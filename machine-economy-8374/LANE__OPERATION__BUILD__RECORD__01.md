# LANE OPERATION BUILD RECORD 01 — 8374 as a function of the Build Lanes (GEN 08)

ProjectID: MACHINE-ECONOMY-ENTRY-01 · Identity: 8374 (BETA) · Date: 2026-11-18
Home: SV-LLM/sandbox, branch `machine-economy-8374`, folder `machine-economy-8374/`
Coordination record only — distinct from authenticated admission, runtime
execution on a lane host, and sovereign KV writes. Authority: NONE.

## Direction executed

The principal's standing direction (restated 2026-11-18 17:36–17:38 CST):
build 8374 **inside the Build Lanes**, as a function of the Build Lanes,
with StegVerse ecosystem support wired in as support — not ownership —
curing the defect that the operation remained coordinator-dependent in
its build form. GEN 07 made the build *reside* in the lanes; GEN 08
builds the four substrate components the transfer left as queue items
(Q-32 host, Q-33 Authority, Q-26/Q-34 exposure, Q-27/Q-35 continuity)
as lane components, updates the operation to current production code,
and proves the whole form from a fresh clone of this branch.

## Components built (all in this repository; stdlib-only; parameterized)

| Component | File | SHA-256 |
|---|---|---|
| host (Q-32) | `components/host/bootstrap.py` | `617e9168f97612c8b53ae5be71c52251341f483a654b0c46026cfc2c1096f772` |
| authority store (Q-33) | `signing/authority.py` | `7a367dc1daac18ceac9aa79bebd6e56f009fe3c73d0b0bcea87afb3fcfb9ccee` |
| lane signing service (Q-33) | `signing/lane_signing.py` | `4fd7bf8ca5ae48270a85cf843a4c162aea7970d33ad08b5c7c977283be002fca` |
| authority drill | `components/authority/authority_battery.py` | (in package manifest) |
| exposure battery (Q-26/34) | `components/exposure/exposure_battery.py` | (in package manifest) |
| funds projection (Q-27/35) | `components/continuity-watch/funds_projection.py` | `5a11b6977ffd171687134175f285a734d9378c356696a2bbffae90e84cd8709b` |
| continuity watch (Q-27/35) | `components/continuity-watch/continuity_watch.sh` | `4b5591823486ed0acbfcdbf8a239cf9d4f8b65d7c0572875521c6f64ecc49594` |
| endpoint (production current) | `operation/endpoint.py` | `395969e8e6936fbd70e0f6bc8fb47103aa250ca6e3e854cab51c564e0b4a0030` |
| settlement (broadcast-failover cure) | `operation/settlement.py` | `b0c78d08a224ed9a91fe7949972af6e1ae9e299a45c9279ce041d9c81918ad28` |
| funds (production projection) | `operation/funds.py` | `274ec65f04669aeec7a67fdf7a87fef6a23e59bb3ebee6ba26a0378dd64f7a51` |

Package manifest at the GEN 08 build commit: 56 members,
`PACKAGE__MANIFEST__01.json` SHA-256
`6d0c9bcaa50da0929c6e6330cc8398463a2e25224e2d24560fe5e1ba405d7fa2`
(regenerated at carriage to include this record; the suite carries the
final manifest as a member, where its hash is verifiable).

Design notes, per component:

- **Host (Q-32):** `bootstrap.py` takes a bare checkout to a running
  instance — renders the tree (fresh GENESIS chains), births the
  instance's own relayer / specimen payer / signing specimen in-tree,
  creates the site Authority store, renders configs + systemd units,
  installs and starts them, and writes `HOST__RECORD__01.json`.
  **Custody rule:** every key is verified (file at mode 0600, address
  re-derives, test signature verifies) BEFORE its address is emitted
  as a funding instruction — the 2026-11-17 $2 stranding as a rule.
- **Authority (Q-33):** grants are scoped (one scope_ref/action/resource
  triple), expiring (valid_before), revocable (revocation list checked
  at admission), and single-use; every store event is hash-chain
  logged. The lane signing service issues no signature without a live
  grant — the scope-less, expiry-less bearer digest pattern (2026-11-17
  vulnerability items 2 and 8) is retired in lane form. The open
  predicate `SIGNING_CUSTODY_SLOTS_UNFILLED` is cured at a site by the
  host bootstrap filling the slots; unfilled, the service still fails
  closed under that exact code.
- **Exposure (Q-26/Q-34):** the proxy allowlist legs are provable
  locally and proved by battery; the tunnel legs ride on the site's
  own credentials, held at mode 0600 outside the repository tree —
  slots, never claims.
- **Continuity (Q-27/Q-35):** the watchdog restores the instance's OWN
  declared unit set (rendered by its bootstrap) and receipts every
  restore into `<instance>/continuity/records.jsonl`; the funds
  projection reconciles the instance's supply accounting and reports
  relayer runway with a LOW_RUNWAY flag below a named threshold.
- **No coordinator-node paths:** the lane tree was grepped for
  `/home/hatch` and workspace paths — none in code or config (the two
  tunnel supervisors' tool binaries are now site slots: `ME_BORE_BIN`
  / `ME_CLOUDFLARED_BIN` or PATH). Two mentions remain inside
  `TRANSFER__PACKAGE__BUILD__RECORD__01.md`, a GEN 07-era historical
  record whose text is provenance and is not rewritten.

## Proof — lane instance from a fresh clone

Clone: `https://github.com/SV-LLM/sandbox.git` branch
`machine-economy-8374` at commit `a96fa92aef550e5cd4e9681fba2aabf264738599`
(GEN 08 build commit `9a31a4493242d65518c9fb331cf181c323e847f0` + the
signing cure below). Nothing was copied from the coordinator's
endpoint tree or the transfer package at runtime; the instance was
rendered by the clone's own host bootstrap. Readback: two files
verified byte-identical between the pushed tree and the clone
(`components/host/bootstrap.py`, `signing/lane_signing.py`).

Instance: prefix `lane8374`, ports 8994/8995/8996.
Relayer `0xe9d4873B32BbC1419a118B221483337dECb73E1F` · payer
`0x76329EcEebFe1b761C71a27Ce007E57e677A1315` · signing specimen
`0x6eB3eBFE3cE96dD744d6f6EB33C50B27277662C8`. Custody verification
3/3 fundable. Genesis chain MATCH, 0 pairs.

Funding (custody-verified addresses only): relayer 0.0019 ETH
(tx `0x523ba40000552cde40f6e294043d0db832d0517355603c574c2fca6c396a382a`,
block 59278148) and payer 20,000 µUSDC (tx
`0x1b9ae2cca29120938861d6879651c370154c1a300cc74670be751948f67b4b40`,
block 59278190), both from the defect-run instance's unspent keys
(see Findings); the first funding round (production relayer → defect
instance 0.002 ETH, tx `0x48701fa7a57783d8ccdfe5a456828613f0b5760f9fbd19233a84f626fff28eff`,
block 59276177; specimen payer → defect instance 20,000 µUSDC, tx
`0xda800bc8e3a022d9e957373b3a776f76a72824234bdc5fa17c9af876d63b2d84`,
block 59276222) is part of the same evidence chain.

Batteries against the lane instance (its own code throughout):

- x402 battery: **10/10**
- x402 v2 battery: **8/8**
- settlement battery: **5/5** (against a second bootstrapped
  throwaway instance with an unfunded relayer, per the battery's
  design; relayer `0xC48Efc6270D37B94C7C4dB2dD8e8207FB8c073c7`)
- agreement battery: **5/5**
- authority revocation drill: **8/8** — grant→sign ALLOW with
  signature verified; consumed grant re-presented refused
  (`AUTHORIZATION_ALREADY_USED`); revoked refused
  (`AUTHORIZATION_REVOKED`); expired refused
  (`AUTHORIZATION_EXPIRED`); wrong-scope refused
  (`AUTHORIZATION_SCOPE_MISMATCH`); unknown token refused
  (`AUTHORIZATION_NOT_ADMITTED`); fresh grant through the endpoint's
  /sign route ALLOW; authority log replays MATCH (13 entries)
- exposure battery: **9/9** — public surface served; /replay, /funds,
  /sign, /seal, /settle-pair all refused 404 at the proxy
- continuity watch `--dry-run`: **verified end state holds, exit 0**
- funds projection: **RECONCILED** — USDC supplied 20,000 −
  settled-out 16,696 = on hand 3,304, remainder **0**; ETH provided
  1,900,000,000,000,000 − burned 516,835,750,478 = on hand
  1,899,483,164,249,522, remainder **0**; relayer runway **3,675**
  settlements at the actual mean cost; no LOW_RUNWAY flag

Settled crossing (the instance's own payer, the instance's own
relayer): full-evaluation ME-EVAL-01, **PAIR-000021 ALLOW**, total
16,696 µUSDC (fee 15,000 + settlement charge 1,696). The first
settlement attempt failed closed `SETTLEMENT_RPC_UNREACHABLE`
(service-form transport window on this node — the standing
intermittency); the designed `/settle-pair` retry broadcast on its
second attempt: **tx
`0x7ffcaaf76ec349ce7f9ec10450a5fbaff65ce3d415cd6f2975cc2031fb459bbc`,
block 59278883, status 0x1, gasUsed 85,756, submitted from the
instance relayer**; settlement pair PAIR-000023. Movement exact:
payTo 96,580 → **113,276 µUSDC** (+16,696); instance payer 20,000 →
3,304 (−16,696).

Instance chains at teardown: endpoint **MATCH, 27 pairs**, anchor
`93fc76acede019fb…`; signing **MATCH, 7 pairs**. Units disabled and
removed after the proof; instance trees retained as evidence on the
coordinator node (evidence custody, not operation).

Production untouched throughout: chain **MATCH, 44 pairs**, anchor
`a7e127d3…`; origin `https://8374.stegverse.org/health` 200. (The
payTo balance rose by the proof crossing's settlement — the
operation's receptor receiving the lane instance's payment, by
design.)

## Findings cured inside this build (each found by the proof, each cured in the lane form)

1. **Signing ALLOW leg 500** (first proof run): the bootstrap writes
   the specimen key `0x`-prefixed; `lane_signing.py` fed it to
   `bytes.fromhex` unprefixed. Drill scored 6/8 (all refusal legs
   passed). Cure commit `a96fa92aef550e5cd4e9681fba2aabf264738599`;
   the proof above ran entirely on the cured clone (drill 8/8).
   The defect-run instance tree is retained as evidence.
2. **Funds projection missed SUBMITTED settlements:** a settlement
   whose broadcast landed after the endpoint recorded it stands as
   SUBMITTED in the chain; the projection counted only SETTLED
   records and would have reported the instance's settled funds as
   missing. Cured: SUBMITTED records are verified against their
   on-chain receipts (status 0x1) and counted.
3. **Funds projection missed the Base L1 fee:** burned accounting
   used `gasUsed × effectiveGasPrice` only, leaving a
   −2,299,750,478 wei remainder; Base receipts carry the L1 data
   fee as `l1Fee`, now included. Remainder after cure: 0.
4. **Continuity watch flagged undeclared doors:** its fixed
   five-unit list failed a healthy tunnel-less instance on the two
   tunnel units it never declared. Cured: the unit set is the
   instance's own rendered set.

## What a lane now holds that it did not before GEN 08

- A **host bootstrap** that stands the whole operation up from this
  branch alone, with custody-verified key birth — no coordinator
  tree, package, or instruction set involved at runtime.
- A **production-form Authority** (scoped / expiring / revocable /
  single-use grants, hash-chained grant log) and a lane signing
  service that admits only under it.
- An **exposure battery** proving the public door's allowlist
  locally, with tunnel credentials as named site slots.
- A **continuity component** that monitors the instance's funds
  (reconciled, with relayer runway) and receipts its own restores.
- The **current production operation code** (endpoint with funds
  projection, settlement with the broadcast-failover cure, offer
  v07) — GEN 07's lane copies had drifted one generation behind.
- `OPERATOR__SLOTS.md` updated: every site-specific value (host
  path, prefix, ports, public URL, tunnel credential location,
  Authority store, funds accounting, runway threshold) is a named
  slot a lane fills at its own site.

## Remaining bound — stated exactly

The build form is complete and proven. What does not exist is a
lane-side physical host: the Build Lanes are sessions transported
by the principal and hold no machine of their own in the record, so
the proven instance above ran on the coordinator node (as the proof
substrate) and production still runs there as interim backbone.
That remainder is a substrate fact, not a build gap:

- failure_code: `LANE_HOST_SUBSTRATE_ABSENT`
- failed_predicate: a Build Lane session holds a persistent host it
  can bootstrap onto and observe for 7 days
- required_evidence_or_repair: a lane-side host (machine / VM /
  device) under a lane's own control; run `components/host`
  entrypoint from a fresh clone of this branch on it; acceptance =
  its HOST__RECORD + the battery set + 7 days of continuity records
  with zero coordinator intervention (BUILD-Q-32 acceptance)
- retry_entrypoint: the first lane session that gains a host
  substrate; the bootstrap is the retry mechanism and is proven
- owning_goal: MACHINE-ECONOMY-ENTRY-01 / BUILD-Q-32
- next_attempt: on that lane session's entry, under the one queue

NOT claimed by this record: production cutover (out of scope);
the 7-day zero-coordinator-intervention observation; any external
(non-insider) crossing — P1 remains the first customer, separately
counted, and no proof crossing in this record is one.
