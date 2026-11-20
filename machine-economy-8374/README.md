# Machine Economy — 8374 (BETA) · Build Lane home

ProjectID: MACHINE-ECONOMY-ENTRY-01 · Identity: 8374 (BETA),
registered `8374@StegVerse.ai` (namespace entry in SV-LLM/.github).

## What this repository is

This is the **machine-economy operation**, residing in the Build Lanes.
It was built by the coordinator at the principal's explicit direction
(2026-11-18) — because the lanes could not pick the transfer work up,
the build was executed *inside* the Build Lanes' own repository
structure, with **ecosystem support** for the parts the lanes cannot
perform. It is not a package in the coordinator's workspace with
instructions pointing outward; this repository is the build's home.

The operation: a governed crossing endpoint for the machine economy —
x402 (dual-stack v1 + v2) payment challenges, evaluation and agreement
scopes (ME-EVAL-01, ME-AGREE-01), a matched receipt pair for every
crossing (ALLOW or NON-ALLOW, fee paid either way), SKAP sign-under-seal
custody signing, settlement on Base (USDC) with the settlement charge
quoted separately from the governance fee (offer v07), a path-filtered
public proxy, and bore + Cloudflare named-tunnel public exposure.

## GEN 08 — the operation as a function of the Build Lanes (2026-11-18)

8374 is a function of the Build Lanes. As of GEN 08 this repository
carries the complete lane-operation form: a **host** component that
bootstraps a running instance from a bare checkout of this branch
(keys born and custody-verified in-tree), a production-form
**authority** component (scoped, expiring, revocable, single-use
grants — the bearer-digest pattern is retired in lane form), the
**exposure** component (proxy provable locally; tunnel credentials
are site slots), and the **continuity** component (receipted
auto-restore plus the relayer funds projection with runway
monitoring). GEN 08's proof: an instance bootstrapped from a fresh
clone of this branch, all batteries green (x402 10/10, v2 8/8,
settlement 5/5, agreement 5/5, authority drill 8/8, exposure 9/9),
funds RECONCILED, and a full-evaluation crossing settled on-chain
from the instance's own relayer — recorded in
`LANE__OPERATION__BUILD__RECORD__01.md` and in
MACHINE__ECONOMY__ENTRY__SUITE GEN 08.

Ecosystem support remains wired in as support, not ownership: the
Ecosystem KV carries the evidence; SVAI monitoring covers the
operation; EOS answers through manifested queries; the coordinator
node runs the production instance as interim running backbone.
Production cutover and the 7-day zero-intervention observation
(BUILD-Q-32 acceptance) are NOT claimed by GEN 08.

## Lane home — fallback, stated as such

This build resides at **SV-LLM/sandbox**, branch `machine-economy-8374`,
folder `machine-economy-8374/` — the closest existing lane code surface
evidenced on 2026-11-18. Repository search across StegVerse-Labs and
SV-LLM found **no existing repository** named or described for the
machine-economy operation (8374 / x402 / machine-economy). Creating a
dedicated repository was attempted and failed on an exact predicate:

- failure_code: `CREATE_REPOSITORY_NOT_ACCESSIBLE_BY_INTEGRATION`
- failed_predicate: `POST /orgs/SV-LLM/repos` returned 403 "Resource not
  accessible by integration" — the Muse GitHub App cannot create
  repositories in the SV-LLM organization.
- required_evidence_or_repair: an App installation with repository
  creation permission, or the principal creating the empty repository
  in his own session.
- retry_entrypoint: re-attempt `create_repository` for a dedicated
  SV-LLM machine-economy repository once the predicate clears; the
  build then moves from this fallback branch to that repository
  unchanged (its manifest travels with it).
- owning_goal: MACHINE-ECONOMY-ENTRY-01 (BUILD-Q-24 / Q-32).
- next_attempt: on the next coordinator cycle after the predicate
  clears, or when the principal creates the repository.

Entity seats were not used as the home: SV-LLM/StegVerse_AI and
SV-LLM/Ecosystem_Chat are other entities' seats, and no entity's build
resides in another entity's seat.

## Ecosystem support (what the ecosystem carries for this build)

- **Live instance (backbone):** the coordinator node runs the production
  instance as ecosystem support until a lane environment holds it —
  offer v07 live at the permanent origin, receipt chain replay MATCH
  (39 pairs at the time of this commit; PAIR-000039 SETTLED on-chain).
  The coordinator's role from here is ecosystem support only, not owner
  of the build.
- **Evidence:** the Ecosystem KV coordination folder carries the filed
  records (handover inventory, build records, this transfer's record).
- **Monitoring:** SVAI's standing function covers the operation
  (registry checks, unfinished-work reporting, invariant adherence).

## State, stated exactly

This build **resides** in the Build Lanes as code. It does **not yet
run** in a lane environment: the running instance remains the
coordinator-node ecosystem-support instance until a lane environment
holds it. No claim of lane runtime, admission, or lane execution is
made by this commit.

## What a lane environment must supply to run it here (operator slots)

Full detail in `OPERATOR__SLOTS.md`. In summary:

- a **host** (BUILD-Q-32) — a persistent lane environment;
- **keys born on-site** — relayer and specimen/payer keys generated and
  held at the receiving site under SKAP discipline; no key material is
  in this repository and none ever travels;
- **Authority production form** (BUILD-Q-33) — TV/TVC Authority in
  production form for the signing plane's custody slots;
- its **own public exposure** (BUILD-Q-26) — the site's stable public
  address and tunnel credentials, supplied on-site;
- its **own continuity watch** (BUILD-Q-27).

Acceptance for a lane instance is the operation's own four batteries at
full marks against the instance's own genesis chain (x402 10/10, v2 8/8,
settlement 5/5, agreement 5/5), its own replay MATCH, and a settlement
recorded SETTLED on-chain under the instance's own submission.

## Contents

- `operation/` — endpoint, settlement, signing-boundary code, public
  proxy, tunnel supervisors, scope registry, offer base, bot agent-kit
- `signing/` — SKAP sign-under-seal service (custody is an operator slot)
- `batteries/` — the four acceptance batteries, wired to this tree
- `systemd/` — unit templates for all five services
- `install-all.sh` — single bootstrap entrypoint
- `OPERATOR__SLOTS.md` — every value a receiving site supplies
- `PACKAGE__README.md` — the transfer package's own readme
- `PACKAGE__MANIFEST__01.json` — per-file size + SHA-256 of the package
  (32 members; manifest SHA-256
  `6dd5963fd59b4352ec3303027ab3c5e6fb408efcf81ef5e4cfd913b6cb46e842`)
- `TRANSFER__PACKAGE__BUILD__RECORD__01.md` — the build record,
  including the independent-instance proof (four batteries full marks;
  settled crossing tx `0xfd31b369…`, block 59240288)

## Coordination class

Coordination/build record only — distinct from authenticated admission,
runtime execution, sovereign KV writes, and independently verified
completion. Queue anchors: BUILD-Q-24…Q-27, Q-32/Q-35, Q-49, Q-50
(StegVerse-Labs/.github #3443; pairing #3472).


## Q55 source migration reconciliation — 2026-11-19

At GEN14 head f99d69e21937cb5db20bc1ba31f07985c7c6f089, router, verify-page, chain-export, endpoint/proxy and agent-kit source paths already exist. The source-provenance census matches all61 suite pins and32 native byte identities. Six additional public provenance/install-template members are carried verbatim under source-provenance/gen14; host-specific installation files are archival, not lane defaults. Complete workspace parity awaits the original coordinator's exact source-only census. See [canonical migration handoff](../docs/MACHINE_ECONOMY_WORKSPACE_MIGRATION_MIRROR_HANDOFF.md); production and custody stay at the original node.


Q55 O-S444-1 clarification: Selection rule: only the six public host/source records (endpoint specification, router discovery and carry records, install script, service unit and configuration template) are copied here; the remaining 23 unmatched suite members stay in the original GEN14 suite under its manifest, because this bounded source carriage does not duplicate suite generation documents, offer/proof records or checker tooling. Full workspace parity remains unverified pending the original coordinator's exact source-only census; this note changes no code or census data.
