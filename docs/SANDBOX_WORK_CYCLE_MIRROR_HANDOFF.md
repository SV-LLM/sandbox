# Sandbox work-cycle repair handoff (candidate)

Updated: 2026-10-28 America/Chicago.
Activity: `5a16c28c-37d4-4b84-9f97-46603e15f2df` (self-generated).

This is an additive source candidate for the existing PR #47 owner lane. It is
not a new Task Registry admission, assignment transfer, claim, or runtime authority.

## Current canonical coordinates

- Existing registered continuation: `SVORG-LLM-ORG-FOUNDATION-001-W07-SANDBOX-WORK-CYCLE`.
- Registry: `StegVerse-org/.github@0b50df09f620304319f99de58af081aa8902c37e:orchestration/task-registry.json`.
- Registry status: `validating`; COSV task.v1 `30000000021222`, lifecycle `CLAIMED_VALIDATION`.
- Applicable canonical handoff: `StegVerse-org/.github:docs/LLM_ORG_FOUNDATION_MIRROR_HANDOFF.md`.
- Current work discussion: `StegVerse-org/.github#163`; source lane: `SV-LLM/sandbox#47`.
- Expected source head: `9b97b93835365f4634c7598f843d030fc8e2dc23`.
- Test dependency: `SV-LLM/.github@a00a72ec54055e11b23841e3718cfd7352ad8a8c`.

The W07 row establishes existing work scope, not proven assignment of PR #47.
Labs canonical Registry generation 321 was fully recovered via Git blob
`6136c5a39d2df3e63490d576ada762c7a25b276f`; no Sandbox-specific row was found in
its 119 tasks or the canonical-task-records directory. Worker registry generation
22 has no Sandbox/W07 task claim. No authentic task-bound claim/fence was observed.

The parent is source-complete. Its current Org Registry vector is
`70000000020122`, while its older handoff reports `71000000100100`; the SV-LLM
mirror is older still. These projections must be reconciled by their owners;
none is Sandbox runtime authorization. Historical goal prompt count is unknown;
this session has one qualifying prompt and does not reset cumulative accounting.

## Repair boundary

Public capability names and `binding.public` cannot establish public data
classification. Until the existing authority supplies authenticated classification
covering all input, payload and output classes, the public shortcut must refuse.
The return path must also refuse legacy public binding receipts.

The predicate evaluator must not manufacture `authenticated=True`. An explicit
admission observation is data for offline predicate evaluation, never a sovereign
reader. Production WorkCycle has no authenticated native admission supplier and
therefore must fail closed; only test fixtures supply simulated admission data.
Do not expose a CLI/manifest option or inject a new authoritative callback to
turn this into production ALLOW.

## Owner continuation

1. Resolve PR #47's exact task scope and source assignment through P1/Registry;
   use the existing W07 record where applicable, without duplicating a goal.
2. Review/apply this bounded candidate to the original branch with expected-head
   protection, update this handoff and README, and run exact-head CI plus independent review.
3. Wire actual admission/classification readback through existing SDK/organization
   interfaces; task/payload/request digests must match independently retained receipts.
4. Obtain authentic WorkerCoordinator claim/fence and sovereign issuer/destination
   readback; supplied self-hashed chains and in-memory claims are insufficient.
5. Reconcile SDK #559's exact capability/route with its owning processor, and
   activation issue #120 before any native transition. No runtime activation,
   merge, release or propagation follows from this candidate or its tests.

No dependency, hosted service, machine or alternative authority is introduced.

## Executed candidate evidence

- Unchanged PR head: 38 binding tests passed locally.
- Four new production-default adversarial cases: 4/4 fail on unchanged head;
  4/4 pass on candidate. They expose public PII downgrade, synthetic admission
  with an admitted fixture claim, manifest-carried fake admission, and legacy
  public return. No native transition was attempted by these tests.
- Candidate: all 20 commands in sandbox-runtime.yml passed, 285 tests including
  44 binding tests and 14 work-cycle tests. This is local source evidence, not
  candidate GitHub CI; PR #47's CI run 40772131959 validates only its old head.
- Independent readback reused the unmodified
  `SV-LLM/.github@a00a72ec:resident-runtime/organization_ledger_readback.py`.
  Fresh designated ledger ref resolved to `e01e34cd686c85aba022b1e7ba8e225bdc159991`.
  The reader verified 56 organization receipts and the eight-receipt Sandbox
  repository chain with retained source equality (`NONE_READBACK_ONLY`). Sandbox
  records are from 2026-10-11. No PR #47 take/return binding class appears in that
  repository chain; historical readback is not current-task activation.
- SDK route table blob `81ee1a3424f2933e530ad8e976f4959fd3b3f77c` still lacks
  `sandbox-work-cycle` / `sv-llm.sandbox.work-cycle.v1`; existing owner issue is
  `StegVerse-org/StegVerse-SDK#559`.

Original branch is preserved. This candidate handoff becomes repository truth
only after original-owner integration; until then the applicable canonical
handoff remains the Org foundation handoff named above. No new cumulative prompt
count or coordination-state value is minted by this candidate.
