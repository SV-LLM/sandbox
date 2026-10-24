# Sandbox work admission records a digest, not the work object

Rigel, 2026-10-24T17:25Z: "The ecosystem holds zero sensitive user data."

## What the ledger records

On ALLOW, `Sandbox.admit` (`runtime/sandbox.py`) appends one `SANDBOX_WORK_ADMITTED` receipt. Its evidence holds:

| field | value |
|---|---|
| `disposition` | `ALLOW` |
| `work_id` | the work object's `work_id` |
| `work_sha256` | the `SV_LLM_CANONICAL_JSON_V1` digest of the canonical work object (`CANON.digest(work)`), the same digest that `CONTRIBUTION_REQUESTED` receipts already carry |
| `parent_transition` | the receipted parent transition (receipt digests and a subject digest only) |
| `authority_effect` | `NONE` |

Before this change, the evidence also held the whole work object (`"work": work`), including `manifested_request`. That receipt is propagated into the SV-LLM organization ledger (`aggregate_transition`), so the manifested request text was persisted in both chains. Now neither chain holds it.

## Where the body comes from after admission

- **The process that admitted the work** keeps the body in memory (`Sandbox._admitted_work`). It is never written to a ledger.
- **A later process** passes `work_source(work_id, work_sha256) -> bytes | None` to `Sandbox`. `Sandbox._work` accepts the returned bytes only if:
  - they parse as canonical JSON;
  - they carry the same `work_id`;
  - they digest to the receipt's `work_sha256`.
- **`WorkCycle`** supplies `work_source` by re-deriving the work object from the materialized manifest in node state (`WorkCycle._work_source`). It uses the same construction as intake (`WorkCycle._work_object`).

## Fail closed

When no matching body is supplied, the work is treated as not admitted. Every later step refuses with its existing six-field denial, and nothing proceeds on an unverified body:
- `assign`, `request` and `record` fail with `WORK_IS_ADMITTED` and the like;
- `synthesize` and `complete` refuse in the same way.

A receipt with no `work_sha256` is also treated as not admitted. `reconstruct` reads only receipts and is unchanged.

## Custody

PII and credentials are stored only in the SKAP Vault (KV/_Vault/SKAP), for every user including the ecosystem. TV/TVC is the credential authority, never the storage place.
- Interim sources: continuity-vault-kit `specs/skap-vault-double-interlock.v1.json` L4-6 @bcc2d75168b84b3d35b7f831df0b4fe039119631.
- Rigel 17:52Z: "EVERY DISCUSSION, EVERY DESIGN DOCUMENT, EVERY COORDINATION SURFACE SHOULD DEMONSTRATE THE INVARIANT REQUIRING THE SKAP VAULT TO BE A PII AND CREDENTIAL STORAGE VAULT FOR EVERY USER".
- Rigel 17:54Z: "INCLUDING StegVerse Ecosystem's PII and Credentials!" and "THE HST IS THE INVARIANT ALREADY".
- The HST line is not located yet: StegVerse-org/.github#163 comment 6387655436.

This change stores no work body anywhere, so nothing new needs custody.

## Tests

- `tests/test_sandbox_runtime.py` `WorkDigestOnly`:
  - the receipt carries the digest and no body;
  - a sentinel request text is absent from every Sandbox and organization ledger file;
  - a fresh `Sandbox` without `work_source` refuses `assign` with `WORK_IS_ADMITTED`;
  - tampered or non-JSON bytes are rejected;
  - matching bytes are accepted.
- `tests/test_work_cycle.py`: a later `WorkCycle` re-derives the admitted work from node state, and no Sandbox receipt contains `manifested_request`.
