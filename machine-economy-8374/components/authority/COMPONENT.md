# Component: authority (BUILD-Q-33)

The production-form Authority for a lane site: the store from which
the site's signing service admits calls. It replaces the proving
form's scope-less, expiry-less bearer digest (the pattern behind
vulnerability items 2 and 8 of the 2026-11-17 review).

- Code: `../../signing/authority.py` (store + CLI), consumed by
  `../../signing/lane_signing.py` at admission on every call.
- Grants are SCOPED (one scope_ref / action / resource triple),
  EXPIRING (valid_before), REVOCABLE (revocation list checked at
  admission), and SINGLE-USE (consumed by the admitted call).
- Every store event (ISSUE / CONSUME / REVOKE / REFUSE) is appended
  to a hash-chained log beside the store; `verify-log` replays it.
- Entrypoint: `entrypoint.sh` (the operator's CLI surface).
- Proved by: `authority_battery.py` — the revocation drill:
  grant → sign ALLOW; revoke → same-shape request refused
  (AUTHORIZATION_REVOKED); expired grant refused
  (AUTHORIZATION_EXPIRED); wrong-scope grant refused
  (AUTHORIZATION_SCOPE_MISMATCH); consumed grant re-presented
  refused (AUTHORIZATION_ALREADY_USED); no grant refused
  (AUTHORIZATION_NOT_ADMITTED). Run against a live lane instance:
  `authority_battery.py <instance-tree> <endpoint-base-url>`.
