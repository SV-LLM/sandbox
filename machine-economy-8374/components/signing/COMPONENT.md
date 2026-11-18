# Component: signing

SKAP sign-under-seal custody signing: governed retrieval per call,
sign in memory, zeroize, nothing cached. Custody is an operator slot —
the specimen is born and sealed at the receiving site; no key material
is in this repository.

- Entrypoint: `entrypoint.sh`
- Code: `../../signing/skap_signing.py` (+ `../../signing/replay.py`)
- Proved by: the settlement battery's custody-signature leg and the
  production specimen's standing replay MATCH. The signing plane
  starts usefully only with the site's own SKAP tree + Authority store
  (production form BUILD-Q-33) — failure_code
  `SIGNING_CUSTODY_SLOTS_UNFILLED` until then; the crossing plane does
  not depend on it.
