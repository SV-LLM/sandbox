# Component: signing

Custody signing for a lane site, in the BUILD-Q-33 production form:
admission by scoped, expiring, revocable, single-use Authority
grants (see `../authority/`); the specimen is born at the site by
the host bootstrap and held in the site SKAP tree
(`signing/custody/`, mode 0600); material is loaded per call and
zeroized; nothing is cached.

- Entrypoint: `entrypoint.sh` → `../../signing/lane_signing.py`
- Code: `../../signing/lane_signing.py` (+ `../../signing/authority.py`);
  `../../signing/skap_signing.py` is the coordinator node's
  production form (ecosystem SKAP retrieval under TV/TVC), retained
  as reference — a lane site does not run it.
- Proved by: `../authority/authority_battery.py` (the revocation
  drill, including an end-to-end ALLOW through the endpoint's /sign
  route) and the lane-instance proof in GEN 08.
- The earlier open predicate `SIGNING_CUSTODY_SLOTS_UNFILLED` is
  cured in this form: the host bootstrap fills the slots at the
  site (specimen + Authority store) before the service starts.
  With the slots unfilled the service still fails closed under
  that exact failure_code.
