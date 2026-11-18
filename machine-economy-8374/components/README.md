# Components — machine-economy-8374

The operation structured as named Build Lane components. Each
component has its own entrypoint and the battery (or check) that
proves it. Components are views over the operation tree in this
repository (`../operation/`, `../signing/`); the entrypoints are the
lane-facing handles, so a lane works component by component instead of
facing the whole tree at once.

| Component | Entrypoint | Proved by |
|---|---|---|
| host | `host/entrypoint.sh` → `host/bootstrap.py` | the GEN 08 lane-instance proof: bootstrap from a fresh clone to a running, settled instance |
| endpoint | `endpoint/entrypoint.sh` → `operation/endpoint.py` | `batteries/x402_battery.py`, `batteries/x402_v2_battery.py`, `batteries/agreement_battery.py` |
| settlement | `settlement/entrypoint.sh` → `operation/settlement.py` | `batteries/settlement_battery.py` |
| authority | `authority/entrypoint.sh` → `signing/authority.py` | `authority/authority_battery.py` — the revocation drill (grant / revoke / expire / wrong-scope / reuse / unknown) |
| signing | `signing/entrypoint.sh` → `signing/lane_signing.py` (lane form, BUILD-Q-33) | the authority drill, including an ALLOW through the endpoint's /sign route |
| exposure | `exposure/entrypoint.sh` → `operation/public_proxy.py` + tunnel supervisors | `exposure/exposure_battery.py` (proxy allowlist legs); tunnel legs are site slots |
| continuity-watch | `continuity-watch/continuity_watch.sh` + `continuity-watch/funds_projection.py` | its own `--dry-run` self-check; the funds projection's RECONCILED verdict on a live instance; restarts receipted in the instance tree |

## Ecosystem support wired in (support, not ownership)

8374 is a function of the Build Lanes. The StegVerse Ecosystem support
wired into this build: the Ecosystem KV carries the evidence
(handover inventory, build records, suite zips); SVAI's standing
monitoring function covers the operation; EOS answers ecosystem
questions through manifested queries over the filed record; the
coordinator node runs the production instance as interim backbone
until a lane environment holds it. None of that support owns the
build; the build lives here.
