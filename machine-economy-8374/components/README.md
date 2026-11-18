# Components — machine-economy-8374

The operation structured as named Build Lane components. Each
component has its own entrypoint and the battery (or check) that
proves it. Components are views over the operation tree in this
repository (`../operation/`, `../signing/`); the entrypoints are the
lane-facing handles, so a lane works component by component instead of
facing the whole tree at once.

| Component | Entrypoint | Proved by |
|---|---|---|
| endpoint | `endpoint/entrypoint.sh` → `operation/endpoint.py` | `batteries/x402_battery.py`, `batteries/x402_v2_battery.py`, `batteries/agreement_battery.py` |
| settlement | `settlement/entrypoint.sh` → `operation/settlement.py` | `batteries/settlement_battery.py` |
| signing | `signing/entrypoint.sh` → `signing/skap_signing.py` | the settlement battery's custody-signature leg; the transfer instance proof |
| exposure | `exposure/entrypoint.sh` → `operation/public_proxy.py` + tunnel supervisors | the batteries run through the public path (instance proof); the proxy path-filter checks in continuity-watch |
| continuity-watch | `continuity-watch/continuity_watch.sh` | its own `--dry-run` self-check (reports the verified end state it would restore) |

## Ecosystem support wired in (support, not ownership)

8374 is a function of the Build Lanes. The StegVerse Ecosystem support
wired into this build: the Ecosystem KV carries the evidence
(handover inventory, build records, suite zips); SVAI's standing
monitoring function covers the operation; EOS answers ecosystem
questions through manifested queries over the filed record; the
coordinator node runs the production instance as interim backbone
until a lane environment holds it. None of that support owns the
build; the build lives here.
