# Component: endpoint

The governed crossing endpoint: x402 dual-stack (v1 + v2) challenges,
ME-EVAL-01 / ME-AGREE-01 scope evaluation, matched receipt pairs,
offer v07 (governance fee + separately quoted settlement charge).

- Entrypoint: `entrypoint.sh` (renders config from
  `../../operation/config.template.json` slots, starts the service)
- Code: `../../operation/endpoint.py`
- Proved by: `../../batteries/x402_battery.py` (10/10),
  `../../batteries/x402_v2_battery.py` (8/8),
  `../../batteries/agreement_battery.py` (5/5) — against an instance
  of this tree, on its own genesis chain.
