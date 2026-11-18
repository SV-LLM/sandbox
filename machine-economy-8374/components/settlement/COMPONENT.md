# Component: settlement

Settlement of verified EIP-3009 authorizations on Base via the
site's gas-only relayer. Carries the 2026-11-18 broadcast-failover
cure: the send fails over across the same candidate routes as the
reads (the failure it cured was a send pinned to a single refusing
route while reads failed over).

- Entrypoint: `entrypoint.sh` (module handle — settlement is invoked
  by the endpoint in-process; the entrypoint runs the module's own
  route/self check)
- Code: `../../operation/settlement.py`
- Proved by: `../../batteries/settlement_battery.py` (5/5), and two
  on-chain settlements of record (PAIR-000039 on the production
  instance; the transfer instance's settled crossing, block 59240288).
