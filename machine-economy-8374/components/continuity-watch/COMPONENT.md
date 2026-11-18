# Component: continuity-watch (NEW, lane form)

The continuity function as a lane component. On the coordinator node
this function exists only as hook-coupled watchdog scripts and the
service installers; this component is its lane form: a standalone,
parameterized watchdog with no node-specific paths hardcoded — every
site value arrives as an environment variable (ME_TREE, ME_PREFIX,
ME_ENDPOINT_PORT, ME_PROXY_PORT, ME_ORIGIN, ME_URL_FILE,
ME_SYSTEMD_DIR, ME_UA).

What it verifies (the verified end state): all five units present and
active; endpoint /health answering; the receipt chain's replay verdict
MATCH; the public proxy healthy with its path filter intact (public
/replay answers 404); and, when the site declares a permanent origin,
the origin answering /health and the public-url pointer equal to it.
What it restores: any unit the host lost, reinstalled from the
instance tree's rendered systemd units — the cure for the
VM-replacement unit-loss failure mode observed seven times on the
coordinator node on 2026-11-18.

- Entrypoint: `continuity_watch.sh` (restore mode);
  `continuity_watch.sh --dry-run` is its self-check — it prints the
  state found and what a restore would do, and changes nothing.
- Proved by: that dry-run self-check against a live instance, plus
  the coordinator-node record of the same cure applied and verified
  repeatedly on 2026-11-18 (watchdog restores + manual cures, each
  closing on the verified end state above).
- Lane slot: this component is the instrument for the continuity
  remainder (BUILD-Q-27) at a receiving site.

## Dry-run record (2026-11-18, tested before commit)

Against the production instance the dry-run reports exactly one FAIL
and exits 1: the signing unit is named `skap-signing.service` in
production, while the lane form names units `$PREFIX-signing` — a
naming map, not a health finding; every health check (endpoint
/health, replay MATCH, proxy /health, path filter, origin /health)
passes. Against a fully matching configuration (all five units present
under lane-form names, pointer = origin) it passes 6/6, exit 0.

## Relayer monitoring (added GEN 08, BUILD-Q-27/Q-35)

`funds_projection.py <instance-tree> [--runway-threshold N]` reads
the instance's own address set live (from HOST__RECORD__01.json),
reconciles the instance's supply accounting (USDC: supplied −
settled-out == payer on hand; ETH: provided − burned == relayer on
hand; remainders must be 0), and reports the relayer RUNWAY in
settlements remaining at the mean actual settlement cost, flagging
LOW_RUNWAY below the named threshold (default 500).

Restarts performed by the watchdog are receipted as append-only
records in `<instance>/continuity/records.jsonl` (UNIT_RESTORED
events) — the continuity history a 7-day zero-intervention
observation (BUILD-Q-32 acceptance) is measured from.
