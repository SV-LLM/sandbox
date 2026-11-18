# Component: host (BUILD-Q-32)

The lane host: takes a bare checkout of this repository to a running
instance, using only the checkout's own code.

- Entrypoint: `entrypoint.sh` → `bootstrap.py`
  `bootstrap.py --source <checkout> --target <tree> --prefix <name>
  --endpoint-port N --signing-port N --proxy-port N [--systemd]
  [--with-tunnels] [--public-url URL]`
- What it does: renders the instance tree (fresh GENESIS chains; no
  receipts, keys, or state copied in); births the instance's own
  relayer, specimen payer, and signing specimen in-tree; creates the
  site Authority store; renders configs and systemd units from the
  repository templates; installs and starts the units under
  `--systemd`; writes `HOST__RECORD__01.json` into the instance tree.
- Custody rule (load-bearing): every key is custody-verified —
  file present at mode 0600, address re-derives from the key, and a
  test signature verifies — BEFORE its address is emitted as a
  funding instruction. This is the $2 stranded lesson (2026-11-17)
  as a bootstrap rule.
- Proved by: the lane-instance proof recorded in
  `LANE__OPERATION__BUILD__RECORD__01.md` (GEN 08 suite): bootstrap
  from a fresh clone, all batteries green, one settled crossing.
- Remainder, stated exactly: BUILD-Q-32 acceptance is a 7-day
  zero-coordinator-intervention observation at a lane site. The
  mechanism (this bootstrap + the continuity component's
  receipted auto-restore) is built; the 7-day observation is NOT
  claimed by any build record.
