# MACHINE-ECONOMY TRANSFER PACKAGE — the lane-receiving end

ProjectID: MACHINE-ECONOMY-ENTRY-01 · Identity: 8374 (BETA)
Built 2026-11-18 under BUILD-Q-24 / BUILD-Q-32 at the principal's
direction, from the filed handover inventory
(HANDOVER__INVENTORY__MACHINE__ECONOMY__OPERATION__01, Ecosystem KV
Drive `1yUWFmNMZLk1m8egQaqAJ-bzwqv7I7_Ht`) and the live operation code.

## What this is

A self-contained instantiation of the machine-economy operation —
governed endpoint (evaluation + receipt pairs at the signing boundary),
SKAP sign-under-seal service (reference wiring), path-filtered public
proxy, and both public-exposure supervisors (bore + Cloudflare named
tunnel) — parameterized so a Build Lane can stand it up on its own
host, under its own keys, and prove it with the operation's own
batteries. Until this package existed, the transfer items
(BUILD-Q-24…Q-27, Q-32/Q-35) named work no lane could pick up as a
single claimable whole; this is the receiving end they pointed at.

## Layout

- `operation/` — endpoint, settlement, x402 specimen library, replay,
  relayer setup, public proxy, both tunnel supervisors, scope registry,
  offer base, bot agent-kit, `config.template.json`
- `signing/` — sign-under-seal service + `config.template.json`
  (custody is an operator slot; see OPERATOR__SLOTS.md)
- `batteries/` — x402_battery.py, x402_v2_battery.py,
  settlement_battery.py, agreement_battery.py, rewired to import from
  this package's own `operation/` tree
- `systemd/` — unit templates for all five services
- `install-all.sh` — the single bootstrap entrypoint
- `OPERATOR__SLOTS.md` — every value the receiving site must supply,
  and the custody rule: keys are born and held at the receiving site

## Bootstrap (summary)

```
./install-all.sh --target /path/to/instance \
    --prefix machine-economy \
    --endpoint-port 8794 --signing-port 8795 --proxy-port 8796 \
    --public-url https://<the site's stable address>
# fund the printed relayer address with dust ETH on Base
# run the batteries against the instance:
python3 batteries/x402_battery.py       http://127.0.0.1:8794
python3 batteries/x402_v2_battery.py    http://127.0.0.1:8794
python3 batteries/settlement_battery.py http://127.0.0.1:8794 <instance>/operation <relayer-address>
python3 batteries/agreement_battery.py  http://127.0.0.1:8794
```

Acceptance is the four batteries at full marks against the instance's
own genesis chain, its own replay MATCH, and — once the site's relayer
is funded and a payer presents a valid authorization — a settlement
recorded SETTLED on-chain under the instance's own submission.

## Coordination class

This package is a coordination/build artifact. It is not an admission,
a runtime execution on any lane, or a sovereign KV write; the transfer
discharges when a lane instance passes the acceptance above on the
lane's own host (BUILD-Q-24…Q-27 / Q-32 / Q-35 remainders).
