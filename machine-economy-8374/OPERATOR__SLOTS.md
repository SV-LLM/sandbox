# OPERATOR SLOTS — what a receiving site must supply

This package carries the machine-economy operation's code, grammar, and
batteries. It carries **no keys, no tokens, no receipts, and no state**.
Everything site-specific is a named slot below. A slot left unfilled
fails closed; nothing in the package reaches back to the coordinator
node.

## Custody rule (load-bearing)

Key material is **born and held at the receiving site** under SKAP
discipline. It is never copied from the coordinator node, never carried
through the queue, and never travels inside this package:

- the settlement relayer key is generated in the instance tree by
  `operation/relayer_setup.py` at bootstrap (mode 0600; the script
  prints only the public address);
- the signing specimen is born at the site by the host bootstrap
  into the site SKAP tree (`signing/custody/specimen_key.json`, mode
  0600) and released per call only under a live Authority grant
  (BUILD-Q-33 lane form) — for the 8374 operation, continuity with
  the published identity is *proven* when an instance's specimen
  resolves to the operation's published address
  (`0x7721aB66161e60fCcA59CCe2A86817cbdd9b16Be`) through the
  ecosystem SKAP retrieval path (BUILD-Q-25), never by transferring
  the coordinator's specimen (SKI-SIGNING_KEY-31c77c60 stays where
  it is sealed); a lane site's own specimen keys its own signing
  plane and is receipted as its own specimen;
- the Cloudflare tunnel token, if the CF exposure form is used, is
  created by the operator in their own Cloudflare account and written
  to `operation/cf-tunnel-token.txt` (mode 0600) at the site.

## Slot list

| Slot | Where it lands | Filled by |
|---|---|---|
| `ENDPOINT_PORT` (default 8794) | endpoint config + unit env | install-all flag |
| `SIGNING_PORT` (default 8795) | signing config + unit env + endpoint's `signing_operation_url` | install-all flag |
| `PROXY_PORT` (default 8796) | proxy unit env | install-all flag |
| `PREFIX` (default `machine-economy`) | systemd unit names | install-all flag |
| `PUBLIC_URL` | `operation/public-url.txt` | install-all flag — the site's own stable public address for the proxy (BUILD-Q-26) |
| Relayer key | `operation/settlement_relayer.json` | generated at bootstrap; **operator funds the printed address with dust ETH on Base** (~$2 covers thousands of settlements) |
| Relayer RPC routes | endpoint `config.json` → `settlement.submission.rpc_primary` / `rpc_fallback` | defaults are the public Base RPCs; the site may substitute its own |
| Site SKAP tree + Authority store | `<instance>/signing/custody/` (`specimen_key.json` 0600 + `authority_store.json` + hash-chained log) | **filled by the host bootstrap** (BUILD-Q-33 lane form): the specimen is born at the site and the Authority store created empty; grants are issued by the site operator via `components/authority/entrypoint.sh` |
| `SIGNING_SPECIMEN_ID`, `SIGNING_KEY_FINGERPRINT`, `SIGNING_PUBLIC_ADDRESS` | `signing/config.json` → `identity` | rendered by the host bootstrap from the site-born specimen's public facts |
| Instance target + prefix | (host bootstrap flags) | the lane fills `--target` (its own host path) and `--prefix` at bootstrap; no path from any other site appears anywhere in the instance |
| Funds accounting | `<instance>/continuity/funds_accounting.json` (`usdc_supplied_micro`, `eth_provided_wei`) | the operator act that funds the instance records the exact amounts it sent; the continuity funds projection reconciles against them |
| Relayer runway threshold | `funds_projection.py --runway-threshold` (default 500 settlements) | site policy slot; below it the projection flags LOW_RUNWAY |
| Bore pinned port | `operation/public-port.pin` (one line, the port number) | operator, only for the bore exposure form |
| CF tunnel token | `operation/cf-tunnel-token.txt` (0600) | operator's own Cloudflare named tunnel (BUILD-Q-34 form) |
| CF origin | `operation/cf-origin.txt` | operator, only for the CF exposure form |

## What is NOT a slot

The offer (tiers, payTo, asset, network), the scope registry
(ME-EVAL-01, ME-AGREE-01), the receipt-pair grammar, and the battery
expectations are the operation's published form — identical at every
site. Changing them is a new offer/scope determination by the
principal, not a site configuration.
