# Verify-any-row page — 8374 (VERIFY-PAGE-01)

The public check surface for the 8374 machine economy: paste any
x402 resource URL and see what **proof** that resource publishes.
Every row in the aggregator feeds is a claim; this page turns a row
into a check.

- Public: `https://8374.stegverse.org/verify`
- Check API: `GET /verify/check?url=<resource URL>` (JSON)
- Local: `http://127.0.0.1:8798` (`verify-page.service`)

## What a check does

For the given resource URL, the service probes, live at request
time:

1. the resource itself, unpaid (GET, then POST `{}` if GET does not
   answer 402) — terms from the 402 challenge body or the v2
   `PAYMENT-REQUIRED` header;
2. `<origin>/.well-known/x402`;
3. `<origin>/openapi.json`;
4. any provenance / replay / receipt / inspect / proof locations
   those documents **name** — followed one level, at most 3.

The result names every location checked, with its outcome. Genuine
proof material published by any service is shown as found;
discovery metadata (`extensions.bazaar`) is reported as discovery
metadata, not as a transaction record. Absence is reported as
"publishes no replayable transaction record" **with** the checked
list — the absence is evidenced, not asserted.

8374's own origin is the one loopback exception: it is served from
the origin's local surfaces (endpoint `/inspect` + `/replay`,
router `/provenance`), and its verdict is the real chain replay —
pairs, terminal anchor, settled pairs with tx hashes — recomputed
at request time, never hardcoded.

The page renders 8374's own verification live, plus a side-by-side
of sample rows drawn live from the ScriptMasterLabs machine feed
(`scriptmasterlabs.com/x402-directory.json`, the aggregator whose
rows this page checks); if that feed is unreachable at render time,
the samples come from the 8374 router's own discovery feed, and the
page says which source it used.

## SSRF discipline

This is a public fetcher, so: http/https only; no URL credentials;
metadata hostnames refused; every target hostname is resolved and
**every** resolved address checked against refused ranges
(loopback, private, link-local, CGNAT, documentation, multicast,
reserved, IPv6 equivalents) before fetching — any refused address
refuses the fetch; redirects followed manually (max 3), each hop
re-validated; POST probes never redirected; 10 s timeout per
attempt; 512 KB cap per probe; `/verify/check` rate-limited per
source IP (30/min sustained, burst 30, plain 429). On this node,
public names resolve locally to 198.18.0.0/15 shadow addresses
assigned by the egress layer and the connection transits the
CONNECT egress proxy, which resolves independently; literal-IP
targets and locally-resolvable names are checked against their real
addresses, which is where the refusal bites.

`VERIFY_FIXTURE_ORIGINS` (battery-only) names exact origins exempt
from the address refusal so local specimen sellers can be checked.
It is **empty** in the production unit.

## Files

- `verify.py` — the service (stdlib only). Egress proxy candidates
  are discovered at call time (env, `/proc` scan, bare proxy
  address) and never stored — the house pattern.
- `battery_verify.py` — the battery: own-origin replay equality,
  specimen-seller absence with a complete checked list, non-x402
  grace, SSRF refusals, page rows all checking, health.
- `systemd/verify-page.service` + `install.sh` — the unit and its
  restore path (VM replacements delete unit files).
- Watchdog: `~/hooks/scripts/verify-page-watchdog.sh` +
  `~/hooks/definitions/verify-page-watchdog.json`.

## Public mount

The public proxy (`machine-economy-endpoint/public_proxy.py`)
allowlist carries `GET /verify` and `GET /verify/check`, routed to
this service on 127.0.0.1:8798 — additive only; the endpoint and
router services are untouched by this build. Through the public
tunnel, source IPs collapse to the tunnel loopback, so the check
rate limit also acts as a global cap on the public surface (the
same posture as the proxy's own crossing limit).
