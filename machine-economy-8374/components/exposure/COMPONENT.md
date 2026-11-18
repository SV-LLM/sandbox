# Component: exposure (BUILD-Q-26 / Q-34)

The public door of a lane instance: the path-filtered public proxy
plus the tunnel supervisors, parameterized by the site's own slots.

- Code: `../../operation/public_proxy.py` (allowlist: GET /health,
  GET /offer, POST /crossing, GET/HEAD /crossing, GET /openapi.json,
  GET /.well-known/x402 — everything else 404), `tunnel_supervisor.py`
  (bore), `cf_tunnel_supervisor.py` + `connect_shim.py` (Cloudflare
  named tunnel), unit templates in `../../systemd/`.
- Entrypoint: `entrypoint.sh` (the proxy).
- Site slots (never in this repository): the site's public URL
  (written to `operation/public-url.txt` by the host bootstrap),
  the bore pinned port (`operation/public-port.pin`), and the
  Cloudflare tunnel token — created by the operator in their own
  Cloudflare account, held at the site at mode 0600 OUTSIDE the
  repository tree; the slot names where the site supplies it.
- Provable locally (and proved by `exposure_battery.py` against a
  running instance): the proxy allowlist behavior — public surface
  served, operator surface (/replay, /funds, /sign, /seal,
  /settle-pair) refused 404.
- NOT provable locally, stated as slots rather than claims: the
  tunnel legs themselves, which need the site's own tunnel
  credentials and its own DNS/Cloudflare (or bore) arrangements.
