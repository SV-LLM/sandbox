# Component: exposure

Public exposure: the path-filtered public proxy (only the published
routes are public; /replay is never public) and the two tunnel
supervisors (bore; Cloudflare named tunnel). The payee is a
server-side constant verified at the crossing — no client path can
redirect a payment.

- Entrypoint: `entrypoint.sh` (starts the public proxy; the tunnel
  supervisors run under their systemd units, see `../../systemd/`)
- Code: `../../operation/public_proxy.py`,
  `../../operation/cf_tunnel_supervisor.py`,
  `../../operation/tunnel_supervisor.py`
- Proved by: the batteries run through the public path in the
  transfer instance proof, and the continuity-watch component's
  path-filter checks (public /replay must answer 404).
