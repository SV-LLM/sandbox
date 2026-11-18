#!/bin/bash
# install-all.sh — bootstrap ONE lane instance of the machine-economy
# operation from this transfer package.
#
#   ./install-all.sh --target DIR [options]
#
# Options (each is an OPERATOR SLOT — see OPERATOR__SLOTS.md):
#   --prefix NAME          systemd unit prefix        (default: machine-economy)
#   --endpoint-port N                                 (default: 8794)
#   --signing-port N                                  (default: 8795)
#   --proxy-port N                                    (default: 8796)
#   --public-url URL       written to operation/public-url.txt
#                          (default: http://127.0.0.1:<proxy-port> — local only)
#   --with-tunnels         also install the bore + Cloudflare tunnel units
#                          (requires the exposure slots: public-port.pin,
#                          and for Cloudflare a cf-tunnel-token.txt YOU
#                          create at your site, mode 0600 — never copied
#                          from another site)
#   --no-systemd           render the tree and configs but do not install
#                          or start units (the operator starts the three
#                          services by hand; env vars are printed)
#
# What it does, in order:
#   1. copies operation/ signing/ batteries/ into --target (fresh
#      receipts dirs — the instance starts from a GENESIS chain; no
#      receipts, keys, or state are ever copied in)
#   2. renders config.json for the endpoint and the signing service
#      from their templates with the slot values given here
#   3. generates the instance's OWN gas-only settlement relayer key in
#      the target tree (relayer_setup.py; prints only the address —
#      fund that address with dust ETH on Base before settlements can
#      land; the key is born at your site and never leaves it)
#   4. renders and installs the systemd units, daemon-reload,
#      enable --now (endpoint, signing, public proxy)
#
# The signing service starts fail-closed: until the operator wires the
# SKAP custody slots (OPERATOR__SLOTS.md) to the site's own sealed
# specimen, /sign refuses — by design. The crossing plane (evaluation,
# receipt pairs, x402 payment verification, settlement) does not depend
# on the signing slot.
set -e
PKG="$(cd "$(dirname "$0")" && pwd)"
TARGET="" PREFIX="machine-economy" EPORT=8794 SPORT=8795 PPORT=8796
PUBLIC_URL="" TUNNELS=0 SYSTEMD=1
while [ $# -gt 0 ]; do
  case "$1" in
    --target) TARGET="$2"; shift 2;;
    --prefix) PREFIX="$2"; shift 2;;
    --endpoint-port) EPORT="$2"; shift 2;;
    --signing-port) SPORT="$2"; shift 2;;
    --proxy-port) PPORT="$2"; shift 2;;
    --public-url) PUBLIC_URL="$2"; shift 2;;
    --with-tunnels) TUNNELS=1; shift;;
    --no-systemd) SYSTEMD=0; shift;;
    *) echo "unknown option: $1" >&2; exit 2;;
  esac
done
[ -n "$TARGET" ] || { echo "--target DIR is required" >&2; exit 2; }
[ -n "$PUBLIC_URL" ] || PUBLIC_URL="http://127.0.0.1:$PPORT"

mkdir -p "$TARGET"
cp -r "$PKG/operation" "$PKG/signing" "$PKG/batteries" "$TARGET/"
find "$TARGET" -name __pycache__ -type d -exec rm -rf {} + 2>/dev/null || true

render() {  # render TEMPLATE OUTFILE with the standard slot set
  sed -e "s|{{ENDPOINT_PORT}}|$EPORT|g" \
      -e "s|{{SIGNING_PORT}}|$SPORT|g" \
      -e "s|{{PROXY_PORT}}|$PPORT|g" \
      -e "s|{{TREE}}|$TARGET|g" \
      -e "s|{{PREFIX}}|$PREFIX|g" \
      -e "s|{{HOME_DIR}}|$HOME|g" \
      -e "s|{{PYTHONPATH_LOCAL}}|$HOME/.local/lib/python3.12/site-packages|g" \
      "$1" > "$2"
}
render "$TARGET/operation/config.template.json" "$TARGET/operation/config.json"
render "$TARGET/signing/config.template.json"  "$TARGET/signing/config.json"
echo "$PUBLIC_URL" > "$TARGET/operation/public-url.txt"

echo "== instance relayer (born at this site; fund the address with dust ETH on Base) =="
(cd "$TARGET/operation" && python3 relayer_setup.py)

if [ "$SYSTEMD" = "1" ]; then
  for u in endpoint signing public-proxy; do
    render "$PKG/systemd/{{PREFIX}}-$u.service.tmpl" "/etc/systemd/system/$PREFIX-$u.service"
  done
  if [ "$TUNNELS" = "1" ]; then
    for u in tunnel cf-tunnel; do
      render "$PKG/systemd/{{PREFIX}}-$u.service.tmpl" "/etc/systemd/system/$PREFIX-$u.service"
    done
  fi
  systemctl daemon-reload
  systemctl enable --now "$PREFIX-endpoint.service" "$PREFIX-signing.service" "$PREFIX-public-proxy.service"
  [ "$TUNNELS" = "1" ] && systemctl enable --now "$PREFIX-tunnel.service" "$PREFIX-cf-tunnel.service" || true
  systemctl is-active "$PREFIX-endpoint.service" "$PREFIX-signing.service" "$PREFIX-public-proxy.service"
else
  echo "no-systemd: start by hand with:"
  echo "  ME_ENDPOINT_PORT=$EPORT python3 $TARGET/operation/endpoint.py"
  echo "  SKAP_SIGNING_PORT=$SPORT HOME=$HOME python3 $TARGET/signing/skap_signing.py"
  echo "  ME_PROXY_PORT=$PPORT ME_UPSTREAM_PORT=$EPORT python3 $TARGET/operation/public_proxy.py"
fi
echo "instance rendered at $TARGET (endpoint :$EPORT, signing :$SPORT, proxy :$PPORT, public-url: $PUBLIC_URL)"
