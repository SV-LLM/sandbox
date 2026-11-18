#!/usr/bin/env bash
# continuity-watch component — lane form.
#
# Parameterized watchdog for a machine-economy-8374 instance: verifies
# the verified end state (endpoint healthy, chain replay MATCH, public
# proxy healthy with its path filter intact, public origin answering)
# and restores missing systemd units from the instance tree when the
# host loses them. Adapted from the coordinator node's watchdog
# (2026-11-18) into a standalone, environment-driven component: NO
# node-specific paths are hardcoded — every site value is an env var.
#
# Required env (site slots, see ../../OPERATOR__SLOTS.md):
#   ME_TREE           instance tree (holds operation/, systemd units)
#   ME_PREFIX         unit prefix (e.g. machine-economy)
# Optional env:
#   ME_ENDPOINT_PORT  (default 8794)   ME_PROXY_PORT (default 8796)
#   ME_ORIGIN         permanent public origin (e.g. https://8374.example)
#   ME_URL_FILE       public-url pointer file (default $ME_TREE/operation/public-url.txt)
#   ME_SYSTEMD_DIR    (default /etc/systemd/system)
#   ME_UA             user agent for origin fetches (default curl/8.5.0)
#
# Modes:
#   continuity_watch.sh            verify; restore what is missing; exit 0 iff verified end state holds
#   continuity_watch.sh --dry-run  self-check: print the state found and what a restore would do; change nothing
set -uo pipefail

: "${ME_TREE:?ME_TREE is required (instance tree path)}"
ME_PREFIX="${ME_PREFIX:-machine-economy}"
ME_ENDPOINT_PORT="${ME_ENDPOINT_PORT:-8794}"
ME_PROXY_PORT="${ME_PROXY_PORT:-8796}"
ME_ORIGIN="${ME_ORIGIN:-}"
ME_URL_FILE="${ME_URL_FILE:-$ME_TREE/operation/public-url.txt}"
ME_SYSTEMD_DIR="${ME_SYSTEMD_DIR:-/etc/systemd/system}"
ME_UA="${ME_UA:-curl/8.5.0}"
DRY=0; [ "${1:-}" = "--dry-run" ] && DRY=1

endpoint_health="http://127.0.0.1:${ME_ENDPOINT_PORT}/health"
endpoint_replay="http://127.0.0.1:${ME_ENDPOINT_PORT}/replay"
proxy_health="http://127.0.0.1:${ME_PROXY_PORT}/health"
proxy_replay="http://127.0.0.1:${ME_PROXY_PORT}/replay"

ok()  { printf 'OK   %s\n' "$1"; }
bad() { printf 'FAIL %s\n' "$1"; failures=$((failures+1)); }
act() { printf 'ACT  %s\n' "$1"; }

failures=0
check() { # name, command...
  local name="$1"; shift
  if "$@" >/dev/null 2>&1; then ok "$name"; else bad "$name"; fi
}

unit_missing() { [ ! -f "$ME_SYSTEMD_DIR/$1.service" ]; }
unit_active()  { systemctl is-active --quiet "$1.service"; }

restore_unit() { # unit-name, source-file
  local unit="$1" src="$2"
  if [ "$DRY" = "1" ]; then act "would restore $unit from $src"; return 0; fi
  cp "$src" "$ME_SYSTEMD_DIR/$unit.service" || return 1
  systemctl daemon-reload || return 1
  systemctl enable --now "$unit.service" >/dev/null 2>&1 || return 1
  act "restored $unit"
}

# 1. Units present + active; restore the ones the host lost.
for pair in "endpoint:$ME_PREFIX-endpoint" "signing:$ME_PREFIX-signing" \
            "public-proxy:$ME_PREFIX-public-proxy" "tunnel:$ME_PREFIX-tunnel" \
            "cf-tunnel:$ME_PREFIX-cf-tunnel"; do
  src_name="${pair%%:*}"; unit="${pair##*:}"
  src="$ME_TREE/systemd/$unit.service"
  if unit_missing "$unit"; then
    [ -f "$src" ] && restore_unit "$unit" "$src" || bad "unit $unit missing and no source at $src"
  fi
  [ "$DRY" = "0" ] && { unit_active "$unit" || bad "unit $unit not active"; }
done

# 2. Endpoint health + chain replay MATCH.
check "endpoint /health" curl --fail --silent --max-time 10 "$endpoint_health"
if curl --fail --silent --max-time 15 "$endpoint_replay" 2>/dev/null | grep -q '"MATCH"'; then
  ok "endpoint /replay verdict MATCH"
else
  bad "endpoint /replay verdict MATCH"
fi

# 3. Proxy health + path filter (/replay must NOT be public).
check "proxy /health" curl --fail --silent --max-time 10 "$proxy_health"
code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 "$proxy_replay" 2>/dev/null || echo 000)"
if [ "$code" = "404" ]; then ok "proxy path filter (/replay = 404)"; else
  bad "proxy path filter (/replay = $code, want 404)"; fi

# 4. Public origin, when the site declares one.
if [ -n "$ME_ORIGIN" ]; then
  check "origin /health ($ME_ORIGIN)" curl --fail --silent --max-time 12 -A "$ME_UA" "$ME_ORIGIN/health"
  if [ -f "$ME_URL_FILE" ]; then
    ptr="$(tr -d '[:space:]' < "$ME_URL_FILE")"
    if [ "$ptr" = "$ME_ORIGIN" ]; then ok "public-url pointer = origin"; else
      bad "public-url pointer = $ptr (want $ME_ORIGIN)"; fi
  fi
fi

if [ "$failures" = "0" ]; then
  printf 'continuity-watch: verified end state holds (%s)\n' "$ME_PREFIX"
  exit 0
fi
printf 'continuity-watch: %s check(s) failing (%s)\n' "$failures" "$ME_PREFIX"
exit 1
