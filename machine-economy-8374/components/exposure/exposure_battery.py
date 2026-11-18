#!/usr/bin/env python3
"""Exposure battery (BUILD-Q-26/Q-34, local legs).

    python3 exposure_battery.py <proxy-base-url>

Proves the doors a site can prove locally: the public proxy serves
the allowlisted public surface and refuses everything else. The
tunnel legs (bore / Cloudflare) ride on the site's own credentials
and are operator slots, not local claims — see COMPONENT.md.
"""
import json, sys, urllib.request, urllib.error

BASE = sys.argv[1].rstrip("/")
results = []
def leg(name, ok, detail=""):
    results.append(ok)
    print(f"{'PASS' if ok else 'FAIL'}  {name}  {detail}")

def req(method, path, data=None):
    r = urllib.request.Request(BASE + path, method=method,
                               data=data)
    try:
        with urllib.request.urlopen(r, timeout=15) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()
    except Exception as e:
        return 0, str(e).encode()

code, _ = req("GET", "/health")
leg("proxy serves /health", code == 200, f"http {code}")
code, body = req("GET", "/offer")
leg("proxy serves /offer", code == 200, f"http {code}")
code, _ = req("GET", "/.well-known/x402")
leg("proxy serves /.well-known/x402", code == 200, f"http {code}")
code, _ = req("POST", "/crossing", b"{}")
leg("unpaid /crossing answers 402 challenge", code == 402, f"http {code}")
for path in ("/replay", "/funds", "/sign", "/seal", "/settle-pair"):
    code, _ = req("GET", path)
    leg(f"proxy refuses {path}", code == 404, f"http {code}")
print(f"exposure battery: {sum(results)}/{len(results)}")
sys.exit(0 if all(results) else 1)
