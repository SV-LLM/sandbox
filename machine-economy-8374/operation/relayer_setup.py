#!/usr/bin/env python3
"""Generate the endpoint's gas-only settlement relayer key (Gate 2).

One-shot, idempotent: if settlement_relayer.json already exists in
this directory its address is printed and nothing is overwritten.
The key file is created mode 0600. This script prints ONLY the
public address -- key material never leaves the file.
"""
import json, os, secrets, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from settlement import address_from_private, N

BASE = os.path.dirname(os.path.abspath(__file__))
KEY_FILE = os.path.join(BASE, "settlement_relayer.json")

if os.path.exists(KEY_FILE):
    doc = json.load(open(KEY_FILE))
    print(address_from_private(int(doc["private_key"], 16)))
    sys.exit(0)

priv = secrets.randbelow(N - 1) + 1
addr = address_from_private(priv)
doc = {"private_key": "0x" + priv.to_bytes(32, "big").hex(),
       "address": addr,
       "purpose": "machine-economy-endpoint gas-only settlement relayer "
                  "(Gate 2): pays Base gas to submit verified EIP-3009 "
                  "authorizations; holds no USDC and no ecosystem "
                  "material by design",
       "network": "eip155:8453",
       "created": "2026-11-17"}
fd = os.open(KEY_FILE, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(fd, "w") as f:
    json.dump(doc, f, indent=2)
    f.write("\n")
print(addr)
