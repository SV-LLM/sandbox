#!/usr/bin/env python3
"""Dev-instance setup for the 8374 router (ROUTER-V1).

Generates the dev instance's THROWAWAY material in the router
dir: a gas-only relayer key (router_relayer.json, mode 0600 —
the production Gate 2 pattern: dust ETH, no USDC) and a
throwaway fee-receptor payTo, and writes router_config.json.
Nothing here is production material: the production carry step
replaces payTo with production's declared receptor and the
relayer with the production settlement configuration (see
README.md, production-carry checklist). Idempotent: existing
key/config are kept unless --force is given.
"""
import json, os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import x402kit

BASE = os.path.dirname(os.path.abspath(__file__))
ENDPOINT = os.path.join(BASE, "..", "machine-economy-endpoint")

def main():
    force = "--force" in sys.argv
    key_path = os.path.join(BASE, "router_relayer.json")
    cfg_path = os.path.join(BASE, "router_config.json")
    if os.path.exists(key_path) and not force:
        relayer = json.load(open(key_path))["address"]
        print(f"relayer key exists: {relayer}")
    else:
        priv, addr = x402kit.new_keypair()
        doc = {"private_key": hex(priv), "address": addr,
               "purpose": "8374 router DEV gas-only settlement "
                          "relayer (ROUTER-V1): pays Base gas to "
                          "submit verified EIP-3009 authorizations; "
                          "holds no USDC; throwaway dev material",
               "network": "eip155:8453"}
        with open(key_path, "w") as f:
            json.dump(doc, f, indent=1)
        os.chmod(key_path, 0o600)
        relayer = addr
        print(f"relayer key generated: {addr}")
    if os.path.exists(cfg_path) and not force:
        cfg = json.load(open(cfg_path))
        print(f"config exists: payTo={cfg['payTo']} "
              f"relayer={cfg['settlement']['relayer_key_file']}")
        return 0
    _p, payto = x402kit.new_keypair()
    cfg = {
        "service": "8374-router",
        "routing_name": "8374.@router",
        "identity": "8374@StegVerse.ai",
        "port": 8797,
        "payTo": payto,
        "payTo_note": "DEV throwaway fee receptor. Production "
                      "carry replaces this with 8374's declared "
                      "receptor 0x7721aB66161e60fCcA59CCe2A86817cbdd9b16Be.",
        "network": "eip155:8453",
        "asset": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
        "scheme": "exact",
        "tiers_micro_usdc": {"receipt-only": 500,
                             "full-evaluation": 15000},
        "current_policy": "ME-POLICY-01",
        "settlement": {
            "enabled": True, "mode": "self-relayer",
            "build": "ROUTER-V1",
            "relayer_key_file": "router_relayer.json",
            "rpc_primary": "https://mainnet.base.org",
            "rpc_fallback": "https://base-rpc.publicnode.com",
            "sweep_interval_seconds": 60},
        "self_origin": "https://8374.stegverse.org",
        "production_receipts_dir": os.path.join(ENDPOINT, "receipts"),
        "production_config_path": os.path.join(ENDPOINT, "config.json"),
        "production_offer_path": os.path.join(ENDPOINT,
                                              "offer.base.json"),
    }
    with open(cfg_path, "w") as f:
        json.dump(cfg, f, indent=1)
    print(f"config written: payTo={payto} (dev throwaway), "
          f"relayer={relayer}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
