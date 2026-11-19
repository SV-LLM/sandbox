#!/usr/bin/env python3
"""Shared support for the ROUTER-V1 batteries (endpoint battery
idiom): throwaway instances only — own temp dir, own receipts /
registry, own throwaway keys, own ports. Nothing here touches
the production endpoint's state; production files are read only
(specimen payer key + production chain provenance checks).
"""
import json, os, subprocess, sys, time
import urllib.error, urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
ENDPOINT_DIR = os.path.join(HERE, "..", "machine-economy-endpoint")

import settlement as settle_mod
import x402kit

RPC_URLS = ["https://mainnet.base.org", "https://base-rpc.publicnode.com"]
USDC = x402kit.USDC_BASE

_opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def call(base, method, path, body=None, headers=None, timeout=90):
    data = json.dumps(body).encode() if body is not None else None
    r = urllib.request.Request(base + path, data=data, method=method,
                               headers={"Content-Type":
                                        "application/json",
                                        **(headers or {})})
    try:
        with _opener.open(r, timeout=timeout) as resp:
            return resp.status, json.load(resp)
    except urllib.error.HTTPError as e:
        return e.code, json.load(e)


def wait_health(base, timeout=40):
    t0 = time.time()
    while time.time() - t0 < timeout:
        try:
            code, _b = call(base, "GET", "/health", timeout=5)
            if code == 200:
                return True
        except Exception:
            pass
        time.sleep(0.5)
    return False


def assert_port_free(port):
    """A stale instance answering on the port would silently
    absorb the battery's calls (observed: a crashed run's router
    survived and a later run tested the ghost). Fail loudly."""
    try:
        code, _b = call(f"http://127.0.0.1:{port}", "GET", "/health",
                        timeout=3)
        raise RuntimeError(f"port {port} already answers /health "
                           f"(http {code}) — stale instance; kill it "
                           "before running this battery")
    except RuntimeError:
        raise
    except Exception:
        pass


def start_proc(args, env, cwd=HERE):
    e = dict(os.environ)
    e.update(env)
    return subprocess.Popen([sys.executable] + args, cwd=cwd, env=e,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, text=True)


def write_key_file(path, priv, purpose):
    doc = {"private_key": hex(priv),
           "address": x402kit.address_from_private(priv),
           "purpose": purpose, "network": "eip155:8453"}
    with open(path, "w") as f:
        json.dump(doc, f, indent=1)
    os.chmod(path, 0o600)
    return doc["address"]


def make_router_instance(tmp, port, payto, relayer_priv):
    """Write a throwaway router config + relayer key into tmp and
    start the router against it. Returns (proc, base_url, env)."""
    key_path = os.path.join(tmp, "router_relayer.json")
    relayer = write_key_file(key_path, relayer_priv,
                             "battery throwaway gas-only relayer")
    cfg = {"service": "8374-router", "routing_name": "8374.@router",
           "identity": "8374@StegVerse.ai", "port": port,
           "payTo": payto, "network": "eip155:8453", "asset": USDC,
           "scheme": "exact",
           "tiers_micro_usdc": {"receipt-only": 500,
                                "full-evaluation": 15000},
           "current_policy": "ME-POLICY-01",
           "settlement": {"enabled": True, "mode": "self-relayer",
                          "build": "ROUTER-V1",
                          "relayer_key_file": key_path,
                          "rpc_primary": RPC_URLS[0],
                          "rpc_fallback": RPC_URLS[1],
                          "sweep_interval_seconds": 60},
           "self_origin": "https://8374.stegverse.org",
           "production_receipts_dir": os.path.join(ENDPOINT_DIR,
                                                   "receipts"),
           "production_config_path": os.path.join(ENDPOINT_DIR,
                                                  "config.json"),
           "production_offer_path": os.path.join(ENDPOINT_DIR,
                                                 "offer.base.json")}
    cfg_path = os.path.join(tmp, "router_config.json")
    with open(cfg_path, "w") as f:
        json.dump(cfg, f, indent=1)
    env = {"ROUTER_DIR": tmp, "ROUTER_CONFIG_PATH": cfg_path,
           "ROUTER_PORT": str(port),
           "ROUTER_RECEIPTS_DIR": os.path.join(tmp, "receipts"),
           "ROUTER_REGISTRY_PATH": os.path.join(tmp, "registry.json")}
    assert_port_free(port)
    proc = start_proc([os.path.join(HERE, "router.py")], env)
    base = f"http://127.0.0.1:{port}"
    if not wait_health(base) or proc.poll() is not None:
        out = proc.stdout.read() if proc.stdout else ""
        raise RuntimeError(f"router instance on {port} never became "
                           f"healthy: {out[:500]}")
    return proc, base, env, relayer


def start_seller(port, payto, price=3000, mode="normal"):
    env = {"SELLER_PORT": str(port), "SELLER_PAYTO": payto,
           "SELLER_PRICE": str(price), "SELLER_MODE": mode}
    assert_port_free(port)
    proc = start_proc([os.path.join(HERE, "seller.py")], env)
    base = f"http://127.0.0.1:{port}"
    if not wait_health(base) or proc.poll() is not None:
        out = proc.stdout.read() if proc.stdout else ""
        raise RuntimeError(f"seller on {port} never became healthy: "
                           f"{out[:500]}")
    return proc, base


def read_chain(receipts_dir):
    entries = []
    if not os.path.isdir(receipts_dir):
        return entries
    for n in sorted(os.listdir(receipts_dir)):
        if n.startswith("segment-") and n.endswith(".jsonl"):
            with open(os.path.join(receipts_dir, n), "rb") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        entries.append(json.loads(line))
    return entries


def replay_verdict(receipts_dir, env):
    e = dict(os.environ)
    e.update(env)
    p = subprocess.run([sys.executable,
                        os.path.join(HERE, "replay_router.py"),
                        "--segments", receipts_dir],
                       capture_output=True, text=True, env=e, cwd=HERE,
                       timeout=120)
    return p.returncode, json.loads(p.stdout)


def pair_contents(receipts_dir, pair_id):
    return [r["content"] for r in read_chain(receipts_dir)
            if r["content"].get("pair_id") == pair_id]


# ---------------- on-chain helpers (Base, live) ----------------
def rpc():
    return settle_mod.Rpc(RPC_URLS, timeout=30)


def usdc_balance(addr):
    data = "0x70a08231" + "0" * 24 + addr[2:].lower()
    return int(rpc().call("eth_call", [{"to": USDC, "data": data},
                                       "latest"]), 16)


def eth_balance(addr):
    return int(rpc().call("eth_getBalance", [addr, "latest"]), 16)


def send_eth(from_priv, to, amount_wei):
    """One EIP-1559 ETH transfer signed by from_priv (settlement.py
    constructions). Returns the tx hash; waits for the receipt."""
    r = rpc()
    frm = x402kit.address_from_private(from_priv)
    fee_hist = r.call("eth_feeHistory", ["0x1", "latest", []])
    base_fee = int(fee_hist["baseFeePerGas"][-1], 16)
    try:
        priority = int(r.call("eth_maxPriorityFeePerGas", []), 16)
    except settle_mod.RpcError:
        priority = 100000
    max_fee = 2 * base_fee + priority
    nonce = int(r.call("eth_getTransactionCount", [frm, "pending"]), 16)
    fields = [8453, nonce, priority, max_fee, 21000,
              bytes.fromhex(to[2:]), amount_wei, b"", []]
    sighash = settle_mod.keccak256(b"\x02" + settle_mod.rlp_encode(fields))
    rr, ss, recid = settle_mod.sign_digest(from_priv, sighash)
    raw = b"\x02" + settle_mod.rlp_encode(fields + [recid, rr, ss])
    tx_hash = r.call("eth_sendRawTransaction", ["0x" + raw.hex()])
    for _ in range(30):
        time.sleep(2)
        rec = r.call("eth_getTransactionReceipt", [tx_hash])
        if rec:
            if rec.get("status") != "0x1":
                raise RuntimeError(f"ETH transfer {tx_hash} reverted")
            return tx_hash
    raise RuntimeError(f"ETH transfer {tx_hash} unconfirmed")


def fund_usdc(from_priv, from_addr, to_addr, amount, relayer_key_path):
    """Fund to_addr with USDC from the specimen payer: the payer
    signs an EIP-3009 authorization and the given gas-only relayer
    submits it (the existing specimen funding pattern). Returns
    the settlement record."""
    now_ts = int(time.time())
    hdr, auth, _dg = x402kit.make_payment_header(
        from_priv, from_addr, to_addr, amount, now_ts - 10,
        now_ts + 3600)
    payload = x402kit.decode_payment_header(hdr)
    pl = payload["payload"]
    payment = {"signature": pl["signature"], "nonce": auth["nonce"],
               "from": auth["from"], "to": auth["to"],
               "value_micro_usdc": amount,
               "valid_after": int(auth["validAfter"]),
               "valid_before": int(auth["validBefore"]),
               "asset": USDC, "payTo": to_addr}
    cfg = {"enabled": True, "mode": "self-relayer",
           "build": "ROUTER-V1-TESTKIT",
           "relayer_key_file": relayer_key_path,
           "rpc_primary": RPC_URLS[0], "rpc_fallback": RPC_URLS[1]}
    return settle_mod.attempt_settlement(payment, cfg, HERE)


def tx_settled(tx_hash, timeout=90):
    """Independent on-chain confirmation: poll the tx receipt
    until it is mined with status 0x1 (or timeout). A settlement
    record's SUBMITTED status means 'broadcast accepted,
    confirmation pending when written' — this is the confirming
    read, not the record's word."""
    t0 = time.time()
    r = rpc()
    while time.time() - t0 < timeout:
        try:
            rec = r.call("eth_getTransactionReceipt", [tx_hash])
        except settle_mod.RpcError:
            rec = None  # transient egress failure: keep polling
        if rec:
            return rec.get("status") == "0x1"
        time.sleep(2)
    return False


def load_json_key(path, *fields):
    doc = json.load(open(path))
    for f in fields:
        if f in doc:
            return int(doc[f], 16), doc.get("address")
    raise KeyError(f"none of {fields} in {path}")


class Battery:
    def __init__(self, name):
        self.name = name
        self.results = []
        self.procs = []

    def check(self, name, ok, evidence):
        self.results.append((name, bool(ok), evidence))
        print(("PASS " if ok else "FAIL ") + name + " -- " + evidence)

    def track(self, proc):
        self.procs.append(proc)
        return proc

    def finish(self):
        for p in self.procs:
            try:
                p.terminate()
                p.wait(timeout=5)
            except Exception:
                try:
                    p.kill()
                except Exception:
                    pass
        failed = [r for r in self.results if not r[1]]
        print(f"\n{self.name}: {len(self.results) - len(failed)}/"
              f"{len(self.results)} checks passed")
        return 1 if failed else 0
