#!/usr/bin/env python3
"""Host bootstrap for a lane instance of the 8374 operation (BUILD-Q-32).

Takes a bare checkout of this repository (the lane home) to a RUNNING
instance, entirely from the checkout's own code:

  1. renders the instance tree at --target (operation/, signing/,
     batteries/, components/ copied from the checkout; fresh receipts
     dirs — the instance starts from a GENESIS chain; no receipts,
     keys, or state are ever copied in);
  2. births the instance's OWN keys in-tree: the gas-only settlement
     relayer (operation/relayer_setup.py), a specimen payer, and the
     signing specimen in the site SKAP tree (signing/custody/), plus
     the site Authority store (signing/authority.py);
  3. CUSTODY-VERIFIES every key before any address is reported as
     fundable: the key file exists with mode 0600, the recorded
     address re-derives from the key, and a test digest signed with
     the key verifies against its public point. An address is
     emitted as a funding instruction ONLY for a key that passes —
     the $2 stranded lesson (2026-11-17: funding directed to an
     address whose key had been discarded) is a bootstrap rule here,
     not a memory;
  4. renders the endpoint + signing configs and the systemd units
     from the checkout's templates with the instance's slot values;
  5. with --systemd, installs and starts the units and waits for
     health; either way it writes HOST__RECORD__01.json into the
     instance tree (addresses, ports, unit names, custody verdicts,
     chain genesis) and prints it.

Stdlib only. Nothing in this script names any other site: every
site value is a flag or derives from --target.
"""
import argparse, hashlib, json, os, secrets, shutil, stat, subprocess
import sys, time, urllib.request
from datetime import datetime, timezone

def now_iso():
    return datetime.now(timezone.utc).isoformat()

def render(text, slots):
    for k, v in slots.items():
        text = text.replace("{{" + k + "}}", str(v))
    return text

def write0600(path, obj):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(obj, f, indent=2); f.write("\n")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--source", required=True,
                    help="checkout root (the folder holding operation/)")
    ap.add_argument("--target", required=True)
    ap.add_argument("--prefix", default="machine-economy")
    ap.add_argument("--endpoint-port", type=int, default=8794)
    ap.add_argument("--signing-port", type=int, default=8795)
    ap.add_argument("--proxy-port", type=int, default=8796)
    ap.add_argument("--public-url", default="")
    ap.add_argument("--systemd", action="store_true")
    ap.add_argument("--with-tunnels", action="store_true")
    a = ap.parse_args()

    src = os.path.abspath(a.source)
    tgt = os.path.abspath(a.target)
    if os.path.exists(tgt) and os.listdir(tgt):
        print(f"target {tgt} is not empty; refusing to bootstrap over "
              "an existing instance", file=sys.stderr)
        return 2
    os.makedirs(tgt)

    # 1. instance tree from the checkout alone
    for part in ("operation", "signing", "batteries", "components"):
        shutil.copytree(os.path.join(src, part), os.path.join(tgt, part),
                        ignore=shutil.ignore_patterns("__pycache__",
                                                      "receipts",
                                                      "custody"))
    os.makedirs(os.path.join(tgt, "operation", "receipts"), exist_ok=True)
    os.makedirs(os.path.join(tgt, "signing", "receipts"), exist_ok=True)
    os.makedirs(os.path.join(tgt, "signing", "custody"), exist_ok=True)
    os.makedirs(os.path.join(tgt, "systemd"), exist_ok=True)
    os.makedirs(os.path.join(tgt, "continuity"), exist_ok=True)

    op_dir = os.path.join(tgt, "operation")
    sys.path.insert(0, op_dir)
    sys.path.insert(0, os.path.join(tgt, "signing"))
    import x402_specimen as xs
    from keccak_pure import keccak256
    from authority import AuthorityStore

    # 2. keys born in-tree
    relayer_addr = subprocess.run(
        [sys.executable, "relayer_setup.py"], cwd=op_dir,
        capture_output=True, text=True, check=True).stdout.strip()

    payer_priv, payer_addr = xs.new_keypair()
    payer_file = os.path.join(op_dir, "specimen_payer.json")
    write0600(payer_file, {
        "specimen": "lane instance specimen payer (born at this site by "
                    "the host bootstrap; throwaway demonstration payer)",
        "address": payer_addr,
        "priv_hex": payer_priv.to_bytes(32, "big").hex(),
        "created": now_iso()})

    spec_priv = secrets.randbelow(xs.N - 1) + 1
    q = xs._mul(spec_priv, xs.G)
    unc = b"\x04" + q[0].to_bytes(32, "big") + q[1].to_bytes(32, "big")
    fingerprint = hashlib.sha256(unc).hexdigest()
    from keccak_pure import eip55
    spec_addr = eip55(keccak256(unc[1:])[-20:].hex())
    specimen_id = "SKI-SIGNING_KEY-" + fingerprint[:8]
    spec_file = os.path.join(tgt, "signing", "custody", "specimen_key.json")
    write0600(spec_file, {
        "private_key": "0x" + spec_priv.to_bytes(32, "big").hex(),
        "address": spec_addr, "specimen_id": specimen_id,
        "key_fingerprint": fingerprint,
        "purpose": "lane site signing specimen (born at this site by the "
                   "host bootstrap; held only in this site SKAP tree)",
        "network": "eip155:8453", "created": now_iso()})

    store_path = os.path.join(tgt, "signing", "custody",
                              "authority_store.json")
    AuthorityStore(store_path)  # creates store + hash-chained log

    # 3. custody verification — sign-and-verify per key, BEFORE any
    #    address is reported fundable
    def custody_check(name, path, priv, recorded_addr):
        checks = {"key_file_exists": os.path.exists(path),
                  "mode_0600": False, "address_rederives": False,
                  "signs_and_verifies": False}
        if checks["key_file_exists"]:
            checks["mode_0600"] = \
                stat.S_IMODE(os.stat(path).st_mode) == 0o600
        qq = xs._mul(priv, xs.G)
        derived = eip55(keccak256(
            qq[0].to_bytes(32, "big") + qq[1].to_bytes(32, "big"))[-20:].hex())
        checks["address_rederives"] = (derived == recorded_addr)
        try:
            test_digest = keccak256(b"8374 host bootstrap custody check "
                                    + recorded_addr.encode())
            sig = xs.sign_digest(priv, test_digest)
            r = int.from_bytes(sig[0:32], "big")
            s = int.from_bytes(sig[32:64], "big")
            z = int.from_bytes(test_digest, "big")
            w = pow(s, -1, xs.N)
            pt = xs._add(xs._mul((z * w) % xs.N, xs.G),
                         xs._mul((r * w) % xs.N, qq))
            checks["signs_and_verifies"] = (pt is not None
                                            and pt[0] % xs.N == r)
        except Exception:
            checks["signs_and_verifies"] = False
        fundable = all(checks.values())
        return {"name": name, "address": recorded_addr,
                "key_file": os.path.relpath(path, tgt),
                "checks": checks, "fundable": fundable}

    relayer_doc = json.load(open(os.path.join(op_dir,
                                              "settlement_relayer.json")))
    custody = [
        custody_check("settlement relayer",
                      os.path.join(op_dir, "settlement_relayer.json"),
                      int(relayer_doc["private_key"], 16), relayer_addr),
        custody_check("specimen payer", payer_file, payer_priv, payer_addr),
        custody_check("signing specimen", spec_file, spec_priv, spec_addr),
    ]

    # 4. configs + units rendered from the checkout's templates
    slots = {"ENDPOINT_PORT": a.endpoint_port, "SIGNING_PORT": a.signing_port,
             "PROXY_PORT": a.proxy_port, "TREE": tgt, "PREFIX": a.prefix,
             "HOME_DIR": os.path.expanduser("~"),
             "PYTHONPATH_LOCAL":
                 os.path.join(os.path.expanduser("~"),
                              ".local/lib/python3.12/site-packages")}
    cfg = render(open(os.path.join(op_dir, "config.template.json")).read(),
                 slots)
    with open(os.path.join(op_dir, "config.json"), "w") as f:
        f.write(cfg)
    scfg = render(open(os.path.join(tgt, "signing",
                                    "config.template.json")).read(), slots)
    scfg = scfg.replace("{{SLOT:SIGNING_SPECIMEN_ID}}", specimen_id)
    scfg = scfg.replace("{{SLOT:SIGNING_KEY_FINGERPRINT}}", fingerprint)
    scfg = scfg.replace("{{SLOT:SIGNING_PUBLIC_ADDRESS}}", spec_addr)
    with open(os.path.join(tgt, "signing", "config.json"), "w") as f:
        f.write(scfg)
    public_url = a.public_url or f"http://127.0.0.1:{a.proxy_port}"
    with open(os.path.join(op_dir, "public-url.txt"), "w") as f:
        f.write(public_url + "\n")
    op_cfg = json.loads(cfg)
    units = {}
    unit_names = ["endpoint", "signing", "public-proxy"]
    if a.with_tunnels:
        unit_names += ["tunnel", "cf-tunnel"]
    for name in unit_names:
        tmpl = os.path.join(src, "systemd",
                            "{{PREFIX}}-" + name + ".service.tmpl")
        out = os.path.join(tgt, "systemd", f"{a.prefix}-{name}.service")
        with open(out, "w") as f:
            f.write(render(open(tmpl).read(), slots))
        units[name] = f"{a.prefix}-{name}.service"

    # 5. install + start
    started = []
    if a.systemd:
        for name in unit_names:
            shutil.copy2(os.path.join(tgt, "systemd", units[name]),
                         f"/etc/systemd/system/{units[name]}")
        subprocess.run(["systemctl", "daemon-reload"], check=True)
        subprocess.run(["systemctl", "enable", "--now"] +
                       [units[n] for n in ("endpoint", "signing",
                                           "public-proxy")] +
                       [units[n] for n in unit_names
                        if n in ("tunnel", "cf-tunnel")], check=True)
        started = [units[n] for n in unit_names]
        # wait for health
        deadline = time.time() + 60
        healthy = {}
        while time.time() < deadline and len(healthy) < 2:
            for label, port in (("endpoint", a.endpoint_port),
                                ("signing", a.signing_port)):
                if label in healthy:
                    continue
                try:
                    with urllib.request.urlopen(
                            f"http://127.0.0.1:{port}/health",
                            timeout=3) as r:
                        healthy[label] = json.load(r)
                except Exception:
                    pass
            if len(healthy) < 2:
                time.sleep(2)
        if len(healthy) < 2:
            print("units started but health not confirmed for: " +
                  ", ".join(set(("endpoint", "signing")) - set(healthy)),
                  file=sys.stderr)
            return 3

    chain_genesis = None
    if a.systemd:
        try:
            with urllib.request.urlopen(
                    f"http://127.0.0.1:{a.endpoint_port}/replay",
                    timeout=10) as r:
                chain_genesis = json.load(r)
        except Exception as e:
            chain_genesis = {"error": str(e)}

    record = {
        "record": "HOST__RECORD__01",
        "component": "host (BUILD-Q-32)",
        "created": now_iso(),
        "instance": {"target": tgt, "prefix": a.prefix,
                     "endpoint_port": a.endpoint_port,
                     "signing_port": a.signing_port,
                     "proxy_port": a.proxy_port,
                     "public_url": public_url,
                     "units": units, "units_started": started},
        "addresses": {
            "relayer": relayer_addr, "specimen_payer": payer_addr,
            "signing_specimen": {"address": spec_addr,
                                 "specimen_id": specimen_id,
                                 "key_fingerprint": fingerprint},
            "payTo": op_cfg["settlement"]["payTo"]},
        "custody_verification": custody,
        "funding_instructions": [
            {"address": c["address"], "asset": asset,
             "instruction": instr}
            for c, asset, instr in (
                (custody[0], "ETH (Base)",
                 "fund the relayer with dust ETH on Base — gas only; "
                 "~$2 covers thousands of settlements"),
                (custody[1], "USDC (Base)",
                 "fund the specimen payer with USDC on Base to make "
                 "funded crossings from this instance"))
            if c["fundable"]],
        "authority_store": os.path.relpath(store_path, tgt),
        "chain_genesis": chain_genesis,
        "note": "Funding instructions are emitted ONLY for addresses "
                "whose keys passed custody verification in this run. "
                "The 7-day zero-coordinator-intervention observation "
                "(BUILD-Q-32 acceptance) is a remainder measured from "
                "the instance's continuity records; this record does "
                "not claim it.",
    }
    with open(os.path.join(tgt, "HOST__RECORD__01.json"), "w") as f:
        json.dump(record, f, indent=1); f.write("\n")
    print(json.dumps(record, indent=1))
    return 0

if __name__ == "__main__":
    sys.exit(main())
