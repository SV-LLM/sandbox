#!/usr/bin/env python3
"""Chain carriage snapshot — BUILD-Q-16 (durability tranche, step 3b).

Snapshots every receipt chain of the machine-economy stack into ONE zip
+ manifest: the endpoint parent chain, every sub-lane chain, and the
SKAP signing operation's chain. Per-chain anchors and pair counts are
taken from the services' own /replay readbacks at snapshot time; every
snapshotted file is listed in the manifest with size + SHA-256.

Carriage is read-only against the live chains: files are copied, never
moved or rewritten. Usage:
    python3 carriage.py [--out PATH.zip]
Prints the package path, size, MD5, and SHA-256 on success."""
import hashlib, json, os, sys, urllib.request, zipfile
from datetime import datetime, timezone

BASE = os.path.dirname(os.path.abspath(__file__))
ENDPOINT_URL = "http://127.0.0.1:8794"
SIGNING_URL = "http://127.0.0.1:8795"
SIGNING_DIR = os.path.join(os.path.dirname(BASE), "skap-signing", "receipts")

def get_json(url):
    with urllib.request.urlopen(url, timeout=15) as r:
        return json.load(r)

def chain_files(d):
    out = []
    if os.path.isdir(d):
        for n in sorted(os.listdir(d)):
            if n.startswith("segment-") and n.endswith(".jsonl"):
                out.append(os.path.join(d, n))
    return out

def snapshot_chain(name, src_dir, zip_prefix, replay_view):
    files = []
    for p in chain_files(src_dir):
        with open(p, "rb") as f:
            data = f.read()
        files.append({"path_in_zip": zip_prefix + "/" + os.path.basename(p),
                      "source": p, "size": len(data),
                      "sha256": hashlib.sha256(data).hexdigest(),
                      "_data": data})
    return {"chain": name,
            "verdict": replay_view["verdict"],
            "entries": replay_view["entries"],
            "pairs": replay_view["pairs"],
            "terminal_anchor": replay_view["terminal_anchor"],
            "files": files}

def main():
    out = os.path.join(BASE, "carriage",
                       "CHAIN__CARRIAGE__BUILD-Q-16.zip")
    if "--out" in sys.argv:
        out = sys.argv[sys.argv.index("--out") + 1]
    man = get_json(ENDPOINT_URL + "/replay")
    op = get_json(SIGNING_URL + "/replay")
    chains = [snapshot_chain("machine-economy-endpoint (parent)",
                             os.path.join(BASE, "receipts"),
                             "chains/machine-economy-endpoint",
                             man["manifold"]["parent"])]
    sub_root = os.path.join(BASE, "receipts", "sublanes")
    if os.path.isdir(sub_root):
        for name in sorted(os.listdir(sub_root)):
            d = os.path.join(sub_root, name)
            if os.path.isdir(d):
                chains.append(snapshot_chain(
                    f"machine-economy-endpoint sublane {name}", d,
                    f"chains/machine-economy-endpoint/sublanes/{name}",
                    man["manifold"]["sublanes"][name]))
    chains.append(snapshot_chain("skap-signing (operation)", SIGNING_DIR,
                                 "chains/skap-signing", op))
    manifest = {"package": "CHAIN__CARRIAGE__BUILD-Q-16",
                "created": datetime.now(timezone.utc).isoformat(),
                "basis": "BUILD-Q-16 durability tranche step 3b; anchors and "
                         "pair counts are the services' /replay readbacks at "
                         "snapshot time; carriage is read-only",
                "manifold_verdict": man["verdict"],
                "chains": [{k: v for k, v in c.items() if k != "files"}
                           | {"files": [{kk: f[kk] for kk in
                                         ("path_in_zip", "size", "sha256")}
                                        for f in c["files"]]}
                          for c in chains]}
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
        for c in chains:
            for f in c["files"]:
                z.writestr(f["path_in_zip"], f["_data"])
        z.writestr("CARRIAGE__MANIFEST.json",
                   json.dumps(manifest, indent=1, sort_keys=True))
    with open(out, "rb") as f:
        data = f.read()
    print(json.dumps({"zip": out, "size": len(data),
                      "md5": hashlib.md5(data).hexdigest(),
                      "sha256": hashlib.sha256(data).hexdigest(),
                      "chains": [(c["chain"], c["pairs"],
                                  c["terminal_anchor"]) for c in chains]},
                     indent=1))

if __name__ == "__main__":
    main()
