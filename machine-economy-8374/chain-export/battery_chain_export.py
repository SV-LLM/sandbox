#!/usr/bin/env python3
"""Proof battery for CHAIN-EXPORT-01 (the public chain export).

(a) export completeness: the manifest's entry/pair counts and
    terminal anchor equal the live chain's (read from the
    endpoint's localhost /replay at run time -- nothing is
    hardcoded), the export's line count equals the live entry
    count, and the export's last entry hash equals the live
    terminal anchor;
(b) independent recompute: verify_chain.py, run as a fresh
    subprocess against the PUBLIC export root, recomputes MATCH
    at the live anchor;
(c) tamper cases on a local copy of the export: a flipped byte,
    a truncated tail, and a dropped middle entry each produce
    MISMATCH with the defect located;
(d) the whole public surface re-verified after the mount,
    including that operator routes stay non-public.

All reads are read-only; no pairs are written anywhere.
Exit 0 when every case passes.
"""
import json, os, subprocess, sys, tempfile
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
VERIFIER = os.path.join(HERE, "verify_chain.py")
PUBLIC = "https://8374.stegverse.org"
LOCAL_CHAIN = "http://127.0.0.1:8799"
LOCAL_REPLAY = "http://127.0.0.1:8794/replay"
UA = "8374-chain-export-battery/1"

results = []


def check(name, ok, detail=""):
    results.append((name, ok, detail))
    print(f"[{'PASS' if ok else 'FAIL'}] {name}"
          + (f" -- {detail}" if detail else ""))


sys.path.insert(0, HERE)
from verify_chain import fetch_url_full  # noqa: E402


def get(url, want_status=False):
    """Battery fetch with the verifier's own transport discipline
    (completeness-checked, Range-resume): some public legs
    short-read responses for this client class -- the defect
    class the export cures -- so the sweep fetches the way the
    published verifier does rather than grade a leg flake as a
    surface failure."""
    import http.client
    try:
        body = fetch_url_full(url)
        return (200, body) if want_status else body
    except urllib.error.HTTPError as e:
        try:
            body = e.read()
        except http.client.IncompleteRead as ie:
            body = ie.partial or b""
        except Exception:
            body = b""
        return (e.code, body) if want_status else body


def run_verifier(*args):
    return subprocess.run([sys.executable, VERIFIER, *args],
                          capture_output=True, text=True, timeout=120)


def main():
    replay = json.loads(get(LOCAL_REPLAY))
    live_entries = replay["entries"]
    live_pairs = replay["pairs"]
    live_anchor = replay["terminal_anchor"]
    print(f"live chain: {live_entries} entries, {live_pairs} pairs, "
          f"anchor {live_anchor}, verdict {replay['verdict']}")

    # (a) completeness ---------------------------------------------
    manifest = json.loads(get(LOCAL_CHAIN + "/chain/manifest.json"))
    check("a1 manifest counts == live chain",
          manifest["entries"] == live_entries
          and manifest["pairs"] == live_pairs,
          f"manifest {manifest['entries']}/{manifest['pairs']} "
          f"vs live {live_entries}/{live_pairs}")
    check("a2 manifest anchor == live anchor",
          manifest["terminal_anchor"] == live_anchor)
    export = get(LOCAL_CHAIN + "/chain/export.ndjson")
    lines = [l for l in export.decode().splitlines() if l.strip()]
    last = json.loads(lines[-1])
    check("a3 export line count == live entries",
          len(lines) == live_entries, f"{len(lines)} lines")
    check("a4 export terminal entry hash == live anchor",
          last["hash"] == live_anchor)
    served_verifier = get(LOCAL_CHAIN + "/chain/verifier.py")
    import hashlib
    check("a5 served verifier hash == manifest pin",
          hashlib.sha256(served_verifier).hexdigest()
          == manifest["verifier"]["sha256"])

    # (b) public recompute -----------------------------------------
    r = run_verifier(PUBLIC + "/chain")
    ok = r.returncode == 0 and "verdict: MATCH" in r.stdout \
        and live_anchor in r.stdout
    check("b1 verifier against PUBLIC root recomputes MATCH",
          ok, f"exit {r.returncode}")
    print("---- verifier output (public root) ----")
    print(r.stdout.strip())
    print("---------------------------------------")

    # (c) tamper cases ----------------------------------------------
    tmp = tempfile.mkdtemp(prefix="chain-export-battery-")
    base = os.path.join(tmp, "export.ndjson")
    with open(base, "wb") as f:
        f.write(export)

    def tampered(name, data):
        p = os.path.join(tmp, name)
        with open(p, "wb") as f:
            f.write(data)
        rr = run_verifier(p, "--anchor", live_anchor)
        located = ("entry" in rr.stdout or "PAIR-" in rr.stdout
                   or "pair" in rr.stdout or "line" in rr.stdout
                   or "anchor" in rr.stdout)
        return rr.returncode != 0 and "verdict: MISMATCH" in rr.stdout \
            and located, rr.stdout.strip().splitlines()[-3:]

    # flipped byte: change one character inside entry 10's content
    raw = bytearray(export)
    pos = sum(len(l) + 1 for l in lines[:9]) + 40
    raw[pos] = ord("X") if raw[pos] != ord("X") else ord("Y")
    ok, tail = tampered("flipped.ndjson", bytes(raw))
    check("c1 flipped byte -> MISMATCH, defect located", ok,
          "; ".join(tail))

    truncated = b"\n".join(l.encode() for l in lines[:-1]) + b"\n"
    ok, tail = tampered("truncated.ndjson", truncated)
    check("c2 truncated tail -> MISMATCH, defect located", ok,
          "; ".join(tail))

    dropped = b"\n".join(l.encode() for j, l in enumerate(lines)
                         if j != 9) + b"\n"
    ok, tail = tampered("dropped.ndjson", dropped)
    check("c3 dropped middle entry -> MISMATCH, defect located", ok,
          "; ".join(tail))

    # (d) public surface sweep --------------------------------------
    expect200 = ["/", "/health", "/offer", "/inspect", "/verify",
                 "/compare", "/conformance", "/frozen-test",
                 "/openapi.json", "/.well-known/x402",
                 "/router", "/router/catalog",
                 # provenance's documented form carries ?origin=
                 # (a bare request is a 400 by the router's own
                 # contract, pre-dating this build)
                 "/router/provenance?origin="
                 "https://8374.stegverse.org",
                 "/router/discovery/resources", "/router/openapi.json",
                 "/chain", "/chain/manifest.json",
                 "/chain/export.ndjson", "/chain/verifier.py"]
    bad = []
    for p in expect200:
        st, _ = get(PUBLIC + p, want_status=True)
        if st != 200:
            bad.append(f"{p}={st}")
    check("d1 public surface all 200", not bad,
          ", ".join(bad) if bad else f"{len(expect200)} routes")
    st, _ = get(PUBLIC + "/crossing", want_status=True)
    check("d2 /crossing answers 402", st == 402, f"got {st}")
    bad = []
    for p in ["/replay", "/funds", "/settle-pair",
              "/router/settle-pair", "/router/replay",
              "/chain/replay", "/chain/funds"]:
        st, _ = get(PUBLIC + p, want_status=True)
        if st != 404:
            bad.append(f"{p}={st}")
    check("d3 operator routes stay non-public (404)", not bad,
          ", ".join(bad) if bad else "all refused")
    wk = json.loads(get(PUBLIC + "/.well-known/x402"))
    ce = wk.get("chain_export") or {}
    check("d4 well-known names the export on the canonical origin",
          ce.get("export_url") == PUBLIC + "/chain/export.ndjson"
          and ce.get("verifier_url") == PUBLIC + "/chain/verifier.py")
    own = json.loads(get(PUBLIC + "/verify/check?url="
                         + urllib.parse.quote(
                             PUBLIC + "/crossing", safe="")))
    ev = " ".join((own.get("proof") or {}).get("evidence") or [])
    check("d5 verify own-row evidence carries the export link",
          "/chain/export.ndjson" in ev
          and (own.get("proof") or {}).get("chain_export", {})
          .get("terminal_anchor") == live_anchor)

    failed = [n for n, ok, _ in results if not ok]
    print(f"\n{len(results) - len(failed)}/{len(results)} passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
