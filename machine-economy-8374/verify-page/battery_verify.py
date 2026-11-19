#!/usr/bin/env python3
"""Battery — verify-any-row service (VERIFY-PAGE-01).

Against THROWAWAY instances (verify service on 8901 with the
specimen-seller origin allowlisted as a test fixture; the router
build's specimen seller on 8902):
  a. check 8374's /crossing -> publishes_replayable_record TRUE,
     pairs + terminal anchor equal an independent /replay read of
     the production endpoint taken at test time;
  b. check the specimen seller (a standard x402 seller publishing
     no proof material) -> FALSE, with the checked list covering
     the challenge, the well-known document and the OpenAPI
     document;
  c. check a non-x402 URL (https://example.com/) -> graceful
     "no x402 terms found" verdict, no crash;
  d. SSRF: http://127.0.0.1:8794/replay and
     http://169.254.169.254/ -> refused, with the refusal reason;
  e. the page renders its side-by-side rows (8374 + samples) and
     every row's URL returns a check verdict (or a named failure
     code -- never a crash);
  f. health.
"""
import json, os, re, subprocess, sys, time
import urllib.error, urllib.parse, urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROUTER_DIR = os.path.expanduser("~/workspace/router-8374")
VPORT, SPORT = 8901, 8902
VBASE = f"http://127.0.0.1:{VPORT}"
SELLER_ORIGIN = f"http://127.0.0.1:{SPORT}"
RESULTS = []


def check(name, ok, detail=""):
    RESULTS.append((name, bool(ok), detail))
    print(f"[{'PASS' if ok else 'FAIL'}] {name} -- {detail}")


def get(url, timeout=180):
    req = urllib.request.Request(url, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")


def get_json(url, timeout=180):
    code, raw = get(url, timeout)
    try:
        return code, json.loads(raw)
    except Exception:
        return code, None


def wait_health(base, tries=40):
    for _ in range(tries):
        try:
            code, _raw = get(base + "/health", timeout=5)
            if code == 200:
                return True
        except Exception:
            pass
        time.sleep(0.5)
    return False


def unit_section():
    """Classifier regression cases (in-process, no network): the
    three external-assessment inputs that previously produced a
    clean pass from malformed evidence, plus genuine-document
    controls. A record finding now carries a validation state:
    verified / discovered / validation_failed."""
    sys.path.insert(0, HERE)
    import verify as V

    real = "0x" + "9f" * 32
    zero = "0x" + "00" * 32
    anchor = "ab" * 32

    def state_of(doc):
        f = V._chain_content(doc)
        return f["state"] if f else None

    check("u1: replay doc, verdict MISMATCH + non-hash anchor -> "
          "validation_failed (not a clean pass)",
          state_of({"verdict": "MISMATCH", "pairs": 5,
                    "terminal_anchor": "not-a-hash"})
          == "validation_failed")
    check("u2: settlement_evidence settled_pairs [{}] -> no "
          "record finding",
          V._chain_content({"settlement_evidence":
                            {"settled_pairs": [{}]}}) is None)
    check("u3: transactions entry carrying only the all-zero "
          "hash -> no record finding",
          V._chain_content({"transactions": [{"tx_hash": zero}]})
          is None)
    check("u4: replay doc, verdict MATCH + 64-hex anchor -> "
          "verified",
          state_of({"verdict": "MATCH", "pairs": 62,
                    "terminal_anchor": anchor}) == "verified")
    check("u5: replay doc, verdict MATCH + malformed anchor -> "
          "validation_failed",
          state_of({"verdict": "MATCH", "pairs": 62,
                    "terminal_anchor": "not-a-hash"})
          == "validation_failed")
    check("u6: replay doc, verdict MISMATCH + valid anchor -> "
          "validation_failed",
          state_of({"verdict": "MISMATCH", "pairs": 62,
                    "terminal_anchor": anchor})
          == "validation_failed")
    f = V._chain_content({"settlement_evidence":
                          {"settled_pairs": [{"tx_hash": real}]}})
    check("u7: settlement evidence, one entry with a real tx "
          "hash -> discovered, counted 1 of 1",
          f is not None and f["state"] == "discovered"
          and "1 of 1" in f["description"],
          f"{f}")
    f = V._chain_content({"settlement_evidence":
                          {"settled_pairs": [{},
                                             {"tx_hash": real}]}})
    check("u8: settlement evidence, empty + real entries -> "
          "discovered, counted 1 of 2",
          f is not None and f["state"] == "discovered"
          and "1 of 2" in f["description"],
          f"{f}")
    check("u9: transactions list, entry with a real tx hash -> "
          "discovered",
          state_of({"transactions": [{"tx_hash": real}]})
          == "discovered")
    check("u10: bare registration hash, no record structure -> "
          "no finding (a hash is not a record)",
          V._chain_content({"registration_hash": "0x" + "cd" * 32})
          is None)
    check("u11: settled_pairs entry that IS a real hash string "
          "-> discovered",
          state_of({"settled_pairs": ["0x" + "ef" * 32]})
          == "discovered")
    check("u12: settled_pairs entry that is the all-zero hash "
          "string -> no finding",
          V._chain_content({"settled_pairs": [zero]}) is None)
    st = {"record_state": "none"}
    V._merge_record_state(st, {"state": "validation_failed"})
    V._merge_record_state(st, {"state": "discovered"})
    V._merge_record_state(st, {"state": "validation_failed"})
    check("u13: state merge keeps the strongest state "
          "(discovered over validation_failed)",
          st["record_state"] == "discovered",
          f"{st}")


def main():
    unit_section()
    env = dict(os.environ)
    env["VERIFY_PORT"] = str(VPORT)
    env["VERIFY_FIXTURE_ORIGINS"] = SELLER_ORIGIN
    vproc = subprocess.Popen(
        [sys.executable, os.path.join(HERE, "verify.py")],
        env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    senv = dict(os.environ)
    senv["SELLER_PORT"] = str(SPORT)
    senv["SELLER_PAYTO"] = "0x" + "11" * 20
    sproc = subprocess.Popen(
        [sys.executable, os.path.join(ROUTER_DIR, "seller.py")],
        cwd=ROUTER_DIR, env=senv,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        ok = wait_health(VBASE)
        check("setup: verify service healthy on throwaway port", ok)
        scode, _ = get(SELLER_ORIGIN + "/.well-known/x402",
                       timeout=10)
        check("setup: specimen seller up", scode == 200,
              f"well-known HTTP {scode}")

        # (a) 8374's own crossing -- the real replay, live-compared
        _c, replay = get_json("http://127.0.0.1:8794/replay",
                              timeout=30)
        code, d = get_json(VBASE + "/verify/check?url=" +
                           urllib.parse.quote(
                               "https://8374.stegverse.org/crossing",
                               safe=""))
        p = (d or {}).get("proof") or {}
        rp = p.get("replay") or {}
        check("a: 8374 /crossing publishes_replayable_record TRUE",
              code == 200 and p.get("publishes_replayable_record")
              is True and rp.get("verdict") == "MATCH"
              and p.get("record_state") == "verified",
              f"http={code}, record="
              f"{p.get('publishes_replayable_record')}, record_state="
              f"{p.get('record_state')}, replay "
              f"verdict={rp.get('verdict')}")
        check("a: pairs + anchor equal the independent /replay read",
              rp.get("pairs") == replay.get("pairs")
              and rp.get("terminal_anchor")
              == replay.get("terminal_anchor"),
              f"service {rp.get('pairs')}/{rp.get('terminal_anchor')}"
              f" vs /replay {replay.get('pairs')}/"
              f"{replay.get('terminal_anchor')}")
        check("a: terms recorded from the unpaid challenge",
              (d or {}).get("terms", {}).get("payTo")
              == "0x7721aB66161e60fCcA59CCe2A86817cbdd9b16Be",
              f"terms={(d or {}).get('terms')}")

        # (b) specimen seller -- no proof publications
        code, d = get_json(VBASE + "/verify/check?url=" +
                           urllib.parse.quote(
                               SELLER_ORIGIN + "/resource", safe=""))
        p = (d or {}).get("proof") or {}
        locs = " ".join(c.get("location", "")
                        for c in p.get("checked") or [])
        check("b: specimen seller publishes_replayable_record FALSE",
              code == 200
              and p.get("publishes_replayable_record") is False
              and p.get("record_state") == "none",
              f"http={code}, record_state={p.get('record_state')}, "
              f"verdict={(d or {}).get('verdict')}")
        check("b: checked list covers challenge + well-known + "
              "openapi",
              "/resource" in locs and "/.well-known/x402" in locs
              and "/openapi.json" in locs,
              f"checked={locs}")
        check("b: specimen terms still recorded (it IS an x402 "
              "seller)",
              ((d or {}).get("terms") or {}).get("amount") == "3000",
              f"terms={(d or {}).get('terms')}")

        # (c) non-x402 URL
        code, d = get_json(VBASE + "/verify/check?url=" +
                           urllib.parse.quote("https://example.com/",
                                              safe=""))
        check("c: non-x402 URL -> graceful 'no x402 terms' verdict",
              code == 200 and d is not None
              and "no x402 terms" in (d.get("verdict") or "")
              and d.get("terms") is None,
              f"http={code}, verdict={(d or {}).get('verdict')}")

        # (d) SSRF refusals
        for target in ("http://127.0.0.1:8794/replay",
                       "http://169.254.169.254/latest/meta-data"):
            code, d = get_json(VBASE + "/verify/check?url=" +
                               urllib.parse.quote(target, safe=""),
                               timeout=30)
            check(f"d: SSRF refused for {target}",
                  code == 400 and d is not None
                  and d.get("failure_code") == "VERIFY_SSRF_REFUSED"
                  and bool(d.get("reason")),
                  f"http={code}, reason={(d or {}).get('reason')}")

        # (e) page + every rendered row checks
        code, page = get(VBASE + "/verify")
        rows = re.findall(r'<tr data-url="([^"]+)"', page or "")
        check("e: page renders 8374 + at least one sample row",
              code == 200 and len(rows) >= 2
              and rows[0] == "https://8374.stegverse.org/crossing",
              f"http={code}, rows={rows}")
        all_ok, details = True, []
        for u in rows:
            c2, d2 = get_json(VBASE + "/verify/check?url=" +
                              urllib.parse.quote(u, safe=""))
            good = d2 is not None and ("verdict" in d2
                                       or "failure_code" in d2)
            all_ok = all_ok and good
            details.append(f"{u} -> "
                           f"{(d2 or {}).get('verdict', (d2 or {}).get('failure_code'))}")
        check("e: every rendered row returns a check verdict",
              all_ok, " | ".join(details))

        # (f) health
        code, d = get_json(VBASE + "/health", timeout=10)
        check("f: health", code == 200
              and (d or {}).get("status") == "ok", f"http={code}")
    finally:
        for proc in (vproc, sproc):
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except Exception:
                proc.kill()
    passed = sum(1 for _n, ok, _d in RESULTS if ok)
    print(f"\nBATTERY: {passed}/{len(RESULTS)} passed")
    return 0 if passed == len(RESULTS) else 1


if __name__ == "__main__":
    sys.exit(main())
