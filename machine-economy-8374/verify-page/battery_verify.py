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
import json, os, re, subprocess, sys, threading, time
import urllib.error, urllib.parse, urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
ROUTER_DIR = os.path.expanduser("~/workspace/router-8374")
VPORT, SPORT, MPORT = 8901, 8902, 8903
VBASE = f"http://127.0.0.1:{VPORT}"
SELLER_ORIGIN = f"http://127.0.0.1:{SPORT}"
MCP_ORIGIN = f"http://127.0.0.1:{MPORT}"
RESULTS = []


class _McpFixture(BaseHTTPRequestHandler):
    """A bounded MCP-shaped fixture: /mcp-neg answers every POST
    with 406 (protocol negotiation, no paid-capability signal);
    /mcp-tools requires the MCP handshake (initialize -> a
    session id -> tools/list carrying it) and its tool names a
    payment_manifest link; /mcp-open refuses the handshake
    (404) but answers a bare tools/list; the manifest declares
    x402 terms."""

    SESSION = "fixture-session-1"

    def log_message(self, *a):
        pass

    def _send(self, status, obj, headers=None):
        b = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b)))
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(b)

    def _tools(self, req_id):
        return {"jsonrpc": "2.0", "id": req_id,
                "result": {"tools": [{
                    "name": "paid_lookup",
                    "description": "x402 paid lookup",
                    "payment_manifest":
                        MCP_ORIGIN + "/payment-manifest.json"}]}}

    def do_GET(self):
        if self.path == "/payment-manifest.json":
            self._send(200, {"accepts": [{
                "scheme": "exact", "network": "eip155:8453",
                "asset": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
                "payTo": "0x" + "22" * 20,
                "maxAmountRequired": "4000"}]})
        else:
            self._send(200, {"name": "fixture-mcp"})

    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(n) if n else b""
        try:
            req = json.loads(raw)
        except Exception:
            req = {}
        method = req.get("method")
        if self.path == "/mcp-neg":
            self._send(406, {"error": "not acceptable"})
        elif self.path == "/mcp-tools":
            if method == "initialize":
                self._send(200, {"jsonrpc": "2.0",
                                 "id": req.get("id"),
                                 "result": {
                                     "protocolVersion":
                                         "2025-03-26",
                                     "capabilities": {},
                                     "serverInfo": {
                                         "name": "fixture",
                                         "version": "1"}}},
                           headers={"Mcp-Session-Id": self.SESSION})
            elif method == "notifications/initialized":
                self._send(202, {})
            elif method == "tools/list" and \
                    self.headers.get("Mcp-Session-Id") \
                    == self.SESSION:
                self._send(200, self._tools(req.get("id")))
            else:
                self._send(400, {"error": "handshake required"})
        elif self.path == "/mcp-open":
            if method == "tools/list":
                self._send(200, self._tools(req.get("id")))
            else:
                self._send(404, {"error": "no handshake here"})
        else:
            self._send(200, {})


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
          "asserted (a well-formed summary is an assertion, "
          "never a recompute)",
          state_of({"verdict": "MATCH", "pairs": 62,
                    "terminal_anchor": anchor}) == "asserted")
    # The five parser inputs from the ChatGPT cycle-2 recheck
    # (R01), verbatim:
    check("u4a: ChatGPT input -- MATCH, pairs=1, anchor "
          "'aaaa...' -> asserted",
          state_of({"verdict": "MATCH", "pairs": 1,
                    "terminal_anchor": "aa" * 32}) == "asserted")
    check("u4b: ChatGPT input -- MATCH, pairs=-1, all-zero "
          "anchor -> validation_failed",
          state_of({"verdict": "MATCH", "pairs": -1,
                    "terminal_anchor": "00" * 32})
          == "validation_failed")
    check("u4c: MATCH + all-zero anchor (0x form) -> "
          "validation_failed (a placeholder is not an anchor)",
          state_of({"verdict": "MATCH", "pairs": 3,
                    "terminal_anchor": zero})
          == "validation_failed")
    check("u4d: MATCH + string pair count -> validation_failed "
          "(not a nonnegative integer)",
          state_of({"verdict": "MATCH", "pairs": "62",
                    "terminal_anchor": anchor})
          == "validation_failed")
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
    st = {"record_state": "none"}
    V._merge_record_state(st, {"state": "validation_failed"})
    V._merge_record_state(st, {"state": "asserted"})
    V._merge_record_state(st, {"state": "discovered"})
    V._merge_record_state(st, {"state": "asserted"})
    check("u14: state merge ranks asserted over "
          "validation_failed and discovered over asserted",
          st["record_state"] == "discovered",
          f"{st}")
    check("u15: every state names its method (Item 1b)",
          all(V._STATE_METHOD[s] for s in
              ("verified", "asserted", "discovered",
               "validation_failed", "none"))
          and "not recomputed" in V._STATE_METHOD["asserted"]
          and "recomputed" in V._STATE_METHOD["verified"]
          and "discovered in the published document"
          in V._STATE_METHOD["discovered"])


def main():
    unit_section()
    env = dict(os.environ)
    env["VERIFY_PORT"] = str(VPORT)
    env["VERIFY_FIXTURE_ORIGINS"] = SELLER_ORIGIN + "," + MCP_ORIGIN
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
    mcpd = ThreadingHTTPServer(("127.0.0.1", MPORT), _McpFixture)
    threading.Thread(target=mcpd.serve_forever, daemon=True).start()
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
        check("a: own row names its method -- recomputed "
              "(Item 1b)",
              p.get("method") == "recomputed from the exported "
              "records at request time",
              f"method={p.get('method')}")

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
        check("b: negative result is bounded -- "
              "NOT_FOUND_IN_CHECKED_LOCATIONS with method + "
              "bounds (R04)",
              p.get("negative_result")
              == "NOT_FOUND_IN_CHECKED_LOCATIONS"
              and "NOT_FOUND_IN_CHECKED_LOCATIONS"
              in ((d or {}).get("verdict") or "")
              and bool(p.get("bounds"))
              and p.get("method", "").startswith("no record "
                                                 "presented"),
              f"negative_result={p.get('negative_result')}, "
              f"method={p.get('method')}")

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

        # (g) MCP probe coverage (Item 4 / R04)
        code, d = get_json(VBASE + "/verify/check?url=" +
                           urllib.parse.quote(
                               MCP_ORIGIN + "/mcp-neg", safe=""))
        p = (d or {}).get("proof") or {}
        chk = " ".join(c.get("result", "")
                       for c in p.get("checked") or [])
        check("g1: MCP 406 is a negotiation outcome, never an "
              "absence finding",
              code == 200 and d is not None
              and d.get("terms") is None
              and "protocol-negotiation outcome" in chk
              and "does not determine whether paid capability "
                  "exists" in (d.get("verdict") or "")
              and "publishes no replayable" not in
                  (d.get("verdict") or ""),
              f"http={code}, verdict={(d or {}).get('verdict')}")
        check("g1: MCP-neg negative is bounded "
              "(NOT_FOUND_IN_CHECKED_LOCATIONS)",
              p.get("negative_result")
              == "NOT_FOUND_IN_CHECKED_LOCATIONS",
              f"negative_result={p.get('negative_result')}")
        code, d = get_json(VBASE + "/verify/check?url=" +
                           urllib.parse.quote(
                               MCP_ORIGIN + "/mcp-tools", safe=""))
        p = (d or {}).get("proof") or {}
        chk = " ".join(c.get("result", "")
                       for c in p.get("checked") or [])
        ev = " ".join(p.get("evidence") or [])
        check("g2: MCP tools/list probe runs and reads the "
              "tools",
              code == 200 and "MCP tools/list answered" in chk
              and "paid_lookup" in ev,
              f"http={code}, checked={chk[:160]}")
        check("g2: payment_manifest link followed; its declared "
              "terms recorded",
              ((d or {}).get("terms") or {}).get("amount")
              == "4000"
              and "payment manifest" in ev,
              f"terms={(d or {}).get('terms')}, ev={ev[:200]}")
        check("g2: the handshake path was used (initialize "
              "answered with a session id)",
              "MCP initialize answered HTTP 200" in chk,
              f"checked={chk[:200]}")
        code, d = get_json(VBASE + "/verify/check?url=" +
                           urllib.parse.quote(
                               MCP_ORIGIN + "/mcp-open", safe=""))
        p = (d or {}).get("proof") or {}
        chk = " ".join(c.get("result", "")
                       for c in p.get("checked") or [])
        check("g3: no-handshake server -- bare tools/list "
              "fallback answers",
              code == 200 and "MCP tools/list answered" in chk
              and ((d or {}).get("terms") or {}).get("amount")
              == "4000",
              f"http={code}, checked={chk[:200]}")

        # (h) static discoverability (Item 7): the API path, the
        # probe specification and the pinned source are in the
        # static body -- no script execution needed
        code, page = get(VBASE + "/verify")
        check("h: static page carries the alternate-API link, "
              "the explicit API path, the probe specification "
              "and the commit-pinned source",
              code == 200
              and 'rel="alternate"' in page
              and "/verify/check?url=" in page
              and "tools/list" in page
              and "NOT_FOUND_IN_CHECKED_LOCATIONS" in page
              and "github.com/SV-LLM/sandbox/blob/" in page,
              f"http={code}")

        # (f) health
        code, d = get_json(VBASE + "/health", timeout=10)
        check("f: health", code == 200
              and (d or {}).get("status") == "ok", f"http={code}")
    finally:
        mcpd.shutdown()
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
