#!/usr/bin/env python3
"""Public chain export for 8374 (CHAIN-EXPORT-01, 2026-11-19).

The cure for the convergent external-assessment finding (Gemini
F-01 / Codex F04): the receipt chain's replay verdict was
server-computed -- an external party was asked to trust the
server's /replay. This service publishes the chain itself:

    GET /chain                 service document (JSON): what this
                               is, the chain rules, and the three
                               documents below
    GET /chain/manifest.json   the export manifest: rules id
                               (receipt-chain-rules/1), segment
                               list, entry count, pair count, the
                               terminal anchor the export must
                               recompute to, and the verifier's
                               URL + SHA-256 (hash-pinned here)
    GET /chain/export.ndjson   every entry of the production
                               endpoint receipt chain, in chain
                               order, one JSON object per line --
                               the stored segment lines VERBATIM
                               (the hash chain is over the stored
                               content; nothing is re-serialized
                               or redacted)
    GET /chain/verifier.py     verify_chain.py, the standalone
                               stdlib-only verifier: fetch the
                               export, recompute linkage, per-entry
                               hashes, pair structure and the
                               terminal anchor locally, compare
                               against the manifest. No trust in
                               this server is required or asked.

The export is a LIVE READ of the production receipts directory at
request time (read-only): it serves the chain as it stands when
asked, so it can never drift from the chain it exports. A torn
tail (an incomplete final line in the active segment, BUILD-Q-16)
is never exported: only complete entries are served, and the
manifest states the torn byte count when one exists.

The export also answers in entry windows --
/chain/export.ndjson?offset=N&limit=M -- because some public
transport legs truncate large single responses for some client
classes (observed 2026-11-19 on the Cloudflare leg: curl and
browsers receive the full stream; naive HTTP/1.1 readers were
short-read at varying points, the GEN 12 relay-read residual
class). Paging is a transport fetch strategy only: the complete
export is the concatenation of the windows in offset order, and
the verifier's recompute over the assembled stream is what
verifies it -- a manipulated window breaks the chain and
recomputes MISMATCH.

Read-only throughout: this service writes nothing, holds no keys,
and reads only the receipts directory and its own verifier file.
Stdlib only. Binds localhost; the public proxy provides the edge.
"""
import hashlib, json, os, urllib.parse
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = int(os.environ.get("CHAIN_EXPORT_PORT", "8799"))
RECEIPTS_DIR = os.environ.get(
    "CHAIN_EXPORT_RECEIPTS_DIR",
    "/home/hatch/workspace/machine-economy-endpoint/receipts")
ORIGIN = os.environ.get("CHAIN_EXPORT_ORIGIN",
                        "https://8374.stegverse.org").rstrip("/")
VERIFIER_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                             "verify_chain.py")
RULES = "receipt-chain-rules/1"
PATENT_PENDING = ("U.S. Provisional Patent Application No. "
                  "64/198,910, filed November 14, 2026 \u2014 patent "
                  "pending.")


def scan_segment(path):
    """(complete_raw_lines, torn_bytes): the raw bytes of every
    complete, decodable line in order, and the count of trailing
    bytes forming an incomplete final line -- the endpoint's
    BUILD-Q-16 torn-tail semantics, applied to raw lines so the
    export carries the stored bytes verbatim."""
    with open(path, "rb") as f:
        data = f.read()
    lines = []
    pos, n = 0, len(data)
    torn = 0
    while pos < n:
        nl = data.find(b"\n", pos)
        if nl == -1:
            torn = n - pos
            break
        raw = data[pos:nl]
        if raw.strip():
            try:
                json.loads(raw)
            except ValueError:
                if nl == n - 1:
                    torn = n - pos
                else:
                    raise ValueError(
                        f"{os.path.basename(path)}: undecodable line "
                        f"inside the sealed span at byte {pos}")
                break
            lines.append(data[pos:nl + 1])
        pos = nl + 1
    return lines, torn


def read_chain(offset=0, limit=None):
    """Live read of the production chain: (export_bytes, manifest
    fields). The byte stream is the window [offset, offset+limit)
    of the chain's entries (the whole chain by default); the
    fields always describe the WHOLE chain. Raises ValueError on
    sealed-span corruption."""
    names = [n for n in sorted(os.listdir(RECEIPTS_DIR))
             if n.startswith("segment-") and n.endswith(".jsonl")]
    body = bytearray()
    entries = 0
    pair_ids = set()
    anchor = "GENESIS"
    torn_total = 0
    segment_details = []
    total_bytes = 0
    for n in names:
        lines, torn = scan_segment(os.path.join(RECEIPTS_DIR, n))
        torn_total += torn
        seg_bytes = bytearray()
        seg_entries = 0
        for raw in lines:
            seg_bytes += raw
            if entries >= offset and (limit is None
                                      or entries < offset + limit):
                body += raw
            e = json.loads(raw)
            entries += 1
            seg_entries += 1
            anchor = e["hash"]
            pid = (e.get("content") or {}).get("pair_id")
            if pid:
                pair_ids.add(pid)
        # Per-segment integrity (additive, GEN 14): the sha256 and
        # byte size of the segment's EXPORTED bytes (its complete
        # lines, verbatim) let a reader detect truncation of a
        # segment before recomputing the chain.
        segment_details.append({
            "name": n, "entries": seg_entries,
            "bytes": len(seg_bytes),
            "sha256": hashlib.sha256(bytes(seg_bytes)).hexdigest(),
            "torn_tail_bytes": torn})
        total_bytes += len(seg_bytes)
    return bytes(body), {"segments": names,
                         "segment_details": segment_details,
                         "export_bytes": total_bytes,
                         "entries": entries,
                         "pairs": len(pair_ids),
                         "terminal_anchor": anchor,
                         "torn_tail_bytes": torn_total}


def verifier_bytes():
    with open(VERIFIER_PATH, "rb") as f:
        return f.read()


def manifest():
    _body, fields = read_chain()
    vb = verifier_bytes()
    return {
        "document": "8374 receipt-chain export manifest",
        "chain": "8374 endpoint receipt chain (production)",
        "rules": RULES,
        "format": ("NDJSON: one JSON object per line, the stored "
                   "segment lines verbatim, in chain order"),
        "hash_rule": ("entry.hash = SHA-256(entry.prev as UTF-8 || "
                      "canonical(entry.content)); canonical = JSON "
                      "with sorted keys and separators (\",\", \":\"); "
                      "the first entry's prev is \"GENESIS\""),
        "pair_rule": ("a receipt pair is two consecutive entries "
                      "sharing content.pair_id (index_in_pair 0 "
                      "then 1); the second member's "
                      "content.pair_anchor equals the first "
                      "member's entry hash"),
        "segments": fields["segments"],
        "segment_details": fields["segment_details"],
        "export_bytes": fields["export_bytes"],
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "entries": fields["entries"],
        "pairs": fields["pairs"],
        "terminal_anchor": fields["terminal_anchor"],
        "torn_tail_bytes": fields["torn_tail_bytes"],
        "export_url": ORIGIN + "/chain/export.ndjson",
        "paging": {
            "parameters": "offset, limit (entry counts) on "
                          "export_url",
            "page_entries_recommended": 32,
            "note": ("the complete export is the concatenation "
                     "of the windows in offset order; paging is "
                     "a transport fetch strategy for legs that "
                     "truncate large single responses -- the "
                     "recompute over the assembled stream is "
                     "the verification")},
        "manifest_url": ORIGIN + "/chain/manifest.json",
        "verifier": {
            "name": "verify_chain.py",
            "url": ORIGIN + "/chain/verifier.py",
            "sha256": hashlib.sha256(vb).hexdigest(),
            "usage": "python3 verify_chain.py " + ORIGIN + "/chain",
            "requires": "Python 3, standard library only",
        },
        "origin": ORIGIN,
        "served": ("live read of the production receipts at request "
                   "time (read-only); the export can never drift "
                   "from the chain it exports"),
        "patent_pending": PATENT_PENDING,
    }


def service_document():
    m = manifest()
    return {
        "service": "8374 chain export",
        "what": ("the production receipt chain behind "
                 "https://8374.stegverse.org/crossing, exported for "
                 "independent recompute: fetch the export, run the "
                 "verifier, and the replay verdict and terminal "
                 "anchor are yours, not the server's"),
        "rules": RULES,
        "entries": m["entries"],
        "pairs": m["pairs"],
        "terminal_anchor": m["terminal_anchor"],
        "export_url": m["export_url"],
        "manifest_url": m["manifest_url"],
        "verifier": m["verifier"],
        "patent_pending": PATENT_PENDING,
    }


class H(BaseHTTPRequestHandler):
    server_version = "chain-export"
    sys_version = ""
    timeout = 75

    def version_string(self):
        return "chain-export"

    def log_message(self, *a):
        pass

    def _send(self, status, body, ctype):
        b = body if isinstance(body, bytes) else body.encode()
        try:
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(b)))
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(b)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _json(self, status, obj):
        self._send(status, json.dumps(obj, indent=1),
                   "application/json")

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        try:
            if path == "/health":
                self._json(200, {"status": "ok",
                                 "service": "chain-export"})
                return
            if path == "/chain":
                self._json(200, service_document())
                return
            if path == "/chain/manifest.json":
                self._json(200, manifest())
                return
            if path == "/chain/export.ndjson":
                qs = urllib.parse.parse_qs(
                    urllib.parse.urlparse(self.path).query)
                try:
                    offset = int((qs.get("offset") or ["0"])[0])
                    limit = (qs.get("limit") or [None])[0]
                    limit = int(limit) if limit is not None else None
                except ValueError:
                    self._json(400, {"error": "offset/limit must "
                                              "be integers",
                                     "failure_code":
                                         "CHAIN_EXPORT_BAD_WINDOW"})
                    return
                if offset < 0 or (limit is not None
                                  and not 1 <= limit <= 500):
                    self._json(400, {"error": "window out of range",
                                     "failure_code":
                                         "CHAIN_EXPORT_BAD_WINDOW"})
                    return
                body, _fields = read_chain(offset, limit)
                # Range support: some public legs drop large
                # responses mid-body for some client classes; a
                # Range resume lets any reader complete the exact
                # bytes (the recompute verifies what arrived).
                rng = self.headers.get("Range") or ""
                if rng.startswith("bytes=") and "," not in rng:
                    try:
                        lo_s, _sep, hi_s = rng[6:].partition("-")
                        lo = int(lo_s) if lo_s else 0
                        hi = int(hi_s) if hi_s else len(body) - 1
                    except ValueError:
                        lo, hi = -1, -1
                    if lo < 0 or lo >= len(body) or hi < lo:
                        self.send_response(416)
                        self.send_header("Content-Range",
                                         f"bytes */{len(body)}")
                        self.send_header("Content-Length", "0")
                        self.end_headers()
                        return
                    hi = min(hi, len(body) - 1)
                    part = body[lo:hi + 1]
                    try:
                        self.send_response(206)
                        self.send_header("Content-Type",
                                         "application/x-ndjson")
                        self.send_header("Content-Range",
                                         f"bytes {lo}-{hi}/"
                                         f"{len(body)}")
                        self.send_header("Content-Length",
                                         str(len(part)))
                        self.end_headers()
                        if self.command != "HEAD":
                            self.wfile.write(part)
                    except (BrokenPipeError, ConnectionResetError):
                        pass
                    return
                self._send(200, body, "application/x-ndjson")
                return
            if path == "/chain/verifier.py":
                self._send(200, verifier_bytes(),
                           "text/x-python; charset=utf-8")
                return
        except ValueError as e:
            self._json(503, {"error": "chain export unavailable",
                             "failure_code": "CHAIN_EXPORT_UNAVAILABLE",
                             "detail": str(e)[:200]})
            return
        except OSError:
            self._json(503, {"error": "chain export unavailable",
                             "failure_code": "CHAIN_EXPORT_UNAVAILABLE"})
            return
        self._json(404, {"error": "not found"})

    do_HEAD = do_GET


if __name__ == "__main__":
    print(f"chain-export on 127.0.0.1:{PORT} "
          f"(receipts {RECEIPTS_DIR}, origin {ORIGIN})")
    ThreadingHTTPServer(("127.0.0.1", PORT), H).serve_forever()
