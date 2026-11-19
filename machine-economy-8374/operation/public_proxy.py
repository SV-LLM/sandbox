#!/usr/bin/env python3
"""Public exposure proxy for the machine-economy endpoint (BUILD-Q-19;
hardened 2026-11-17 for public exposure ahead of public advertisement).

The public surface is exactly these operations:
    GET  /health    -> minimal body {"status": "ok", "service": ...}
    GET  /offer     -> public-terms projection of the offer, carrying
                       the patent_pending declaration
    POST /crossing  -> forwarded; the caller receives its own pair data
    GET  /inspect   -> the one-link inspection surface (2026-11-18):
                       live service + chain state, on-chain
                       settlement evidence, resolving pointers, and
                       the compact determination block; HTML by
                       default, JSON at /inspect?format=json
    GET  /          -> the landing page (2026-11-18): what 8374
                       is, the live terms, how a crossing works,
                       the outage property, and the links below
    GET  /frozen-test -> the frozen pair-first outage test page:
                       the HTML rendering of the frozen document
                       by default (and at ?format=html), the
                       byte-exact markdown at ?format=text
    GET  /conformance -> suite, battery and discovery conformance
                       (HTML; JSON at /conformance?format=json)
    GET  /compare   -> test comparisons: the frozen test's
                       reference result and the open reporting
                       table for other frameworks
    POST /router/register, GET /router/catalog,
    GET  /router/provenance, GET /router/quote,
    POST /router/route, GET /router/discovery/resources,
    GET  /router, GET /router/, GET /router/openapi.json
                    -> the 8374 router layer (ROUTER-V1, BUILD-Q-54
                       carry 2026-11-19; the Bazaar discovery feed
                       added the same day; the service document +
                       OpenAPI routes added by the route-contract
                       cure, 2026-11-19), forwarded to the sibling
                       router service on 127.0.0.1:8797. Its operator
                       route /router/settle-pair and /router/replay
                       are NOT public (localhost-only, as below).
                       The public /.well-known/x402 additionally
                       names the router catalog URL (appended at
                       this surface; the endpoint document itself is
                       unchanged).

Everything else -- every other path, every other method -- is refused
here with a static 404 and never reaches the endpoint. In particular
/replay, /sign, /seal, /sign-segment and the operator route
/settle-pair stay localhost-only, and the SKAP signing operation
(127.0.0.1:8795) is not proxied at all and remains localhost-only.

Controls at this surface:
- exact (method, path) allowlist: query strings, trailing slashes,
  case variants and encoded variants do not match and are refused;
- every HTTP method funnels through the same refusal path; framework
  default error pages are suppressed and the Server banner is neutral;
- the /offer body is a whitelist projection of the endpoint's offer:
  the public terms (resources, protocol, payment requirements, price
  schedule lines, pricing modes) plus identity and the patent_pending
  declaration. Internal narrative (activation gate, service view,
  derivation/basis text, queue and build references) is withheld;
- the /health body is replaced with a minimal liveness body;
- POST /crossing token-bucket rate limit (30/min sustained, burst 10,
  per source). The tunnel is raw TCP, so public sources collapse to
  the tunnel's loopback address: the limit therefore also acts as a
  global cap on public crossing attempts. That is the control against
  refusal-pair flooding (chain bloat via garbage crossings): attempts
  refused here never reach the endpoint and write no pair;
- request body cap 64 KiB; chunked request bodies refused;
- upstream 5xx bodies are replaced with a static named code: no
  exception text, file paths, or internals leave this surface;
- upstream connect/read timeout 60 s; client socket timeout 75 s.

Stdlib only. Binds localhost; the tunnel provides the public edge.
"""
import http.client, json, os, threading, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

UPSTREAM_HOST = "127.0.0.1"
UPSTREAM_PORT = int(os.environ.get("ME_UPSTREAM_PORT", "8794"))
# The 8374 router layer (ROUTER-V1, carried 2026-11-19 under
# BUILD-Q-54) is a sibling service on its own port; /router/*
# paths route to it, everything else to the governed endpoint.
# The router's operator route /router/settle-pair is NOT in the
# public set (same posture as the endpoint's /settle-pair), and
# /router/replay stays localhost-only.
ROUTER_UPSTREAM_PORT = int(os.environ.get("ME_ROUTER_UPSTREAM_PORT",
                                          "8797"))
PORT = int(os.environ.get("ME_PROXY_PORT", "8796"))
ALLOWED = {("GET", "/health"), ("GET", "/offer"), ("POST", "/crossing"),
           ("GET", "/crossing"), ("HEAD", "/crossing"),
           ("GET", "/openapi.json"), ("GET", "/.well-known/x402"),
           ("GET", "/.well-known/402index-verify.txt"),
           ("GET", "/inspect"),
           ("GET", "/"), ("GET", "/frozen-test"),
           ("GET", "/conformance"), ("GET", "/compare"),
           ("POST", "/router/register"), ("GET", "/router/catalog"),
           ("GET", "/router/provenance"), ("GET", "/router/quote"),
           ("POST", "/router/route"),
           ("GET", "/router/discovery/resources"),
           ("GET", "/router"), ("GET", "/router/"),
           ("GET", "/router/openapi.json")}
# GET routes whose query string is part of their form (a ?format=
# twin); every other route keeps the exact-match rule, query
# included. PAGE_ROUTES additionally negotiate their own
# Content-Type (HTML / markdown), passed through verbatim below.
QUERY_ROUTES = {"/inspect", "/frozen-test", "/conformance",
                "/router/catalog", "/router/provenance",
                "/router/quote", "/router/discovery/resources"}
PAGE_ROUTES = {"/inspect", "/", "/frozen-test", "/conformance",
               "/compare"}
MAX_BODY = 64 * 1024
RATE_PER_MIN = 30
RATE_BURST = 10
UPSTREAM_TIMEOUT = 60
PATENT_PENDING = ("U.S. Provisional Patent Application No. 64/198,910, "
                  "filed November 14, 2026 \u2014 patent pending. The "
                  "governed-crossing and receipt-pair mechanism served "
                  "by this endpoint is subject matter of the pending "
                  "application.")
HOP = {"host", "connection", "content-length", "keep-alive",
       "proxy-connection", "proxy-authorization", "te", "trailer",
       "transfer-encoding", "upgrade"}

_buckets = {}
_buckets_lock = threading.Lock()


def _rate_ok(source):
    now = time.monotonic()
    with _buckets_lock:
        tokens, last = _buckets.get(source, (float(RATE_BURST), now))
        tokens = min(float(RATE_BURST),
                     tokens + (now - last) * RATE_PER_MIN / 60.0)
        if tokens >= 1.0:
            _buckets[source] = (tokens - 1.0, now)
            return True
        _buckets[source] = (tokens, now)
        return False


def _project_offer(offer):
    """Whitelist projection of the endpoint's offer document to its
    public terms, plus the identity block and the patent_pending
    declaration. Withheld: activation_gate, service_view, project_id,
    suite, status, terms, provider contact/negotiating narrative,
    pricing derivation/basis/source text, accepts notes, protocol
    flow narrative."""
    out = {}
    for k in ("document", "version", "issued"):
        if k in offer:
            out[k] = offer[k]
    out["identity"] = {"designation": "8374", "form": "@8374",
                       "namespace": "8374@StegVerse.ai"}
    out["patent_pending"] = PATENT_PENDING
    prov = offer.get("provider") or {}
    out["provider"] = {k: prov[k] for k in ("legal_name", "role")
                       if k in prov}
    if "offered_resources" in offer:
        out["offered_resources"] = offer["offered_resources"]
    proto = offer.get("protocol") or {}
    out["protocol"] = {k: proto[k] for k in
                       ("primary_dialect", "alternate_dialect", "scheme",
                        "transport", "x402Version") if k in proto}
    pr = offer.get("payment_requirements") or {}
    accepts = []
    for a in pr.get("accepts") or []:
        acc = {k: a[k] for k in ("scheme", "network", "asset", "payTo",
                                 "resource", "mimeType",
                                 "maxTimeoutSeconds") if k in a}
        extra = a.get("extra") or {}
        acc["extra"] = {k: extra[k] for k in ("name", "version")
                        if k in extra}
        accepts.append(acc)
    out["payment_requirements"] = {"accepts": accepts}
    pricing = offer.get("pricing") or {}
    classes = []
    for c in pricing.get("classes") or []:
        cc = {}
        if "class" in c:
            cc["class"] = c["class"]
        if "lines" in c:
            cc["lines"] = c["lines"]
        if "tiers" in c:
            cc["tiers"] = [{k: t[k] for k in
                            ("tier", "status", "amount_micro_usdc",
                             "amount_usd", "unit", "price")
                            if k in t} for t in c["tiers"]]
        classes.append(cc)
    mode = pricing.get("pricing_mode") or {}
    out["pricing"] = {
        "classes": classes,
        "active_mode": mode.get("active_mode"),
        "fee_paid_either_way": mode.get("fee_paid_either_way"),
        "modes": [{k: m[k] for k in ("mode", "description", "active")
                   if k in m}
                  for m in mode.get("modes") or []],
    }
    return out


class H(BaseHTTPRequestHandler):
    server_version = "machine-economy"
    sys_version = ""
    timeout = 75

    def version_string(self):
        return "machine-economy"

    def log_message(self, *a):
        pass

    def send_error(self, code, message=None, explain=None):
        # Never emit the framework HTML error page on this surface.
        if code == 400:
            self._static(400, {"error": "bad request",
                               "failure_code": "PUBLIC_BAD_REQUEST"})
        else:
            self._static(404, {"error": "not found"})

    def _static(self, status, obj):
        b = json.dumps(obj).encode()
        try:
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(b)))
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(b)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _refuse(self):
        # Refusals are logged (shape only, never bodies) so a
        # rejected prober/client can be diagnosed from the journal —
        # added 2026-11-18 after a directory probe 404'd invisibly.
        try:
            print("refused:", self.command, self.path,
                  "| TE:", self.headers.get("Transfer-Encoding"),
                  "| CL:", self.headers.get("Content-Length"),
                  "| UA:", self.headers.get("User-Agent"),
                  flush=True)
        except Exception:  # noqa: BLE001
            pass
        self._static(404, {"error": "not found"})

    def _read_chunked(self):
        """Consume one chunked request body, bounded by MAX_BODY.
        Returns the reframed body bytes, or None on any malformed
        framing (the caller refuses). Trailers are discarded."""
        out = bytearray()
        while True:
            line = self.rfile.readline(64)
            if not line:
                return None
            try:
                size = int(line.strip().split(b";")[0], 16)
            except ValueError:
                return None
            if size < 0 or len(out) + size > MAX_BODY:
                return None
            if size == 0:
                while True:
                    t = self.rfile.readline(8192)
                    if t in (b"\r\n", b"\n", b""):
                        break
                return bytes(out)
            chunk = self.rfile.read(size)
            if len(chunk) != size:
                return None
            out += chunk
            if self.rfile.read(2) != b"\r\n":
                return None

    def _handle(self):
        path_only = self.path.split("?", 1)[0]
        # The QUERY_ROUTES carry a ?format= twin, so for them the
        # query string is part of the form; every other route keeps
        # the exact-match rule, query included.
        if (self.command, self.path) not in ALLOWED \
                and not (self.command == "GET"
                         and path_only in QUERY_ROUTES
                         and (self.command, path_only) in ALLOWED):
            self._refuse()
            return
        body = None
        if self.command == "POST":
            te = (self.headers.get("Transfer-Encoding") or "").lower()
            has_cl = self.headers.get("Content-Length") is not None
            if te == "chunked" and not has_cl:
                # The Cloudflare tunnel leg reframes body-less and
                # streamed requests as chunked (observed 2026-11-18:
                # empty POSTs arrived chunked and were refused,
                # breaking transport parity with the bore leg and
                # directory probes). Dechunk here, bounded, and
                # forward under our own Content-Length: the body is
                # fully consumed and reframed by this proxy, never
                # passed through framed by the sender.
                if not _rate_ok(self.client_address[0]):
                    self._static(429, {"error": "rate limited",
                                       "failure_code":
                                           "PUBLIC_RATE_LIMIT"})
                    return
                body = self._read_chunked()
                if body is None:
                    self._refuse()
                    return
            elif te and te != "identity":
                self._refuse()
                return
            else:
                try:
                    n = int(self.headers.get("Content-Length", 0))
                except (TypeError, ValueError):
                    self._refuse()
                    return
                if n < 0:
                    self._refuse()
                    return
                if n > MAX_BODY:
                    self._static(413, {"error": "request too large",
                                       "failure_code":
                                           "PUBLIC_BODY_TOO_LARGE"})
                    return
                if not _rate_ok(self.client_address[0]):
                    self._static(429, {"error": "rate limited",
                                       "failure_code":
                                           "PUBLIC_RATE_LIMIT"})
                    return
                body = self.rfile.read(n) if n else None
        headers = {k: v for k, v in self.headers.items()
                   if k.lower() not in HOP}
        upstream_port = ROUTER_UPSTREAM_PORT \
            if path_only == "/router" \
            or path_only.startswith("/router/") else UPSTREAM_PORT
        conn = http.client.HTTPConnection(UPSTREAM_HOST, upstream_port,
                                          timeout=UPSTREAM_TIMEOUT)
        try:
            conn.request(self.command, self.path, body=body,
                         headers=headers)
            resp = conn.getresponse()
            data = resp.read()
            status = resp.status
            resp_cl = resp.getheader("Content-Length")
            resp_ct = resp.getheader("Content-Type")
            resp_x402 = {h: resp.getheader(h) for h in
                         ("PAYMENT-REQUIRED", "PAYMENT-RESPONSE")}
        except Exception:
            self._static(502, {"error": "upstream unavailable",
                               "failure_code": "PUBLIC_UPSTREAM_UNAVAILABLE"})
            return
        finally:
            conn.close()
        if status >= 500:
            self._static(502, {"error": "upstream error",
                               "failure_code": "PUBLIC_UPSTREAM_ERROR"})
            return
        if self.path == "/health":
            self._static(200, {"status": "ok",
                               "service": "machine-economy-endpoint"})
            return
        if self.path == "/offer":
            try:
                projected = _project_offer(json.loads(data))
            except Exception:
                self._static(502, {"error": "upstream error",
                                   "failure_code": "PUBLIC_UPSTREAM_ERROR"})
                return
            self._static(200, projected)
            return
        if self.path == "/.well-known/x402":
            # Additive discovery (BUILD-Q-54 carry, 2026-11-19): the
            # public resource list also names the router catalog.
            # The endpoint's own document is unchanged; the router
            # catalog URL is appended here, at the public surface,
            # in the same projection posture as /offer above.
            try:
                doc = json.loads(data)
                resources = list(doc.get("resources") or [])
                origin = ""
                for r in resources:
                    if isinstance(r, str) and r.endswith("/crossing"):
                        origin = r[: -len("/crossing")]
                        break
                catalog_url = (origin or "https://8374.stegverse.org") \
                    + "/router/catalog"
                if catalog_url not in resources:
                    resources.append(catalog_url)
                doc["resources"] = resources
            except Exception:
                self._static(502, {"error": "upstream error",
                                   "failure_code": "PUBLIC_UPSTREAM_ERROR"})
                return
            self._static(200, doc)
            return
        # The caller's own response, verbatim. For HEAD the
        # upstream Content-Length is preserved (the body itself is
        # correctly empty), so a probe sees the challenge's shape.
        # The x402 v2 signaling headers ride with the response
        # (BUILD-Q-48): PAYMENT-REQUIRED on challenges,
        # PAYMENT-RESPONSE on settled crossings.
        try:
            self.send_response(status)
            # The page routes negotiate their own type (HTML page,
            # markdown document, or JSON twin); every other
            # verbatim response is JSON.
            if path_only in PAGE_ROUTES and resp_ct:
                self.send_header("Content-Type", resp_ct)
            else:
                self.send_header("Content-Type", "application/json")
            if self.command == "HEAD" and resp_cl:
                self.send_header("Content-Length", resp_cl)
            else:
                self.send_header("Content-Length", str(len(data)))
            for hname, hval in resp_x402.items():
                if hval:
                    self.send_header(hname, hval)
            self.end_headers()
            if data:
                self.wfile.write(data)
        except (BrokenPipeError, ConnectionResetError):
            pass

    do_GET = _handle
    do_POST = _handle
    do_PUT = _handle
    do_DELETE = _handle
    do_PATCH = _handle
    do_HEAD = _handle
    do_OPTIONS = _handle


if __name__ == "__main__":
    print(f"machine-economy public proxy on 127.0.0.1:{PORT} -> "
          f"http://{UPSTREAM_HOST}:{UPSTREAM_PORT}; "
          f"public paths: {sorted(ALLOWED)}")
    ThreadingHTTPServer(("127.0.0.1", PORT), H).serve_forever()
