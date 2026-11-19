#!/usr/bin/env python3
"""Verify-any-row service for 8374 (VERIFY-PAGE-01, 2026-11-19).

Public question this service answers, for any x402 resource URL:
what PROOF does that resource publish? Every other row in the
aggregator feeds is a claim; this page turns each row into a check.

    GET /verify            -> the page (HTML): a URL input wired to
                              the check API, 8374's own verification
                              rendered live, and a side-by-side of
                              sample rows drawn live from the
                              ScriptMasterLabs machine feed (the
                              router's own discovery feed is the
                              fallback source).
    GET /verify/check?url= -> the check (JSON):
        {resource, origin, terms, proof: {publishes_replayable_
        record, record_state, evidence[], checked[]}, verdict}
        record_state distinguishes discovery from validation:
        verified (a published replay document with verdict MATCH
        and a well-formed 64-hex terminal anchor), discovered (a
        record structure whose entries carry valid, non-zero tx
        hashes, with no replay validation published),
        validation_failed (a replay document is published but its
        verdict is not MATCH and/or its anchor is malformed -- the
        record does NOT validate), or none. Entry-level evidence
        counts only valid, non-zero tx hashes: an empty entry or
        an all-zero hash is not evidence.
    GET /health            -> {"status": "ok", ...}

Probe set for a resource (the checked list names every location
actually probed, with its outcome):
  1. the resource itself, unpaid (GET, then POST {} if GET does not
     answer 402) -- the 402 challenge body (or the v2
     PAYMENT-REQUIRED header) carries the terms and may carry
     proof material;
  2. <origin>/.well-known/x402;
  3. <origin>/openapi.json;
  4. any provenance / replay / receipt / inspect / proof locations
     those documents NAME -- followed one level, at most 3.

Honesty both ways: genuine proof material published by any service
is shown as found; absence is reported as "publishes no replayable
transaction record" WITH the checked list -- the absence is
evidenced, not asserted. Discovery metadata (extensions.bazaar) is
reported as what it is -- discovery metadata, not a transaction
record.

8374's own origin is the one loopback exception: it is served from
the origin's local surfaces (endpoint /inspect + /replay, router
/provenance on 127.0.0.1) and its proof verdict is the REAL replay,
computed at request time -- pairs, terminal anchor, settled pairs
with tx hashes, verdict -- never hardcoded.

SSRF discipline (this is a public fetcher):
  - http/https only; no URL credentials; metadata hostnames refused;
  - every target hostname is resolved and EVERY resolved address is
    checked against refused ranges (loopback, private, link-local,
    CGNAT, documentation, multicast, reserved; IPv6 equivalents)
    before any fetch; any refused address refuses the fetch;
  - redirects are followed manually, at most 3, re-validating each
    hop; POST probes are not redirected;
  - 10 s timeout per attempt; 512 KB response cap per probe;
  - /verify/check is rate-limited per source IP (30/min sustained,
    burst 30) with a plain 429.
  Note on this node's DNS: public names resolve locally to
  198.18.0.0/15 shadow addresses assigned by the egress layer; the
  connection itself transits the node's CONNECT egress proxy, which
  resolves independently. Literal-IP targets and locally-resolvable
  names (hosts file, localhost) are checked against the real
  addresses above, which is where the refusal bites.
  VERIFY_FIXTURE_ORIGINS (battery-only) names exact origins exempt
  from the address refusal so local specimen sellers can be
  checked; it is empty in production.

Egress: all non-local fetches transit the node's hatch egress
CONNECT proxy, discovered at call time (this process's env, then a
/proc scan, then the bare proxy address) and never stored -- the
house pattern (settlement.py). Stdlib only.
"""
import base64, html, ipaddress, json, os, re, socket, threading, time
import urllib.error, urllib.parse, urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = int(os.environ.get("VERIFY_PORT", "8798"))
OWN_ORIGIN = os.environ.get("VERIFY_OWN_ORIGIN",
                            "https://8374.stegverse.org").rstrip("/")
ENDPOINT_LOCAL = os.environ.get("VERIFY_ENDPOINT_LOCAL",
                                "http://127.0.0.1:8794").rstrip("/")
ROUTER_LOCAL = os.environ.get("VERIFY_ROUTER_LOCAL",
                              "http://127.0.0.1:8797").rstrip("/")
SML_FEED = os.environ.get(
    "VERIFY_SML_FEED",
    "https://scriptmasterlabs.com/x402-directory.json?limit=100&offset=0")
FIXTURE_ORIGINS = {o.rstrip("/") for o in
                   os.environ.get("VERIFY_FIXTURE_ORIGINS",
                                  "").split(",") if o.strip()}
PATENT_PENDING = ("U.S. Provisional Patent Application No. "
                  "64/198,910, filed November 14, 2026 \u2014 patent "
                  "pending.")
MAX_BODY = 512 * 1024
TIMEOUT = 10
MAX_REDIRECTS = 3
RATE_PER_MIN = 30
RATE_BURST = 30
UA = ("Mozilla/5.0 (compatible; 8374Verify/1.0; "
      "+https://8374.stegverse.org/verify)")
TX_RE = re.compile(r"0x[0-9a-fA-F]{64}")
HASH64_RE = re.compile(r"^0x[0-9a-fA-F]{64}$")
ANCHOR_RE = re.compile(r"^(0x)?[0-9a-fA-F]{64}$")
ZERO_TX_HASH = "0x" + "0" * 64


def _valid_tx_hash(v):
    """A syntactically valid AND non-zero transaction hash. The
    all-zero hash is a placeholder, not evidence of a settlement."""
    return isinstance(v, str) and bool(HASH64_RE.match(v)) \
        and v.lower() != ZERO_TX_HASH


def _entry_tx_hash(entry):
    """The valid non-zero tx hash an entry carries in a hash field
    (tx_hash / txHash / transaction_hash / hash), in a nested
    settlement object, or as the entry itself; None when the entry
    carries none. An empty object, or an entry whose only hash is
    the all-zero placeholder, carries NO evidence."""
    if isinstance(entry, str):
        return entry if _valid_tx_hash(entry) else None
    if isinstance(entry, dict):
        containers = [entry]
        s = entry.get("settlement")
        if isinstance(s, dict):
            containers.append(s)
        for cont in containers:
            for k, v in cont.items():
                kl = k.lower()
                if (("tx" in kl and "hash" in kl) or kl == "hash") \
                        and _valid_tx_hash(v):
                    return v
    return None
PROOF_PATH_RE = re.compile(
    r"(replay|provenance|receipt|inspect|proof|verify)", re.I)
METADATA_HOSTS = {"metadata.google.internal", "metadata.google",
                  "instance-data", "instance-data-compute"}

REFUSED_NETS = []
for _cidr in ("0.0.0.0/8", "127.0.0.0/8", "10.0.0.0/8",
              "100.64.0.0/10", "169.254.0.0/16", "172.16.0.0/12",
              "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24",
              "192.168.0.0/16", "198.51.100.0/24", "203.0.113.0/24",
              "224.0.0.0/4", "240.0.0.0/4",
              "::/128", "::1/128", "100::/64", "2001::/32",
              "2001:db8::/32", "fc00::/7", "fe80::/10", "ff00::/8"):
    REFUSED_NETS.append(ipaddress.ip_network(_cidr))


# ---------------- egress proxy discovery (house pattern) ----------
def _proxy_candidates():
    out = []
    for k in ("https_proxy", "HTTPS_PROXY", "http_proxy", "HTTP_PROXY"):
        v = os.environ.get(k)
        if v and "hatch-egress-proxy" in v:
            out.append(v)
    try:
        for pid in os.listdir("/proc"):
            if not pid.isdigit():
                continue
            try:
                with open(f"/proc/{pid}/environ", "rb") as f:
                    env = f.read().decode(errors="replace")
                for kv in env.split("\0"):
                    key, _, val = kv.partition("=")
                    if key in ("https_proxy", "HTTPS_PROXY") \
                            and "hatch-egress-proxy" in val:
                        out.append(val)
            except OSError:
                continue
    except OSError:
        pass
    out.append("http://hatch-egress-proxy:3128")
    seen, uniq = set(), []
    for p in out:
        if p not in seen:
            seen.add(p)
            uniq.append(p)
    return uniq


def _opener(proxy):
    if proxy:
        return urllib.request.build_opener(
            urllib.request.ProxyHandler({"http": proxy,
                                         "https": proxy}),
            _NoRedirect())
    return urllib.request.build_opener(_NoRedirect())


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


# ---------------- SSRF validation ----------------------------------
class SSRFRefusal(Exception):
    pass


def _origin_of(url):
    p = urllib.parse.urlparse(url)
    if not p.hostname:
        return None
    port = p.port
    default = 443 if p.scheme == "https" else 80
    netloc = p.hostname.lower()
    if port and port != default:
        netloc += f":{port}"
    return f"{p.scheme}://{netloc}"


def validate_target(url):
    """Raise SSRFRefusal unless the URL is a fetchable public
    target. Returns the parsed URL. Fixture origins (battery-only)
    skip the address refusal only."""
    p = urllib.parse.urlparse(url)
    if p.scheme not in ("http", "https"):
        raise SSRFRefusal(
            f"scheme {p.scheme or '(none)'} refused: http/https only")
    if p.username or p.password:
        raise SSRFRefusal("URLs with credentials are refused")
    host = (p.hostname or "").lower()
    if not host:
        raise SSRFRefusal("URL has no host")
    if host in METADATA_HOSTS:
        raise SSRFRefusal(f"host {host} refused: metadata address")
    origin = _origin_of(url)
    if origin in FIXTURE_ORIGINS:
        return p
    try:
        literal = ipaddress.ip_address(host)
        addrs = [literal]
    except ValueError:
        try:
            infos = socket.getaddrinfo(host, None)
        except OSError as e:
            raise SSRFRefusal(f"host {host} does not resolve: {e}")
        addrs = []
        for info in infos:
            try:
                addrs.append(ipaddress.ip_address(info[4][0]))
            except ValueError:
                continue
        if not addrs:
            raise SSRFRefusal(f"host {host} does not resolve")
    for a in addrs:
        for net in REFUSED_NETS:
            if a in net:
                raise SSRFRefusal(
                    f"target address {a} refused: {net} is a "
                    "loopback/private/link-local/reserved range")
    return p


# ---------------- fetch ---------------------------------------------
class FetchResult:
    def __init__(self, status=None, headers=None, body=b"",
                 final_url=None, error=None, truncated=False):
        self.status = status
        self.headers = headers or {}
        self.body = body
        self.final_url = final_url
        self.error = error
        self.truncated = truncated

    def json(self):
        try:
            return json.loads(self.body.decode("utf-8", "replace"))
        except Exception:
            return None


def _one_attempt(url, method, body, proxy):
    req = urllib.request.Request(url, data=body, method=method)
    req.add_header("User-Agent", UA)
    req.add_header("Accept", "application/json, text/html;q=0.5, */*;q=0.1")
    if body is not None:
        req.add_header("Content-Type", "application/json")
    opener = _opener(proxy)
    try:
        with opener.open(req, timeout=TIMEOUT) as r:
            raw = r.read(MAX_BODY + 1)
            return FetchResult(
                status=r.status,
                headers={k.lower(): v for k, v in r.headers.items()},
                body=raw[:MAX_BODY], final_url=url,
                truncated=len(raw) > MAX_BODY)
    except urllib.error.HTTPError as e:
        try:
            raw = e.read(MAX_BODY + 1)
        except Exception:
            raw = b""
        return FetchResult(
            status=e.code,
            headers={k.lower(): v for k, v in
                     (e.headers.items() if e.headers else [])},
            body=raw[:MAX_BODY], final_url=url,
            truncated=len(raw) > MAX_BODY)
    except Exception as e:  # transport failure on this candidate
        return FetchResult(error=f"{type(e).__name__}: {e}",
                           final_url=url)


def fetch(url, method="GET", body=None, follow_redirects=True):
    """Validated fetch through the egress proxy candidates.
    Redirects (GET only) are followed manually, re-validating each
    hop. Returns a FetchResult; SSRFRefusal propagates."""
    validate_target(url)
    current, redirects = url, 0
    while True:
        result = None
        for proxy in _proxy_candidates() + [None]:
            result = _one_attempt(current, method, body, proxy)
            if result.error is None:
                break
        if result is None or result.error is not None:
            return result or FetchResult(error="no egress candidate",
                                         final_url=current)
        if follow_redirects and method == "GET" \
                and result.status in (301, 302, 303, 307, 308):
            loc = result.headers.get("location")
            if not loc:
                return result
            redirects += 1
            if redirects > MAX_REDIRECTS:
                return FetchResult(
                    status=result.status, final_url=current,
                    error=f"more than {MAX_REDIRECTS} redirects")
            nxt = urllib.parse.urljoin(current, loc)
            validate_target(nxt)  # re-check each hop: no rebinding
            current = nxt
            result.final_url = current
            continue
        result.final_url = current
        return result


def fetch_local(url):
    """Direct localhost fetch for our own origin's local surfaces
    (the one loopback exception) and the router discovery fallback.
    No proxy, no redirect following beyond one hop."""
    req = urllib.request.Request(url, method="GET")
    req.add_header("User-Agent", UA)
    req.add_header("Accept", "application/json")
    opener = urllib.request.build_opener(_NoRedirect())
    try:
        with opener.open(req, timeout=TIMEOUT) as r:
            raw = r.read(MAX_BODY + 1)
            return FetchResult(status=r.status, body=raw[:MAX_BODY],
                               final_url=url,
                               truncated=len(raw) > MAX_BODY)
    except urllib.error.HTTPError as e:
        try:
            raw = e.read(MAX_BODY + 1)
        except Exception:
            raw = b""
        return FetchResult(status=e.code, body=raw[:MAX_BODY],
                           final_url=url,
                           truncated=len(raw) > MAX_BODY)
    except Exception as e:
        return FetchResult(error=f"{type(e).__name__}: {e}",
                           final_url=url)


# ---------------- proof scanning ------------------------------------
def _walk_strings(obj, path=""):
    if isinstance(obj, str):
        yield path, obj
    elif isinstance(obj, dict):
        for k, v in obj.items():
            yield from _walk_strings(v, f"{path}.{k}")
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield from _walk_strings(v, f"{path}[{i}]")


def _named_proof_urls(doc, origin):
    """URLs a document NAMES as proof locations: any string value
    that is an http(s) URL whose path matches the proof pattern,
    plus URL values under proof-named keys."""
    out = []
    for path, s in _walk_strings(doc):
        if not (s.startswith("http://") or s.startswith("https://")):
            continue
        u = urllib.parse.urlparse(s)
        key_proof = bool(PROOF_PATH_RE.search(path))
        path_proof = bool(PROOF_PATH_RE.search(u.path or ""))
        if key_proof or path_proof:
            if s not in out:
                out.append(s)
    return out[:3]


# Record validation states. Discovery (finding a record
# structure) and validation (the record's own published replay
# checks out) are different findings and are reported differently:
#   verified          -- a replay document whose published verdict
#                        is MATCH and whose terminal anchor is a
#                        well-formed 64-hex hash;
#   discovered        -- a record structure whose entries carry
#                        valid, non-zero tx hashes, but which
#                        publishes no replay validation;
#   validation_failed -- a replay document is published, but its
#                        verdict is not MATCH and/or its terminal
#                        anchor is not a 64-hex hash: the record
#                        does NOT validate.
_STATE_RANK = {"none": 0, "validation_failed": 1, "discovered": 2,
               "verified": 3}


def _merge_record_state(state, finding):
    if finding and _STATE_RANK[finding["state"]] \
            > _STATE_RANK[state["record_state"]]:
        state["record_state"] = finding["state"]


def _chain_content(doc):
    """Does this JSON document itself present a transaction record?
    Returns {"description", "state", "verdict"} or None. Entry-level
    evidence counts only entries carrying a syntactically valid,
    non-zero tx hash in a hash field (or as the entry itself): an
    empty entry, or one carrying only the all-zero hash, is not
    evidence. A bare hash somewhere in a document (an identity
    registration, a schema example) is NOT a replayable record of
    the resource's transactions and never counts here."""
    if not isinstance(doc, dict):
        return None
    verdict = doc.get("verdict") or doc.get("replay_verdict")
    pairs = doc.get("pairs")
    anchor = doc.get("terminal_anchor")
    if verdict and pairs is not None and anchor:
        anchor_ok = isinstance(anchor, str) \
            and bool(ANCHOR_RE.match(anchor))
        if verdict == "MATCH" and anchor_ok:
            return {"description":
                    f"receipt-chain replay document: {pairs} "
                    f"pairs, verdict MATCH, terminal anchor "
                    f"{anchor} (anchor well-formed; published "
                    "replay validates)",
                    "state": "verified", "verdict": verdict}
        why = []
        if verdict != "MATCH":
            why.append(f"published replay verdict is {verdict}, "
                       "not MATCH")
        if not anchor_ok:
            why.append("terminal anchor is not a 64-hex hash")
        return {"description":
                f"receipt-chain replay document: {pairs} pairs, "
                f"verdict {verdict}, terminal anchor {anchor} "
                f"-- replay does NOT validate ({'; '.join(why)})",
                "state": "validation_failed", "verdict": verdict}
    se = doc.get("settlement_evidence")
    if isinstance(se, dict) \
            and isinstance(se.get("settled_pairs"), list) \
            and se["settled_pairs"]:
        settled = se["settled_pairs"]
        n = sum(1 for e in settled if _entry_tx_hash(e))
        if n:
            return {"description":
                    f"settlement evidence: {n} of {len(settled)} "
                    "settled pair entries carry valid tx hashes",
                    "state": "discovered", "verdict": None}
    for key in ("receipts", "settled_pairs", "settlements",
                "transactions", "pairs"):
        val = doc.get(key)
        if isinstance(val, list) and val:
            n = sum(1 for e in val if _entry_tx_hash(e))
            if n:
                return {"description":
                        f"'{key}' list: {n} of {len(val)} entr(ies) "
                        "carrying valid tx hashes",
                        "state": "discovered", "verdict": None}
    return None


def _loose_tx_note(doc):
    """Tx hashes present in a document that did NOT qualify as a
    replayable record -- reported factually, never counted."""
    if not isinstance(doc, dict):
        return None
    txs = set(TX_RE.findall(json.dumps(doc)))
    if txs:
        return (f"names {len(txs)} on-chain transaction hash(es) "
                "but presents no replayable record structure (no "
                "chain replay, no settlement-evidence list)")
    return None


def _terms_from_challenge(doc, headers):
    """Accepts terms from a 402 challenge body, or from the v2
    PAYMENT-REQUIRED header (base64 JSON) when the body is empty."""
    chal = doc if isinstance(doc, dict) else None
    if chal is None:
        hdr = headers.get("payment-required")
        if hdr:
            try:
                chal = json.loads(base64.b64decode(hdr))
            except Exception:
                chal = None
    if not isinstance(chal, dict):
        return None, None
    acc = (chal.get("accepts") or [{}])
    if not acc or not isinstance(acc[0], dict):
        return None, chal
    a = acc[0]
    amount = a.get("maxAmountRequired", a.get("amount"))
    terms = {"scheme": a.get("scheme"), "network": a.get("network"),
             "asset": a.get("asset"), "payTo": a.get("payTo"),
             "amount": str(amount) if amount is not None else None,
             "mimeType": a.get("mimeType")}
    if all(v is None for v in terms.values()):
        return None, chal
    return terms, chal


def _scan_doc(doc, label, origin, checked, evidence, state):
    """Scan one fetched document for proof material; record
    findings factually. state carries the running verdict flags."""
    if not isinstance(doc, dict):
        return
    if isinstance(doc.get("extensions"), dict) \
            and "bazaar" in doc["extensions"]:
        evidence.append(
            f"{label} carries extensions.bazaar (discovery "
            "metadata; not a transaction record)")
    found = _chain_content(doc)
    if found:
        evidence.append(f"{label}: {found['description']}")
        _merge_record_state(state, found)
    else:
        note = _loose_tx_note(doc)
        if note:
            evidence.append(f"{label} {note}")
    for u in _named_proof_urls(doc, origin):
        if u not in state["named"]:
            state["named"].append(u)


def check_generic(url):
    """The full check for any non-own origin. Raises SSRFRefusal."""
    p = validate_target(url)
    origin = _origin_of(url)
    checked, evidence = [], []
    state = {"record_state": "none", "named": []}
    terms = None

    # 1. the resource itself, unpaid
    r = fetch(url, "GET")
    used = "GET"
    if r.error:
        checked.append({"location": url,
                        "result": f"GET failed: {r.error}"})
    else:
        checked.append({"location": url,
                        "result": f"GET answered HTTP {r.status}"})
    if r.status != 402:
        r2 = fetch(url, "POST", body=b"{}")
        if r2.error:
            checked.append({"location": url,
                            "result": f"POST failed: {r2.error}"})
        else:
            checked.append({"location": url,
                            "result": f"POST (unpaid) answered "
                                      f"HTTP {r2.status}"})
            if r2.status == 402:
                r, used = r2, "POST"
    chal_doc = None
    if r.status == 402:
        terms, chal_doc = _terms_from_challenge(r.json(), r.headers)
        checked.append({"location": url,
                        "result": "402 challenge received via "
                                  f"{used}; terms "
                                  + ("recorded" if terms else
                                     "not parseable")})
        if chal_doc is not None:
            _scan_doc(chal_doc, "the 402 challenge", origin, checked,
                      evidence, state)
    else:
        doc = r.json()
        if doc is not None:
            _scan_doc(doc, "the resource response", origin, checked,
                      evidence, state)

    # 2 + 3. the origin's discovery documents
    for suffix, label in (("/.well-known/x402",
                           "origin /.well-known/x402"),
                          ("/openapi.json", "origin /openapi.json")):
        durl = origin + suffix
        d = fetch(durl, "GET")
        if d.error:
            checked.append({"location": durl,
                            "result": f"fetch failed: {d.error}"})
            continue
        checked.append({"location": durl,
                        "result": f"HTTP {d.status}"})
        doc = d.json()
        if doc is not None:
            _scan_doc(doc, label, origin, checked, evidence, state)

    # 4. named proof locations, one level
    for u in state["named"][:3]:
        if _origin_of(u) == OWN_ORIGIN:
            continue  # our own origin is checked from local surfaces
        try:
            d = fetch(u, "GET")
        except SSRFRefusal as e:
            checked.append({"location": u,
                            "result": f"named in a document; fetch "
                                      f"refused: {e}"})
            continue
        if d.error:
            checked.append({"location": u,
                            "result": f"named in a document; fetch "
                                      f"failed: {d.error}"})
            continue
        checked.append({"location": u,
                        "result": f"named in a document; HTTP "
                                  f"{d.status}"})
        doc = d.json()
        if doc is not None:
            found = _chain_content(doc)
            if found:
                evidence.append(f"GET {u}: {found['description']}")
                _merge_record_state(state, found)
            else:
                note = _loose_tx_note(doc)
                if note:
                    evidence.append(f"GET {u} {note}")

    rs = state["record_state"]
    proof = {"publishes_replayable_record":
             rs in ("verified", "discovered"),
             "record_state": rs,
             "evidence": evidence, "checked": checked}
    if rs == "verified":
        core = ("publishes a replayable transaction record -- "
                "its published replay validates (verdict MATCH, "
                "well-formed terminal anchor) (see evidence)")
    elif rs == "discovered":
        core = ("publishes a transaction record whose entries "
                "carry valid tx hashes, but publishes no replay "
                "validation for it -- record discovered, not "
                "verified (see evidence)")
    elif rs == "validation_failed":
        core = ("publishes a transaction record whose replay "
                "does NOT validate -- it is not a verified "
                "replayable record (see evidence)")
    else:
        core = None
    if terms and core:
        verdict = "x402 resource; " + core
    elif terms:
        verdict = ("x402 resource; publishes no replayable "
                   "transaction record -- the locations under "
                   "'checked' were probed and none presented one")
    elif core:
        verdict = ("no x402 terms found at this URL (no 402 "
                   "challenge answered); " + core)
    else:
        verdict = ("no x402 terms found at this URL (no 402 "
                   "challenge answered); publishes no replayable "
                   "transaction record -- see 'checked'")
    return {"resource": url, "origin": origin, "terms": terms,
            "proof": proof, "verdict": verdict}


# ---------------- our own origin (local surfaces) -------------------
def check_own(url):
    """8374's own origin, served from the local surfaces; the proof
    verdict is the real replay, computed at request time."""
    p = urllib.parse.urlparse(url)
    path = p.path or "/"
    checked, evidence = [], []
    terms = None
    # terms: unpaid challenge against the local surface for the path
    base = ROUTER_LOCAL if path.startswith("/router") \
        else ENDPOINT_LOCAL
    try:
        req = urllib.request.Request(base + path, data=b"{}",
                                     method="POST")
        req.add_header("User-Agent", UA)
        req.add_header("Content-Type", "application/json")
        opener = urllib.request.build_opener(_NoRedirect())
        try:
            with opener.open(req, timeout=TIMEOUT) as r:
                status, hdrs, raw = r.status, r.headers, \
                    r.read(MAX_BODY)
        except urllib.error.HTTPError as e:
            status, hdrs, raw = e.code, e.headers, \
                e.read(MAX_BODY)
        checked.append({"location": f"{OWN_ORIGIN}{path}",
                        "result": f"unpaid probe answered HTTP "
                                  f"{status} (served from the "
                                  "origin's local surface)"})
        if status == 402:
            doc = None
            try:
                doc = json.loads(raw)
            except Exception:
                pass
            terms, _c = _terms_from_challenge(
                doc, {k.lower(): v for k, v in hdrs.items()})
    except Exception as e:
        checked.append({"location": f"{OWN_ORIGIN}{path}",
                        "result": f"local probe failed: {e}"})
    # proof: the real replay + inspect, computed now
    replay = fetch_local(ENDPOINT_LOCAL + "/replay").json() or {}
    inspect = fetch_local(ENDPOINT_LOCAL +
                          "/inspect?format=json").json() or {}
    prov = fetch_local(ROUTER_LOCAL + "/router/provenance?origin=" +
                       urllib.parse.quote(OWN_ORIGIN, safe=""))
    prov = prov.json() or {}
    chain = inspect.get("receipt_chain") or {}
    settled = ((inspect.get("settlement_evidence") or {})
               .get("settled_pairs") or [])
    checked.append({
        "location": f"{OWN_ORIGIN}/inspect",
        "result": "receipt chain + settlement evidence read live "
                  "from the origin's local surface"})
    checked.append({
        "location": f"{OWN_ORIGIN}/router/provenance"
                      f"?origin={OWN_ORIGIN}",
        "result": "router provenance read live (recomputed from "
                  "the production receipt chain, read-only)"})
    pairs = replay.get("pairs", chain.get("pairs"))
    anchor = replay.get("terminal_anchor",
                        chain.get("terminal_anchor"))
    verdict_replay = replay.get("verdict",
                                chain.get("replay_verdict"))
    evidence.append(
        f"receipt chain replays {verdict_replay}: {pairs} pairs, "
        f"terminal anchor {anchor} (recomputed at request time)")
    n_settled_valid = sum(1 for e in settled if _entry_tx_hash(e))
    evidence.append(
        f"settlement evidence: {n_settled_valid} settled pairs "
        f"with valid tx hashes (of {len(settled)} published), "
        f"published at {OWN_ORIGIN}/inspect")
    prov_block = prov.get("provenance") or {}
    if prov_block:
        evidence.append(
            "router provenance: "
            f"{prov_block.get('pairs')} pairs, replay verdict "
            f"{prov_block.get('replay_verdict')}, status "
            f"{prov_block.get('status')}")
    proof = {"publishes_replayable_record":
             verdict_replay == "MATCH",
             "record_state": "verified" if verdict_replay == "MATCH"
             else "validation_failed",
             "replay": {"pairs": pairs,
                        "entries": replay.get("entries"),
                        "verdict": verdict_replay,
                        "terminal_anchor": anchor},
             "settled_pairs": settled,
             "evidence": evidence, "checked": checked}
    if terms:
        verdict = ("x402 resource; publishes a replayable "
                   "transaction record -- its receipt chain "
                   f"replays {verdict_replay} at {pairs} pairs "
                   "(see evidence)")
    else:
        verdict = ("8374 origin; publishes a replayable transaction "
                   f"record -- its receipt chain replays "
                   f"{verdict_replay} at {pairs} pairs (see "
                   "evidence); no 402 terms at this path")
    return {"resource": url, "origin": OWN_ORIGIN, "terms": terms,
            "proof": proof, "verdict": verdict}


def run_check(url):
    if _origin_of(url) == OWN_ORIGIN:
        return check_own(url)
    return check_generic(url)


# ---------------- side-by-side samples -------------------------------
_samples_cache = {"at": 0.0, "urls": [], "source": "none"}
_samples_lock = threading.Lock()
SAMPLES_TTL = 600


def _samples_from_sml():
    r = fetch(SML_FEED, "GET")
    doc = r.json()
    if not isinstance(doc, dict):
        return []
    urls, origins = [], set()
    for item in doc.get("resources") or []:
        if not isinstance(item, dict):
            continue
        if item.get("type") not in ("http", None):
            continue
        u = item.get("resource")
        if not isinstance(u, str) or not u.startswith("http"):
            continue
        o = _origin_of(u)
        if not o or o == OWN_ORIGIN or o in origins:
            continue
        origins.add(o)
        urls.append(u)
        if len(urls) >= 4:
            break
    return urls


def _samples_from_discovery():
    r = fetch_local(ROUTER_LOCAL +
                    "/router/discovery/resources?limit=100")
    doc = r.json()
    if not isinstance(doc, dict):
        return []
    urls, origins = [], set()
    for item in doc.get("items") or []:
        u = item.get("resource") if isinstance(item, dict) else None
        if not isinstance(u, str):
            continue
        o = _origin_of(u)
        if not o or o in origins:
            continue
        origins.add(o)
        urls.append(u)
        if len(urls) >= 5:
            break
    return urls


def get_samples():
    now = time.monotonic()
    with _samples_lock:
        if now - _samples_cache["at"] < SAMPLES_TTL \
                and _samples_cache["urls"]:
            return _samples_cache["urls"], _samples_cache["source"]
    urls = _samples_from_sml()
    source = "scriptmasterlabs"
    if not urls:
        urls = _samples_from_discovery()
        source = "router-discovery" if urls else "none"
    with _samples_lock:
        _samples_cache.update({"at": now, "urls": urls,
                               "source": source})
    return urls, source


# ---------------- page ----------------------------------------------
PAGE_CSS = ("body{font-family:system-ui,sans-serif;margin:2em auto;"
            "max-width:62em;padding:0 1em;line-height:1.45}"
            "table{border-collapse:collapse;margin:1em 0}"
            "td,th{border:1px solid #999;padding:.35em .6em;"
            "text-align:left;vertical-align:top}"
            "code{word-break:break-all}"
            "input{width:32em;max-width:90%}"
            ".muted{color:#555}")


def render_page():
    samples, source = get_samples()
    rows = ["https://8374.stegverse.org/crossing"] + samples
    src_note = {"scriptmasterlabs":
                "sample rows drawn live from the ScriptMasterLabs "
                "machine feed (scriptmasterlabs.com/"
                "x402-directory.json)",
                "router-discovery":
                "the aggregator feed was unreachable at render "
                "time; sample rows drawn from the 8374 router's "
                "own discovery feed",
                "none":
                "no sample feed was reachable at render time"}\
        .get(source, source)
    row_html = "\n".join(
        f"<tr data-url=\"{html.escape(u, quote=True)}\">"
        f"<td><code>{html.escape(u)}</code></td>"
        "<td class='terms'>checking&hellip;</td>"
        "<td class='proof'>&hellip;</td>"
        "<td class='verdict'>&hellip;</td></tr>" for u in rows)
    rows_json = json.dumps(rows)
    return f"""<!DOCTYPE html>
<html><head><meta charset='utf-8'>
<title>8374 -- verify any row</title>
<style>{PAGE_CSS}</style></head>
<body>
<h1>8374 -- verify any row</h1>
<p>Every row in the x402 aggregator feeds is a claim. This page
turns a row into a check: paste any x402 resource URL and see what
<strong>proof</strong> that resource publishes -- the terms from its
unpaid 402 challenge, and whether it publishes a replayable
transaction record (a receipt chain or settlement evidence a third
party can recompute). Checks run live at request time; when a
record is absent, the locations that were checked are named.</p>
<p>{PATENT_PENDING}</p>
<h2>Check a resource</h2>
<p><input id='u' type='text' placeholder='https://example.com/paid-resource'>
<button id='go'>Check</button></p>
<div id='out'></div>
<h2>8374 itself, live</h2>
<div id='own'>checking&hellip;</div>
<h2>Side by side</h2>
<p class='muted'>{html.escape(src_note)}. Every row below is
checked by the same API as the box above.</p>
<table><tr><th>resource</th><th>terms (unpaid 402 probe)</th>
<th>replayable record published</th><th>verdict</th></tr>
{row_html}
</table>
<p class='muted'>8374's own row is served from the origin's local
surfaces; its verdict is the real chain replay, recomputed at
request time. Source: <code>verify.py</code>, SV-LLM/sandbox
branch machine-economy-8374, machine-economy-8374/verify-page/.</p>
<script>
var ROWS = {rows_json};
function esc(s) {{ return String(s == null ? '' : s).replace(
  /[&<>"']/g, function(c) {{ return {{'&':'&amp;','<':'&lt;',
  '>':'&gt;','"':'&quot;',"'":'&#39;'}}[c]; }}); }}
function termsText(t) {{
  if (!t) return 'no 402 terms';
  return esc(t.scheme) + ' / ' + esc(t.network) + ' / amount ' +
    esc(t.amount) + ' / payTo ' + esc(t.payTo);
}}
function recordStateText(p) {{
  if (!p) return 'no';
  var rs = p.record_state;
  if (rs === 'verified') return 'yes -- verified (replay validates)';
  if (rs === 'discovered') return 'record found -- discovered, no replay validation published';
  if (rs === 'validation_failed') return 'record found -- replay FAILED validation';
  return p.publishes_replayable_record ? 'yes' : 'no';
}}
function showResult(el, d) {{
  var h = '<p><strong>' + esc(d.verdict) + '</strong></p>';
  if (d.proof) {{
    h += '<p>record state: <strong>' +
      esc(recordStateText(d.proof)) + '</strong></p>';
  }}
  if (d.proof && d.proof.replay) {{
    h += '<p>receipt chain: ' + esc(d.proof.replay.pairs) +
      ' pairs, replay ' + esc(d.proof.replay.verdict) +
      ', terminal anchor <code>' +
      esc(d.proof.replay.terminal_anchor) + '</code></p>';
  }}
  if (d.proof && d.proof.evidence && d.proof.evidence.length) {{
    h += '<ul>' + d.proof.evidence.map(function(e) {{
      return '<li>' + esc(e) + '</li>'; }}).join('') + '</ul>';
  }}
  if (d.proof && d.proof.checked) {{
    h += '<p class="muted">checked: ' + d.proof.checked.map(
      function(c) {{ return esc(c.location) + ' -- ' +
      esc(c.result); }}).join(' &middot; ') + '</p>';
  }}
  el.innerHTML = h;
}}
function check(url, el) {{
  fetch('/verify/check?url=' + encodeURIComponent(url))
    .then(function(r) {{ return r.json(); }})
    .then(function(d) {{ showResult(el, d); }})
    .catch(function(e) {{ el.textContent = 'check failed: ' + e; }});
}}
document.getElementById('go').addEventListener('click', function() {{
  var u = document.getElementById('u').value.trim();
  if (u) check(u, document.getElementById('out'));
}});
check(ROWS[0], document.getElementById('own'));
ROWS.forEach(function(u) {{
  var tr = document.querySelector('tr[data-url="' +
    CSS.escape(u) + '"]');
  if (!tr) return;
  fetch('/verify/check?url=' + encodeURIComponent(u))
    .then(function(r) {{ return r.json(); }})
    .then(function(d) {{
      tr.querySelector('.terms').textContent = termsText(d.terms);
      tr.querySelector('.proof').textContent =
        recordStateText(d.proof);
      tr.querySelector('.verdict').textContent = d.verdict || '';
    }})
    .catch(function(e) {{
      tr.querySelector('.verdict').textContent =
        'check failed: ' + e;
    }});
}});
</script>
</body></html>"""


# ---------------- HTTP surface ---------------------------------------
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


class H(BaseHTTPRequestHandler):
    server_version = "verify-page"
    sys_version = ""
    timeout = 75

    def version_string(self):
        return "verify-page"

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
        self._send(status, json.dumps(obj),
                   "application/json")

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if path == "/health":
            self._json(200, {"status": "ok",
                             "service": "verify-page"})
            return
        if path == "/verify":
            self._send(200, render_page(),
                       "text/html; charset=utf-8")
            return
        if path == "/verify/check":
            if not _rate_ok(self.client_address[0]):
                self._json(429, {"error": "rate limited",
                                 "failure_code": "VERIFY_RATE_LIMIT"})
                return
            qs = urllib.parse.parse_qs(
                urllib.parse.urlparse(self.path).query)
            url = (qs.get("url") or [""])[0].strip()
            if not url:
                self._json(400, {"error": "url query parameter "
                                          "required",
                                 "failure_code": "VERIFY_URL_REQUIRED"})
                return
            try:
                self._json(200, run_check(url))
            except SSRFRefusal as e:
                self._json(400, {"resource": url,
                                 "error": "target refused",
                                 "failure_code": "VERIFY_SSRF_REFUSED",
                                 "reason": str(e)})
            except Exception as e:  # never crash on a bad target
                self._json(502, {"resource": url,
                                 "error": "check failed",
                                 "failure_code": "VERIFY_CHECK_FAILED",
                                 "reason": f"{type(e).__name__}: {e}"})
            return
        self._json(404, {"error": "not found"})

    do_HEAD = do_GET


if __name__ == "__main__":
    print(f"verify-page on 127.0.0.1:{PORT} "
          f"(own origin {OWN_ORIGIN})")
    ThreadingHTTPServer(("127.0.0.1", PORT), H).serve_forever()
