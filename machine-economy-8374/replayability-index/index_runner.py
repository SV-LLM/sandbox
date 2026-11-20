#!/usr/bin/env python3
"""Q58: bounded public discovery + unpaid checker batches; stdlib only."""
import argparse
import collections
import concurrent.futures
import datetime
import fcntl
import hashlib
import html
import json
import pathlib
import time
import urllib.error
import urllib.parse
import urllib.request

CHECKER = "https://8374.stegverse.org/verify/check"
SOURCES = {
    "scriptmasterlabs": "https://scriptmasterlabs.com/x402-directory.json?limit=5&offset=0",
    "agora": "https://agora402.io/api/v1/discover?limit=5&offset=0",
    "x402-list": "https://x402-list.com/api/v1/services?limit=5&page=1",
    "402-index": "https://402index.io/api/v1/services?limit=5&page=1",
    "agent402": "https://agent402.tools/api/index",
    "cdp-bazaar": "https://api.cdp.coinbase.com/platform/v2/x402/discovery/resources?limit=5&offset=0"
}
CAP = 8 * 1024 * 1024


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args):
        return None


def read_json(url):
    req = urllib.request.Request(url, headers={"Accept": "application/json",
        "User-Agent": "8374-Replayability-Index/0.1"}, method="GET")
    try:
        try:
            response = urllib.request.build_opener(NoRedirect()).open(req, timeout=90)
        except urllib.error.HTTPError as exc:
            response = exc
        with response:
            body = response.read(CAP + 1)
            status = response.code
            retry_after = response.headers.get("Retry-After")
        if len(body) > CAP:
            return {"url":url,"received_at":now(),"http_status":status,
                    "failure_code":"PUBLIC_RESPONSE_TOO_LARGE","retry_after":retry_after}
        try:
            doc = json.loads(body)
        except (ValueError, RecursionError):
            return {"url":url,"received_at":now(),"http_status":status,
                    "failure_code":"PUBLIC_RESPONSE_NOT_JSON","retry_after":retry_after,
                    "body_sha256":hashlib.sha256(body).hexdigest(),"body_bytes":len(body)}
        return {"http_status": status, "received_at": now(), "url": url,
                "body_sha256": hashlib.sha256(body).hexdigest(),
                "body_bytes": len(body), "retry_after": retry_after, "document": doc}
    except (OSError, ValueError, RecursionError) as exc:
        return {"url": url, "received_at": now(), "failure_code": "PUBLIC_READ_UNAVAILABLE",
                "error_class": type(exc).__name__, "detail": str(exc)[:300]}


def valid_url(url):
    if not isinstance(url, str) or len(url) > 8192 or any(ord(c) < 32 for c in url):
        return False
    try:
        p = urllib.parse.urlsplit(url)
        return p.scheme in ("http", "https") and bool(p.hostname) and not p.username and not p.password
    except ValueError:
        return False


def terms(row):
    """Keep advertised units/alternatives as stated, without price conversions."""
    keys = ("price", "priceKnown", "currency", "network", "networks", "asset", "payTo",
            "payment", "pricing", "accepts", "amount", "maxAmountRequired", "amount_atomic", "payToByNetwork", "payTosByNetwork", "evmDomainByNetwork")
    return {k: row[k] for k in keys if k in row}


def extract(name, doc):
    if not isinstance(doc, dict):
        raise ValueError("catalog root is not an object")
    output = []
    def add(url, row, extra=None):
        if valid_url(url):
            output.append({"resource": url, "source": name,
                           "advertised_terms": terms(row), **(extra or {})})
    if name == "agent402":
        rows = doc.get("sellers")
        if not isinstance(rows, list):
            raise ValueError("sellers array absent")
        for seller in rows:
            if not isinstance(seller, dict): continue
            base = seller.get("homepage") if seller.get("origin") == "self" else seller.get("origin")
            if not valid_url(base): base = seller.get("homepage")
            tools = seller.get("tools", [])
            if not isinstance(tools, list):
                raise ValueError("seller tools is not an array")
            for tool in tools:
                if not isinstance(tool, dict): continue
                url = tool.get("url")
                if not url and valid_url(base) and isinstance(tool.get("route"), str):
                    url = urllib.parse.urljoin(base, tool["route"])
                add(url, tool, {"seller_advertised_terms": terms(seller)})
        return output
    key = {"scriptmasterlabs": "resources", "agora": "agents", "cdp-bazaar": "items"}.get(name)
    if key:
        rows = doc.get(key)
    else:
        rows = next((doc[k] for k in ("services", "data", "items", "results")
                     if isinstance(doc.get(k), list)), None)
    if not isinstance(rows, list):
        raise ValueError("recognized listing array absent")
    for row in rows:
        if not isinstance(row, dict): continue
        url = row.get("resource") or row.get("url") or row.get("endpoint") or row.get("base_url")
        if isinstance(url, dict): url = url.get("url")
        add(url, row)
    return output


def enumerate_catalogs(reader=read_json):
    reports = []
    candidates = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
        observed_pages = list(pool.map(reader, SOURCES.values()))
    for (name, url), observed in zip(SOURCES.items(), observed_pages):
        doc = observed.get("document")
        report = {k: v for k, v in observed.items() if k != "document"}
        report["source"] = name
        report["coverage"] = "SINGLE_REQUESTED_PAGE_NOT_FULL_DIRECTORY"
        report["pagination_as_published"] = ({k: doc[k] for k in
            ("pagination", "meta", "total", "count", "offset", "complete", "page", "pages", "sellerCount")
            if k in doc} if isinstance(doc, dict) else {})
        try:
            if observed.get("http_status") != 200:
                raise ValueError("catalog did not return HTTP200")
            rows = extract(name, doc)
            if not rows and any(isinstance(doc.get(k), list) and doc[k] for k in ("sellers","services","data","items","results","resources","agents")):
                raise ValueError("nonempty listing page yielded no recognized resource URL; not empty")
            report["rows_extracted"] = len(rows)
            report["state"] = "PAGE_ENUMERATED"
            candidates[name] = rows
        except ValueError as exc:
            report["state"] = "UNAVAILABLE_OR_UNRECOGNIZED_NOT_EMPTY"
            report["failed_predicate"] = str(exc)
            candidates[name] = []
        reports.append(report)
    # Round-robin prevents one large feed taking the whole first edition.
    merged = {}
    maximum = max((len(v) for v in candidates.values()), default=0)
    ordered = []
    for i in range(maximum):
        for name in SOURCES:
            if i >= len(candidates[name]): continue
            row = candidates[name][i]
            url = row["resource"]
            if url not in merged:
                merged[url] = {"resource": url, "advertisements": []}
                ordered.append(merged[url])
            merged[url]["advertisements"].append(row)
    return reports, ordered


def verdict(observation):
    if observation.get("http_status") != 200:
        return "REFUSED_OR_ERROR"
    doc = observation.get("document")
    if not isinstance(doc, dict): return "UNKNOWN"
    p = doc.get("proof")
    if not isinstance(p, dict): return "UNKNOWN"
    state = p.get("record_state")
    replay = p.get("replay")
    if state == "verified" and isinstance(replay, dict) and replay.get("verdict") == "MATCH":
        return "CHECKER_VERIFIED_MATCH"
    if state in ("asserted", "discovered"):
        return "RECORD_PRESENT_NOT_RECOMPUTED"
    if state == "validation_failed": return "RECORD_VALIDATION_FAILED"
    if (state == "none" and p.get("publishes_replayable_record") is False
            and p.get("negative_result") == "NOT_FOUND_IN_CHECKED_LOCATIONS"
            and isinstance(p.get("checked"), list) and len(p["checked"]) > 0):
        return "ABSENT_IN_CHECKED_LOCATIONS"
    return "UNKNOWN"


def probe(rows, limit=12, reader=read_json, at=None):
    if type(limit) is not int or not 1 <= limit <= 20:
        raise ValueError("batch limit must be1..20; no implicit unlimited run")
    epoch = time.time() if at is None else at
    checked = []
    for row in rows[:limit]:
        target = row["resource"]
        url = CHECKER + "?" + urllib.parse.urlencode({"url": target})
        observation = reader(url)
        checked.append({**row, "checker_observation": observation,
            "verdict": verdict(observation),
            "verify_permalink": "https://8374.stegverse.org/verify?" + urllib.parse.urlencode({"url": target}),
            "evidence_class": "CHECKER_OBSERVATION_NOT_INDEPENDENT_INDEX_REPLAY"})
        if observation.get("http_status") == 429:
            break
    return checked, {"attempts": len(checked), "remaining_selected_inputs": len(rows) - len(checked),
                     "next_not_before_epoch": epoch + 60,
                     "rate_policy": "MAX20CHECKER_CALLS_PER60SECOND_BATCH_NO_SLEEP_NO_RETRIES"}


def render(report):
    escape = lambda x: html.escape(str(x), quote=True)
    rows = []
    for row in report["rows"]:
        obs = row["checker_observation"]
        doc = obs.get("document") if isinstance(obs.get("document"), dict) else {}
        p = doc.get("proof", {})
        rows.append("<tr><td><a href='" + escape(row["verify_permalink"]) + "'>" + escape(row["resource"])
            + "</a></td><td><pre>" + escape(json.dumps(row["advertisements"], ensure_ascii=False))
            + "</pre></td><td>" + escape(row["verdict"]) + "<br>" + escape(obs.get("received_at"))
            + "</td><td><pre>" + escape(json.dumps(p.get("checked", []), ensure_ascii=False)) + "</pre></td></tr>")
    return ("<!doctype html><html lang='en'><meta charset='utf-8'><meta name='viewport' content='width=device-width'>"
        "<title>8374 Replayability Index — bounded first edition</title><style>body{font:16px system-ui;max-width:1100px;margin:auto;padding:16px}"
        "table{border-collapse:collapse;width:100%}td,th{border:1px solid #bbb;padding:8px;vertical-align:top}pre{white-space:pre-wrap;overflow-wrap:anywhere}"
        "a{overflow-wrap:anywhere}</style><h1>Replayability Index — first edition</h1><p>" + escape(report["scope"])
        + "</p><p>Generated " + escape(report["generated_at"]) + "; " + str(len(report["rows"])) + " rows. Counts: "
        + escape(json.dumps(report["verdict_distribution"])) + "</p><p>Advertised terms are catalog claims with original units. "
        "Checker observations are time-bound. Hash integrity does not prove assertion truth; an absence verdict covers only listed locations. "
        "This is not a market-wide census, certification, payment or revenue evidence.</p><h2>Discovery coverage</h2><pre>"
        + escape(json.dumps(report["discovery_sources"], indent=2)) + "</pre><table><tr><th>Resource / live check</th>"
        "<th>Advertisements as listed</th><th>Observed verdict / date</th><th>Locations checked</th></tr>" + "".join(rows) + "</table></html>")


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--output", type=pathlib.Path, required=True)
    p.add_argument("--limit", type=int, default=14)
    args = p.parse_args()
    if not 1 <= args.limit <= 20: p.error("limit must be1..20")
    args.output.mkdir(parents=True, exist_ok=True)
    lock = (args.output / "batch.lock").open("a")
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        print(json.dumps({"failure_code":"CHECKER_BATCH_ALREADY_RUNNING","next_attempt":"after existing process exits"}))
        return 2
    checkpoint = args.output / "checkpoint.json"
    if checkpoint.exists():
        prior = json.loads(checkpoint.read_text())
        if time.time() < prior["next_not_before_epoch"]:
            print(json.dumps({"failure_code": "CHECKER_BATCH_WINDOW_NOT_REOPENED", "next_attempt": prior["next_not_before_epoch"]}))
            return 2
    # Reserve the batch window before any checker call, including crash cases.
    checkpoint.write_text(json.dumps({"next_not_before_epoch": time.time()+3600,
                                     "reservation":"crash-safe maximum-run hold; replaced after normal close"}) + "\n")
    sources, candidates = enumerate_catalogs()
    selected = candidates[:args.limit]
    rows, rate = probe(selected, args.limit)
    rate["next_not_before_epoch"] = time.time() + 60
    report = {"schema": "stegverse.replayability-index/v1", "generated_at": now(),
        "scope": "Bounded first edition: one requested page per named discovery door; first" + str(args.limit)
            + " distinct public URLs in deterministic round-robin order. No global enumeration/absence claim.",
        "discovery_sources": sources, "distinct_enumerated_urls": len(candidates),
        "selection_limit": args.limit, "rows": rows, "batch": rate,
        "verdict_distribution": dict(collections.Counter(r["verdict"] for r in rows)),
        "publication_state": "FILED_REPORT_ORIGIN_PUBLICATION_NOT_PERFORMED",
        "authority": "NONE", "native_goal_task_id": None}
    (args.output / "index.json").write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n")
    (args.output / "index.html").write_text(render(report))
    checkpoint.write_text(json.dumps(rate) + "\n")
    print(json.dumps({"rows":len(rows),"distribution":report["verdict_distribution"],"enumerated":len(candidates)}))
    return 0 if rows else 2


if __name__ == "__main__":
    raise SystemExit(main())
