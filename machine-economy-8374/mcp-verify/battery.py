#!/usr/bin/env python3
"""Execute the packaged MCP process; preserve transcript and exact acceptance."""
import argparse
import datetime
import hashlib
import json
import pathlib
import subprocess
import sys


def requests(absent_url):
    return [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
            "protocolVersion": "2025-11-25", "capabilities": {},
            "clientInfo": {"name": "q57-packaged-battery", "version": "0.1.0"}}},
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
        *[{"jsonrpc": "2.0", "id": i, "method": "tools/call", "params": {
            "name": "verify_x402_resource", "arguments": {"url": url}}}
          for i, url in enumerate([
              "https://8374.stegverse.org/crossing", absent_url,
              "ftp://invalid.example/resource"], 3)]
    ]


def evaluate(messages):
    by_id = {m.get("id"): m for m in messages}
    checks = {}
    checks["handshake"] = by_id.get(1, {}).get("result", {}).get("protocolVersion") == "2025-11-25"
    tools = by_id.get(2, {}).get("result", {}).get("tools", [])
    checks["single_tool"] = [t.get("name") for t in tools] == ["verify_x402_resource"]
    def upstream(i):
        return by_id.get(i, {}).get("result", {}).get("structuredContent", {}).get("result", {})
    own, absent, invalid = (upstream(i) for i in (3, 4, 5))
    checks["own_verified_match"] = (own.get("proof", {}).get("record_state") == "verified"
        and own.get("proof", {}).get("replay", {}).get("verdict") == "MATCH")
    proof = absent.get("proof", {})
    checks["listed_absence_bounded"] = (proof.get("record_state") == "none"
        and proof.get("publishes_replayable_record") is False
        and proof.get("negative_result") == "NOT_FOUND_IN_CHECKED_LOCATIONS"
        and isinstance(proof.get("checked"), list) and len(proof["checked"]) > 0)
    checks["invalid_url_structured_refusal"] = (
        invalid.get("failure_code") == "VERIFY_SSRF_REFUSED"
        and by_id.get(5, {}).get("result", {}).get("isError") is True)
    return checks


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--package", required=True, type=pathlib.Path)
    p.add_argument("--output", required=True, type=pathlib.Path)
    p.add_argument("--absent-url", default="https://verdict.scriptmasterlabs.com/seal")
    args = p.parse_args()
    reqs = requests(args.absent_url)
    payload = "".join(json.dumps(r) + "\n" for r in reqs)
    cmd = [sys.executable, "-I", "-B", str(args.package.resolve())]
    proc = subprocess.run(cmd, input=payload, text=True, capture_output=True, timeout=390)
    messages = [json.loads(line) for line in proc.stdout.splitlines()]
    checks = evaluate(messages)
    result = {"schema": "stegverse.q57-packaged-mcp-battery/v1",
              "executed_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
              "evidence_class": "PACKAGED_PROCESS_LIVE_CHECKER_ATTEMPT",
              "package_sha256": hashlib.sha256(args.package.read_bytes()).hexdigest(),
              "command": cmd, "requests": reqs, "responses": messages,
              "process_exit": proc.returncode, "stderr": proc.stderr,
              "checks": checks,
              "status": "PASS" if proc.returncode == 0 and all(checks.values()) else "NON_ALLOW"}
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"status": result["status"], "checks": checks}, sort_keys=True))
    return 0 if result["status"] == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
