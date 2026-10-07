"""Sandbox adapter for the vendored StegBrowser llm.v1 profile.

Path: admitted Sandbox work -> pre-invocation binding checks -> StegBrowser
llm.v1 (fresh Chromium context, ordinary HTTPS, context destroyed) -> local
ALLOW/DENY/FAIL_CLOSED -> SANDBOX_TOOL_OBSERVATION_RECORDED. No LLM-adapter hop
and no InTr hop: ordinary HTTPS is not an inter-organization transition.

Every attempt is recorded, including a Sandbox-side DENY before StegBrowser
runs. The browser session is ephemeral; the Sandbox ledgers are not.

The invocation is admitted data. It lives in the work object at
manifested_request.tool_invocations[] as:
  {invocation_id, tool: "StegBrowser", profile: "llm.v1", prompt, secure_url,
   allowed_origins: [hostname | "*.suffix"], browser_actions: [...],
   response_marker, lease_seconds?: 1..900, provider?, model?}
Sandbox issues the StegBrowser lease from those values (task_id = work_id).
A caller may propose prompt, secure_url or lease only to have them checked
against the admitted values; a caller lease is never used.

A browser result is a tool observation, not an entity contribution: provider
and model are manifest labels, not attestation, and no registered entity
declares a browser surface yet.
"""
from __future__ import annotations
import importlib, importlib.util, json, sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import urlsplit

VENDOR = Path(__file__).resolve().parent / "vendor" / "stegbrowser_llm"
sys.path.insert(0, str(VENDOR.parent))
MANIFEST = json.loads((VENDOR / "vendor-manifest.json").read_text())
TOOL, PROFILE = "StegBrowser", "llm.v1"
LEASE_SCHEMA = "stegbrowser.ecosystem-ephemeral-lease.v1"
REQUEST_SCHEMA = "stegbrowser.llm-profile-request.v1"
JOURNEY_SCHEMA = "stegverse.packet-carried-endpoint-receipt-journey/v1"
MAX_LEASE_SECONDS = 900
NAVIGATED_STAGES = {"BROWSER_ACTION", "RESULT_OBSERVATION", "RESULT_BINDING", "RETURN_COMPLETE"}


def _host(url: str) -> str | None:
    try:
        parts = urlsplit(url)
    except ValueError:
        return None
    return parts.hostname.lower().rstrip(".") if parts.scheme == "https" and parts.hostname else None


def _host_allowed(host: str, allowed: list[str]) -> bool:
    for origin in allowed:
        candidate = str(origin).lower().rstrip(".")
        if candidate.startswith("*."):
            if host == candidate[2:] or host.endswith("." + candidate[2:]):
                return True
        elif host == candidate:
            return True
    return False


def _iso(t: datetime) -> str:
    return t.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


class StegBrowserTool:
    def __init__(self, sandbox):
        self.sandbox = sandbox
        self.canon = sandbox.canon
        sandbox.registration.verify_vendor(VENDOR)  # AT-01: executed bytes match the manifest
        self.transition = importlib.import_module("stegbrowser_llm.llm_transition")

    # -- admitted data ------------------------------------------------------------
    def _invocation(self, work: Mapping[str, Any], invocation_id: str) -> tuple[dict[str, Any] | None, str | None]:
        rows = [i for i in (work["manifested_request"].get("tool_invocations") or [])
                if isinstance(i, Mapping) and i.get("invocation_id") == invocation_id]
        if len(rows) != 1:
            return None, "TOOL_INVOCATION_DECLARED"
        inv = dict(rows[0])
        ok = (inv.get("tool") == TOOL and inv.get("profile") == PROFILE
              and isinstance(inv.get("prompt"), str) and inv["prompt"].strip()
              and isinstance(inv.get("response_marker"), str) and inv["response_marker"].strip()
              and isinstance(inv.get("secure_url"), str) and _host(inv["secure_url"]) is not None
              and isinstance(inv.get("allowed_origins"), list) and inv["allowed_origins"]
              and all(isinstance(o, str) and o for o in inv["allowed_origins"])
              and isinstance(inv.get("browser_actions"), list) and inv["browser_actions"]
              and isinstance(inv.get("lease_seconds", 300), int)
              and 1 <= inv.get("lease_seconds", 300) <= MAX_LEASE_SECONDS)
        return (inv, None) if ok else (None, "TOOL_INVOCATION_WELL_FORMED")

    def _ids(self, work_id: str, invocation_id: str) -> tuple[int, str]:
        attempt = 1 + sum(1 for r in self.sandbox.observations(work_id)
                          if r["evidence"].get("invocation_id") == invocation_id)
        oid = "obs-" + self.canon.digest({"work_id": work_id, "invocation_id": invocation_id, "attempt": attempt})[7:31]
        return attempt, oid

    def journey(self, work_id: str, inv: Mapping[str, Any], attempt: int, observation_id: str) -> dict[str, Any]:
        """G4: the six journey fields, derived from admitted work and invocation only."""
        outbound = self.canon.digest({"work_id": work_id, "invocation": dict(inv), "attempt": attempt})
        return {"schema": JOURNEY_SCHEMA, "journey_id": observation_id,
                "origin_endpoint": "SV-LLM/sandbox", "ephemeral_endpoint": "StegBrowser.llm.v1",
                "outbound_manifest_sha256": outbound,
                "return_manifest_sha256": self.canon.digest({"outbound_manifest_sha256": outbound, "direction": "RETURN"}),
                "return_predecessor_manifest_sha256": outbound}

    def request(self, inv: Mapping[str, Any], journey: Mapping[str, Any]) -> dict[str, Any]:
        req = {"schema": REQUEST_SCHEMA, "profile": PROFILE, "prompt": inv["prompt"],
               "response_marker": inv["response_marker"], "secure_url": inv["secure_url"],
               "browser_actions": [dict(a) for a in inv["browser_actions"]], "journey": dict(journey)}
        for label in ("provider", "model"):
            if inv.get(label) is not None:
                req[label] = inv[label]
        return req

    def lease(self, work_id: str, inv: Mapping[str, Any], observation_id: str, issued: datetime) -> dict[str, Any]:
        return {"schema": LEASE_SCHEMA, "lease_id": "lease-" + observation_id, "task_id": work_id,
                "requester": "SV-LLM/sandbox", "purpose": "llm.v1 " + inv["invocation_id"],
                "issued_at": _iso(issued),
                "expires_at": _iso(issued + timedelta(seconds=inv.get("lease_seconds", 300))),
                "allowed_origins": list(inv["allowed_origins"]), "allowed_actions": ["navigate"],
                "max_navigations": 1}

    # -- invocation ---------------------------------------------------------------
    def invoke(self, work_id: str, invocation_id: str, *, proposed: Mapping[str, Any] | None = None,
               playwright_factory=None, now: datetime | None = None) -> dict[str, Any]:
        proposed = dict(proposed or {})
        attempt, oid = self._ids(work_id, invocation_id)
        base = {"observation_id": oid, "work_id": work_id, "invocation_id": invocation_id, "attempt": attempt,
                "tool": TOOL, "tool_profile": PROFILE, "source_commit": MANIFEST["source_commit"],
                "evidence_refs": []}

        def deny(predicate: str, **known) -> dict[str, Any]:
            obs = {**base, "disposition": "DENY", "decided_by": "SANDBOX_PRE_INVOCATION",
                   "failed_predicate": predicate, "stegbrowser_invoked": False, "request_commitment": None,
                   "sandbox_request_digest": None, "lease_id": None, "allowed_origins": None,
                   "observed_origin": None, "local_disposition": None, "local_receipt_commitment": None,
                   "terminal_receipt": None, "result_commitment": None, "result": None, **known}
            return self.sandbox.record_tool_observation(obs)

        work = self.sandbox._work(work_id)
        if work is None:
            return deny("WORK_ID_IS_ADMITTED")
        inv, problem = self._invocation(work, invocation_id)
        if problem:
            return deny(problem)
        issued = now or datetime.now(timezone.utc)
        journey = self.journey(work_id, inv, attempt, oid)
        req = self.request(inv, journey)
        lease = self.lease(work_id, inv, oid, issued)
        known = {"sandbox_request_digest": self.canon.digest(req), "lease_id": lease["lease_id"],
                 "allowed_origins": lease["allowed_origins"]}
        caller_lease = proposed.get("lease")
        if caller_lease is not None and (not isinstance(caller_lease, Mapping) or caller_lease.get("task_id") != work_id
                                         or sorted(caller_lease.get("allowed_origins") or []) != sorted(inv["allowed_origins"])):
            return deny("LEASE_TASK_ID_EQUALS_WORK_ID" if not isinstance(caller_lease, Mapping)
                        or caller_lease.get("task_id") != work_id else "LEASE_ORIGINS_EQUAL_ADMITTED_ORIGINS", **known)
        prompt_ok = proposed.get("prompt", inv["prompt"]) == inv["prompt"] and all(
            a.get("value") == inv["prompt"] for a in inv["browser_actions"] if isinstance(a, Mapping) and a.get("op") == "fill")
        if not prompt_ok:
            return deny("LLM_PROMPT_BOUND_TO_MANIFESTED_REQUEST", **known)
        url = proposed.get("secure_url", inv["secure_url"])
        host = _host(url) if isinstance(url, str) else None
        if url != inv["secure_url"] or host is None or not _host_allowed(host, inv["allowed_origins"]):
            return deny("SECURE_URL_ORIGIN_ALLOWED_BY_LEASE", **known)

        if playwright_factory is None and importlib.util.find_spec("playwright") is None:
            # AT-20: no real browser runtime here. Fail closed now; never wait for another machine.
            obs = {**base, **known, "disposition": "FAIL_CLOSED", "decided_by": "SANDBOX_RUNTIME_CHECK",
                   "failed_predicate": "SANDBOX_ENVIRONMENT_PYTHON_PLAYWRIGHT_CHROMIUM_AVAILABLE",
                   "stegbrowser_invoked": False, "request_commitment": None, "observed_origin": None,
                   "local_disposition": None, "local_receipt_commitment": None, "terminal_receipt": None,
                   "result_commitment": None, "result": None}
            return self.sandbox.record_tool_observation(obs)
        outcome = self.transition.execute_manifested_llm_browser_transition(
            req, lease, playwright_factory=playwright_factory)
        receipt, executed = outcome["receipt"], outcome.get("execution_result")
        result = None
        if executed is not None:
            r = executed["result"]
            result = {"response_text": r["response_text"], "response_marker": r["response_marker"],
                      "provider_label": r["provider"], "model_label": r["model"],
                      "labels_are_attestation": False,
                      "endpoint_receipts_commitment": self.canon.digest(executed["endpoint_receipts"]),
                      "navigation_decision_commitment": executed["navigation_decision_commitment"]}
        obs = {**base, **known, "disposition": outcome["disposition"], "decided_by": "STEGBROWSER",
               "stegbrowser_invoked": True, "local_disposition": outcome["disposition"],
               "request_commitment": receipt["request_commitment"],
               "local_receipt_commitment": receipt["receipt_commitment"],
               "evaluation_stage": receipt["evaluation_stage"], "failed_predicate": receipt["failed_predicate"],
               "failure_code": receipt["failure_code"], "retry_entrypoint": receipt["retry_entrypoint"],
               "terminal_receipt": receipt["terminal_receipt"],
               "observed_origin": host if receipt["evaluation_stage"] in NAVIGATED_STAGES else None,
               "observed_origin_basis": "REQUESTED_SECURE_URL_HOST_AFTER_SUCCESSFUL_NAVIGATION; final URL after redirects is not reported by StegBrowser",
               "result_commitment": executed["result"]["response_commitment"] if executed else None,
               "result": result}
        return self.sandbox.record_tool_observation(obs)
