"""Local, non-authorizing manifested LLM browser attempt outcome.

This entrypoint turns execution errors into actionable, correlateable non-ALLOW
results without pretending that an uninvoked InTr endpoint made a decision.
The caller owns ingestion into the existing organization transition ledger.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any, Mapping

from .llm_browser_execution import execute_manifested_llm_browser_operation

SCHEMA = "stegbrowser.llm-browser-attempt-outcome.v1"
RECEIPT_SCHEMA = "stegbrowser.llm-browser-local-attempt-receipt.v1"


def _digest(value: Mapping[str, Any]) -> str:
    wire = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return "sha256:" + hashlib.sha256(wire).hexdigest()


def execute_manifested_llm_browser_transition(
    request: Mapping[str, Any],
    lease: Mapping[str, Any],
    *,
    playwright_factory=None,
) -> dict[str, Any]:
    """Return a local, non-authorizing outcome for each attempted browser call.

    The outbound manifest remains the controlling invocation. This function
    neither issues nor simulates InTr authorization, organization ledger
    append, Master Records organization record, or provider-authentication proof.
    """
    attempt: dict[str, Any] = {"stage": "MANIFEST_VALIDATION"}
    journey = request.get("journey")
    if not isinstance(journey, Mapping):
        journey = {}

    try:
        output = execute_manifested_llm_browser_operation(
            request, lease, playwright_factory=playwright_factory,
            attempt_evidence=attempt,
        )
        disposition = "ALLOW"
        failure_code = None
        predicate = None
    except Exception as error:
        output = None
        disposition = "DENY" if isinstance(error, PermissionError) else "FAIL_CLOSED"
        stage = attempt["stage"]
        failure_code = "LLM_BROWSER_" + stage + "_" + type(error).__name__.upper()
        predicate = "EXACT_MANIFESTED_" + stage + "_SUCCEEDED"

    receipt: dict[str, Any] = {
        "schema": RECEIPT_SCHEMA,
        "producer": "StegBrowser.llm_transition",
        "disposition_scope": "LOCAL_BROWSER_OPERATION_ONLY",
        "transition_authority": "NONE",
        "task_id": lease.get("task_id"),
        "lease_id": lease.get("lease_id"),
        "request_commitment": attempt.get("request_commitment"),
        "outbound_manifest_sha256": journey.get("outbound_manifest_sha256"),
        "return_manifest_sha256": journey.get("return_manifest_sha256"),
        "predecessor_manifest_sha256": journey.get("return_predecessor_manifest_sha256"),
        "requested_action": "llm.v1.manifested_browser_query",
        "evaluation_stage": attempt["stage"],
        "disposition": disposition,
        "consequence_committed": disposition == "ALLOW",
        "failure_code": failure_code,
        "failed_predicate": predicate,
        "required_evidence_or_repair": (
            "Repair the named stage using the existing manifested capability and retry "
            "the same governed operation with an updated admitted attempt."
            if disposition != "ALLOW" else None
        ),
        "retry_entrypoint": (
            "src.stegbrowser.llm_transition.execute_manifested_llm_browser_transition"
            if disposition != "ALLOW" else None
        ),
        "terminal_receipt": attempt.get("terminal_receipt"),
        "organization_receipt_claimed": False,
        "master_records_reconstruction_claimed": False,
    }
    receipt["receipt_commitment"] = _digest(receipt)
    return {
        "schema": SCHEMA,
        "disposition": disposition,
        "disposition_scope": "LOCAL_BROWSER_OPERATION_ONLY",
        "authority_effect": "NONE_LOCAL_OBSERVATION",
        "receipt": receipt,
        "execution_result": output,
    }
