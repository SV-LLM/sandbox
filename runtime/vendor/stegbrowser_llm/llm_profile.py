"""LLM interaction profile for a manifested ephemeral StegBrowser session.

StegBrowser is the capability; LLM is an interaction profile. Test 5 varies the
manifest only. The packet carries endpoint transition receipts across the two
one-way InTr legs so the caller can submit the completed journey to the
existing organization record.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any, Mapping

PROFILE = "llm.v1"
REQUEST_SCHEMA = "stegbrowser.llm-profile-request.v1"
RESULT_SCHEMA = "stegbrowser.llm-profile-result.v1"
JOURNEY_SCHEMA = "stegverse.packet-carried-endpoint-receipt-journey/v1"


def _sha256(value: Any) -> str:
    data = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _require_text(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be a non-empty string")
    return value.strip()


def validate_journey(value: Mapping[str, Any]) -> dict[str, Any]:
    if value.get("schema") != JOURNEY_SCHEMA:
        raise ValueError(f"journey schema must be {JOURNEY_SCHEMA}")
    normalized = {
        "schema": JOURNEY_SCHEMA,
        "journey_id": _require_text(value.get("journey_id"), "journey_id"),
        "origin_endpoint": _require_text(value.get("origin_endpoint"), "origin_endpoint"),
        "ephemeral_endpoint": _require_text(value.get("ephemeral_endpoint"), "ephemeral_endpoint"),
        "outbound_manifest_sha256": _require_text(value.get("outbound_manifest_sha256"), "outbound_manifest_sha256"),
        "return_manifest_sha256": _require_text(value.get("return_manifest_sha256"), "return_manifest_sha256"),
        "return_predecessor_manifest_sha256": _require_text(
            value.get("return_predecessor_manifest_sha256"), "return_predecessor_manifest_sha256"
        ),
    }
    if normalized["return_predecessor_manifest_sha256"] != normalized["outbound_manifest_sha256"]:
        raise ValueError("return manifest must predecessor-link to outbound manifest")
    return normalized


def validate_llm_profile_request(value: Mapping[str, Any]) -> dict[str, Any]:
    if value.get("schema") != REQUEST_SCHEMA:
        raise ValueError(f"schema must be {REQUEST_SCHEMA}")
    if value.get("profile") != PROFILE:
        raise ValueError(f"profile must be {PROFILE}")
    prompt = _require_text(value.get("prompt"), "prompt")
    marker = _require_text(value.get("response_marker"), "response_marker")
    provider = value.get("provider")
    if provider is not None:
        provider = _require_text(provider, "provider")
    secure_url = value.get("secure_url")
    if secure_url is not None:
        secure_url = _require_text(secure_url, "secure_url")
        if not secure_url.startswith("https://"):
            raise ValueError("secure_url must use https")
    model = value.get("model")
    if model is not None:
        model = _require_text(model, "model")
    actions = value.get("browser_actions")
    if actions is not None and (not isinstance(actions, list) or not actions):
        raise ValueError("browser_actions must be a non-empty list when supplied")
    journey = validate_journey(value.get("journey") if isinstance(value.get("journey"), Mapping) else {})
    normalized = {
        "schema": REQUEST_SCHEMA,
        "profile": PROFILE,
        "prompt": prompt,
        "response_marker": marker,
        "provider": provider,
        "model": model,
        "secure_url": secure_url,
        "browser_actions": ([dict(x) for x in actions if isinstance(x, Mapping)] if actions is not None else None),
        "journey": journey,
    }
    normalized["request_commitment"] = _sha256(normalized)
    return normalized


def _endpoint_receipt(*, journey: Mapping[str, Any], leg: int, direction: str,
                      endpoint: str, counterparty: str, manifest_sha256: str,
                      **evidence: Any) -> dict[str, Any]:
    body = {
        "journey_id": journey["journey_id"],
        "leg": leg,
        "direction": direction,
        "endpoint": endpoint,
        "counterparty": counterparty,
        "manifest_sha256": manifest_sha256,
        **evidence,
    }
    return {"schema": "stegverse.repo-transition-receipt/v1", "evidence": body}


def begin_llm_profile_packet(request: Mapping[str, Any]) -> dict[str, Any]:
    normalized = validate_llm_profile_request(request)
    journey = normalized["journey"]
    return {
        "request": normalized,
        "endpoint_receipts": [
            _endpoint_receipt(
                journey=journey, leg=1, direction="EGRESS",
                endpoint=journey["origin_endpoint"], counterparty=journey["ephemeral_endpoint"],
                manifest_sha256=journey["outbound_manifest_sha256"],
            )
        ],
    }


def bind_llm_profile_result(*, packet: Mapping[str, Any], response_text: str,
                            provider: str, model: str) -> dict[str, Any]:
    receipts = list(packet.get("endpoint_receipts") or [])
    if len(receipts) != 1:
        raise ValueError("packet must arrive with exactly the origin EGRESS receipt")
    normalized = validate_llm_profile_request(packet.get("request") if isinstance(packet.get("request"), Mapping) else {})
    journey = normalized["journey"]
    if normalized["response_marker"] not in _require_text(response_text, "response_text"):
        raise ValueError("LLM response does not contain its manifested response marker")
    provider = _require_text(provider, "provider")
    model = _require_text(model, "model")
    receipts.extend([
        _endpoint_receipt(
            journey=journey, leg=1, direction="INGRESS",
            endpoint=journey["ephemeral_endpoint"], counterparty=journey["origin_endpoint"],
            manifest_sha256=journey["outbound_manifest_sha256"],
            custody="RETURN_WITH_MANIFEST", manifest_read=True,
            manifest_directed=True, receipt_appended=True,
        ),
        _endpoint_receipt(
            journey=journey, leg=2, direction="EGRESS",
            endpoint=journey["ephemeral_endpoint"], counterparty=journey["origin_endpoint"],
            manifest_sha256=journey["return_manifest_sha256"],
            predecessor_manifest_sha256=journey["outbound_manifest_sha256"],
            custody="RETURN_WITH_MANIFEST", manifest_read=True,
            manifest_directed=True, receipt_appended=True, next_leg_directed=True,
        ),
    ])
    result = {
        "schema": RESULT_SCHEMA,
        "profile": PROFILE,
        "request_commitment": normalized["request_commitment"],
        "response_marker": normalized["response_marker"],
        "provider": provider,
        "model": model,
        "response_text": response_text,
        "journey_id": journey["journey_id"],
    }
    result["response_commitment"] = _sha256(result)
    return {"result": result, "endpoint_receipts": receipts}


def complete_llm_profile_packet(packet: Mapping[str, Any]) -> dict[str, Any]:
    receipts = list(packet.get("endpoint_receipts") or [])
    result = packet.get("result")
    if len(receipts) != 3 or not isinstance(result, Mapping):
        raise ValueError("returned packet must contain result and three endpoint receipts")
    request = packet.get("request")
    if not isinstance(request, Mapping):
        raise ValueError("returned packet request missing")
    journey = validate_llm_profile_request(request)["journey"]
    receipts.append(_endpoint_receipt(
        journey=journey, leg=2, direction="INGRESS",
        endpoint=journey["origin_endpoint"], counterparty=journey["ephemeral_endpoint"],
        manifest_sha256=journey["return_manifest_sha256"],
        predecessor_manifest_sha256=journey["outbound_manifest_sha256"],
        returned_endpoint_receipts=True,
    ))
    return {"result": dict(result), "endpoint_receipts": receipts}
