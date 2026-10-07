"""Core entity-neutral boundary objects for SV-LLM/Anthropic.

This module performs source-level validation and packaging only. It does not
call any model, execute transitions, or make governance dispositions.

Contributions are canonical sv-llm.contribution/v0.1 envelopes (SV-LLM/schemas):
content digests are sha256:<hex> over SV_LLM_CANONICAL_JSON_V1 bytes for JSON
content, or over the exact bytes otherwise, and every outcome (CONTRIBUTED,
REFUSED, UNAVAILABLE, FAILED) carries a recomputable digest.
"""
from __future__ import annotations

import base64
from hashlib import sha256
from typing import Any, Iterable
import json
import uuid

ENTITY = "Anthropic"
AUTHORITY_EFFECT = "NONE"
EPISTEMIC_STATES = {"OBSERVED", "DERIVED", "PROJECTED"}
NON_SUCCESS = {"REFUSED", "UNAVAILABLE", "FAILED"}
WORK_SCHEMA = "sv-llm.sandbox-work/v0.1"
CONTRIBUTION_SCHEMA = "sv-llm.contribution/v0.1"
MAX_SAFE = 9007199254740991


class ContractError(ValueError):
    pass


def _check(value: Any) -> None:
    """SV_LLM_CANONICAL_JSON_V1 value domain: integers within +/-(2^53-1), no floats, no lone surrogates."""
    if value is None or isinstance(value, bool):
        return
    if isinstance(value, int):
        if not -MAX_SAFE <= value <= MAX_SAFE:
            raise ContractError("integer outside the canonical range")
    elif isinstance(value, float):
        raise ContractError("non-integer numbers are not canonical; carry them as strings")
    elif isinstance(value, str):
        if any(0xD800 <= ord(ch) <= 0xDFFF for ch in value):
            raise ContractError("lone surrogate")
    elif isinstance(value, list):
        for item in value:
            _check(item)
    elif isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise ContractError("member names must be strings")
            _check(key)
            _check(item)
    else:
        raise ContractError(f"not a JSON value: {type(value).__name__}")


def canonical(value: Any) -> bytes:
    _check(value)
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def digest(value: Any) -> str:
    return "sha256:" + sha256(canonical(value)).hexdigest()


def is_json_media_type(media_type: str) -> bool:
    key = media_type.split(";", 1)[0].strip(" \t").lower()
    if not key.startswith("application/"):
        return False
    sub = key[len("application/"):]
    return sub == "json" or (sub.endswith("+json") and len(sub) > len("+json"))


def validate_work_object(work: dict[str, Any]) -> None:
    if work.get("schema") != WORK_SCHEMA:
        raise ContractError(f"work object must declare schema {WORK_SCHEMA}")
    required = {"work_id", "manifested_request", "parent_transition", "canonical_context_refs",
                "requested_capabilities", "permitted_capabilities", "participation_policy",
                "expected_output_or_handoff"}
    missing = sorted(required - set(work))
    if missing:
        raise ContractError(f"missing work fields: {', '.join(missing)}")
    if not isinstance(work["canonical_context_refs"], list):
        raise ContractError("canonical_context_refs must be references, not copied canonical context")
    if not isinstance(work["permitted_capabilities"], list) or not work["permitted_capabilities"]:
        raise ContractError("permitted_capabilities must be a non-empty list")


def _envelope(work: dict[str, Any], capability: str, epistemic_state: str, status: str,
              evidence_refs: Iterable[str], provenance: Iterable[str], uncertainty: str | None) -> dict[str, Any]:
    validate_work_object(work)
    if capability not in work["permitted_capabilities"]:
        raise ContractError("capability is not permitted by manifested work object")
    if epistemic_state not in EPISTEMIC_STATES:
        raise ContractError("invalid epistemic state")
    return {"schema": CONTRIBUTION_SCHEMA, "contribution_id": str(uuid.uuid4()), "work_id": work["work_id"],
            "entity": ENTITY, "capability": capability, "epistemic_state": epistemic_state,
            "evidence_refs": list(evidence_refs), "provenance": list(provenance), "uncertainty": uncertainty,
            "status": status, "authority_effect": AUTHORITY_EFFECT}


def contribution(*, work: dict[str, Any], capability: str, epistemic_state: str, content: Any,
                 content_media_type: str = "application/json", evidence_refs: Iterable[str] = (),
                 provenance: Iterable[str] = (), uncertainty: str | None = None) -> dict[str, Any]:
    """A CONTRIBUTED envelope carrying its content inline.

    JSON media types carry the JSON value; any other media type takes bytes and
    carries them base64-encoded, digested over the exact bytes.
    """
    env = _envelope(work, capability, epistemic_state, "CONTRIBUTED", evidence_refs, provenance, uncertainty)
    env["content_media_type"] = content_media_type
    if is_json_media_type(content_media_type):
        env["content"] = content
        env["content_digest"] = digest(content)
    else:
        if not isinstance(content, (bytes, bytearray)):
            raise ContractError("non-JSON content must be bytes")
        env["content"] = base64.b64encode(bytes(content)).decode("ascii")
        env["content_digest"] = "sha256:" + sha256(bytes(content)).hexdigest()
    _check(env)
    return env


def non_success(*, work: dict[str, Any], capability: str, status: str, reason_or_failed_predicate: str,
                epistemic_state: str = "OBSERVED", evidence_refs: Iterable[str] = (),
                provenance: Iterable[str] = (), uncertainty: str | None = None) -> dict[str, Any]:
    """A REFUSED, UNAVAILABLE or FAILED envelope; its digest is over the inline status record."""
    if status not in NON_SUCCESS:
        raise ContractError("status must be REFUSED, UNAVAILABLE or FAILED")
    if not reason_or_failed_predicate:
        raise ContractError("a non-success outcome names its reason or failed predicate")
    env = _envelope(work, capability, epistemic_state, status, evidence_refs, provenance, uncertainty)
    record = {"status": status, "reason_or_failed_predicate": reason_or_failed_predicate,
              "evidence_refs": env["evidence_refs"], "provenance": env["provenance"], "uncertainty": uncertainty}
    env["non_success_status_record"] = record
    env["content_digest"] = digest(record)
    return env


def inference_window(*, work: dict[str, Any], dispositions: list[str], projections: dict[str, Any]) -> list[dict[str, Any]]:
    """Package one PROJECTED contribution per supplied disposition.

    Dispositions are supplied by the applicable Admissibility Matrix. This
    function never invents or chooses a governance disposition.
    """
    validate_work_object(work)
    if "forward_disposition_inference" not in work["permitted_capabilities"]:
        raise ContractError("forward_disposition_inference is not permitted")
    if not dispositions:
        raise ContractError("applicable dispositions are required")
    if set(projections) != set(dispositions):
        raise ContractError("Inference Window must be disposition-complete")
    return [
        contribution(
            work=work,
            capability="forward_disposition_inference",
            epistemic_state="PROJECTED",
            content={"disposition": d, "projection": projections[d]},
            provenance=(f"admissibility-matrix-disposition:{d}",),
            uncertainty="forward-looking projection; not observed history",
        )
        for d in dispositions
    ]
