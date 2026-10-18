#!/usr/bin/env python3
"""Deterministic capability routing: requested capabilities -> participants, from declarations only.

A manifest may name its participants explicitly (payload.work.participants as a
list) or ask the Sandbox to derive them: participants = "DERIVE_FROM_DECLARATIONS".
Derivation is a pure function of (a) the work's requested capabilities and (b) the
registered entities' own contracts/entity-capability.json declarations, taken in
a fixed order. No model is called, nothing is fetched, no availability of any
entity is checked: an entity is routed because it declares the capability, and
it answers later in the cycle or its request stays outstanding (nothing waits).

Each requested capability is routed to the first declaring entity in order; every
other declaring entity is recorded as an alternate in the evidence. A capability
no registered entity declares, a malformed declaration, or an empty request is a
FAIL_CLOSED answer carrying the six actionable fields. authority_effect is NONE:
routing selects who is asked, never what is decided.
"""
from __future__ import annotations

import json
from typing import Any, Mapping, Sequence

SCHEMA = "sv-llm.capability-routing/v0.1"
DERIVE = "DERIVE_FROM_DECLARATIONS"
DECLARATION_SCHEMA = "sv-llm.entity-capability/v0.1"
AUTHORITY_EFFECT = "NONE"
OWNING_EXISTING_GOAL = "SVORG-LLM-ORG-FOUNDATION-001"
RETRY_ENTRYPOINT = "runtime.capability_routing.derive_participants(requested, declarations, order=...)"
ALLOW, FAIL_CLOSED = "ALLOW", "FAIL_CLOSED"


def _six(code: str, predicate: str, repair: str, next_attempt: str) -> dict[str, Any]:
    return {"failure_code": code, "failed_predicate": predicate, "required_evidence_or_repair": repair,
            "retry_entrypoint": RETRY_ENTRYPOINT, "owning_existing_goal": OWNING_EXISTING_GOAL,
            "next_attempt": next_attempt}


def _declared(entity: str, declaration: Any) -> list[str] | str:
    """The capability ids an entity declares, or a reason string when the declaration is unusable."""
    try:
        doc = json.loads(declaration) if isinstance(declaration, (bytes, bytearray, str)) else declaration
    except (ValueError, UnicodeDecodeError) as exc:
        return f"{entity}: declaration is not JSON ({exc})"
    if not isinstance(doc, dict) or doc.get("schema") != DECLARATION_SCHEMA:
        return f"{entity}: declaration schema is not {DECLARATION_SCHEMA}"
    if doc.get("entity") != entity:
        return f"{entity}: declaration names entity {doc.get('entity')!r}"
    caps = doc.get("capabilities")
    if not isinstance(caps, list) or not all(isinstance(c, str) and c for c in caps):
        return f"{entity}: capabilities is not a list of non-empty strings"
    return caps


def derive_participants(requested: Any, declarations: Mapping[str, Any], *,
                        order: Sequence[str] | None = None) -> dict[str, Any]:
    """Route each requested capability to a declaring entity.

    requested: the work's requested_capabilities. declarations: entity name -> declaration
    (bytes, str or dict). order: entity names in routing precedence (default: sorted names).
    Returns {"schema", "disposition", "participants", "evidence", "authority_effect"} and the
    six fields on FAIL_CLOSED. Deterministic for equal inputs.
    """
    base: dict[str, Any] = {"schema": SCHEMA, "authority_effect": AUTHORITY_EFFECT, "participants": [], "evidence": {}}
    if not isinstance(requested, list) or not requested or not all(isinstance(c, str) and c for c in requested):
        return {**base, "disposition": FAIL_CLOSED, **_six(
            "CAPABILITY_ROUTING_FAIL_CLOSED_REQUEST_WELL_FORMED", "REQUESTED_CAPABILITIES_WELL_FORMED",
            "requested_capabilities must be a non-empty list of capability-id strings.",
            "Repair payload.work.requested_capabilities and derive again.")}
    names = list(order) if order is not None else sorted(declarations)
    if len(set(names)) != len(names) or set(names) != set(declarations):
        return {**base, "disposition": FAIL_CLOSED, **_six(
            "CAPABILITY_ROUTING_FAIL_CLOSED_ORDER_COVERS_DECLARATIONS", "ORDER_IS_A_PERMUTATION_OF_DECLARED_ENTITIES",
            "order must list each declared entity exactly once.", "Pass a consistent order and derive again.")}
    declared: dict[str, list[str]] = {}
    problems: list[str] = []
    for name in names:
        caps = _declared(name, declarations[name])
        (problems.append(caps) if isinstance(caps, str) else declared.__setitem__(name, caps))
    if problems:
        return {**base, "disposition": FAIL_CLOSED, **_six(
            "CAPABILITY_ROUTING_FAIL_CLOSED_DECLARATIONS_WELL_FORMED", "ENTITY_DECLARATIONS_WELL_FORMED",
            "; ".join(problems), "Correct the named contracts/entity-capability.json and derive again.")}
    participants, alternates, missing = [], {}, []
    for cap in dict.fromkeys(requested):  # first occurrence order, duplicates collapsed
        declaring = [n for n in names if cap in declared[n]]
        if not declaring:
            missing.append(cap)
            continue
        participants.append({"entity": declaring[0], "capability": cap})
        alternates[cap] = declaring[1:]
    evidence = {"order": names, "declared": declared, "alternates": alternates, "not_declared_by_any_entity": missing}
    if missing:
        return {**base, "disposition": FAIL_CLOSED, "evidence": evidence, **_six(
            "CAPABILITY_ROUTING_FAIL_CLOSED_CAPABILITY_DECLARED_BY_A_REGISTERED_ENTITY",
            "EVERY_REQUESTED_CAPABILITY_DECLARED_BY_A_REGISTERED_ENTITY",
            f"No registered entity declares: {', '.join(missing)}. Register an entity that declares it "
            "(contracts/entity-capability.json + organization tree capability_declaration_ref) or narrow the request.",
            "Derive again once a declaring entity is registered.")}
    return {**base, "disposition": ALLOW, "participants": participants, "evidence": evidence}
