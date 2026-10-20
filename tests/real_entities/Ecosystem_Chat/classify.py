"""Deterministic question -> capability selection for Ecosystem_Chat.

Maps a question (text plus optional declared hints) onto the shared
sv-llm.capability-id/v0.1 vocabulary so a Sandbox assignment can be driven by
the question instead of by hand. The selection is lexical and deterministic:
no model is called, no network is touched, and the result confers no
authority. Only capabilities the entity declares in
contracts/entity-capability.json may be selected; anything else is refused
with the six actionable fields.

The vocabulary and its meanings are owned by SV-LLM/schemas; this module only
chooses among them and never defines a capability.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Sequence

SELECTION_SCHEMA = "sv-llm.capability-selection/v0.1"
VOCABULARY = ("reasoning", "synthesis", "code_analysis", "code_generation", "document_analysis",
              "cross_repository_contract_analysis", "adversarial_review", "candidate_repair",
              "forward_disposition_inference")
AUTHORITY_EFFECT = "NONE"
OWNING_EXISTING_GOAL = "SVORG-LLM-ORG-FOUNDATION-001"
RETRY_ENTRYPOINT = "sv_llm_ecosystem_chat.classify.select(question, declared_capabilities)"

# Lexical cues per capability. Each cue is a lower-case token or phrase. A cue must start at a word boundary
# (so "patch" does not match "dispatch", "how" does not match "show") and its last word may carry one regular
# inflection (combine -> combined, predict -> predictions, allow -> allowed); a match counts once per cue.
CUES: dict[str, tuple[str, ...]] = {
    "cross_repository_contract_analysis": (
        "contract", "contracts", "schema", "schemas", "invariant", "invariants", "interface", "interfaces",
        "binding", "bindings", "across repositories", "across repos", "between repositories", "organization tree",
        "registry", "task registry", "declared", "declaration", "capability_declaration_ref", "mirror handoff"),
    "document_analysis": (
        "document", "documents", "handoff", "handoffs", "readme", "spec", "specification", "what does the doc",
        "summarize", "summarise", "extract", "compare the docs", "docs say", "according to"),
    "code_analysis": (
        "code", "function", "functions", "module", "class", "script", "workflow", "yml", "yaml", "python",
        "traceback", "stack trace", "bug", "defect", "line", "l1", "why does the test", "test fails", "failing test"),
    "code_generation": (
        "write a", "write the", "implement", "generate code", "add a function", "add a test", "create a script",
        "draft a pr", "patch", "diff"),
    "adversarial_review": (
        "review", "challenge", "counterexample", "counter-example", "what could go wrong", "attack", "weakness",
        "assumption", "assumptions", "falsify", "adversarial", "red team", "poke holes"),
    "candidate_repair": (
        "fix", "repair", "remediate", "remediation", "correct the", "how do i fix", "propose a fix", "workaround"),
    "forward_disposition_inference": (
        "would this be allowed", "would it be allow", "allow or deny", "allowed or denied", "disposition", "fail_closed", "fail closed",
        "projected", "projection", "if we merged", "what happens if", "will the ingress", "predict"),
    "synthesis": (
        "combine", "merge the findings", "synthesize", "synthesise", "roll up", "roll-up", "consolidate",
        "across these inputs", "overall picture", "reconcile", "reconciliation"),
    "reasoning": (
        "why", "how", "explain", "explanation", "what is", "what are", "which", "does", "is it", "should", "implication",
        "implications", "conclusion", "derive"),
}

# Hints a caller may declare on the question (already-known facts, not inferred from text).
HINT_CAPABILITY: dict[str, str] = {
    "source_code_attached": "code_analysis",
    "document_attached": "document_analysis",
    "multiple_repositories": "cross_repository_contract_analysis",
    "candidate_claim": "adversarial_review",
    "disposition_evidence_attached": "forward_disposition_inference",
    "multiple_inputs": "synthesis",
}

_WS = re.compile(r"\s+")


# Regular inflections the last word of a cue may carry. Decoys like dispatch/prefix/show/inspect/preview
# still fail the left boundary; classify (class+ify) and different (diff+erent) carry no listed suffix.
_INFLECTION = r"(?:s|es|d|ed|ing|ion|ions|ation|ations|ly)?"


def _cue_pattern(cue: str) -> re.Pattern[str]:
    """Token match: the cue starts at a word boundary and ends at one after an optional regular inflection."""
    return re.compile(r"(?<!\w)" + re.escape(_WS.sub(" ", cue.strip().lower())) + _INFLECTION + r"(?!\w)")


_CUE_PATTERNS: dict[str, tuple[tuple[str, re.Pattern[str]], ...]] = {
    cap: tuple((cue, _cue_pattern(cue)) for cue in cues) for cap, cues in CUES.items()}


class DeclarationError(ValueError):
    """contracts/entity-capability.json is missing, unreadable or does not declare a list of string ids."""


def declared_capabilities(repo_root: str | Path | None = None) -> list[str]:
    """Capabilities this entity declares in contracts/entity-capability.json.

    Raises DeclarationError (never a bare KeyError/JSONDecodeError) when the declaration is absent,
    not JSON, or its "capabilities" is not a list of strings; callers fail closed on it.
    """
    root = Path(repo_root) if repo_root is not None else Path(__file__).resolve().parents[2]
    path = root / "contracts" / "entity-capability.json"
    try:
        decl = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise DeclarationError(f"{path}: cannot read entity declaration: {exc}") from exc
    caps = decl.get("capabilities") if isinstance(decl, dict) else None
    if not isinstance(caps, list) or not all(isinstance(c, str) for c in caps):
        raise DeclarationError(f'{path}: "capabilities" must be a list of capability-id strings')
    return list(caps)


def _normalize(text: str) -> str:
    return _WS.sub(" ", text.strip().lower())


def _six(failure_code: str, failed_predicate: str, repair: str, next_attempt: str) -> dict[str, Any]:
    return {"failure_code": failure_code, "failed_predicate": failed_predicate,
            "required_evidence_or_repair": repair, "retry_entrypoint": RETRY_ENTRYPOINT,
            "owning_existing_goal": OWNING_EXISTING_GOAL, "next_attempt": next_attempt}


def select(question: Any, declared: Sequence[str], *, max_capabilities: int = 3) -> dict[str, Any]:
    """Select capabilities for a question.

    question: {"text": str, "hints": [str, ...]?}. declared: the entity's declared capability ids.
    Returns {"schema", "disposition": ALLOW|FAIL_CLOSED, "selected": [...], "ranking": [...],
             "evidence": {...}, "authority_effect": "NONE"} plus the six fields on FAIL_CLOSED.
    """
    base: dict[str, Any] = {"schema": SELECTION_SCHEMA, "authority_effect": AUTHORITY_EFFECT,
                            "selected": [], "ranking": [], "evidence": {}}
    if not isinstance(max_capabilities, int) or isinstance(max_capabilities, bool) or max_capabilities < 1:
        return {**base, "disposition": "FAIL_CLOSED", **_six(
            "CAPABILITY_SELECTION_FAIL_CLOSED_MAX_CAPABILITIES_POSITIVE", "MAX_CAPABILITIES_POSITIVE_INT",
            f"max_capabilities must be an int >= 1, got {max_capabilities!r}.", "Pass max_capabilities >= 1 and select again.")}
    declared_list = list(declared) if isinstance(declared, (list, tuple)) else None
    if declared_list is None or not all(isinstance(c, str) for c in declared_list):
        return {**base, "disposition": "FAIL_CLOSED", **_six(
            "CAPABILITY_SELECTION_FAIL_CLOSED_DECLARED_IDS_ARE_STRINGS", "DECLARED_CAPABILITIES_ARE_STRINGS",
            "declared must be a list/tuple of capability-id strings (see declared_capabilities()).",
            "Pass the entity's declared capability ids and select again.")}
    unknown = sorted(set(declared_list) - set(VOCABULARY))
    if unknown:
        return {**base, "disposition": "FAIL_CLOSED", **_six(
            "CAPABILITY_SELECTION_FAIL_CLOSED_DECLARED_IDS_NOT_IN_VOCABULARY", "DECLARED_CAPABILITIES_IN_VOCABULARY",
            f"Declared ids not in sv-llm.capability-id/v0.1: {', '.join(unknown)}",
            "Correct contracts/entity-capability.json and select again.")}
    if not isinstance(question, dict) or not isinstance(question.get("text"), str) or not question["text"].strip():
        return {**base, "disposition": "FAIL_CLOSED", **_six(
            "CAPABILITY_SELECTION_FAIL_CLOSED_QUESTION_WELL_FORMED", "QUESTION_WELL_FORMED",
            "Supply {'text': <non-empty string>, 'hints': [...]?}.", "Repair the question and select again.")}
    text = _normalize(question["text"])
    raw_hints = question.get("hints")
    hints = list(raw_hints) if isinstance(raw_hints, (list, tuple)) else ([] if raw_hints is None else None)
    if hints is None or not all(isinstance(h, str) for h in hints):
        return {**base, "disposition": "FAIL_CLOSED", **_six(
            "CAPABILITY_SELECTION_FAIL_CLOSED_HINTS_ARE_STRINGS", "HINTS_ARE_STRINGS",
            "hints must be a list of strings.", "Repair the hints and select again.")}
    bad_hints = sorted(set(hints) - set(HINT_CAPABILITY))
    if bad_hints:
        return {**base, "disposition": "FAIL_CLOSED", **_six(
            "CAPABILITY_SELECTION_FAIL_CLOSED_HINTS_KNOWN", "HINTS_KNOWN",
            f"Unknown hints: {', '.join(bad_hints)}; known: {', '.join(sorted(HINT_CAPABILITY))}",
            "Use known hints and select again.")}

    scores: dict[str, int] = {c: 0 for c in VOCABULARY}
    matched: dict[str, list[str]] = {c: [] for c in VOCABULARY}
    for cap, cues in _CUE_PATTERNS.items():
        for cue, pattern in cues:
            if pattern.search(text):
                scores[cap] += 1
                matched[cap].append(cue)
    for h in hints:
        cap = HINT_CAPABILITY[h]
        scores[cap] += 2
        matched[cap].append(f"hint:{h}")
    # "reasoning" is the generic fallback: it only wins outright when nothing specific matched.
    specific = {c: s for c, s in scores.items() if c != "reasoning" and s > 0}
    if not specific and scores["reasoning"] == 0:
        return {**base, "disposition": "FAIL_CLOSED", **_six(
            "CAPABILITY_SELECTION_FAIL_CLOSED_NO_CUE_MATCHED", "QUESTION_MAPS_TO_A_CAPABILITY",
            "The question matched no capability cue; restate it or add a hint "
            "(source_code_attached, document_attached, multiple_repositories, candidate_claim, "
            "disposition_evidence_attached, multiple_inputs).", "Restate the question and select again.")}
    ranking = sorted(((s, c) for c, s in scores.items() if s > 0), key=lambda x: (-x[0], VOCABULARY.index(x[1])))
    ordered = [c for _, c in ranking]
    if specific:
        ordered = [c for c in ordered if c != "reasoning"] + (["reasoning"] if scores["reasoning"] > 0 else [])
    not_declared = [c for c in ordered if c not in declared_list]
    selected = [c for c in ordered if c in declared_list][:max_capabilities]
    evidence = {"normalized_text": text, "matched": {c: v for c, v in matched.items() if v},
                "ranking": [{"capability": c, "score": scores[c]} for c in ordered],
                "not_declared_by_entity": not_declared}
    if not selected:
        return {**base, "disposition": "FAIL_CLOSED", "ranking": ordered, "evidence": evidence, **_six(
            "CAPABILITY_SELECTION_FAIL_CLOSED_CAPABILITY_NOT_DECLARED", "SELECTED_CAPABILITY_DECLARED_BY_ENTITY",
            f"The question maps to {', '.join(ordered)}, which this entity does not declare; "
            "route the work to an entity that declares it.", "Select against another entity's declaration.")}
    return {**base, "disposition": "ALLOW", "selected": selected, "ranking": ordered, "evidence": evidence}
