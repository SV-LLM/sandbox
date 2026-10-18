"""Offline evaluator for stegverse.ai-invariant-conformance-proposal/v1 artifacts.

Implements the Ecosystem Chat sandbox check described in SV-LLM/StegVerse_AI
docs/CANONICAL_INVARIANT_AVAILABILITY_AND_ECOSYSTEM_CHAT_SANDBOX_ENFORCEMENT.md:
before an approved solution is proposed to the SDK, the Sandbox evaluates the
proposal itself against the canonical invariant sources it actually received,
instead of trusting what the proposal says about itself.

The caller supplies the canonical source documents (repository, path, revision,
bytes). This module never fetches them. From those bytes it computes:

- the applicable invariant set: every key of `invariants` and every entry of
  `prohibitions` in each cited `stegverse.task-registry-global-invariants/v1`
  document. The proposal cannot narrow or redefine it, and prompt wording plays
  no part.
- each cited source's sha256, compared with the digest the proposal recorded.
- violations found in the proposed changes themselves (added dependency
  manifests, install commands, schedules, sleeps and polling loops, or a
  canonical `false` invariant set to true), whatever the proposal's prose says.

The evaluator returns a disposition:

- FAIL_CLOSED: the proposal cannot be evaluated. It is malformed, a cited
  source is missing or does not match its digest, two sources conflict,
  coverage is incomplete, an assessment lacks evidence, or an invariant is
  left unresolved.
- DENY: the proposal is evaluable but nonconforming. It violates an invariant,
  adds a dependency, routes by identity, attests itself, inflates its evidence
  class, claims a runtime transition, or reopens a settled finding without new
  evidence.
- ALLOW: neither.

It performs no network access and is not a governance transition. ALLOW means
the proposal may be offered to the SDK. It is not an SDK, Interlock/InTr or
Organization disposition.
"""
from __future__ import annotations

import hashlib
import json
import re
import sys
from typing import Any

import invariant_evaluation

SCHEMA = "stegverse.ai-invariant-conformance-proposal/v1"
CANONICAL_SCHEMA = "stegverse.task-registry-global-invariants/v1"
MANDATORY_SOURCE = ("StegVerse-Labs/.github", "data/task-registry-global-invariants.json")
ALLOW, DENY, FAIL_CLOSED = "ALLOW", "DENY", "FAIL_CLOSED"

# Diagnostic classifications from the StegVerse_AI document; they never replace the disposition.
INVARIANT_VIOLATION = "INVARIANT_VIOLATION"
IMPLEMENTATION_NONCONFORMANCE = "IMPLEMENTATION_NONCONFORMANCE"
EVIDENCE_INSUFFICIENT = "EVIDENCE_INSUFFICIENT"
CANONICAL_CONFLICT = "CANONICAL_CONFLICT"

REQUIRED = ("schema", "task_id", "cosv_id", "manifest_binding", "canonical_sources", "current_build_refs",
            "proposed_changes", "invariant_assessment", "dependency_delta", "review_finding_deltas",
            "evidence_class", "approval_effect", "runtime_transition_claimed")
# Carried for the reader only; the evaluator never reads them, so who wrote the proposal cannot change its result.
IGNORED = frozenset({"author", "prompt", "notes"})
SELF_ATTESTATION = frozenset({"compliant", "conformant", "conformance", "conformance_result", "approved",
                              "verified", "valid", "passes", "disposition"})
# Classes a proposal can hold before submission; runtime classes are earned downstream, never declared here.
PROPOSAL_EVIDENCE_CLASSES = frozenset({"SOURCE_ONLY", "SOURCE_IMPLEMENTED", "MERGED", "CI_VALIDATED"})
RESULTS = frozenset({"CONFORMS", "VIOLATES", "NOT_APPLICABLE", "UNRESOLVED", "NOT_YET_EVALUATED"})
SETTLED = frozenset({"RESOLVED", "ACCEPTED"})
REOPENED = frozenset({"OPEN", "REOPENED"})
IDENTITY_ROUTING_KEY = re.compile(r"(model|provider|repository|adapter|source_identity|author)", re.I)
SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
PLACEHOLDER = "RESOLVE_AT_EVALUATION"

DEPENDENCY_MANIFESTS = frozenset({"pyproject.toml", "setup.py", "setup.cfg", "Pipfile", "Pipfile.lock",
                                  "poetry.lock", "package.json", "package-lock.json", "yarn.lock",
                                  "pnpm-lock.yaml", "Gemfile", "Gemfile.lock", "go.mod", "Cargo.toml"})
REQUIREMENTS_FILE = re.compile(r"(^|/)requirements[^/]*\.txt$")
INSTALL = re.compile(r"\b(pip3?|python3? -m pip|npm|yarn|pnpm|apt-get|apt|brew|gem|cargo|go)\s+(install|add|ci|get)\b")
SCHEDULER = re.compile(r"^\s*(schedule|workflow_run|repository_dispatch)\s*:", re.M)
WAIT = re.compile(r"\b(time\.sleep|asyncio\.sleep|wait_for_timeout)\s*\(|\bwhile\s+True\s*:")
ASSIGN_TRUE = r"[\"']?{key}[\"']?\s*[:=]\s*(true|True)\b"

# Predicate -> (classification, repair).
PREDICATES: dict[str, tuple[str, str]] = {
    "PROPOSAL_WELL_FORMED": (EVIDENCE_INSUFFICIENT, "Supply every required field with the documented type."),
    "MANDATORY_SOURCE_CITED": (EVIDENCE_INSUFFICIENT,
                               "Cite StegVerse-Labs/.github data/task-registry-global-invariants.json."),
    "CANONICAL_SOURCE_SUPPLIED": (EVIDENCE_INSUFFICIENT,
                                  "Resolve every cited canonical source and pass its bytes to the evaluator."),
    "CANONICAL_SOURCE_BOUND": (EVIDENCE_INSUFFICIENT,
                               "Record the revision and sha256 of the exact canonical bytes evaluated."),
    "CANONICAL_SOURCES_CONSISTENT": (CANONICAL_CONFLICT,
                                     "Resolve the conflicting canonical values at their owner; do not pick one."),
    "INVARIANT_IDS_CANONICAL": (EVIDENCE_INSUFFICIENT,
                                "Assess only invariant ids resolved from the cited sources, each once."),
    "COVERAGE_COMPLETE": (EVIDENCE_INSUFFICIENT, "Assess every applicable invariant the evaluator resolved."),
    "ASSESSMENT_EVIDENCED": (EVIDENCE_INSUFFICIENT,
                             "Give evidence_refs and a cited source_ref for every assessed invariant."),
    "CONFORMANCE_RESOLVED": (EVIDENCE_INSUFFICIENT,
                             "Resolve each UNRESOLVED invariant with evidence before submission."),
    "MANIFEST_ROUTING_BOUND": (EVIDENCE_INSUFFICIENT,
                               "Bind manifest_id, canonical_manifest_sha256, processing_capability and "
                               "processing_route_id."),
    "ROUTING_BY_CAPABILITY_ONLY": (INVARIANT_VIOLATION,
                                   "Remove model, provider, repository or adapter identity from routing."),
    "INVARIANT_CONFORMS": (INVARIANT_VIOLATION, "Repair the proposed change that violates the invariant."),
    "NO_ADDED_DEPENDENCY": (INVARIANT_VIOLATION,
                            "Reuse existing components; remove the added dependency, install, scheduler or wait."),
    "NO_SELF_ATTESTATION": (INVARIANT_VIOLATION,
                            "Remove self-declared conformance; the evaluator computes it."),
    "APPROVAL_EFFECT_NONE": (INVARIANT_VIOLATION, "Set approval_effect to NONE."),
    "EVIDENCE_CLASS_NOT_INFLATED": (INVARIANT_VIOLATION,
                                    "Declare a pre-submission evidence class; runtime classes are observed, "
                                    "not declared."),
    "RUNTIME_TRANSITION_NOT_CLAIMED": (INVARIANT_VIOLATION,
                                       "Set runtime_transition_claimed to false; only the invoked boundary "
                                       "records a transition."),
    "NO_REVIEW_CHURN": (INVARIANT_VIOLATION,
                        "Reopen a settled finding only with new_evidence_refs naming a new source change."),
}
RETRY_ENTRYPOINT = "runtime.conformance_proposal.evaluate"
OWNING_EXISTING_GOAL = "SVORG-LLM-ORG-FOUNDATION-001"


class _Result:
    def __init__(self) -> None:
        self.fail_closed: set[str] = set()
        self.deny: set[str] = set()
        self.findings: list[dict[str, Any]] = []

    def fail(self, predicate: str, detail: str, invariant_id: str | None = None) -> None:
        self.fail_closed.add(predicate)
        self._find(predicate, detail, invariant_id)

    def refuse(self, predicate: str, detail: str, invariant_id: str | None = None) -> None:
        self.deny.add(predicate)
        self._find(predicate, detail, invariant_id)

    def _find(self, predicate: str, detail: str, invariant_id: str | None) -> None:
        f = {"predicate": predicate, "classification": PREDICATES[predicate][0], "detail": detail}
        if invariant_id is not None:
            f["invariant_id"] = invariant_id
        if f not in self.findings:
            self.findings.append(f)


def _sha(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _str(v: Any) -> bool:
    return isinstance(v, str) and bool(v.strip())


def _well_formed(p: Any, r: _Result) -> bool:
    if not isinstance(p, dict):
        r.fail("PROPOSAL_WELL_FORMED", "proposal is not a JSON object")
        return False
    if p.get("schema") != SCHEMA:
        r.fail("PROPOSAL_WELL_FORMED", f"schema is not {SCHEMA}")
    for k in REQUIRED:
        if k not in p:
            r.fail("PROPOSAL_WELL_FORMED", f"missing field {k}")
    for k in p:
        if k in SELF_ATTESTATION:
            r.refuse("NO_SELF_ATTESTATION", f"proposal declares {k}")
        elif k not in REQUIRED and k not in IGNORED:
            r.fail("PROPOSAL_WELL_FORMED", f"unknown field {k}")
    types = {"manifest_binding": dict, "canonical_sources": list, "current_build_refs": list,
             "proposed_changes": list, "invariant_assessment": list, "dependency_delta": dict,
             "review_finding_deltas": list}
    for k, t in types.items():
        if k in p and not isinstance(p[k], t):
            r.fail("PROPOSAL_WELL_FORMED", f"{k} is not a {t.__name__}")
    return not r.fail_closed


def _resolve_sources(p: dict, supplied: list[dict], r: _Result) -> tuple[dict[str, Any], list[dict]]:
    """Bind each cited source to supplied bytes and return (applicable invariants, resolved refs)."""
    by_ref = {}
    for s in supplied:
        by_ref[(s["repository"], s["path"])] = s
    cited = set()
    applicable: dict[str, Any] = {}
    resolved = []
    for c in p["canonical_sources"]:
        if not isinstance(c, dict) or not all(_str(c.get(k)) for k in ("repository", "path", "revision", "digest")):
            r.fail("PROPOSAL_WELL_FORMED", "canonical source lacks repository, path, revision or digest")
            continue
        ref = (c["repository"], c["path"])
        cited.add(ref)
        s = by_ref.get(ref)
        if s is None:
            r.fail("CANONICAL_SOURCE_SUPPLIED", f"{ref[0]}:{ref[1]} was cited but not resolved")
            continue
        digest = _sha(s["content"])
        if PLACEHOLDER in (c["revision"], c["digest"]) or c["revision"] != s["revision"] or c["digest"] != digest:
            r.fail("CANONICAL_SOURCE_BOUND",
                   f"{ref[0]}:{ref[1]} cited {c['revision']} {c['digest']}, evaluated {s['revision']} {digest}")
            continue
        resolved.append({"repository": ref[0], "path": ref[1], "revision": s["revision"], "digest": digest})
        try:
            doc = json.loads(s["content"])
        except (ValueError, UnicodeDecodeError):
            doc = None
        if not isinstance(doc, dict) or doc.get("schema") != CANONICAL_SCHEMA:
            if ref == MANDATORY_SOURCE:
                r.fail("CANONICAL_SOURCE_BOUND", f"{ref[0]}:{ref[1]} is not a {CANONICAL_SCHEMA} document")
            continue
        invariants = doc.get("invariants") if isinstance(doc.get("invariants"), dict) else {}
        prohibitions = doc.get("prohibitions") if isinstance(doc.get("prohibitions"), list) else []
        for key, value in invariants.items():
            iid = "invariant:" + key
            if iid in applicable and applicable[iid] != value:
                r.fail("CANONICAL_SOURCES_CONSISTENT", f"{iid} has conflicting canonical values", iid)
            applicable[iid] = value
        for name in prohibitions:
            if isinstance(name, str):
                applicable["prohibition:" + name] = True
    if MANDATORY_SOURCE not in cited:
        r.fail("MANDATORY_SOURCE_CITED", f"{MANDATORY_SOURCE[0]}:{MANDATORY_SOURCE[1]} is not cited")
    return applicable, resolved


def _assessment(p: dict, applicable: dict[str, Any], resolved: list[dict], violated: set[str], r: _Result) -> dict:
    cited_refs = {f"{s['repository']}:{s['path']}" for s in resolved}
    seen: dict[str, str] = {}
    for a in p["invariant_assessment"]:
        iid = a.get("invariant_id") if isinstance(a, dict) else None
        if not isinstance(iid, str) or iid not in applicable or iid in seen:
            r.fail("INVARIANT_IDS_CANONICAL", f"assessment id {iid!r} is unknown or repeated")
            continue
        result = a.get("result")
        if not isinstance(result, str) or result not in RESULTS:
            r.fail("PROPOSAL_WELL_FORMED", f"{iid} result {result!r} is not one of {sorted(RESULTS)}")
            continue
        seen[iid] = result
        if result in ("UNRESOLVED", "NOT_YET_EVALUATED"):
            r.fail("CONFORMANCE_RESOLVED", f"{iid} is {result}", iid)
            continue
        refs = a.get("evidence_refs")
        if (not isinstance(a.get("source_ref"), str) or a["source_ref"] not in cited_refs
                or not isinstance(refs, list) or not refs
                or not all(_str(x) for x in refs)):
            r.fail("ASSESSMENT_EVIDENCED", f"{iid} lacks a cited source_ref or evidence_refs", iid)
        if result == "VIOLATES":
            r.refuse("INVARIANT_CONFORMS", f"{iid} is assessed as violated", iid)
        elif iid in violated:
            r.refuse("INVARIANT_CONFORMS", f"{iid} is assessed {result} but the proposed changes violate it", iid)
    missing = sorted(set(applicable) - set(seen))
    if missing:
        r.fail("COVERAGE_COMPLETE", f"{len(missing)} applicable invariants not assessed: {', '.join(missing[:10])}"
               + (" ..." if len(missing) > 10 else ""))
    return {"applicable": len(applicable), "assessed": len(seen),
            "conforms": sum(1 for v in seen.values() if v == "CONFORMS"),
            "not_applicable": sum(1 for v in seen.values() if v == "NOT_APPLICABLE"),
            "unresolved": sorted(k for k, v in seen.items() if v in ("UNRESOLVED", "NOT_YET_EVALUATED")),
            "missing": missing}


def _inspect_changes(p: dict, applicable: dict[str, Any], r: _Result) -> set[str]:
    """Find violations in the proposed changes themselves; returns the invariant ids they violate."""
    violated: set[str] = set()
    delta = p["dependency_delta"]
    if not isinstance(delta.get("added", []), list):
        r.fail("PROPOSAL_WELL_FORMED", "dependency_delta.added is not a list")
    elif delta.get("added"):
        r.refuse("NO_ADDED_DEPENDENCY", f"dependency_delta.added names {delta['added']}")
    forbidden_true = [k.split(":", 1)[1] for k, v in applicable.items() if k.startswith("invariant:") and v is False]
    for ch in p["proposed_changes"]:
        if not isinstance(ch, dict) or not _str(ch.get("path")) or not isinstance(ch.get("content", ""), str):
            r.fail("PROPOSAL_WELL_FORMED", "proposed change lacks a path or has non-text content")
            continue
        path, text = ch["path"], ch.get("content", "")
        if ch.get("action") != "delete":
            if path.rsplit("/", 1)[-1] in DEPENDENCY_MANIFESTS or REQUIREMENTS_FILE.search(path):
                r.refuse("NO_ADDED_DEPENDENCY", f"{path} declares dependencies")
            for rx, what in ((INSTALL, "installs a package"), (SCHEDULER, "adds a schedule or cross-workflow trigger"),
                             (WAIT, "waits by sleeping or polling")):
                if rx.search(text):
                    r.refuse("NO_ADDED_DEPENDENCY", f"{path} {what}")
            for key in forbidden_true:
                if re.search(ASSIGN_TRUE.format(key=re.escape(key)), text):
                    iid = "invariant:" + key
                    violated.add(iid)
                    r.refuse("INVARIANT_CONFORMS", f"{path} sets {key} true; the canonical value is false", iid)
    return violated


def _evaluator_violations(p: dict, canonical_sources: list[dict], applicable: dict[str, Any], r: _Result) -> set[str]:
    """Ask RT-INVARIANT-EVALUATION-001 the same question per applicable invariant, for every proposed JSON change.

    The evaluator reads what a JSON subject asserts about each invariant and answers DENY only when an
    assertion contradicts the canonical value; its ALLOW and UNDECIDABLE answers change nothing here, so the
    proposal's own assessment still carries coverage. Keeping both on one evaluator stops the two drifting.
    """
    violated: set[str] = set()
    canon = None
    for s in canonical_sources:  # same resolution as _resolve_sources: the last entry per (repository, path) wins
        if (s.get("repository"), s.get("path")) == MANDATORY_SOURCE:
            canon = s
    if canon is None or not applicable:
        return violated
    inv_src = {"repository": canon["repository"], "path": canon["path"], "revision": canon["revision"]}
    for ch in p["proposed_changes"]:
        if not isinstance(ch, dict) or ch.get("action") == "delete" or not _str(ch.get("path")):
            continue
        text = ch.get("content", "")
        if not isinstance(text, str) or not text.lstrip().startswith(("{", "[")):
            continue
        try:
            json.loads(text)
        except (ValueError, RecursionError):
            continue  # not JSON (or too deep for the stdlib parser): the text checks above already apply
        subject = {"repository": "proposal", "path": ch["path"], "revision": "proposed"}
        sources = [dict(canon), {**subject, "content": text.encode("utf-8")}]
        for iid in sorted(applicable):
            question = {"schema": invariant_evaluation.QUESTION_SCHEMA, "question_id": f"{ch['path']}#{iid}",
                        "invariant_id": iid, "owning_existing_goal": OWNING_EXISTING_GOAL,
                        "invariants_source": inv_src, "subject": subject}
            answer = invariant_evaluation.evaluate(question, sources, None)
            if answer["disposition"] == invariant_evaluation.FAIL_CLOSED:
                # The evaluator could not bind the question (e.g. an invariant that only a secondary source
                # declares). Not a violation, but never silent: keep its six fields in the findings.
                r.findings.append({"predicate": "EVALUATOR_ANSWER_UNBOUND", "classification": EVIDENCE_INSUFFICIENT,
                                   "invariant_id": iid, "path": ch["path"],
                                   **{k: answer[k] for k in ("failure_code", "failed_predicate",
                                                             "required_evidence_or_repair", "retry_entrypoint",
                                                             "owning_existing_goal", "next_attempt")}})
                continue
            if answer["disposition"] == invariant_evaluation.DENY:
                violated.add(iid)
                cites = [c for c in answer["citations"] if c.startswith("proposal@proposed:")]
                r.refuse("INVARIANT_CONFORMS", f"{ch['path']} contradicts the canonical value of {iid} "
                         f"(evaluator citation {', '.join(cites) or 'n/a'})", iid)
    return violated


def _routing(p: dict, r: _Result) -> None:
    mb = p["manifest_binding"]
    if not (_str(mb.get("manifest_id")) and isinstance(mb.get("canonical_manifest_sha256"), str)
            and SHA256.match(mb["canonical_manifest_sha256"]) and _str(mb.get("processing_capability"))
            and _str(mb.get("processing_route_id"))):
        r.fail("MANIFEST_ROUTING_BOUND", "manifest_binding is not bound to a manifest, capability and route")
    for k in mb:
        if IDENTITY_ROUTING_KEY.search(k):
            r.refuse("ROUTING_BY_CAPABILITY_ONLY", f"manifest_binding.{k} routes by identity")


def _claims(p: dict, r: _Result) -> None:
    if p["approval_effect"] != "NONE":
        r.refuse("APPROVAL_EFFECT_NONE", f"approval_effect is {p['approval_effect']!r}")
    if not isinstance(p["evidence_class"], str) or p["evidence_class"] not in PROPOSAL_EVIDENCE_CLASSES:
        r.refuse("EVIDENCE_CLASS_NOT_INFLATED", f"evidence_class is {p['evidence_class']!r}")
    if p["runtime_transition_claimed"] is not False:
        r.refuse("RUNTIME_TRANSITION_NOT_CLAIMED", "runtime_transition_claimed is not false")
    for d in p["review_finding_deltas"]:
        if (not isinstance(d, dict) or not _str(d.get("finding_id")) or not isinstance(d.get("status"), str)
                or not isinstance(d.get("previous_status", ""), str)):
            r.fail("PROPOSAL_WELL_FORMED", "review finding delta lacks finding_id or a text status")
            continue
        new = d.get("new_evidence_refs")
        if d.get("previous_status") in SETTLED and d["status"] in REOPENED and not (isinstance(new, list) and new):
            r.refuse("NO_REVIEW_CHURN", f"{d['finding_id']} reopened without new evidence")


def evaluate(proposal: Any, canonical_sources: list[dict]) -> dict[str, Any]:
    """Evaluate a conformance proposal against supplied canonical sources.

    canonical_sources: [{"repository", "path", "revision", "content": bytes}], resolved by the caller.
    """
    r = _Result()
    coverage = None
    resolved: list[dict] = []
    if _well_formed(proposal, r):
        _claims(proposal, r)
        _routing(proposal, r)
        applicable, resolved = _resolve_sources(proposal, canonical_sources, r)
        violated = _inspect_changes(proposal, applicable, r)
        violated |= _evaluator_violations(proposal, canonical_sources, applicable, r)
        coverage = _assessment(proposal, applicable, resolved, violated, r)
    disposition = FAIL_CLOSED if r.fail_closed else DENY if r.deny else ALLOW
    out = {"disposition": disposition,
           "failed_predicates": sorted(r.fail_closed) + sorted(r.deny),
           "findings": r.findings, "coverage": coverage, "resolved_sources": resolved,
           "authority_effect": "NONE"}
    if disposition != ALLOW:
        first = (sorted(r.fail_closed) or sorted(r.deny))[0]
        out.update({"failure_code": f"CONFORMANCE_PROPOSAL_{disposition}_{first}", "failed_predicate": first,
                    "required_evidence_or_repair": PREDICATES[first][1], "retry_entrypoint": RETRY_ENTRYPOINT,
                    "owning_existing_goal": OWNING_EXISTING_GOAL,
                    "next_attempt": "Repair the proposal and evaluate it again against the same resolved sources."})
    return out


def main(argv: list[str]) -> int:
    """python conformance_proposal.py PROPOSAL.json REPOSITORY:PATH@REVISION=FILE ..."""
    if len(argv) < 2:
        print(main.__doc__, file=sys.stderr)
        return 2
    with open(argv[0], "rb") as fh:
        proposal = json.loads(fh.read())
    sources = []
    for spec in argv[1:]:
        ref, _, file = spec.rpartition("=")
        repo_path, _, revision = ref.rpartition("@")
        repo, _, path = repo_path.partition(":")
        with open(file, "rb") as fh:
            sources.append({"repository": repo, "path": path, "revision": revision, "content": fh.read()})
    result = evaluate(proposal, sources)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["disposition"] == ALLOW else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
