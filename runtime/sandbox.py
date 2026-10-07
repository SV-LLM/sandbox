"""SV-LLM Sandbox runtime: bounded multi-entity collaboration with receipted outcomes.

Every attempted transition yields exactly one receipt in the Sandbox repository
ledger, whether it is admitted or denied. DENY is a disposition, not a stop.
Each receipt is also handed to the organization propagation hook (the SV-LLM
organization ledger's aggregate_transition) when one is configured.

Transition classes:
  SANDBOX_WORK_ADMITTED / SANDBOX_WORK_DENIED
  CAPABILITY_ASSIGNMENT / CAPABILITY_ASSIGNMENT_DENIED
  CONTRIBUTION_REQUESTED / CONTRIBUTION_REQUEST_DENIED
  ENTITY_CONTRIBUTION_RECORDED (CONTRIBUTED, UNAVAILABLE, FAILED)
  ENTITY_CONTRIBUTION_REFUSED (REFUSED)
  ENTITY_CONTRIBUTION_DENIED (an envelope that fails verification)
  SANDBOX_SYNTHESIS_RECORDED / SANDBOX_SYNTHESIS_DENIED
  SANDBOX_WORK_COMPLETED / SANDBOX_WORK_COMPLETION_DENIED
  SANDBOX_TOOL_OBSERVATION_RECORDED (ALLOW, DENY or FAIL_CLOSED tool attempts; runtime/stegbrowser_tool.py)
  ORGANIZATION_PROPAGATION_FAILED (repo-level FAIL_CLOSED; no org receipt is fabricated)
  ORGANIZATION_PROPAGATION_RECOVERED (repropagate() succeeded for a failed receipt)

Synthesis binds every recorded contribution/refusal and every recorded tool
observation, so observation-only work can complete. Completion is refused while
any of the work's receipts still awaits organization propagation. Master
Records is never a completion predicate.

Contracts (SV_LLM_CANONICAL_JSON_V1, sv-llm.* schemas) and the registration
predicates come from SV-LLM/.github: org-runtime/sandbox_registration.py and its
digest-verified vendored copy of SV-LLM/schemas. Sandbox-to-entity dispatch is
intra-organization. The StegBrowser tool adapter may perform ordinary HTTPS
browser interaction; that is not an inter-organization transition and uses
neither InTr nor LLM-adapter. Nothing here confers governance authority.
"""
from __future__ import annotations
import importlib.util, json, sys
from pathlib import Path
from typing import Any, Callable

sys.path.insert(0, str(Path(__file__).resolve().parent))
from ledger import Ledger, sha  # noqa: E402

ALLOW, DENY, FAIL_CLOSED = "ALLOW", "DENY", "FAIL_CLOSED"
NON_SUCCESS = ("REFUSED", "UNAVAILABLE", "FAILED")


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


class Sandbox:
    def __init__(self, *, dotgithub_root: Path, ledger: Ledger | None = None,
                 propagate: Callable[[dict[str, Any], str], Any] | None = None):
        root = Path(dotgithub_root)
        sys.path.insert(0, str(root / "org-runtime"))
        self.registration = _load("sandbox_registration", root / "org-runtime/sandbox_registration.py")
        self.canon = self.registration.CANON
        from jsonschema import Draft202012Validator
        from referencing import Registry, Resource
        vendor = self.registration.VENDOR
        docs = [json.loads((vendor / n).read_text()) for n in ("entity-capability.schema.json", "capability-id.schema.json")]
        local = Path(__file__).resolve().parent / "contracts"
        self.registration.verify_vendor(local)
        docs +=[json.loads((local / n).read_text()) for n in ("sandbox-work.schema.json", "contribution.schema.json")]
        registry = Registry().with_resources((d["$id"], Resource.from_contents(d)) for d in docs)
        by_id = {d["title"]: Draft202012Validator(d, registry=registry) for d in docs}
        self.work_validator = by_id["sv-llm.sandbox-work/v0.1"]
        self.contribution_validator = by_id["sv-llm.contribution/v0.1"]
        self.ledger = ledger or Ledger()
        self.propagate = propagate

    # -- recording ---------------------------------------------------------------
    def _record(self, transition_class: str, subject: Any, outcome: dict[str, Any]) -> dict[str, Any]:
        receipt = self.ledger.append(transition_class, predecessor=sha(subject), successor=sha(outcome),
                                     evidence=outcome)
        result = {"transition_class": transition_class, **outcome, "repo_receipt_sha256": receipt["receipt_sha256"]}
        if self.propagate is not None:
            try:
                org = self.propagate(receipt, transition_class)
            except Exception as exc:  # organization ledger unavailable or refused the receipt
                return self._propagation_failed(receipt, exc, result)
            result["org_receipt_sha256"] = org["receipt_sha256"]
        return result

    def _propagation_failed(self, receipt: dict[str, Any], exc: Exception, result: dict[str, Any]) -> dict[str, Any]:
        """Record a repo-level FAIL_CLOSED for a failed organization propagation. No org receipt is fabricated."""
        failure = {"disposition": FAIL_CLOSED, "failed_predicate": "ORGANIZATION_PROPAGATION_SUCCEEDED",
                   "failed_receipt_sha256": receipt["receipt_sha256"],
                   "failed_transition_class": receipt["transition_class"],
                   "work_id": receipt["evidence"].get("work_id"), "error_type": type(exc).__name__,
                   "retry_entrypoint": "runtime.sandbox.Sandbox.repropagate", "authority_effect": "NONE"}
        logged = self.ledger.append("ORGANIZATION_PROPAGATION_FAILED", predecessor=receipt["receipt_sha256"],
                                    successor=sha(failure), evidence=failure)
        return {**result, "disposition": FAIL_CLOSED, "failed_predicate": "ORGANIZATION_PROPAGATION_SUCCEEDED",
                "recorded_disposition": result.get("disposition"),
                "propagation_failure_receipt_sha256": logged["receipt_sha256"],
                "retry_entrypoint": "runtime.sandbox.Sandbox.repropagate"}

    def pending_propagation(self, work_id: str | None = None) -> list[str]:
        """Repo receipts whose organization propagation failed and has not been recovered."""
        chain = self.ledger.chain()
        failed = {r["evidence"]["failed_receipt_sha256"]: r["evidence"].get("work_id") for r in chain
                  if r["transition_class"] == "ORGANIZATION_PROPAGATION_FAILED"}
        recovered = {r["evidence"]["recovered_receipt_sha256"] for r in chain
                     if r["transition_class"] == "ORGANIZATION_PROPAGATION_RECOVERED"}
        return [d for d, w in failed.items() if d not in recovered and (work_id is None or w == work_id)]

    def repropagate(self, receipt_sha256: str) -> dict[str, Any]:
        """Retry organization propagation of an existing repo receipt without repeating its action."""
        if receipt_sha256 not in self.pending_propagation():
            return {"disposition": DENY, "failed_predicate": "RECEIPT_PROPAGATION_PENDING", "authority_effect": "NONE"}
        receipt = next(r for r in self.ledger.chain() if r["receipt_sha256"] == receipt_sha256)
        try:
            org = self.propagate(receipt, receipt["transition_class"])
        except Exception as exc:
            return {"disposition": FAIL_CLOSED, "failed_predicate": "ORGANIZATION_PROPAGATION_SUCCEEDED",
                    "error_type": type(exc).__name__, "retry_entrypoint": "runtime.sandbox.Sandbox.repropagate",
                    "authority_effect": "NONE"}
        recovered = {"disposition": ALLOW, "recovered_receipt_sha256": receipt_sha256,
                     "work_id": receipt["evidence"].get("work_id"), "org_receipt_sha256": org["receipt_sha256"],
                     "authority_effect": "NONE"}
        return self._record("ORGANIZATION_PROPAGATION_RECOVERED", {"intended_action": "REPROPAGATE",
                                                                    "receipt_sha256": receipt_sha256}, recovered)

    def _deny(self, transition_class: str, subject: Any, predicate: str, **extra) -> dict[str, Any]:
        return self._record(transition_class, subject, {"disposition": DENY, "failed_predicate": predicate,
                                                        "authority_effect": "NONE", **extra})

    def _parse(self, data: bytes | str):
        try:
            return self.canon.parse(data), None
        except self.canon.CanonicalError as exc:
            return None, exc.failed_predicate

    def _receipts(self, work_id: str, transition_class: str | None = None) -> list[dict[str, Any]]:
        return [r for r in self.ledger.chain()
                if r["evidence"].get("work_id") == work_id and r["evidence"].get("disposition") == ALLOW
                and (transition_class is None or r["transition_class"] == transition_class)]

    def _work(self, work_id: str) -> dict[str, Any] | None:
        rows = self._receipts(work_id, "SANDBOX_WORK_ADMITTED")
        return rows[0]["evidence"]["work"] if rows else None

    # -- S1: admission -----------------------------------------------------------
    def admit(self, work_bytes: bytes, *, parent_repo_receipt: dict[str, Any],
              parent_org_receipt: dict[str, Any], subject: Any) -> dict[str, Any]:
        attempt = {"intended_action": "ADMIT_SANDBOX_WORK", "work_sha256": sha(work_bytes)}
        work, failed = self._parse(work_bytes)
        if failed:
            return self._deny("SANDBOX_WORK_DENIED", attempt, "WORK_IS_CANONICAL_JSON", detail=failed)
        errors = sorted(self.work_validator.iter_errors(work), key=lambda e: list(e.absolute_path))
        if errors:
            return self._deny("SANDBOX_WORK_DENIED", attempt, "WORK_IS_SCHEMA_VALID", detail=errors[0].message[:300])
        work_id, parent = work["work_id"], work["parent_transition"]
        if self._work(work_id) is not None:
            return self._deny("SANDBOX_WORK_DENIED", attempt, "WORK_ID_NOT_ALREADY_ADMITTED", work_id=work_id)
        repo_body = {k: v for k, v in parent_repo_receipt.items() if k != "receipt_sha256"}
        if (parent_repo_receipt.get("schema") != "stegverse.repo-transition-receipt/v1"
                or sha(repo_body) != parent_repo_receipt.get("receipt_sha256")
                or parent_repo_receipt["receipt_sha256"] != parent["repo_receipt_sha256"]):
            return self._deny("SANDBOX_WORK_DENIED", attempt, "PARENT_REPO_RECEIPT_MATCHES", work_id=work_id)
        if not str(parent_repo_receipt.get("repository", "")).startswith("SV-LLM/"):
            return self._deny("SANDBOX_WORK_DENIED", attempt, "PARENT_IS_SV_LLM_TRANSITION", work_id=work_id)
        if parent_repo_receipt.get("transition_class") != parent["transition_class"]:
            return self._deny("SANDBOX_WORK_DENIED", attempt, "PARENT_TRANSITION_CLASS_MATCHES", work_id=work_id)
        org_body = {k: v for k, v in parent_org_receipt.items() if k != "receipt_sha256"}
        if (parent_org_receipt.get("schema") != "stegverse.organization-transition-receipt/v1"
                or parent_org_receipt.get("organization") != "SV-LLM"
                or sha(org_body) != parent_org_receipt.get("receipt_sha256")
                or parent_org_receipt["receipt_sha256"] != parent["org_receipt_sha256"]):
            return self._deny("SANDBOX_WORK_DENIED", attempt, "PARENT_ORG_RECEIPT_MATCHES", work_id=work_id)
        if parent_org_receipt.get("repo_receipt_sha256") != parent["repo_receipt_sha256"]:
            return self._deny("SANDBOX_WORK_DENIED", attempt, "ORG_RECEIPT_PROPAGATES_REPO_RECEIPT", work_id=work_id)
        if sha(subject) != parent["subject_or_artifact_digest"] \
                or parent_repo_receipt.get("successor_state_sha256") != parent["subject_or_artifact_digest"]:
            return self._deny("SANDBOX_WORK_DENIED", attempt, "SUBJECT_IS_PARENT_SUCCESSOR_STATE", work_id=work_id)
        return self._record("SANDBOX_WORK_ADMITTED", attempt,
                            {"disposition": ALLOW, "work_id": work_id, "work": work,
                             "parent_transition": parent, "authority_effect": "NONE"})

    # -- capability assignment -----------------------------------------------------
    def assign(self, work_id: str, entity: str, capability: str, *, declaration: bytes | None,
               tree: Any | None = None) -> dict[str, Any]:
        attempt = {"intended_action": "ASSIGN_CAPABILITY", "work_id": work_id, "entity": entity, "capability": capability}
        work = self._work(work_id)
        if work is None:
            return self._deny("CAPABILITY_ASSIGNMENT_DENIED", attempt, "WORK_IS_ADMITTED", work_id=work_id, entity=entity)
        if capability not in work["requested_capabilities"] or capability not in work["permitted_capabilities"]:
            return self._deny("CAPABILITY_ASSIGNMENT_DENIED", attempt, "CAPABILITY_REQUESTED_AND_PERMITTED_BY_WORK",
                              work_id=work_id, entity=entity, capability=capability)
        registration = self.registration.register(entity, declaration=declaration, tree=tree)
        if registration["disposition"] != ALLOW:
            return self._deny("CAPABILITY_ASSIGNMENT_DENIED", attempt, registration["failed_predicate"],
                              work_id=work_id, entity=entity, capability=capability)
        if capability not in registration["capabilities"]:
            return self._deny("CAPABILITY_ASSIGNMENT_DENIED", attempt, "CAPABILITY_NOT_DECLARED_BY_ENTITY",
                              work_id=work_id, entity=entity, capability=capability)
        evidence = self.registration.assignment_evidence(registration, capability)
        return self._record("CAPABILITY_ASSIGNMENT", attempt,
                            {"disposition": ALLOW, "work_id": work_id, "entity": entity,
                             "capability_assignment_evidence": evidence, "authority_effect": "NONE"})

    def _assignment(self, work_id: str, entity: str, capability: str) -> dict[str, Any] | None:
        for r in self._receipts(work_id, "CAPABILITY_ASSIGNMENT"):
            e = r["evidence"]
            if e["entity"] == entity and e["capability_assignment_evidence"]["capability"] == capability:
                return e["capability_assignment_evidence"]
        return None

    # -- contribution request (the same bounded contract for every participant) ------
    def request(self, work_id: str, entity: str, capability: str) -> dict[str, Any]:
        attempt = {"intended_action": "REQUEST_CONTRIBUTION", "work_id": work_id, "entity": entity, "capability": capability}
        work = self._work(work_id)
        if work is None or self._assignment(work_id, entity, capability) is None:
            return self._deny("CONTRIBUTION_REQUEST_DENIED", attempt, "CAPABILITY_ASSIGNED_FOR_ADMITTED_WORK",
                              work_id=work_id, entity=entity, capability=capability)
        return self._record("CONTRIBUTION_REQUESTED", attempt,
                            {"disposition": ALLOW, "work_id": work_id, "entity": entity, "capability": capability,
                             "work_sha256": self.canon.digest(work), "authority_effect": "NONE"})

    # -- contribution recording -----------------------------------------------------
    def record(self, envelope_bytes: bytes, *, retained: bytes | None = None) -> dict[str, Any]:
        attempt = {"intended_action": "RECORD_ENTITY_CONTRIBUTION", "envelope_sha256": sha(envelope_bytes)}
        envelope, failed = self._parse(envelope_bytes)
        if failed:
            return self._deny("ENTITY_CONTRIBUTION_DENIED", attempt, "ENVELOPE_IS_CANONICAL_JSON", detail=failed)
        errors = sorted(self.contribution_validator.iter_errors(envelope), key=lambda e: list(e.absolute_path))
        if errors:
            return self._deny("ENTITY_CONTRIBUTION_DENIED", attempt, "ENVELOPE_IS_SCHEMA_VALID",
                              detail=errors[0].message[:300])
        work_id, entity, capability = envelope["work_id"], envelope["entity"], envelope["capability"]
        ids = dict(work_id=work_id, entity=entity, contribution_id=envelope["contribution_id"])
        work = self._work(work_id)
        assignment = self._assignment(work_id, entity, capability) if work else None
        requested = any(r["evidence"]["entity"] == entity and r["evidence"]["capability"] == capability
                        for r in self._receipts(work_id, "CONTRIBUTION_REQUESTED"))
        if work is None or assignment is None or not requested:
            return self._deny("ENTITY_CONTRIBUTION_DENIED", attempt, "CONTRIBUTION_WAS_REQUESTED", **ids)
        if any(r["evidence"].get("contribution_id") == envelope["contribution_id"]
               for r in self._receipts(work_id) if r["transition_class"].startswith("ENTITY_CONTRIBUTION_")):
            return self._deny("ENTITY_CONTRIBUTION_DENIED", attempt, "CONTRIBUTION_ID_UNIQUE", **ids)
        if "artifact_refs" in envelope and retained is None:
            return self._deny("ENTITY_CONTRIBUTION_DENIED", attempt, "ARTIFACT_CONTENT_RETAINED", **ids)
        try:
            self.canon.verify_contribution(envelope, work=work, declaration=assignment["declaration"], retained=retained)
        except self.canon.CanonicalError as exc:
            return self._deny("ENTITY_CONTRIBUTION_DENIED", attempt, exc.failed_predicate, **ids)
        outcome = {"disposition": ALLOW, **ids, "status": envelope["status"], "content_digest": envelope["content_digest"],
                   "envelope": envelope, "authority_effect": "NONE"}
        if retained is not None:
            outcome["retained_content_sha256"] = sha(retained)
        cls = "ENTITY_CONTRIBUTION_REFUSED" if envelope["status"] == "REFUSED" else "ENTITY_CONTRIBUTION_RECORDED"
        return self._record(cls, attempt, outcome)

    def contributions(self, work_id: str) -> list[dict[str, Any]]:
        return [r for r in self._receipts(work_id)
                if r["transition_class"] in ("ENTITY_CONTRIBUTION_RECORDED", "ENTITY_CONTRIBUTION_REFUSED")]

    def observations(self, work_id: str) -> list[dict[str, Any]]:
        """Every recorded tool observation for the work item, whatever its disposition."""
        return [r for r in self.ledger.chain() if r["transition_class"] == "SANDBOX_TOOL_OBSERVATION_RECORDED"
                and r["evidence"].get("work_id") == work_id]

    def record_tool_observation(self, observation: dict[str, Any]) -> dict[str, Any]:
        """Append SANDBOX_TOOL_OBSERVATION_RECORDED. Called by tool adapters (runtime/stegbrowser_tool.py)."""
        self.canon.check_value(observation)
        attempt = {"intended_action": "RECORD_SANDBOX_TOOL_OBSERVATION", "work_id": observation.get("work_id"),
                   "observation_id": observation.get("observation_id")}
        return self._record("SANDBOX_TOOL_OBSERVATION_RECORDED", attempt,
                            {**observation, "observation_digest": self.canon.digest(observation),
                             "authority_effect": "NONE"})

    # -- synthesis ------------------------------------------------------------------
    def synthesize(self, work_id: str, input_ids: list[str], synthesis: Any) -> dict[str, Any]:
        """Bind every recorded contribution/refusal and every recorded tool observation; omit nothing."""
        attempt = {"intended_action": "RECORD_SANDBOX_SYNTHESIS", "work_id": work_id, "input_ids": input_ids}
        if self._work(work_id) is None:
            return self._deny("SANDBOX_SYNTHESIS_DENIED", attempt, "WORK_IS_ADMITTED", work_id=work_id)
        recorded = {r["evidence"]["contribution_id"]: ("CONTRIBUTION", r) for r in self.contributions(work_id)}
        recorded.update({r["evidence"]["observation_id"]: ("TOOL_OBSERVATION", r) for r in self.observations(work_id)})
        if not recorded:
            return self._deny("SANDBOX_SYNTHESIS_DENIED", attempt, "SYNTHESIS_INPUTS_RECORDED", work_id=work_id)
        if sorted(input_ids) != sorted(recorded) or len(set(input_ids)) != len(input_ids):
            # Disagreement, refusal, unavailability, failure and every tool observation survive synthesis.
            return self._deny("SANDBOX_SYNTHESIS_DENIED", attempt, "SYNTHESIS_BINDS_EVERY_RECORDED_INPUT",
                              work_id=work_id)
        try:
            self.canon.check_value(synthesis)
        except self.canon.CanonicalError as exc:
            return self._deny("SANDBOX_SYNTHESIS_DENIED", attempt, exc.failed_predicate, work_id=work_id)
        lineage = []
        for iid in sorted(input_ids):
            kind, r = recorded[iid]
            e = r["evidence"]
            if kind == "CONTRIBUTION":
                lineage.append({"kind": kind, "contribution_id": iid, "entity": e["entity"], "status": e["status"],
                                "content_digest": e["content_digest"], "uncertainty": e["envelope"]["uncertainty"],
                                "disagreement_refs": e["envelope"].get("disagreement_refs", []),
                                "repo_receipt_sha256": r["receipt_sha256"]})
            else:
                lineage.append({"kind": kind, "observation_id": iid, "tool": e["tool"], "tool_profile": e["tool_profile"],
                                "disposition": e["disposition"], "failed_predicate": e.get("failed_predicate"),
                                "observation_digest": e["observation_digest"],
                                "repo_receipt_sha256": r["receipt_sha256"]})
        return self._record("SANDBOX_SYNTHESIS_RECORDED", attempt,
                            {"disposition": ALLOW, "work_id": work_id, "lineage": lineage, "synthesis": synthesis,
                             "synthesis_digest": self.canon.digest(synthesis), "authority_effect": "NONE"})

    # -- completion -----------------------------------------------------------------
    def complete(self, work_id: str) -> dict[str, Any]:
        attempt = {"intended_action": "COMPLETE_SANDBOX_WORK", "work_id": work_id}
        work = self._work(work_id)
        syntheses = self._receipts(work_id, "SANDBOX_SYNTHESIS_RECORDED")
        if work is None or not syntheses:
            return self._deny("SANDBOX_WORK_COMPLETION_DENIED", attempt, "SYNTHESIS_RECORDED", work_id=work_id)
        if self._receipts(work_id, "SANDBOX_WORK_COMPLETED"):
            return self._deny("SANDBOX_WORK_COMPLETION_DENIED", attempt, "WORK_NOT_ALREADY_COMPLETED", work_id=work_id)
        if self.pending_propagation(work_id):
            # A transition whose required organization propagation failed cannot support completion.
            return self._deny("SANDBOX_WORK_COMPLETION_DENIED", attempt, "ORGANIZATION_PROPAGATION_COMPLETE",
                              work_id=work_id, pending=self.pending_propagation(work_id))
        return self._record("SANDBOX_WORK_COMPLETED", attempt,
                            {"disposition": ALLOW, "work_id": work_id,
                             "expected_output_or_handoff": work["expected_output_or_handoff"],
                             "synthesis_receipt_sha256": syntheses[-1]["receipt_sha256"], "authority_effect": "NONE"})

    # -- reconstruction ---------------------------------------------------------------
    def reconstruct(self, work_id: str) -> dict[str, Any]:
        """Rebuild a work item's history from receipts alone, back to its parent transition."""
        chain = self.ledger.chain()
        by_digest = {r["receipt_sha256"]: r for r in chain}
        rows = [r for r in chain if r["evidence"].get("work_id") == work_id]
        admitted = [r for r in rows if r["transition_class"] == "SANDBOX_WORK_ADMITTED"]
        completed = [r for r in rows if r["transition_class"] == "SANDBOX_WORK_COMPLETED"]
        if len(admitted) != 1 or len(completed) != 1:
            raise ValueError("WORK_NOT_ADMITTED_AND_COMPLETED_ONCE")
        synthesis = by_digest[completed[0]["evidence"]["synthesis_receipt_sha256"]]
        for item in synthesis["evidence"]["lineage"]:
            source = by_digest[item["repo_receipt_sha256"]]
            if item.get("kind", "CONTRIBUTION") == "TOOL_OBSERVATION":
                body = {k: v for k, v in source["evidence"].items() if k not in ("observation_digest", "authority_effect")}
                if source["evidence"]["observation_id"] != item["observation_id"] \
                        or self.canon.digest(body) != item["observation_digest"]:
                    raise ValueError("SYNTHESIS_LINEAGE_MISMATCH")
                continue
            if source["evidence"]["contribution_id"] != item["contribution_id"] \
                    or source["evidence"]["content_digest"] != item["content_digest"]:
                raise ValueError("SYNTHESIS_LINEAGE_MISMATCH")
            envelope = source["evidence"]["envelope"]
            if "artifact_refs" not in envelope:
                self.canon.verify_contribution(envelope)
        return {"work_id": work_id, "parent_transition": admitted[0]["evidence"]["parent_transition"],
                "admitted": admitted[0]["receipt_sha256"], "synthesis": synthesis["receipt_sha256"],
                "completed": completed[0]["receipt_sha256"],
                "contributions": [i["contribution_id"] for i in synthesis["evidence"]["lineage"] if "contribution_id" in i],
                "observations": [i["observation_id"] for i in synthesis["evidence"]["lineage"] if "observation_id" in i],
                "receipts": [r["receipt_sha256"] for r in rows]}
