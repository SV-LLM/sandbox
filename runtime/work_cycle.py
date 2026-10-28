#!/usr/bin/env python3
"""SV-LLM work cycle: materialized manifest -> Sandbox -> organization ledger -> result egress.

The SV-LLM boundary (SV-LLM/.github org-runtime/crossing.py::ingress) materializes
a manifest addressed to repository `sandbox`, write-once, in the node state the
materializer supplied, and records ORGANIZATION_INGRESS_MATERIALIZED on the
SV-LLM/.github repository ledger and the organization ledger. It selects no
processor there. This module is the Sandbox side of that hand-off:

  binding  after selection and the parent readback and before admission, protected
           work requires a verified StegNode/InTr binding with the native StegOS
           posture verifier and an authentic WorkerCoordinator claim/fence
           (runtime/work_cycle_binding.py, StegVerse-org/.github#163); public
           retrieval keeps its exemption. A refused binding is a six-field Sandbox
           receipt, the intake is marked terminal once, and nothing is assigned or
           requested. Before egress the return crossing is revalidated against the
           take-time binding receipt; a refusal emits nothing.
  intake   each materialization not yet taken in. Processing is selected only by
           the manifest's declared `processing.capability` bound to
           `processing.route_id`, which this service must admit
           (runtime/contracts/sandbox-service.json, evaluated by SV-LLM/.github
           org-boundary/runtime/manifest_selection.py). The parent transition is
           the ORGANIZATION_INGRESS_MATERIALIZED receipt pair, read back from the
           organization ledger by exact key. The work is admitted, each declared
           participant assigned, and its contribution requested. When the work
           names participants = "DERIVE_FROM_DECLARATIONS", runtime/capability_routing.py
           derives them from the registered entities' declarations alone, in the
           organization tree's row order.
  respond  an entity surface answers each outstanding request with its own
           package (the entity repository's core.py). No SV-LLM code invokes a
           model: until an admitted Sandbox tool does, with credentials held by
           TV/TVC, an entity answers UNAVAILABLE NO_ADMITTED_INVOCATION_SURFACE.
           A request whose entity surface the pass does not supply reaches its E0
           terminal in the same pass (StegVerse-org/.github#163, operating-mode
           ladder): the Sandbox records the entity-neutral UNAVAILABLE
           ENTITY_SURFACE_NOT_SUPPLIED contribution, bound to the digest of the
           pass's supplied entity set and carrying a six-field FAIL_CLOSED
           (e0_terminal), so close() synthesizes and completes. No request stays
           outstanding, nothing waits and nothing polls; supplying the surface is
           a new manifest (a new work item), never a wait on this one.
  close    work whose every requested contribution is recorded is synthesized
           and completed, and the result is egressed to the organization the
           manifest's `return_to` names (crossing.py::egress). The mesh is the
           durable queue: the receiver's availability is never a predicate.
           When the manifest's payload carries an `sdk_proposal`, the proposal is
           evaluated first by runtime/conformance_proposal.py against the
           canonical sources the manifest itself carries as digest-bound
           attachments (nothing is fetched); the disposition rides in the
           receipted result, and the proposal is offered to the SDK only on ALLOW.

Every attempt, admitted or refused, is a Sandbox receipt propagated to the
organization ledger, or a crossing receipt on both ledgers. Each pass is
idempotent: intake and result markers are written once in node state.

Run (one pass, nothing waits):
  STEGVERSE_REPO_LEDGER_ROOT=<.github repo ledger> STEGVERSE_ORG_LEDGER_ROOT=<org ledger> \\
  python -B runtime/work_cycle.py --dotgithub <SV-LLM/.github> --mesh-root <mesh> \\
      --node-state-root <node state> --sandbox-ledger <sandbox repo ledger> --standing <standing.json> \\
      [--entity-repo <SV-LLM/Anthropic> ...]

Nothing here confers governance authority.
"""
from __future__ import annotations
import argparse, base64, binascii, hashlib, importlib.util, json, os, sys
from pathlib import Path
from typing import Any, Callable

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "runtime"))
from ledger import Ledger, epoch_refusal  # noqa: E402
from sandbox import Sandbox, ALLOW  # noqa: E402
import conformance_proposal  # noqa: E402
import capability_routing  # noqa: E402
import work_cycle_binding  # noqa: E402

SERVICE = json.loads((ROOT / "runtime/contracts/sandbox-service.json").read_text())
NO_INVOCATION = "NO_ADMITTED_INVOCATION_SURFACE"
SURFACE_NOT_SUPPLIED = "ENTITY_SURFACE_NOT_SUPPLIED"
RESPOND_ENTRYPOINT = "SV-LLM/sandbox runtime/work_cycle.py::respond"
OWNING_EXISTING_GOAL = "SVORG-LLM-ORG-FOUNDATION-001"
CONTRIBUTION_SCHEMA = "sv-llm.contribution/v0.1"
RESULT_SCHEMA = "sv-llm.sandbox-work-result/v1"
SYNTHESIS_SCHEMA = "sv-llm.sandbox-work-cycle-synthesis/v1"
WORK_FIELDS = ("requested_capabilities", "permitted_capabilities", "participation_policy",
               "expected_output_or_handoff", "participants")


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class Entity:
    """An SV-LLM entity's own surface: its capability declaration and its core package."""

    def __init__(self, core: Path, declaration: Path):
        self.core = _load("sv_llm_entity_" + Path(core).parent.name.lower() + "_core", Path(core))
        self.name = self.core.ENTITY
        self.declaration = Path(declaration).read_bytes()

    @classmethod
    def from_repo(cls, repo: Path) -> "Entity":
        """An entity repository: src/<package>/core.py and contracts/entity-capability.json."""
        cores = sorted((Path(repo) / "src").glob("*/core.py"))
        if len(cores) != 1:
            raise ValueError(f"ENTITY_CORE_NOT_UNIQUE: {repo}")
        return cls(cores[0], Path(repo) / "contracts/entity-capability.json")

    def answer(self, work: dict[str, Any], capability: str) -> dict[str, Any]:
        return self.core.non_success(work=work, capability=capability, status="UNAVAILABLE",
                                     reason_or_failed_predicate=NO_INVOCATION,
                                     provenance=["SV-LLM/sandbox runtime/work_cycle.py::respond"])


def entity_set_digest(names) -> str:
    """sha256 over the canonical JSON of the pass's supplied entity names, sorted (SV_LLM_CANONICAL_JSON_V1)."""
    return "sha256:" + hashlib.sha256(json.dumps(sorted(names), sort_keys=True, separators=(",", ":"),
                                                 ensure_ascii=False).encode("utf-8")).hexdigest()


def unsupplied_contribution_id(work_id: str, entity: str, capability: str, set_digest: str) -> str:
    """Deterministic: the same request in a pass with the same supplied entity set always yields the same id."""
    return "surface-not-supplied:" + hashlib.sha256("\0".join((work_id, entity, capability, set_digest)).encode("utf-8")).hexdigest()


def unsupplied_terminal(entity: str, capability: str) -> dict[str, Any]:
    """The six-field FAIL_CLOSED that a request with no supplied entity surface terminates with at E0."""
    return {"disposition": "FAIL_CLOSED", "failure_code": SURFACE_NOT_SUPPLIED,
            "failed_predicate": "ENTITY_SURFACE_SUPPLIED_FOR_REQUESTED_CONTRIBUTION",
            "required_evidence_or_repair": "supply the entity's surface (entity repository core.py and "
                                           "contracts/entity-capability.json) to the pass that takes the work in",
            "retry_entrypoint": RESPOND_ENTRYPOINT, "owning_existing_goal": OWNING_EXISTING_GOAL,
            "next_attempt": "a new manifest for the same work, taken in by a pass that supplies the " + entity
                            + " surface for " + capability + "; this work is complete and nothing waits on it",
            "mode": "E0"}


def unsupplied_envelope(work: dict[str, Any], entity: str, capability: str, set_digest: str, digest) -> dict[str, Any]:
    """The entity-neutral UNAVAILABLE envelope the Sandbox records for an unsupplied surface: the same shape an entity's
    core.non_success emits, attributed to the requested entity, with the Sandbox as its provenance."""
    refs = ["entity-set:" + set_digest]
    provenance = [RESPOND_ENTRYPOINT + " (entity surface not supplied)"]
    record = {"status": "UNAVAILABLE", "reason_or_failed_predicate": SURFACE_NOT_SUPPLIED, "evidence_refs": refs,
              "provenance": provenance, "uncertainty": None}
    return {"schema": CONTRIBUTION_SCHEMA,
            "contribution_id": unsupplied_contribution_id(work["work_id"], entity, capability, set_digest),
            "work_id": work["work_id"], "entity": entity, "capability": capability, "epistemic_state": "OBSERVED",
            "evidence_refs": list(refs), "provenance": list(provenance), "uncertainty": None, "status": "UNAVAILABLE",
            "authority_effect": "NONE", "non_success_status_record": record, "content_digest": digest(record)}


class WorkCycle:
    def __init__(self, *, dotgithub: Path, sandbox_ledger: Path, node_state_root: Path,
                 entities: dict[str, Entity] | None = None, hb_epoch: Any = None,
                 admitted_claims: list[dict[str, Any]] | None = None):
        self.dotgithub = Path(dotgithub).resolve()
        # The supplied heartbeat epoch every receipt of this cycle carries, on the
        # Sandbox ledger, the .github repository ledger and the organization
        # ledger. Absent or invalid, each append is refused six-field FAIL_CLOSED
        # (SV_LLM_LEDGER_APPEND_CLOCK_FALLBACK); it is never read from a clock.
        self.hb_epoch = hb_epoch
        self.crossing = _load("sv_llm_crossing", self.dotgithub / "org-runtime/crossing.py")
        self.kernel = self.crossing.kernel
        self.agg = self.crossing.organization_ledger
        self.selection = self.kernel.manifest_selection(self.dotgithub)
        self.node_state_root = Path(node_state_root)
        self.node_state = self.kernel.addressed_node_state_store(self.node_state_root)
        self.entities = entities or {}
        # The WorkerCoordinator claims/fences admitted for this pass. No Registry/WorkerCoordinator surface supplies
        # them yet, so main() passes none and every protected take fails closed. The posture verifier is never a
        # parameter: it is the vendored StegOS one, digest-checked, or none.
        self.admitted_claims = list(admitted_claims or [])
        self.posture_verifier = work_cycle_binding.native_posture_verifier()
        # Routing precedence is declared by the canonical organization tree's row order, never by name.
        tree = json.loads((self.dotgithub / "data/organization-tree.json").read_text(encoding="utf-8"))
        self.tree_order = [row["name"] for row in tree.get("repositories", []) if isinstance(row, dict) and "name" in row]
        # The Sandbox ledger records only the admitted work's digest; a later run
        # re-derives the body from the materialized manifest in node state.
        self.sandbox = Sandbox(dotgithub_root=self.dotgithub, ledger=Ledger(Path(sandbox_ledger), hb_epoch=hb_epoch),
                               propagate=self._propagate, work_source=self._work_source)

    def _propagate(self, receipt: dict[str, Any], transition_class: str) -> dict[str, Any]:
        """Propagate a Sandbox receipt to the organization ledger at the supplied epoch (no clock fallback)."""
        return self.agg.aggregate_transition(receipt, org_transition_class=transition_class,
                                             boundary_evidence={"source": "SV-LLM/sandbox"},
                                             authority_effect="NONE", hb_epoch=self.hb_epoch)

    @staticmethod
    def _key(prefix: str, name: str) -> str:
        return prefix + hashlib.sha256(name.encode()).hexdigest() + ".json"

    # -- intake ---------------------------------------------------------------------
    def _parent(self, materialization_sha256: str):
        """The ORGANIZATION_INGRESS_MATERIALIZED org receipt and its retained source repo receipt."""
        store = self.agg.open_store(self.agg.ledger_root())
        cursor = (store.get(self.agg.HEAD_KEY) or {}).get("receipt_sha256")
        while cursor:
            org = store.get(self.agg.receipt_key(cursor))
            if org is None:
                return None
            if org.get("org_transition_class") == self.crossing.INGRESS_MATERIALIZED:
                source = store.get(self.agg.source_key(org["source_transition_sha256"]))
                evidence = (source or {}).get("evidence") or {}
                if evidence.get("materialization_sha256") == materialization_sha256:
                    self.agg.verify_source(source)
                    return org, source
            cursor = org.get("previous_receipt_sha256")
        return None

    def _refuse(self, attempt: dict[str, Any], predicate: str, **extra) -> dict[str, Any]:
        return self.sandbox._deny("SANDBOX_WORK_DENIED", attempt, predicate, **extra)

    def _take(self, key: str) -> dict[str, Any]:
        record = self.node_state.get(key)
        packet = record["packet"]
        manifest = (packet.get("payload") or {}).get("manifest") or {}
        attempt = {"intended_action": "TAKE_MATERIALIZED_MANIFEST_INTO_SANDBOX", "materialization_key": key,
                   "manifest_id": manifest.get("manifest_id")}
        try:
            selected = self.selection.select_processing(SERVICE, manifest)
        except SystemExit as refused:
            return {"admit": self._refuse(attempt, "PROCESSING_SELECTED_BY_ADMITTED_MANIFEST", detail=str(refused))}
        parent = self._parent(self.kernel.sha(record))
        if parent is None:
            return {"admit": self._refuse(attempt, "PARENT_INGRESS_RECEIPT_PRESENT")}
        org, source = parent
        spec = (manifest.get("payload") or {}).get("work")
        if not isinstance(spec, dict) or any(f not in spec for f in WORK_FIELDS):
            return {"admit": self._refuse(attempt, "WORK_DECLARED_BY_MANIFEST")}
        binding = self._bind(manifest, org, source)
        if binding["disposition"] != ALLOW:
            # Terminal: intake() writes its marker once from this refusal; nothing is assigned or requested.
            return {"admit": binding, "selection": selected, "binding": binding, "assign": [], "request": []}
        subject = source["evidence"]
        work = self._work_object(manifest, org, source, spec)
        admitted = self.sandbox.admit(self.sandbox.canon.canonical(work), parent_repo_receipt=source,
                                      parent_org_receipt=org, subject=subject)
        out = {"admit": admitted, "selection": selected, "binding": binding, "assign": [], "request": []}
        if admitted["disposition"] != ALLOW:
            return out
        participants = spec["participants"]
        if participants == capability_routing.DERIVE:
            # Participants derived from the registered entities' own declarations, in a fixed order.
            # No entity availability is consulted; an unroutable request is refused with six fields.
            on_tree = [n for n in self.tree_order if n in self.entities]  # off-tree surfaces are never routed to
            routed = capability_routing.derive_participants(
                work["requested_capabilities"], {n: self.entities[n].declaration for n in on_tree}, order=on_tree)
            out["routing"] = routed
            if routed["disposition"] != ALLOW:
                out["assign"].append(self._refuse(
                    {"intended_action": "DERIVE_PARTICIPANTS_FROM_DECLARATIONS", "work_id": work["work_id"]},
                    "PARTICIPANTS_DERIVABLE_FROM_DECLARATIONS",
                    routing={k: routed[k] for k in ("failure_code", "failed_predicate", "required_evidence_or_repair",
                                                    "retry_entrypoint", "owning_existing_goal", "next_attempt")}))
                return out
            participants = routed["participants"]
        for p in participants:
            entity, capability = p.get("entity"), p.get("capability")
            surface = self.entities.get(entity)
            assigned = self.sandbox.assign(work["work_id"], entity, capability,
                                           declaration=surface.declaration if surface else None)
            out["assign"].append(assigned)
            if assigned["disposition"] == ALLOW:
                out["request"].append(self.sandbox.request(work["work_id"], entity, capability))
        return out

    # -- binding ----------------------------------------------------------------------
    def _bindings(self, transition_class: str) -> list[dict[str, Any]]:
        return [{**r["evidence"], "repo_receipt_sha256": r["receipt_sha256"]} for r in self.sandbox.ledger.chain()
                if r["transition_class"] == transition_class and r["evidence"].get("disposition") == ALLOW]

    def _bind(self, manifest: dict[str, Any], org: dict[str, Any], source: dict[str, Any]) -> dict[str, Any]:
        """The take-time binding, recorded as a Sandbox receipt bound to the parent ingress receipt pair."""
        task_id = manifest.get("manifest_id")
        verdict = work_cycle_binding.evaluate_take(
            manifest, task_id=task_id, hb_epoch=self.hb_epoch, admitted_claims=self.admitted_claims,
            bound=self._bindings("SANDBOX_WORK_BINDING_VERIFIED"), verifier=self.posture_verifier)
        verdict = {**verdict, "work_id": task_id, "parent_repo_receipt_sha256": source["receipt_sha256"],
                   "parent_org_receipt_sha256": org["receipt_sha256"]}
        attempt = {"intended_action": "BIND_MATERIALIZED_MANIFEST_BEFORE_ADMISSION", "manifest_id": task_id,
                   "transition_request_sha256": verdict["transition_request_sha256"]}
        cls = "SANDBOX_WORK_BINDING_VERIFIED" if verdict["disposition"] == ALLOW else "SANDBOX_WORK_BINDING_REFUSED"
        return self.sandbox._record(cls, attempt, verdict)

    def _rebind(self, work: dict[str, Any], completion: dict[str, Any]) -> dict[str, Any]:
        """Revalidate the manifest-selected return crossing against the take-time binding, before any egress."""
        manifest = work["manifested_request"]
        taken = [b for b in self._bindings("SANDBOX_WORK_BINDING_VERIFIED") if b.get("work_id") == work["work_id"]]
        verdict = work_cycle_binding.evaluate_return(
            manifest, taken[-1] if taken else None, task_id=work["work_id"], hb_epoch=self.hb_epoch,
            admitted_claims=self.admitted_claims, verifier=self.posture_verifier)
        verdict = {**verdict, "work_id": work["work_id"], "completion_repo_receipt_sha256": completion["receipt_sha256"]}
        attempt = {"intended_action": "REVALIDATE_RETURN_CROSSING_BEFORE_EGRESS", "work_id": work["work_id"],
                   "completion_repo_receipt_sha256": completion["receipt_sha256"]}
        cls = "SANDBOX_RETURN_BINDING_REVALIDATED" if verdict["disposition"] == ALLOW else "SANDBOX_RETURN_BINDING_REFUSED"
        return self.sandbox._record(cls, attempt, verdict)

    @staticmethod
    def _work_object(manifest: dict[str, Any], org: dict[str, Any], source: dict[str, Any],
                     spec: dict[str, Any]) -> dict[str, Any]:
        return {"schema": "sv-llm.sandbox-work/v0.1", "work_id": manifest["manifest_id"],
                "manifested_request": manifest,
                "parent_transition": {"transition_class": source["transition_class"],
                                      "repo_receipt_sha256": source["receipt_sha256"],
                                      "org_receipt_sha256": org["receipt_sha256"],
                                      "subject_or_artifact_digest": source["successor_state_sha256"]},
                "canonical_context_refs": spec.get("canonical_context_refs", []),
                **{f: spec[f] for f in WORK_FIELDS if f != "participants"}}

    def _work_source(self, work_id: str, work_sha256: str) -> bytes | None:
        """Re-derive an admitted work object from its materialized manifest in node state.

        Returns canonical bytes only when they digest to the admission receipt's
        work_sha256 (Sandbox._work checks it again); otherwise None, and the work
        is treated as not admitted."""
        for key in self.node_state.list_prefix(SERVICE["materialization_prefix"]):
            record = self.node_state.get(key)
            manifest = ((record or {}).get("packet", {}).get("payload") or {}).get("manifest") or {}
            if manifest.get("manifest_id") != work_id:
                continue
            spec = (manifest.get("payload") or {}).get("work")
            parent = self._parent(self.kernel.sha(record))
            if not isinstance(spec, dict) or any(f not in spec for f in WORK_FIELDS) or parent is None:
                continue
            data = self.sandbox.canon.canonical(self._work_object(manifest, *parent, spec))
            if self.sandbox.canon.digest(self.sandbox.canon.parse(data)) == work_sha256:
                return data
        return None

    def intake(self) -> list[dict[str, Any]]:
        results = []
        for key in self.node_state.list_prefix(SERVICE["materialization_prefix"]):
            marker = self._key(SERVICE["intake_prefix"], key)
            if self.node_state.exists(marker):
                continue
            taken = self._take(key)
            self.node_state.put_once(marker, {"schema": "sv-llm.sandbox-intake-marker/v1", "materialization_key": key,
                                              "admit_disposition": taken["admit"]["disposition"],
                                              "admit_repo_receipt_sha256": taken["admit"]["repo_receipt_sha256"]})
            results.append(taken)
        return results

    # -- respond --------------------------------------------------------------------
    def _admitted(self) -> list[str]:
        return [r["evidence"]["work_id"] for r in self.sandbox.ledger.chain()
                if r["transition_class"] == "SANDBOX_WORK_ADMITTED"]

    def _outstanding(self, work_id: str) -> list[tuple[str, str]]:
        answered = {(r["evidence"]["entity"], r["evidence"]["envelope"]["capability"])
                    for r in self.sandbox.contributions(work_id)}
        return [(r["evidence"]["entity"], r["evidence"]["capability"])
                for r in self.sandbox._receipts(work_id, "CONTRIBUTION_REQUESTED")
                if (r["evidence"]["entity"], r["evidence"]["capability"]) not in answered]

    def respond(self) -> list[dict[str, Any]]:
        """Answer every outstanding request in this pass. A supplied surface answers with its own package; an
        unsupplied one terminates at E0 as UNAVAILABLE ENTITY_SURFACE_NOT_SUPPLIED with a six-field FAIL_CLOSED."""
        results = []
        set_digest = entity_set_digest(self.entities)
        for work_id in self._admitted():
            work = self.sandbox._work(work_id)
            for entity, capability in self._outstanding(work_id):
                surface = self.entities.get(entity)
                if surface is None:
                    envelope = unsupplied_envelope(work, entity, capability, set_digest, self.sandbox.canon.digest)
                    results.append(self.sandbox.record(self.sandbox.canon.canonical(envelope),
                                                       terminal=unsupplied_terminal(entity, capability)))
                    continue
                envelope = surface.answer(work, capability)
                results.append(self.sandbox.record(self.sandbox.canon.canonical(envelope)))
        return results

    # -- close ----------------------------------------------------------------------
    def close(self, *, standing: dict[str, Any], mesh_root: Path) -> list[dict[str, Any]]:
        results = []
        for work_id in self._admitted():
            work = self.sandbox._work(work_id)
            if self._outstanding(work_id) or not self.sandbox._receipts(work_id, "CONTRIBUTION_REQUESTED"):
                continue
            completed = self.sandbox._receipts(work_id, "SANDBOX_WORK_COMPLETED")
            out: dict[str, Any] = {"work_id": work_id}
            if not completed:
                recorded = self.sandbox.contributions(work_id)
                ids = [r["evidence"]["contribution_id"] for r in recorded]
                statuses = {r["evidence"]["contribution_id"]: {"entity": r["evidence"]["entity"],
                                                               "status": r["evidence"]["status"]} for r in recorded}
                synthesis = {"schema": SYNTHESIS_SCHEMA, "inputs": statuses,
                             "contributed": sum(1 for s in statuses.values() if s["status"] == "CONTRIBUTED"),
                             "non_success": sum(1 for s in statuses.values() if s["status"] != "CONTRIBUTED")}
                out["synthesize"] = self.sandbox.synthesize(work_id, ids, synthesis)
                out["complete"] = self.sandbox.complete(work_id)
                if out["complete"]["disposition"] != ALLOW:
                    results.append(out)
                    continue
                completed = self.sandbox._receipts(work_id, "SANDBOX_WORK_COMPLETED")
            out["egress"] = self._return(work, completed[-1], standing=standing, mesh_root=mesh_root)
            results.append(out)
        return results

    def _return(self, work: dict[str, Any], completion: dict[str, Any], *, standing: dict[str, Any],
                mesh_root: Path) -> dict[str, Any] | None:
        manifest = work["manifested_request"]
        marker = self._key(SERVICE["result_prefix"], work["work_id"])
        organization = (manifest.get("return_to") or {}).get("organization")
        if organization is None or self.node_state.exists(marker):
            return None
        rebound = self._rebind(work, completion)
        if rebound["disposition"] != ALLOW:
            # No alternative authority and no egress; the refusal is terminal for this work, recorded once.
            self.node_state.put_once(marker, {"schema": "sv-llm.sandbox-result-marker/v1", "work_id": work["work_id"],
                                              "transition_class": rebound["transition_class"],
                                              "binding_repo_receipt_sha256": rebound["repo_receipt_sha256"]})
            return rebound
        synthesis = self.sandbox.ledger.chain()
        synthesis = next(r for r in synthesis if r["receipt_sha256"] == completion["evidence"]["synthesis_receipt_sha256"])
        result = {"manifest_id": "sv-llm-sandbox-result-" + work["work_id"],
                  "destination": {"organization": organization},
                  "payload": {"schema": RESULT_SCHEMA, "request_manifest_id": manifest["manifest_id"],
                              "work_id": work["work_id"],
                              "completion_repo_receipt_sha256": completion["receipt_sha256"],
                              "return_binding_repo_receipt_sha256": rebound["repo_receipt_sha256"],
                              "synthesis": synthesis["evidence"]["synthesis"],
                              "synthesis_digest": synthesis["evidence"]["synthesis_digest"],
                              "authority_effect": "NONE"}}
        declared = (manifest.get("payload") or {}).get("sdk_proposal")
        if declared is not None:
            result["payload"]["sdk_proposal_conformance"] = self._proposal_conformance(declared)
        emitted = self.crossing.egress(result, standing=standing, mesh_root=mesh_root, root=self.dotgithub,
                                     hb_epoch=self.hb_epoch)
        self.node_state.put_once(marker, {"schema": "sv-llm.sandbox-result-marker/v1", "work_id": work["work_id"],
                                          "transition_class": emitted["transition_class"],
                                          "org_receipt_sha256": emitted["org_receipt_sha256"]})
        return emitted

    @staticmethod
    def _proposal_conformance(declared: Any) -> dict[str, Any]:
        """Evaluate a manifest-carried SDK proposal against the canonical bytes the manifest carries.

        declared: {"conformance_proposal": <stegverse.ai-invariant-conformance-proposal/v1>,
                   "canonical_source_attachments": [{"repository", "path", "revision", "content_base64"}]}.
        An attachment that is not well formed is simply not supplied, so the evaluator answers
        FAIL_CLOSED CANONICAL_SOURCE_SUPPLIED for the source it cites: nothing is fetched or awaited.
        """
        declared = declared if isinstance(declared, dict) else {}
        attachments = declared.get("canonical_source_attachments")
        sources = []
        for a in attachments if isinstance(attachments, list) else []:
            if not (isinstance(a, dict) and all(isinstance(a.get(k), str) and a[k]
                                                for k in ("repository", "path", "revision", "content_base64"))):
                continue
            try:
                content = base64.b64decode(a["content_base64"], validate=True)
            except (binascii.Error, ValueError):
                continue
            sources.append({"repository": a["repository"], "path": a["path"], "revision": a["revision"],
                            "content": content})
        evaluation = conformance_proposal.evaluate(declared.get("conformance_proposal"), sources)
        offered = evaluation["disposition"] == ALLOW
        return {"schema": "sv-llm.sdk-proposal-conformance/v1", "evaluation": evaluation,
                "proposal_offered_to_sdk": offered,
                "proposal": declared.get("conformance_proposal") if offered else None,
                "authority_effect": "NONE"}

    # -- one pass -----------------------------------------------------------------------
    def run(self, *, standing: dict[str, Any], mesh_root: Path) -> dict[str, Any]:
        """One pass: boundary ingress, intake, respond, close. Never waits for anything."""
        ingress = self.crossing.ingress(mesh_root=mesh_root, node_state_root=self.node_state_root, root=self.dotgithub,
                                        hb_epoch=self.hb_epoch)
        return {"ingress": ingress, "intake": self.intake(), "respond": self.respond(),
                "close": self.close(standing=standing, mesh_root=mesh_root)}


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    p.add_argument("--dotgithub", type=Path, required=True)
    p.add_argument("--mesh-root", type=Path, required=True)
    p.add_argument("--node-state-root", type=Path, required=True)
    p.add_argument("--sandbox-ledger", type=Path, required=True)
    p.add_argument("--standing", type=Path, required=True)
    p.add_argument("--entity-repo", type=Path, action="append", default=[])
    p.add_argument("--hb-epoch", type=str, default=None,
                   help="heartbeat epoch, supplied (ASCII [0-9]+, >= 32); never derived from a clock")
    ns = p.parse_args()
    refusal = epoch_refusal(ns.hb_epoch)
    if refusal is not None:
        print(json.dumps(refusal, sort_keys=True))
        return 1
    entities = {e.name: e for e in (Entity.from_repo(repo) for repo in ns.entity_repo)}
    cycle = WorkCycle(dotgithub=ns.dotgithub, sandbox_ledger=ns.sandbox_ledger,
                      node_state_root=ns.node_state_root, entities=entities, hb_epoch=ns.hb_epoch)
    out = cycle.run(standing=json.loads(ns.standing.read_text()), mesh_root=ns.mesh_root)
    print(json.dumps(out, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
