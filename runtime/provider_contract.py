"""Sandbox resolution of provider interaction contracts (AT-04 Stage 2 contract layer).

A provider-specific live call is governed by the provider's own contract
(sv-llm.provider-interaction-contract/v0.1, held in SV-LLM/<Provider> and
vendored byte-for-byte under runtime/provider_contracts/ with digests). The
Sandbox never hard-codes a provider URL or selector: it resolves the contract
of the entity assigned to the work and records the outcome.

Every attempt yields exactly one receipt:
  PROVIDER_INTERACTION_RESOLVED  ALLOW: an APPROVED, verified contract; the
                                 evidence carries the resolved surface.
  PROVIDER_INTERACTION_REFUSED   DENY or FAIL_CLOSED, with failed_predicate.

Predicates, in order:
  CAPABILITY_ASSIGNED_FOR_ADMITTED_WORK          DENY
  PROVIDER_INTERACTION_CONTRACT_PRESENT          FAIL_CLOSED
  PROVIDER_INTERACTION_CONTRACT_SCHEMA_VALID     FAIL_CLOSED
  PROVIDER_INTERACTION_CONTRACT_BOUND_TO_ASSIGNED_ENTITY  DENY
  PROVIDER_AUTOMATION_SURFACE_APPROVED           FAIL_CLOSED
  PROVIDER_INTERACTION_CONTRACT_VERIFIED         FAIL_CLOSED

Resolution contacts no provider and starts no browser. Invoking StegBrowser
from a resolved surface is a later step, taken only once a provider's contract
is APPROVED with its explicit written automation permission.
"""
from __future__ import annotations
import json
from pathlib import Path
from typing import Any

VENDOR = Path(__file__).resolve().parent / "provider_contracts"
CONTRACT = "provider-interaction-contract.json"
SCHEMA_TITLE = "sv-llm.provider-interaction-contract/v0.1"
ALLOW, DENY, FAIL_CLOSED = "ALLOW", "DENY", "FAIL_CLOSED"


class ProviderInteraction:
    def __init__(self, sandbox, contracts: Path = VENDOR):
        self.sandbox = sandbox
        self.canon = sandbox.canon
        self.contracts = Path(contracts)
        sandbox.registration.verify_vendor(self.contracts)  # executed contract bytes match the manifest
        from jsonschema import Draft202012Validator
        local = Path(__file__).resolve().parent / "contracts"
        schema = json.loads((local / "provider-interaction-contract.schema.json").read_text())
        assert schema["title"] == SCHEMA_TITLE
        self.validator = Draft202012Validator(schema)

    def _refuse(self, attempt: dict[str, Any], disposition: str, predicate: str, **extra) -> dict[str, Any]:
        return self.sandbox._record("PROVIDER_INTERACTION_REFUSED", attempt,
                                    {"disposition": disposition, "failed_predicate": predicate,
                                     "work_id": attempt["work_id"], "entity": attempt["entity"],
                                     "capability": attempt["capability"], "authority_effect": "NONE", **extra})

    def resolve(self, work_id: str, entity: str, capability: str) -> dict[str, Any]:
        attempt = {"intended_action": "RESOLVE_PROVIDER_INTERACTION_CONTRACT", "work_id": work_id,
                   "entity": entity, "capability": capability}
        assignment = self.sandbox._assignment(work_id, entity, capability) if self.sandbox._work(work_id) else None
        if assignment is None:
            return self._refuse(attempt, DENY, "CAPABILITY_ASSIGNED_FOR_ADMITTED_WORK")
        declaration = assignment["declaration"]
        repository = declaration["repository"]
        path = self.contracts / repository / CONTRACT
        manifest = json.loads((self.contracts / "vendor-manifest.json").read_text())
        if f"{repository}/{CONTRACT}" not in manifest["files"] or not path.is_file():
            return self._refuse(attempt, FAIL_CLOSED, "PROVIDER_INTERACTION_CONTRACT_PRESENT", repository=repository)
        raw = path.read_bytes()
        try:
            contract = self.canon.parse(raw)
        except self.canon.CanonicalError as exc:
            return self._refuse(attempt, FAIL_CLOSED, "PROVIDER_INTERACTION_CONTRACT_SCHEMA_VALID",
                                repository=repository, detail=exc.failed_predicate)
        errors = sorted(self.validator.iter_errors(contract), key=lambda e: list(e.absolute_path))
        if errors:
            return self._refuse(attempt, FAIL_CLOSED, "PROVIDER_INTERACTION_CONTRACT_SCHEMA_VALID",
                                repository=repository, detail=errors[0].message[:300])
        bound = {"repository": repository, "contract_sha256": self.canon.digest(contract),
                 "surface_status": contract["surface_status"]}
        if contract["entity"] != declaration["entity"] or contract["repository"] != repository:
            return self._refuse(attempt, DENY, "PROVIDER_INTERACTION_CONTRACT_BOUND_TO_ASSIGNED_ENTITY", **bound)
        if contract["surface_status"] != "APPROVED":
            return self._refuse(attempt, FAIL_CLOSED, "PROVIDER_AUTOMATION_SURFACE_APPROVED", **bound,
                                terms_basis=contract["terms_basis"], unblock_condition=contract["unblock_condition"])
        if contract["verified"] is not True:
            return self._refuse(attempt, FAIL_CLOSED, "PROVIDER_INTERACTION_CONTRACT_VERIFIED", **bound)
        surface = contract["surface"]
        resolved = {"profile": surface["profile"], "secure_url": surface["secure_url"],
                    "allowed_origins": [surface["origin"].split("://", 1)[1]],
                    "selectors": contract["selectors"], "result_extraction": contract["result_extraction"],
                    "evidence_requirements": contract["evidence_requirements"],
                    "provider_attribution_allowed": contract["attribution"]["provider_attribution_allowed"],
                    "automation_permission": contract["automation_permission"]}
        return self.sandbox._record("PROVIDER_INTERACTION_RESOLVED", attempt,
                                    {"disposition": ALLOW, "work_id": work_id, "entity": entity,
                                     "capability": capability, **bound, "resolved_surface": resolved,
                                     "authority_effect": "NONE"})
