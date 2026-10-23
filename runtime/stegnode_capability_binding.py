"""Non-authorizing StegNode continuity/posture binding for Sandbox capability requests.

Inputs must be authentic observations supplied by the existing StegNode and InTr
interfaces. This module never registers devices, resolves credentials, or mints authority.
Public retrieval can proceed without a node; protected execution requires independent
node, posture and manifest admission evidence.
"""
from __future__ import annotations

SCHEMA = "sv-llm.stegnode-capability-binding/v1"
TIERS = {"SECURE": 1, "HIGH": 2, "HIGHEST": 3}


def evaluate_binding(*, public: bool, node: dict | None = None,
                     posture: dict | None = None, manifest: dict | None = None,
                     required_tier: str = "SECURE", posture_verifier=None) -> dict:
    base = {"schema": SCHEMA, "authority_effect": "NONE",
            "node_registration_created": False, "credential_material_persisted": False}
    def result(disposition, predicate):
        return {**base, "disposition": disposition, "predicate": predicate}
    if required_tier not in TIERS:
        return result("FAIL_CLOSED", "UNRECOGNIZED_REQUIRED_SECURITY_TIER")
    if public:
        return result("ALLOW", "PUBLIC_INFORMATION_NODE_NOT_REQUIRED")
    if not isinstance(node, dict) or not node.get("continuity_established") or not node.get("class_established") or not node.get("node_id"):
        return result("FAIL_CLOSED", "EXISTING_STEGNODE_NOT_AUTHENTICALLY_OBSERVED")
    if not isinstance(posture, dict) or posture.get("schema") != "stegos.intr-security-posture-resolution.v1":
        return result("FAIL_CLOSED", "INTR_POSTURE_RESOLUTION_NOT_OBSERVED")
    instance = posture.get("posture_instance")
    if not isinstance(instance, dict) or instance.get("resolution_authority") != "INTERLOCK_INTR" or instance.get("credential_authority") != "TV/TVC" or instance.get("transferable") is not False or instance.get("reusable_across_tasks") is not False:
        return result("FAIL_CLOSED", "INTR_POSTURE_INSTANCE_PREDICATES_MISSING")
    effective = posture.get("effective_posture", {}).get("tier") if isinstance(posture.get("effective_posture"), dict) else None
    if effective not in TIERS or TIERS[effective] < TIERS[required_tier]:
        return result("DENY", "EFFECTIVE_POSTURE_BELOW_CAPABILITY_FLOOR")
    if not isinstance(manifest, dict) or manifest.get("disposition") != "ALLOW" or manifest.get("authenticated") is not True or not manifest.get("task_id"):
        return result("FAIL_CLOSED", "AUTHENTIC_MANIFEST_ADMISSION_NOT_OBSERVED")
    if instance.get("task_id") != manifest["task_id"]:
        return result("DENY", "POSTURE_INSTANCE_TASK_BINDING_MISMATCH")
    if not callable(posture_verifier):\n        return result("FAIL_CLOSED", "AUTHENTIC_INTR_POSTURE_VERIFIER_NOT_BOUND")\n    try:\n        verified = posture_verifier(instance, manifest) is True\n    except Exception:\n        verified = False\n    if not verified:
        return result("FAIL_CLOSED", "POSTURE_INSTANCE_CRYPTOGRAPHIC_VERIFICATION_NOT_OBSERVED")
    return {**result("ALLOW", "EXISTING_NODE_POSTURE_AND_MANIFEST_EVIDENCE_PRESENT"),
            "node_id": node["node_id"], "task_id": manifest["task_id"],
            "security_tier": effective, "execution_authorized_by_binding": False}
