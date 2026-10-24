import unittest
from runtime.stegnode_capability_binding import evaluate_binding as evaluate

NODE = {"node_id": "stegnode-existing", "continuity_established": True, "class_established": True}
POSTURE = {"schema": "stegos.intr-security-posture-resolution.v1",
           "effective_posture": {"tier": "HIGHEST"}, "instance_verified": True,
           "posture_instance": {"task_id": "task-1", "resolution_authority": "INTERLOCK_INTR",
                                "credential_authority": "TV/TVC", "transferable": False,
                                "reusable_across_tasks": False}}
MANIFEST = {"task_id": "task-1", "disposition": "ALLOW", "authenticated": True}
VERIFIER = lambda instance, manifest: instance["task_id"] == manifest["task_id"]

class NodeCapabilityBindingTests(unittest.TestCase):
    def test_public_no_node_required(self):
        self.assertEqual(evaluate(public=True)["disposition"], "ALLOW")
    def test_new_device_not_auto_registered(self):
        result = evaluate(public=False)
        self.assertEqual(result["disposition"], "FAIL_CLOSED")
        self.assertFalse(result["node_registration_created"])
    def test_existing_node_protected_binding(self):
        result = evaluate(public=False, node=NODE, posture=POSTURE, manifest=MANIFEST, required_tier="HIGHEST", posture_verifier=VERIFIER)
        self.assertEqual(result["disposition"], "ALLOW")
        self.assertFalse(result["execution_authorized_by_binding"])
    def test_posture_cannot_downgrade(self):
        p = {**POSTURE, "effective_posture": {"tier": "SECURE"}}
        self.assertEqual(evaluate(public=False, node=NODE, posture=p, manifest=MANIFEST, required_tier="HIGHEST", posture_verifier=VERIFIER)["disposition"], "DENY")
    def test_missing_verification_fails_closed(self):
        p = {**POSTURE, "instance_verified": False}
        self.assertEqual(evaluate(public=False, node=NODE, posture=p, manifest=MANIFEST)["disposition"], "FAIL_CLOSED")
    def test_task_mismatch_denied(self):
        m = {**MANIFEST, "task_id": "other"}
        self.assertEqual(evaluate(public=False, node=NODE, posture=POSTURE, manifest=m, posture_verifier=VERIFIER)["disposition"], "DENY")
    def test_no_manifest_not_authorized(self):
        self.assertEqual(evaluate(public=False, node=NODE, posture=POSTURE)["disposition"], "FAIL_CLOSED")
    def test_caller_flag_cannot_authenticate_posture(self):
        r = evaluate(public=False, node=NODE, posture=POSTURE, manifest=MANIFEST)
        self.assertEqual(r["predicate"], "AUTHENTIC_INTR_POSTURE_VERIFIER_NOT_BOUND")
    def test_no_secret_or_registration_side_effect(self):
        r = evaluate(public=False, node=NODE, posture=POSTURE, manifest=MANIFEST)
        self.assertFalse(r["credential_material_persisted"])
        self.assertFalse(r["node_registration_created"])

if __name__ == "__main__":
    unittest.main()
