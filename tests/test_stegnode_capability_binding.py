import unittest
from runtime.stegnode_capability_binding import evaluate_binding as evaluate

NODE = {"node_id": "stegnode-existing", "continuity_established": True, "class_established": True}
def posture(effective="HIGHEST", automatic="SECURE"):
    return {"schema": "stegos.intr-security-posture-resolution.v1", "task_id": "task-1",
            "automatic_posture": {"tier": automatic}, "selected_posture": {"tier": effective},
            "effective_posture": {"tier": effective}, "instance_verified": True,
            "posture_instance": {"task_id": "task-1", "resolution_authority": "INTERLOCK_INTR",
                                 "credential_authority": "TV/TVC", "transferable": False,
                                 "reusable_across_tasks": False, "automatic_tier": automatic,
                                 "selected_tier": effective, "effective_tier": effective}}
POSTURE = posture()
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
        r = evaluate(public=False, node=NODE, posture=posture("SECURE"), manifest=MANIFEST, required_tier="HIGHEST", posture_verifier=VERIFIER)
        self.assertEqual((r["disposition"], r["predicate"]), ("DENY", "EFFECTIVE_POSTURE_BELOW_CAPABILITY_FLOOR"))
    def test_undigested_wrapper_tier_cannot_raise_the_verified_instance_tier(self):
        p = posture("SECURE")
        p["effective_posture"] = {"tier": "HIGHEST"}                       # the instance still says SECURE
        r = evaluate(public=False, node=NODE, posture=p, manifest=MANIFEST, required_tier="HIGHEST", posture_verifier=VERIFIER)
        self.assertEqual((r["disposition"], r["predicate"]), ("DENY", "POSTURE_RESOLUTION_WRAPPER_MATCHES_VERIFIED_INSTANCE"))
    def test_the_instance_automatic_tier_is_a_floor(self):
        p = posture("HIGH")
        p["automatic_posture"]["tier"] = p["posture_instance"]["automatic_tier"] = "HIGHEST"  # effective HIGH is below it
        r = evaluate(public=False, node=NODE, posture=p, manifest=MANIFEST, posture_verifier=VERIFIER)
        self.assertEqual((r["disposition"], r["predicate"]), ("DENY", "EFFECTIVE_POSTURE_BELOW_CAPABILITY_FLOOR"))
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
    def test_verifier_exception_fails_closed(self):
        def broken_verifier(instance, manifest):
            raise RuntimeError("authentic verifier unavailable")
        result = evaluate(public=False, node=NODE, posture=POSTURE,
                          manifest=MANIFEST, posture_verifier=broken_verifier)
        self.assertEqual(result["disposition"], "FAIL_CLOSED")
        self.assertEqual(result["predicate"], "POSTURE_INSTANCE_CRYPTOGRAPHIC_VERIFICATION_NOT_OBSERVED")

    def test_verifier_false_fails_closed(self):
        result = evaluate(public=False, node=NODE, posture=POSTURE,
                          manifest=MANIFEST, posture_verifier=lambda *_: False)
        self.assertEqual(result["disposition"], "FAIL_CLOSED")

    def test_unrecognized_security_tier_fails_closed(self):
        result = evaluate(public=True, required_tier="UNDEFINED")
        self.assertEqual(result["disposition"], "FAIL_CLOSED")

    def test_protected_binding_never_persists_credentials(self):
        result = evaluate(public=False, node=NODE, posture=POSTURE,
                          manifest=MANIFEST, posture_verifier=VERIFIER)
        self.assertFalse(result["credential_material_persisted"])
        self.assertFalse(result["node_registration_created"])
        self.assertFalse(result["execution_authorized_by_binding"])

    def test_no_secret_or_registration_side_effect(self):
        r = evaluate(public=False, node=NODE, posture=POSTURE, manifest=MANIFEST)
        self.assertFalse(r["credential_material_persisted"])
        self.assertFalse(r["node_registration_created"])

if __name__ == "__main__":
    unittest.main()
