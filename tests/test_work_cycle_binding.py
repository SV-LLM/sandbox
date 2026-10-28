"""Native StegNode/InTr binding at WorkCycle._take and ._return (StegVerse-org/.github#163), offline.

Deterministic, at the supplied epoch 4000: missing, forged, mismatched, stale, replayed, wrong-task, wrong-head and
low-tier bindings are refused before admission with six fields, the intake is terminal once and nothing is assigned or
requested; public retrieval keeps its exemption; a valid FIXTURE claim/fence (admitted only by this test) ALLOWs and
_return revalidates it before egress. With no admitted WorkerCoordinator claim/fence -- the production state -- every
protected take FAILS CLOSED. Source-level evidence only: CI-class, never SANDBOX_RUNTIME_OBSERVED.

Run: SV_LLM_DOTGITHUB_ROOT=<SV-LLM/.github checkout> python -B tests/test_work_cycle_binding.py
"""
from __future__ import annotations
import copy, json, os, shutil, sys, tempfile, unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOTGITHUB = Path(os.environ["SV_LLM_DOTGITHUB_ROOT"]).resolve()
sys.path.insert(0, str(ROOT / "runtime"))
sys.path.insert(0, str(ROOT / "tests"))
import work_cycle_binding as wcb  # noqa: E402
import work_cycle_binding_fixture as fx  # noqa: E402
from work_cycle import WorkCycle, Entity  # noqa: E402
from test_work_cycle import REAL, STANDING, manifest, load, chain  # noqa: E402

EPOCH = 4000
SIX = ["failed_predicate", "failure_code", "next_attempt", "owning_existing_goal", "required_evidence_or_repair",
       "retry_entrypoint"]


class WorkCycleBinding(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        base = self.base = Path(self.tmp.name)
        os.environ["STEGVERSE_REPO_LEDGER_ROOT"] = str(base / "dotgithub-ledger")
        os.environ["STEGVERSE_ORG_LEDGER_ROOT"] = str(base / "org-ledger")
        self.mesh = base / "mesh"
        self.entities = {e: Entity(REAL / e / "core.py", REAL / e / "entity-capability.json")
                         for e in ("Anthropic", "OpenAI")}
        self.cycle = WorkCycle(dotgithub=DOTGITHUB, sandbox_ledger=base / "sandbox-ledger",
                               node_state_root=base / "node-state", entities=self.entities, hb_epoch=EPOCH)
        self.cycle.crossing.open_organization_ledger(root=DOTGITHUB, hb_epoch=EPOCH)
        peers = load("peer_organization", DOTGITHUB / "org-runtime/tests/peer_organization.py")
        self.labs = peers.materialize(base / "peers", "StegVerse-Labs",
                                      [{"service_id": "stegverse-labs.org-control", "repository": "StegVerse-Labs/.github",
                                        "boundary_role": "BOUNDARY_LOCAL_CONTROL"}])

    def tearDown(self):
        self.tmp.cleanup()

    def send(self, m, packet_id=None):
        k = self.labs.kernel
        self.labs.publish(k.build_packet(origin_org="StegVerse-Labs", origin_service="stegverse-labs.org-control",
                                         destination_org="SV-LLM", destination_service="sv-llm.org-control",
                                         payload={"manifest": m}, standing=STANDING,
                                         packet_id=packet_id or "in-" + m["manifest_id"]),
                          mesh_root=self.mesh, epoch=EPOCH)

    def run_pass(self):
        return self.cycle.run(standing=STANDING, mesh_root=self.mesh)

    def org_classes(self):
        return [r["org_transition_class"] for r in chain(self.base / "org-ledger")]

    def assert_refused_before_admission(self, taken, disposition, predicate):
        b = taken["binding"]
        self.assertEqual((b["disposition"], b["failed_predicate"], b["failure_code"]), (disposition, predicate, predicate), b)
        self.assertEqual(sorted(k for k in SIX if k in b), SIX)
        self.assertTrue(all(isinstance(b[k], str) and b[k] for k in SIX))
        self.assertEqual(b["owning_existing_goal"], "StegVerse-org/.github#163")
        self.assertEqual(b["retry_entrypoint"], wcb.TAKE_ENTRYPOINT)
        self.assertEqual(b["authority_effect"], "NONE")
        self.assertEqual(b["transition_class"], "SANDBOX_WORK_BINDING_REFUSED")
        self.assertTrue(b["org_receipt_sha256"])                       # the refusal is on the organization ledger
        self.assertIs(taken["admit"], b)
        self.assertEqual((taken["assign"], taken["request"]), ([], []))
        self.assertNotIn("SANDBOX_WORK_ADMITTED", self.org_classes())
        self.assertNotIn("CAPABILITY_ASSIGNMENT", self.org_classes())

    def take_one(self, m, packet_id=None):
        self.send(m, packet_id)
        out = self.run_pass()
        taken, = out["intake"]
        self.assertEqual((out["respond"], out["close"]), ([], []))
        return taken

    # -- no claim/fence: the production state ------------------------------------------
    def test_no_admitted_claim_fence_fails_closed_and_never_allows(self):
        m, _claim = fx.bind(manifest("bind-no-claim"), EPOCH)          # the claim is never admitted
        taken = self.take_one(m)
        self.assert_refused_before_admission(taken, "FAIL_CLOSED", wcb.NO_CLAIM_FENCE)
        b = taken["binding"]
        self.assertEqual((b["claim_ref"], b["fence_ref"], b["projection_only"]),
                         ("wc-claim:bind-no-claim", "wc-fence:1", False))
        self.assertEqual(b["parent_org_receipt_sha256"], self.org_ledger_ingress())
        # Terminal once: a later pass neither re-takes nor re-records it.
        before = len(self.org_classes())
        again = self.run_pass()
        self.assertEqual((again["intake"], again["respond"], again["close"]), ([], [], []))
        self.assertEqual(len(self.org_classes()), before)

    def test_a_projection_only_claim_with_null_refs_fails_closed(self):
        m, claim = fx.bind(manifest("bind-projection"), EPOCH,
                           claim_overrides={"claim_ref": None, "fence_ref": None, "projection_only": True})
        self.cycle.admitted_claims.append(claim)
        taken = self.take_one(m)
        self.assert_refused_before_admission(taken, "FAIL_CLOSED", wcb.NO_CLAIM_FENCE)
        self.assertEqual((taken["binding"]["claim_ref"], taken["binding"]["fence_ref"],
                          taken["binding"]["projection_only"]), (None, None, True))

    def test_missing_binding_fails_closed(self):
        taken = self.take_one(manifest("bind-missing"))
        self.assert_refused_before_admission(taken, "FAIL_CLOSED", "EXISTING_STEGNODE_NOT_AUTHENTICALLY_OBSERVED")

    # -- forged / mismatched -------------------------------------------------------------
    def test_a_forged_claim_is_denied(self):
        m, claim = fx.bind(manifest("bind-forged"), EPOCH)
        self.cycle.admitted_claims.append(claim)
        m["payload"]["binding"]["worker_claim"]["fence_ref"] = "wc-fence:forged"   # digest no longer matches
        taken = self.take_one(m)
        self.assert_refused_before_admission(taken, "DENY", "WORKERCOORDINATOR_CLAIM_SELF_DIGEST_MATCHES")

    def test_a_self_consistent_claim_that_was_not_admitted_is_denied(self):
        m, claim = fx.bind(manifest("bind-mismatch"), EPOCH)
        self.cycle.admitted_claims.append(claim)
        other = fx.claim(m, valid_until_epoch=EPOCH + 600, fence_ref="wc-fence:2")
        m["payload"]["binding"]["worker_claim"] = other
        taken = self.take_one(m)
        self.assert_refused_before_admission(taken, "DENY", "WORKERCOORDINATOR_CLAIM_ADMITTED")

    def test_a_forged_posture_instance_fails_native_verification(self):
        m, claim = fx.bind(manifest("bind-forged-posture"), EPOCH)
        self.cycle.admitted_claims.append(claim)
        m["payload"]["binding"]["posture"]["posture_instance"]["effective_tier"] = "HIGHEST"
        taken = self.take_one(m)
        self.assert_refused_before_admission(taken, "FAIL_CLOSED",
                                             "POSTURE_INSTANCE_CRYPTOGRAPHIC_VERIFICATION_NOT_OBSERVED")
        self.assertEqual(taken["binding"]["native_reason"], "posture_instance_digest_mismatch")

    def test_a_wrong_task_claim_is_denied(self):
        m, _ = fx.bind(manifest("bind-wrong-task"), EPOCH)
        wrong = fx.claim(m, valid_until_epoch=EPOCH + 600, task_id="another-task")
        m["payload"]["binding"]["worker_claim"] = wrong
        self.cycle.admitted_claims.append(wrong)
        taken = self.take_one(m)
        self.assert_refused_before_admission(taken, "DENY", "WORKERCOORDINATOR_CLAIM_TASK_BINDING")

    def test_a_wrong_task_posture_instance_fails_native_verification(self):
        m, claim = fx.bind(manifest("bind-wrong-task-posture"), EPOCH)
        other, _ = fx.bind(manifest("bind-other-task"), EPOCH)
        m["payload"]["binding"]["posture"] = other["payload"]["binding"]["posture"]
        self.cycle.admitted_claims.append(claim)
        taken = self.take_one(m)
        self.assert_refused_before_admission(taken, "DENY", "POSTURE_INSTANCE_TASK_BINDING_MISMATCH")

    def test_a_wrong_head_claim_is_denied(self):
        m, _ = fx.bind(manifest("bind-wrong-head"), EPOCH)
        other = copy.deepcopy(m)
        other["payload"]["work"]["intent"] = "a different request"
        wrong = fx.claim(other, valid_until_epoch=EPOCH + 600)        # same task id, another request head
        m["payload"]["binding"]["worker_claim"] = wrong
        self.cycle.admitted_claims.append(wrong)
        taken = self.take_one(m)
        self.assert_refused_before_admission(taken, "DENY", "WORKERCOORDINATOR_FENCE_HEAD_BINDING")

    # -- stale / replayed / low tier --------------------------------------------------------
    def test_a_stale_posture_instance_fails_native_verification(self):
        m, claim = fx.bind(manifest("bind-stale-posture"), EPOCH - 1000)  # issued at 3000, expired at 3900
        claim = fx.claim(m, valid_until_epoch=EPOCH + 600)
        m["payload"]["binding"]["worker_claim"] = claim
        self.cycle.admitted_claims.append(claim)
        taken = self.take_one(m)
        self.assert_refused_before_admission(taken, "FAIL_CLOSED",
                                             "POSTURE_INSTANCE_CRYPTOGRAPHIC_VERIFICATION_NOT_OBSERVED")
        self.assertEqual(taken["binding"]["native_reason"], "posture_instance_inactive")

    def test_a_stale_claim_is_denied(self):
        m, claim = fx.bind(manifest("bind-stale-claim"), EPOCH, valid_for=-1)
        self.cycle.admitted_claims.append(claim)
        taken = self.take_one(m)
        self.assert_refused_before_admission(taken, "DENY", "WORKERCOORDINATOR_CLAIM_NOT_STALE")

    def test_a_replayed_posture_instance_is_denied(self):
        m, claim = fx.bind(manifest("bind-replay"), EPOCH)
        self.cycle.admitted_claims.append(claim)
        self.send(m)
        first, = self.run_pass()["intake"]
        self.assertEqual(first["binding"]["disposition"], "ALLOW", first["binding"])
        self.send(m, packet_id="in-bind-replay-again")                   # the same binding, a second time
        second, = self.run_pass()["intake"]
        b = second["binding"]
        self.assertEqual((b["disposition"], b["failed_predicate"]), ("DENY", "POSTURE_INSTANCE_NOT_REPLAYED"))
        self.assertEqual((second["assign"], second["request"]), ([], []))
        self.assertEqual(self.org_classes().count("SANDBOX_WORK_ADMITTED"), 1)

    def test_a_low_tier_posture_is_denied(self):
        m, claim = fx.bind(manifest("bind-low-tier"), EPOCH, tier="SECURE", required_tier="HIGHEST")
        self.cycle.admitted_claims.append(claim)
        taken = self.take_one(m)
        self.assert_refused_before_admission(taken, "DENY", "EFFECTIVE_POSTURE_BELOW_CAPABILITY_FLOOR")

    def test_without_the_vendored_native_verifier_protected_work_fails_closed(self):
        tampered = self.base / "vendor"
        shutil.copytree(wcb.VENDOR, tampered)
        (tampered / wcb.NATIVE_MODULE).write_text("def verify_task_security_posture_instance(*a, **k):\n    return None\n")
        original = wcb.VENDOR
        try:
            wcb.VENDOR = tampered
            self.assertIsNone(wcb.native_posture_verifier())             # digest mismatch: never loaded
            wcb.VENDOR = self.base / "absent"
            self.assertIsNone(wcb.native_posture_verifier())
        finally:
            wcb.VENDOR = original
        self.assertTrue(callable(wcb.native_posture_verifier()))
        m, claim = fx.bind(manifest("bind-no-verifier"), EPOCH)
        self.cycle.admitted_claims.append(claim)
        self.cycle.posture_verifier = None
        taken = self.take_one(m)
        self.assert_refused_before_admission(taken, "FAIL_CLOSED", "AUTHENTIC_INTR_POSTURE_VERIFIER_NOT_BOUND")

    def test_the_vendored_verifier_is_the_pinned_stegos_bytes(self):
        pinned = json.loads((wcb.VENDOR / "vendor-manifest.json").read_text())
        self.assertEqual(pinned["canonical_source"], "StegVerse-Labs/StegOS")
        self.assertEqual(pinned["source_commit"], "2d76c7780d09c8a53ad15004f5f9ef46b74a893f")
        self.assertEqual(pinned["files"][wcb.NATIVE_MODULE], wcb._file_sha256(wcb.VENDOR / wcb.NATIVE_MODULE))
        self.assertEqual(pinned["files"][wcb.NATIVE_MODULE],
                         "sha256:07c4dcd5df1e3e07c6be345e6960d9d9574ce64426eca5f4bdca597abd1b9029")

    # -- public retrieval ----------------------------------------------------------------------
    def test_public_retrieval_needs_no_node_posture_or_claim(self):
        m = manifest("bind-public", participants=[])
        m["payload"]["work"]["requested_capabilities"] = ["page_load.v1"]
        m["payload"]["work"]["permitted_capabilities"] = ["page_load.v1"]
        m["payload"]["binding"] = {"public": True}
        self.send(m)
        taken, = self.run_pass()["intake"]
        b = taken["binding"]
        self.assertEqual((b["disposition"], b["predicate"], b["public"]),
                         ("ALLOW", "PUBLIC_INFORMATION_NODE_NOT_REQUIRED", True), b)
        self.assertEqual(b["transition_class"], "SANDBOX_WORK_BINDING_VERIFIED")

    def test_declaring_public_does_not_exempt_protected_capabilities(self):
        m = manifest("bind-public-protected")
        m["payload"]["binding"] = {"public": True}                       # adversarial_review is not public retrieval
        taken = self.take_one(m)
        self.assert_refused_before_admission(taken, "FAIL_CLOSED", "EXISTING_STEGNODE_NOT_AUTHENTICALLY_OBSERVED")

    # -- valid fixture claim: ALLOW, then _return closes it -----------------------------------
    def test_a_valid_fixture_claim_allows_and_return_revalidates_before_egress(self):
        m, claim = fx.bind(manifest("bind-valid"), EPOCH)
        self.cycle.admitted_claims.append(claim)
        self.send(m)
        out = self.run_pass()
        taken, = out["intake"]
        b = taken["binding"]
        self.assertEqual((b["disposition"], b["claim_sha256"], b["fence_ref"]), ("ALLOW", claim["claim_sha256"], "wc-fence:1"))
        self.assertIs(b["execution_authorized_by_binding"], False)
        self.assertEqual(taken["admit"]["disposition"], "ALLOW")
        closed, = out["close"]
        self.assertEqual(closed["complete"]["disposition"], "ALLOW")
        self.assertEqual(closed["egress"]["transition_class"], "ORGANIZATION_EGRESS_EMITTED")
        classes = self.org_classes()
        self.assertLess(classes.index("SANDBOX_WORK_BINDING_VERIFIED"), classes.index("SANDBOX_WORK_ADMITTED"))
        self.assertEqual(classes[-2:], ["SANDBOX_RETURN_BINDING_REVALIDATED", "ORGANIZATION_EGRESS_EMITTED"])
        # Lineage both ways: the return binding names the take binding; the egressed result names the return binding.
        rebound, = [r for r in self.cycle.sandbox.ledger.chain()
                    if r["transition_class"] == "SANDBOX_RETURN_BINDING_REVALIDATED"]
        self.assertEqual(rebound["evidence"]["take_binding_receipt_sha256"], b["repo_receipt_sha256"])
        got = self.labs.consume_addressed(mesh_root=self.mesh)
        payload = got[0]["result"]["packet"]["payload"]["manifest"]["payload"]
        self.assertEqual(payload["return_binding_repo_receipt_sha256"], rebound["receipt_sha256"])
        again = self.run_pass()                                          # closed once
        self.assertEqual([c.get("egress") for c in again["close"]], [None])

    def test_a_return_whose_claim_fence_is_no_longer_held_emits_nothing(self):
        m, claim = fx.bind(manifest("bind-return-revoked"), EPOCH)
        self.cycle.admitted_claims.append(claim)
        c = self.cycle
        self.send(m)
        c.crossing.ingress(mesh_root=self.mesh, node_state_root=c.node_state_root, root=DOTGITHUB, hb_epoch=EPOCH)
        taken, = c.intake()
        self.assertEqual(taken["binding"]["disposition"], "ALLOW")
        c.respond()
        c.admitted_claims = []                                           # the fence is gone before the return
        closed, = c.close(standing=STANDING, mesh_root=self.mesh)
        refused = closed["egress"]
        self.assertEqual((refused["transition_class"], refused["disposition"], refused["failed_predicate"]),
                         ("SANDBOX_RETURN_BINDING_REFUSED", "FAIL_CLOSED", wcb.NO_CLAIM_FENCE))
        self.assertEqual(refused["retry_entrypoint"], wcb.RETURN_ENTRYPOINT)
        self.assertNotIn("ORGANIZATION_EGRESS_EMITTED", self.org_classes())
        self.assertEqual(self.labs.consume_addressed(mesh_root=self.mesh), [])
        again = c.close(standing=STANDING, mesh_root=self.mesh)          # terminal once, nothing re-attempted
        self.assertEqual([x.get("egress") for x in again], [None])

    def org_ledger_ingress(self):
        rows = [r for r in chain(self.base / "org-ledger")
                if r["org_transition_class"] == "ORGANIZATION_INGRESS_MATERIALIZED"]
        return rows[-1]["receipt_sha256"]


if __name__ == "__main__":
    unittest.main()
