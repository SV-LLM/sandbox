"""Step 2 (successor order 3): Sandbox runtime with its own ledger, fixture entities only.

Requires SV_LLM_DOTGITHUB_ROOT pointing at an SV-LLM/.github checkout (the
workflow pins it), and jsonschema.

Run: SV_LLM_DOTGITHUB_ROOT=<path> python -B tests/test_sandbox_runtime.py
"""
from __future__ import annotations
import ast, base64, copy, importlib.util, json, os, subprocess, sys, tempfile, unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOTGITHUB = Path(os.environ["SV_LLM_DOTGITHUB_ROOT"]).resolve()
sys.path.insert(0, str(ROOT / "runtime"))
from ledger import Ledger, sha  # noqa: E402
from sandbox import Sandbox, ALLOW, DENY, FAIL_CLOSED, DENY_ENTRYPOINTS, DENY_REPAIRS, OWNING_EXISTING_GOAL  # noqa: E402

FIX = ROOT / "tests/fixtures"
A, B, C = "FixtureEntityA", "FixtureEntityB", "FixtureEntityC"
# Every non-ALLOW carries these (StegVerse-org/.github docs/ORGANIZATION_ROLE_RUNTIME_REALITY_DEPLOYMENT.md).
SIX_FIELDS = ("failure_code", "failed_predicate", "required_evidence_or_repair", "retry_entrypoint",
              "owning_existing_goal", "next_attempt")
# Master Records boundary migration (MASTER-RECORDS-BULK-SEMANTIC-REMEDIATION-002).
MASTER_RECORDS_PROHIBITION = "MASTER_RECORDS_ORGANIZATION_RECORD"
LEGACY_MASTER_RECORDS_PROHIBITION = "MASTER_RECORDS_CUSTODY"


def load_aggregate():
    spec = importlib.util.spec_from_file_location("sv_llm_org_aggregate", DOTGITHUB / "resident-runtime/aggregate_repo_transition.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class Harness:
    """Isolated SV-LLM repo and org ledgers, a real parent transition, and a Sandbox."""

    def __init__(self):
        self.tmp = tempfile.TemporaryDirectory()
        base = Path(self.tmp.name)
        os.environ["STEGVERSE_ORG_LEDGER_ROOT"] = str(base / "org-ledger")
        self.aggregate = load_aggregate()
        self.org_receipts = []

        def propagate(receipt, transition_class):
            org = self.aggregate.aggregate_transition(receipt, org_transition_class=transition_class,
                                                      boundary_evidence={"source": "SV-LLM/sandbox"},
                                                      authority_effect="NONE")
            self.org_receipts.append(org)
            return org

        self.sandbox = Sandbox(dotgithub_root=DOTGITHUB, ledger=Ledger(base / "sandbox-ledger"), propagate=propagate)
        self.canon = self.sandbox.canon
        # Parent: a real SV-LLM/.github repository transition, aggregated into the org ledger.
        self.subject = {"intended_action": "CONTINUE_INTO_SANDBOX", "manifest_id": "fixture-manifest-001"}
        env = dict(os.environ, STEGVERSE_REPO_LEDGER_ROOT=str(base / "dotgithub-ledger"))
        run = subprocess.run([sys.executable, str(DOTGITHUB / ".stegverse/transition-ledger/emit.py"),
                              "--transition-id", "ORGANIZATION_INGRESS_MATERIALIZED:fixture",
                              "--transition-class", "ORGANIZATION_INGRESS_MATERIALIZED",
                              "--predecessor-state-sha256", sha({"fixture": "predecessor"}),
                              "--successor-state-sha256", sha(self.subject),
                              "--evidence-json", json.dumps({"disposition": "ALLOW"})],
                             capture_output=True, text=True, env=env, check=True)
        self.parent_repo = json.loads(run.stdout)
        # The parent is the first organization append on this fresh ledger, so it declares genesis.
        self.parent_org = self.aggregate.aggregate_transition(self.parent_repo, org_transition_class="ORGANIZATION_INGRESS_MATERIALIZED",
                                                              authority_effect="NONE", genesis=True)
        self.tree = json.loads((FIX / "organization-tree.json").read_text())

    def declaration(self, entity):
        return (FIX / f"{entity}.entity-capability.json").read_bytes()

    def work(self, **changes):
        work = json.loads((FIX / "sandbox-work.json").read_text())
        work["parent_transition"].update(repo_receipt_sha256=self.parent_repo["receipt_sha256"],
                                         org_receipt_sha256=self.parent_org["receipt_sha256"],
                                         subject_or_artifact_digest=sha(self.subject))
        work.update(changes)
        return work

    def admit(self, work=None):
        return self.sandbox.admit(json.dumps(work or self.work()).encode(), parent_repo_receipt=self.parent_repo,
                                  parent_org_receipt=self.parent_org, subject=self.subject)

    def envelope(self, entity, capability, cid, status, *, content=None, media="application/json", refs=None,
                 reason="NOT_IN_BOUNDS", uncertainty="bounded to supplied context"):
        env = {"schema": "sv-llm.contribution/v0.1", "contribution_id": cid, "work_id": "fixture-work-001",
               "entity": entity, "capability": capability, "epistemic_state": "DERIVED",
               "evidence_refs": ["fixture-view-001"], "provenance": [f"{entity}-run-{cid}"],
               "uncertainty": uncertainty, "status": status, "authority_effect": "NONE"}
        if status == "CONTRIBUTED":
            env["content_media_type"] = media
            if refs is not None:
                env["artifact_refs"] = refs
                env["content_digest"] = self.canon.retained_content_digest(media, content)
            else:
                env["content"] = content
                env["content_digest"] = self.canon.content_digest(media, content)
        else:
            rec = {"status": status, "reason_or_failed_predicate": reason, "evidence_refs": env["evidence_refs"],
                   "provenance": env["provenance"], "uncertainty": env["uncertainty"]}
            env["non_success_status_record"] = rec
            env["content_digest"] = self.canon.digest(rec)
        return env

    def setup_assignments(self):
        assert self.admit()["disposition"] == ALLOW
        for entity in (A, B):
            for capability in ("adversarial_review", "synthesis"):
                assert self.sandbox.assign("fixture-work-001", entity, capability, declaration=self.declaration(entity),
                                           tree=self.tree)["disposition"] == ALLOW
                assert self.sandbox.request("fixture-work-001", entity, capability)["disposition"] == ALLOW


def raw(value):
    return json.dumps(value).encode()


class EndToEnd(unittest.TestCase):
    """Order-3 exit conditions with two fixture entities."""

    def test_full_collaboration_reconstructs_to_parent(self):
        h = Harness()
        h.setup_assignments()
        s = h.sandbox
        big = os.urandom(1024 * 1024)  # 1 MiB: well beyond the 128 KiB single-argument limit (A2)
        retained = json.dumps({"finding": "clause 7 contradicts clause 3", "confidence": "medium"}, indent=2).encode()
        outcomes = [
            s.record(raw(h.envelope(A, "adversarial_review", "a-json", "CONTRIBUTED",
                                    content={"finding": "contradiction", "between": ["clause 3", "clause 7"]}))),
            s.record(raw(h.envelope(A, "adversarial_review", "a-bytes", "CONTRIBUTED",
                                    content=base64.b64encode(big).decode(), media="application/octet-stream"))),
            s.record(raw(h.envelope(B, "adversarial_review", "b-artifact", "CONTRIBUTED", content=retained,
                                    media="application/json; charset=utf-8", refs=["fixture-retained-001"])),
                     retained=retained),
            s.record(raw(h.envelope(B, "adversarial_review", "b-refused", "REFUSED", reason="OUTSIDE_DECLARED_BOUNDS"))),
            s.record(raw(h.envelope(A, "synthesis", "a-failed", "FAILED", reason="FIXTURE_FAILURE", uncertainty=None))),
            s.record(raw(h.envelope(B, "synthesis", "b-unavailable", "UNAVAILABLE", reason="FIXTURE_UNAVAILABLE"))),
        ]
        for o in outcomes:
            self.assertEqual(o["disposition"], ALLOW, o)
            self.assertIn("org_receipt_sha256", o)
        self.assertEqual(outcomes[3]["transition_class"], "ENTITY_CONTRIBUTION_REFUSED")
        self.assertEqual({o["status"] for o in outcomes}, {"CONTRIBUTED", "REFUSED", "FAILED", "UNAVAILABLE"})
        self.assertEqual({o["entity"] for o in outcomes}, {A, B})

        ids = [o["contribution_id"] for o in outcomes]
        omitted = s.synthesize("fixture-work-001", ids[:-1], {"summary": "drops the unavailable one"})
        self.assertEqual((omitted["disposition"], omitted["failed_predicate"]),
                         (DENY, "SYNTHESIS_BINDS_EVERY_RECORDED_INPUT"))
        synth = s.synthesize("fixture-work-001", ids, {"summary": "one contradiction found; one refusal; one failure; one unavailable",
                                                       "disagreement": ["a-json", "b-refused"]})
        self.assertEqual(synth["disposition"], ALLOW)
        done = s.complete("fixture-work-001")
        self.assertEqual(done["disposition"], ALLOW)
        self.assertEqual(done["expected_output_or_handoff"], {"successor_transition_class": "SANDBOX_SYNTHESIS_RECORDED"})

        rebuilt = s.reconstruct("fixture-work-001")
        self.assertEqual(rebuilt["parent_transition"]["repo_receipt_sha256"], h.parent_repo["receipt_sha256"])
        self.assertEqual(rebuilt["parent_transition"]["org_receipt_sha256"], h.parent_org["receipt_sha256"])
        self.assertEqual(sorted(rebuilt["contributions"]), sorted(ids))
        lineage = s.ledger.chain()
        synthesis_receipt = next(r for r in lineage if r["transition_class"] == "SANDBOX_SYNTHESIS_RECORDED"
                                 and r["evidence"]["disposition"] == ALLOW)
        self.assertEqual({i["status"] for i in synthesis_receipt["evidence"]["lineage"]},
                         {"CONTRIBUTED", "REFUSED", "FAILED", "UNAVAILABLE"})

        # Every Sandbox receipt, ALLOW and DENY, propagated to the SV-LLM organization ledger.
        chain = s.ledger.chain()
        sandbox_org = [o for o in h.org_receipts]
        self.assertEqual(len(sandbox_org), len(chain))
        self.assertEqual([o["repo_receipt_sha256"] for o in sandbox_org], [r["receipt_sha256"] for r in chain])
        self.assertTrue(all(o["source_repository"] == "SV-LLM/sandbox" for o in sandbox_org))
        # The 1 MiB evidence went through in-process; the receipt carries it inline.
        big_receipt = next(r for r in chain if r["evidence"].get("contribution_id") == "a-bytes")
        self.assertEqual(base64.b64decode(big_receipt["evidence"]["envelope"]["content"]), big)


class Denials(unittest.TestCase):
    """DENY is a disposition: each refused attempt yields exactly one receipt and work continues."""

    def setUp(self):
        self.h = Harness()

    def assertDenied(self, result, predicate):
        self.assertEqual(result["disposition"], DENY, result)
        self.assertEqual(result["failed_predicate"], predicate, result)
        self.assertIn("repo_receipt_sha256", result)
        self.assertIn("org_receipt_sha256", result)

    def test_admission(self):
        h = self.h
        bad = h.work()
        before = len(h.sandbox.ledger.chain())
        self.assertDenied(h.sandbox.admit(b'{"a":1,"a":2}', parent_repo_receipt=h.parent_repo,
                                          parent_org_receipt=h.parent_org, subject=h.subject), "WORK_IS_CANONICAL_JSON")
        self.assertDenied(h.admit({**bad, "permitted_capabilities": ["governance"]}), "WORK_IS_SCHEMA_VALID")
        w = copy.deepcopy(bad); w["parent_transition"]["repo_receipt_sha256"] = sha("other")
        self.assertDenied(h.admit(w), "PARENT_REPO_RECEIPT_MATCHES")
        w = copy.deepcopy(bad); w["parent_transition"]["transition_class"] = "OTHER"
        self.assertDenied(h.admit(w), "PARENT_TRANSITION_CLASS_MATCHES")
        w = copy.deepcopy(bad); w["parent_transition"]["org_receipt_sha256"] = sha("other")
        self.assertDenied(h.admit(w), "PARENT_ORG_RECEIPT_MATCHES")
        w = copy.deepcopy(bad); w["parent_transition"]["subject_or_artifact_digest"] = sha("other")
        self.assertDenied(h.admit(w), "SUBJECT_IS_PARENT_SUCCESSOR_STATE")
        tampered = dict(h.parent_repo, evidence={"disposition": "DENY"})
        self.assertDenied(h.sandbox.admit(raw(bad), parent_repo_receipt=tampered, parent_org_receipt=h.parent_org,
                                          subject=h.subject), "PARENT_REPO_RECEIPT_MATCHES")
        self.assertEqual(len(h.sandbox.ledger.chain()), before + 7)
        self.assertEqual(h.admit()["disposition"], ALLOW)  # work continues after denials
        self.assertDenied(h.admit(), "WORK_ID_NOT_ALREADY_ADMITTED")

    def test_assignment_and_request(self):
        h = self.h
        s = h.sandbox
        self.assertDenied(s.assign("fixture-work-001", A, "adversarial_review", declaration=h.declaration(A), tree=h.tree),
                          "WORK_IS_ADMITTED")
        h.admit()
        self.assertDenied(s.assign("fixture-work-001", A, "code_generation", declaration=h.declaration(A), tree=h.tree),
                          "CAPABILITY_REQUESTED_AND_PERMITTED_BY_WORK")
        self.assertDenied(s.assign("fixture-work-001", C, "synthesis", declaration=None, tree=h.tree),
                          "CAPABILITY_DECLARATION_REF_PRESENT")
        self.assertDenied(s.assign("fixture-work-001", A, "synthesis", declaration=h.declaration(B), tree=h.tree),
                          "DECLARATION_DIGEST_MATCHES")
        self.assertDenied(s.assign("fixture-work-001", "FixtureEntityZ", "synthesis", declaration=h.declaration(A), tree=h.tree),
                          "ENTITY_IS_IN_CANONICAL_ORGANIZATION_TREE")
        self.assertDenied(s.request("fixture-work-001", A, "synthesis"), "CAPABILITY_ASSIGNED_FOR_ADMITTED_WORK")
        ok = s.assign("fixture-work-001", A, "synthesis", declaration=h.declaration(A), tree=h.tree)
        self.assertEqual(ok["disposition"], ALLOW)
        evidence = ok["capability_assignment_evidence"]
        h.canon.verify_capability_assignment(evidence)  # declaration carried inline (C4)

    def test_contribution(self):
        h = self.h
        h.setup_assignments()
        s = h.sandbox
        good = h.envelope(A, "adversarial_review", "c1", "CONTRIBUTED", content={"x": 1})
        self.assertDenied(s.record(raw(good).replace(b'"x": 1', b'"x": 1.0')), "ENVELOPE_IS_CANONICAL_JSON")
        self.assertDenied(s.record(raw({**good, "authority_effect": "GOVERNANCE"})), "ENVELOPE_IS_SCHEMA_VALID")
        self.assertDenied(s.record(raw({**good, "content_digest": sha("other")})), "CONTENT_DIGEST_MISMATCH")
        self.assertDenied(s.record(raw({**good, "work_id": "other-work"})), "CONTRIBUTION_WAS_REQUESTED")
        self.assertDenied(s.record(raw(h.envelope(A, "code_analysis", "c2", "CONTRIBUTED", content={"x": 1}))),
                          "CONTRIBUTION_WAS_REQUESTED")
        mismatch = h.envelope(B, "adversarial_review", "c3", "REFUSED")
        mismatch["non_success_status_record"]["provenance"] = ["someone-else"]
        mismatch["content_digest"] = h.canon.digest(mismatch["non_success_status_record"])
        self.assertDenied(s.record(raw(mismatch)), "STATUS_RECORD_FIELD_MISMATCH")
        refs = h.envelope(B, "adversarial_review", "c4", "CONTRIBUTED", content=b"{}", refs=["r"])
        self.assertDenied(s.record(raw(refs)), "ARTIFACT_CONTENT_RETAINED")
        self.assertEqual(s.record(raw(good))["disposition"], ALLOW)
        self.assertDenied(s.record(raw(good)), "CONTRIBUTION_ID_UNIQUE")

    def test_synthesis_and_completion_order(self):
        h = self.h
        s = h.sandbox
        self.assertDenied(s.synthesize("fixture-work-001", [], {"s": 1}), "WORK_IS_ADMITTED")
        h.setup_assignments()
        self.assertDenied(s.synthesize("fixture-work-001", [], {"s": 1}), "SYNTHESIS_INPUTS_RECORDED")
        self.assertDenied(s.complete("fixture-work-001"), "SYNTHESIS_RECORDED")
        s.record(raw(h.envelope(A, "adversarial_review", "c1", "CONTRIBUTED", content={"x": 1})))
        self.assertDenied(s.synthesize("fixture-work-001", ["c1"], {"s": 1.5}), "NON_INTEGER_NUMBER")
        self.assertEqual(s.synthesize("fixture-work-001", ["c1"], {"s": 1})["disposition"], ALLOW)
        self.assertEqual(s.complete("fixture-work-001")["disposition"], ALLOW)
        self.assertDenied(s.complete("fixture-work-001"), "WORK_NOT_ALREADY_COMPLETED")


class SixFieldDeny(unittest.TestCase):
    """Every DENY path carries all six conformance fields, in the result and in its ledger receipt."""

    def assertSixFields(self, outcome, predicate=None):
        for field in SIX_FIELDS:
            self.assertIsInstance(outcome.get(field), str, (field, outcome))
            self.assertTrue(outcome[field], (field, outcome))
        prefix = "SANDBOX_DENY_" if outcome["disposition"] == DENY else "SANDBOX_FAIL_CLOSED_"
        self.assertEqual(outcome["failure_code"], prefix + outcome["failed_predicate"])
        self.assertEqual(outcome["owning_existing_goal"], OWNING_EXISTING_GOAL)
        self.assertTrue(outcome["retry_entrypoint"].startswith("runtime.sandbox.Sandbox."), outcome)
        self.assertTrue(hasattr(Sandbox, outcome["retry_entrypoint"].rsplit(".", 1)[1]), outcome)
        if predicate is not None:
            self.assertEqual(outcome["failed_predicate"], predicate)

    def test_every_deny_call_site_is_covered(self):
        tree = ast.parse((ROOT / "runtime/sandbox.py").read_text())
        calls = [n for n in ast.walk(tree) if isinstance(n, ast.Call) and getattr(n.func, "attr", None) == "_deny"]
        self.assertEqual(len(calls), 27)
        for call in calls:
            self.assertIn(call.args[0].value, DENY_ENTRYPOINTS)
            if isinstance(call.args[2], ast.Constant):  # registration/canon predicates use the generic pair
                self.assertIn(call.args[2].value, DENY_REPAIRS)

    def test_every_denial_scenario_records_six_fields(self):
        denials = 0
        for name in [n for n in dir(Denials) if n.startswith("test_")]:
            case = Denials(name)
            case.setUp()
            getattr(case, name)()
            for receipt in case.h.sandbox.ledger.chain():
                evidence = receipt["evidence"]
                if evidence.get("disposition") == DENY:
                    denials += 1
                    self.assertSixFields(evidence)
                    method = DENY_ENTRYPOINTS[receipt["transition_class"]]
                    self.assertEqual(evidence["retry_entrypoint"], "runtime.sandbox.Sandbox." + method)
        self.assertGreaterEqual(denials, 27)

    def test_completion_pending_propagation_and_repropagate_deny(self):
        h = Harness()
        h.setup_assignments()
        s = h.sandbox
        s.record(raw(h.envelope(A, "adversarial_review", "c1", "CONTRIBUTED", content={"x": 1})))
        s.synthesize("fixture-work-001", ["c1"], {"s": 1})
        propagate = s.propagate
        s.propagate = lambda receipt, cls: (_ for _ in ()).throw(RuntimeError("org ledger down"))
        s.record_tool_observation({"work_id": "fixture-work-001", "observation_id": "o1", "tool": "t",
                                   "tool_profile": "p", "disposition": ALLOW})
        s.propagate = propagate
        denied = s.complete("fixture-work-001")
        self.assertSixFields(denied, "ORGANIZATION_PROPAGATION_COMPLETE")
        self.assertEqual(denied["retry_entrypoint"], "runtime.sandbox.Sandbox.complete")
        self.assertIn("repropagate", denied["next_attempt"])
        refused = s.repropagate(sha("not-a-receipt"))
        self.assertSixFields(refused, "RECEIPT_PROPAGATION_PENDING")
        self.assertEqual(refused["retry_entrypoint"], "runtime.sandbox.Sandbox.repropagate")

    def test_fail_closed_propagation_paths_carry_six_fields(self):
        h = Harness()
        s = h.sandbox
        propagate = s.propagate
        s.propagate = lambda receipt, cls: (_ for _ in ()).throw(RuntimeError("org ledger down"))
        failed = s.complete("fixture-work-001")  # a DENY whose propagation then fails
        self.assertEqual(failed["disposition"], FAIL_CLOSED)
        self.assertSixFields(failed, "ORGANIZATION_PROPAGATION_SUCCEEDED")
        logged = next(r for r in s.ledger.chain() if r["transition_class"] == "ORGANIZATION_PROPAGATION_FAILED")
        self.assertSixFields(logged["evidence"], "ORGANIZATION_PROPAGATION_SUCCEEDED")
        for outcome in (failed, logged["evidence"]):
            self.assertEqual(outcome["retry_entrypoint"], "runtime.sandbox.Sandbox.repropagate")
        pending = s.pending_propagation()
        self.assertEqual(len(pending), 1)
        retried = s.repropagate(pending[0])  # organization ledger still down
        self.assertEqual(retried["disposition"], FAIL_CLOSED)
        self.assertSixFields(retried, "ORGANIZATION_PROPAGATION_SUCCEEDED")
        s.propagate = propagate
        self.assertEqual(s.repropagate(pending[0])["disposition"], ALLOW)
        non_allow = [r["evidence"] for r in s.ledger.chain() if r["evidence"].get("disposition") != ALLOW]
        self.assertTrue(non_allow)
        for evidence in non_allow:
            self.assertSixFields(evidence)

    def test_six_fields_are_deterministic(self):
        receipts = []
        for _ in range(2):
            h = Harness()
            h.sandbox.assign("fixture-work-001", A, "synthesis", declaration=h.declaration(A), tree=h.tree)
            receipts.append(h.sandbox.ledger.chain()[0])
        self.assertEqual(receipts[0]["evidence"], receipts[1]["evidence"])
        self.assertEqual(receipts[0]["successor_state_sha256"], receipts[1]["successor_state_sha256"])


class LedgerIntegrity(unittest.TestCase):
    def test_tampering_is_detected(self):
        h = Harness()
        h.admit()
        path = next(h.sandbox.ledger.receipts_dir.glob("*.json"))
        receipt = json.loads(path.read_text())
        receipt["evidence"]["disposition"] = "DENY"
        path.write_text(json.dumps(receipt))
        with self.assertRaises(ValueError):
            h.sandbox.ledger.chain()

    def test_receipt_shape_matches_sv_llm_repo_contract(self):
        h = Harness()
        h.admit()
        receipt = h.sandbox.ledger.chain()[0]
        contract = json.loads((DOTGITHUB / ".stegverse/transition-ledger/contract.json").read_text())
        self.assertEqual(receipt["schema"], contract["receipt_schema"])
        for field in contract["required_fields"]:
            self.assertIn(field, receipt)
        self.assertEqual(receipt["repository"], "SV-LLM/sandbox")


class MasterRecordsProhibitionName(unittest.TestCase):
    """Master Records boundary migration: fixtures emit the new prohibition name, and a declaration
    that still lists the legacy name keeps registering when the tree binds its digest."""

    def test_new_and_legacy_names_register(self):
        h = Harness()
        assert h.admit()["disposition"] == ALLOW
        fixture = json.loads(h.declaration(A))
        self.assertIn(MASTER_RECORDS_PROHIBITION, fixture["prohibited"])
        self.assertNotIn(LEGACY_MASTER_RECORDS_PROHIBITION, fixture["prohibited"])
        result = h.sandbox.assign("fixture-work-001", A, "synthesis", declaration=h.declaration(A), tree=h.tree)
        self.assertEqual(result["disposition"], ALLOW, result)
        legacy = copy.deepcopy(fixture)
        legacy["prohibited"] = [LEGACY_MASTER_RECORDS_PROHIBITION if p == MASTER_RECORDS_PROHIBITION else p
                                for p in legacy["prohibited"]]
        tree = copy.deepcopy(h.tree)
        row = next(r for r in tree["repositories"] if r["name"] == A)
        row["capability_declaration_ref"]["declaration_sha256"] = h.canon.digest(legacy)
        result = h.sandbox.assign("fixture-work-001", A, "adversarial_review", declaration=raw(legacy), tree=tree)
        self.assertEqual(result["disposition"], ALLOW, result)


class Vendor(unittest.TestCase):
    def test_vendored_contracts_verified(self):
        h = Harness()
        manifest = h.sandbox.registration.verify_vendor(ROOT / "runtime/contracts")
        self.assertEqual(set(manifest["files"]), {"sandbox-work.schema.json", "contribution.schema.json",
                                                  "provider-interaction-contract.schema.json"})


if __name__ == "__main__":
    unittest.main(verbosity=2)
