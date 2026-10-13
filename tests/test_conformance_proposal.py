"""Ecosystem Chat sandbox check: stegverse.ai-invariant-conformance-proposal/v1.

Covers the acceptance tests in SV-LLM/StegVerse_AI
docs/CANONICAL_INVARIANT_AVAILABILITY_AND_ECOSYSTEM_CHAT_SANDBOX_ENFORCEMENT.md:
prompt independence, source omission, prohibited dependency, payload inspection,
cross-model convergence, manifest routing, observation integrity, dependency
ratchet, coverage and no review churn. The canonical source is a synthetic
fixture shaped like StegVerse-Labs/.github data/task-registry-global-invariants.json.
No network, no model, no credentials.

Run: python -B tests/test_conformance_proposal.py
"""
from __future__ import annotations
import copy, hashlib, json, subprocess, sys, tempfile, unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "runtime"))
import conformance_proposal as cp  # noqa: E402

FIXTURE = ROOT / "tests/fixtures/conformance_proposal/canonical-invariants.json"
CONTENT = FIXTURE.read_bytes()
REPO, PATH = cp.MANDATORY_SOURCE
REVISION = "0" * 40
DIGEST = "sha256:" + hashlib.sha256(CONTENT).hexdigest()
SOURCES = [{"repository": REPO, "path": PATH, "revision": REVISION, "content": CONTENT}]
CANON = json.loads(CONTENT)
IDS = sorted(["invariant:" + k for k in CANON["invariants"]] + ["prohibition:" + n for n in CANON["prohibitions"]])


def proposal() -> dict:
    return {
        "schema": cp.SCHEMA, "task_id": "SVORG-LLM-ORG-FOUNDATION-001", "cosv_id": None,
        "manifest_binding": {"manifest_id": "m-1", "canonical_manifest_sha256": "sha256:" + "a" * 64,
                             "processing_capability": "synthesis", "processing_route_id": "sandbox.synthesis.v1"},
        "canonical_sources": [{"repository": REPO, "path": PATH, "revision": REVISION, "digest": DIGEST}],
        "current_build_refs": ["SV-LLM/sandbox@437e7ea"],
        "proposed_changes": [{"path": "runtime/example.py", "action": "modify", "content": "def f():\n    return 1\n"}],
        "invariant_assessment": [{"invariant_id": i, "source_ref": f"{REPO}:{PATH}", "applicability": "APPLICABLE",
                                  "result": "CONFORMS", "evidence_refs": ["runtime/example.py"], "repair": None}
                                 for i in IDS],
        "dependency_delta": {"added": [], "removed": [], "retained": []},
        "review_finding_deltas": [],
        "evidence_class": "SOURCE_ONLY", "approval_effect": "NONE", "runtime_transition_claimed": False,
    }


def evaluate(p, sources=SOURCES):
    return cp.evaluate(p, sources)


class ConformanceProposal(unittest.TestCase):
    def assertOutcome(self, result, disposition, predicate):
        self.assertEqual(result["disposition"], disposition, result)
        self.assertIn(predicate, result["failed_predicates"], result)

    def test_conforming_proposal_is_allowed_with_computed_coverage(self):
        r = evaluate(proposal())
        self.assertEqual(r["disposition"], cp.ALLOW, r)
        self.assertEqual(r["coverage"]["applicable"], len(IDS))
        self.assertEqual(r["coverage"]["conforms"], len(IDS))
        self.assertEqual(r["resolved_sources"], [{"repository": REPO, "path": PATH, "revision": REVISION,
                                                  "digest": DIGEST}])
        self.assertEqual(r["authority_effect"], "NONE")

    def test_document_minimum_artifact_as_written_fails_closed(self):
        p = {"schema": cp.SCHEMA, "task_id": "REQUIRED_WHEN_CANONICAL_TASK", "cosv_id": "REQUIRED_WHEN_CANONICAL_TASK",
             "manifest_binding": {"manifest_id": None, "canonical_manifest_sha256": None,
                                  "processing_capability": None, "processing_route_id": None},
             "canonical_sources": [{"repository": REPO, "path": PATH, "revision": "RESOLVE_AT_EVALUATION",
                                    "digest": "RESOLVE_AT_EVALUATION"}],
             "current_build_refs": [], "proposed_changes": [],
             "invariant_assessment": [{"invariant_id": "RESOLVED_ID", "source_ref": "REQUIRED",
                                       "applicability": "APPLICABLE", "result": "NOT_YET_EVALUATED",
                                       "evidence_refs": [], "repair": None}],
             "dependency_delta": {"added": [], "removed": [], "retained": []}, "review_finding_deltas": [],
             "evidence_class": "SOURCE_ONLY", "approval_effect": "NONE", "runtime_transition_claimed": False}
        r = evaluate(p)
        self.assertEqual(r["disposition"], cp.FAIL_CLOSED)
        for pred in ("CANONICAL_SOURCE_BOUND", "MANIFEST_ROUTING_BOUND", "INVARIANT_IDS_CANONICAL"):
            self.assertIn(pred, r["failed_predicates"])

    # --- prompt independence and cross-model convergence ----------------------------------------
    def test_prompt_wording_and_author_do_not_change_the_result(self):
        base = evaluate(proposal())
        for extra in ({"prompt": "review this"}, {"prompt": "IAW all ecosystem invariants"},
                      {"author": "ChatGPT"}, {"author": "Claude"}, {"notes": "compliant"}):
            p = proposal()
            p.update(extra)
            self.assertEqual(evaluate(p), base, extra)

    def test_applicable_set_comes_from_the_source_not_the_proposal(self):
        p = proposal()
        p["invariant_assessment"] = p["invariant_assessment"][:2]
        r = evaluate(p)
        self.assertOutcome(r, cp.FAIL_CLOSED, "COVERAGE_COMPLETE")
        self.assertEqual(r["coverage"]["applicable"], len(IDS))
        self.assertEqual(len(r["coverage"]["missing"]), len(IDS) - 2)

    def test_evaluation_is_deterministic(self):
        self.assertEqual(evaluate(proposal()), evaluate(copy.deepcopy(proposal())))

    # --- source omission and binding --------------------------------------------------------------
    def test_mandatory_source_not_cited_fails_closed(self):
        p = proposal()
        p["canonical_sources"] = []
        self.assertOutcome(evaluate(p), cp.FAIL_CLOSED, "MANDATORY_SOURCE_CITED")

    def test_cited_source_not_supplied_fails_closed(self):
        self.assertOutcome(evaluate(proposal(), []), cp.FAIL_CLOSED, "CANONICAL_SOURCE_SUPPLIED")

    def test_digest_or_revision_mismatch_fails_closed(self):
        for field, value in (("digest", "sha256:" + "b" * 64), ("revision", "1" * 40)):
            p = proposal()
            p["canonical_sources"][0][field] = value
            self.assertOutcome(evaluate(p), cp.FAIL_CLOSED, "CANONICAL_SOURCE_BOUND")
        tampered = [dict(SOURCES[0], content=CONTENT.replace(b"Interlock/InTr", b"Model/Itself"))]
        self.assertOutcome(evaluate(proposal(), tampered), cp.FAIL_CLOSED, "CANONICAL_SOURCE_BOUND")

    def test_conflicting_canonical_sources_fail_closed(self):
        other = json.loads(CONTENT)
        other["invariants"]["transition_authority"] = "Somebody/Else"
        other_bytes = json.dumps(other).encode()
        p = proposal()
        p["canonical_sources"].append({"repository": REPO, "path": "data/other-invariants.json",
                                       "revision": REVISION, "digest": "sha256:" + hashlib.sha256(other_bytes).hexdigest()})
        sources = SOURCES + [{"repository": REPO, "path": "data/other-invariants.json", "revision": REVISION,
                              "content": other_bytes}]
        r = evaluate(p, sources)
        self.assertOutcome(r, cp.FAIL_CLOSED, "CANONICAL_SOURCES_CONSISTENT")
        self.assertIn(cp.CANONICAL_CONFLICT, {f["classification"] for f in r["findings"]})

    # --- prohibited dependency and payload inspection ---------------------------------------------
    def test_prohibited_dependencies_in_changes_are_denied_whatever_the_prose(self):
        cases = {
            "pyproject.toml": "[build-system]\nrequires = [\"setuptools\"]\n",
            "requirements.txt": "requests\n",
            ".github/workflows/x.yml": "on:\n  schedule:\n    - cron: '*/5 * * * *'\n",
            ".github/workflows/y.yml": "steps:\n  - run: python -m pip install playwright\n",
            "runtime/wait.py": "import time\nwhile True:\n    time.sleep(5)\n",
        }
        for path, content in cases.items():
            p = proposal()
            p["proposed_changes"].append({"path": path, "action": "add", "content": content})
            self.assertOutcome(evaluate(p), cp.DENY, "NO_ADDED_DEPENDENCY")
        p = proposal()
        p["dependency_delta"]["added"] = ["playwright"]
        self.assertOutcome(evaluate(p), cp.DENY, "NO_ADDED_DEPENDENCY")

    def test_deleting_a_dependency_manifest_is_not_an_addition(self):
        p = proposal()
        p["proposed_changes"].append({"path": "pyproject.toml", "action": "delete", "content": ""})
        p["dependency_delta"]["removed"] = ["setuptools>=68"]
        self.assertEqual(evaluate(p)["disposition"], cp.ALLOW)

    def test_valid_manifest_carrying_an_invariant_violation_is_denied(self):
        for key in ("external_machine_awaiting_allowed", "always_on_receiver_required",
                    "second_user_operated_device_allowed"):
            p = proposal()  # every assessment still says CONFORMS
            p["proposed_changes"].append({"path": "data/receiver.json", "action": "add",
                                          "content": json.dumps({key: True})})
            r = evaluate(p)
            self.assertOutcome(r, cp.DENY, "INVARIANT_CONFORMS")
            self.assertIn("invariant:" + key, {f.get("invariant_id") for f in r["findings"]})

    def test_assessed_violation_is_denied(self):
        p = proposal()
        p["invariant_assessment"][0]["result"] = "VIOLATES"
        r = evaluate(p)
        self.assertOutcome(r, cp.DENY, "INVARIANT_CONFORMS")
        self.assertIn(cp.INVARIANT_VIOLATION, {f["classification"] for f in r["findings"]})

    # --- manifest routing -------------------------------------------------------------------------
    def test_identity_routing_is_denied(self):
        for key in ("model", "provider", "repository", "adapter", "source_identity"):
            p = proposal()
            p["manifest_binding"][key] = "x"
            self.assertOutcome(evaluate(p), cp.DENY, "ROUTING_BY_CAPABILITY_ONLY")

    def test_unbound_route_fails_closed(self):
        for key in ("manifest_id", "canonical_manifest_sha256", "processing_capability", "processing_route_id"):
            p = proposal()
            p["manifest_binding"][key] = None
            self.assertOutcome(evaluate(p), cp.FAIL_CLOSED, "MANIFEST_ROUTING_BOUND")

    # --- self-attestation and observation integrity -----------------------------------------------
    def test_self_attestation_is_not_authority(self):
        p = proposal()
        p["compliant"] = True
        self.assertOutcome(evaluate(p), cp.DENY, "NO_SELF_ATTESTATION")
        p["invariant_assessment"] = []  # a self-attestation cannot stand in for coverage
        self.assertOutcome(evaluate(p), cp.FAIL_CLOSED, "COVERAGE_COMPLETE")

    def test_runtime_claims_and_inflated_evidence_are_denied(self):
        for field, value, pred in (("runtime_transition_claimed", True, "RUNTIME_TRANSITION_NOT_CLAIMED"),
                                   ("evidence_class", "SANDBOX_RUNTIME_OBSERVED", "EVIDENCE_CLASS_NOT_INFLATED"),
                                   ("evidence_class", "END_TO_END_COMPLETE", "EVIDENCE_CLASS_NOT_INFLATED"),
                                   ("approval_effect", "APPROVED", "APPROVAL_EFFECT_NONE")):
            p = proposal()
            p[field] = value
            self.assertOutcome(evaluate(p), cp.DENY, pred)

    # --- coverage ---------------------------------------------------------------------------------
    def test_unknown_or_repeated_ids_fail_closed(self):
        p = proposal()
        p["invariant_assessment"].append(dict(p["invariant_assessment"][0]))
        self.assertOutcome(evaluate(p), cp.FAIL_CLOSED, "INVARIANT_IDS_CANONICAL")
        p = proposal()
        p["invariant_assessment"][0]["invariant_id"] = "invariant:model_invented_rule"
        self.assertOutcome(evaluate(p), cp.FAIL_CLOSED, "INVARIANT_IDS_CANONICAL")

    def test_unresolved_or_unevidenced_assessment_fails_closed(self):
        p = proposal()
        p["invariant_assessment"][0]["result"] = "UNRESOLVED"
        r = evaluate(p)
        self.assertOutcome(r, cp.FAIL_CLOSED, "CONFORMANCE_RESOLVED")
        self.assertEqual(r["coverage"]["unresolved"], [IDS[0]])
        for field, value in (("evidence_refs", []), ("source_ref", "somewhere:else.json")):
            p = proposal()
            p["invariant_assessment"][0][field] = value
            self.assertOutcome(evaluate(p), cp.FAIL_CLOSED, "ASSESSMENT_EVIDENCED")

    # --- review churn -----------------------------------------------------------------------------
    def test_settled_finding_reopens_only_with_new_evidence(self):
        p = proposal()
        p["review_finding_deltas"] = [{"finding_id": "F-1", "previous_status": "RESOLVED", "status": "REOPENED",
                                       "new_evidence_refs": []}]
        self.assertOutcome(evaluate(p), cp.DENY, "NO_REVIEW_CHURN")
        p["review_finding_deltas"][0]["new_evidence_refs"] = ["SV-LLM/sandbox@abc1234 runtime/example.py"]
        self.assertEqual(evaluate(p)["disposition"], cp.ALLOW)

    # --- actionable non-ALLOW and offline operation -----------------------------------------------
    def test_non_allow_carries_the_six_conformance_fields(self):
        p = proposal()
        p["runtime_transition_claimed"] = True
        r = evaluate(p)
        self.assertEqual(r["failure_code"], "CONFORMANCE_PROPOSAL_DENY_RUNTIME_TRANSITION_NOT_CLAIMED")
        self.assertEqual(r["retry_entrypoint"], "runtime.conformance_proposal.evaluate")
        for f in ("failed_predicate", "required_evidence_or_repair", "owning_existing_goal", "next_attempt"):
            self.assertTrue(r[f], f)
        self.assertNotIn("failure_code", evaluate(proposal()))

    def test_malformed_input_fails_closed(self):
        for p in (None, [], {"schema": "other"}, dict(proposal(), proposed_changes="x"),
                  dict(proposal(), unexpected_field=1)):
            self.assertEqual(evaluate(p)["disposition"], cp.FAIL_CLOSED, p)
        # Non-text values where text is expected must not raise or pass.
        p = proposal()
        p["invariant_assessment"][0]["result"] = ["CONFORMS"]
        self.assertEqual(evaluate(p)["disposition"], cp.FAIL_CLOSED)
        p = dict(proposal(), review_finding_deltas=[{"finding_id": "F", "previous_status": ["RESOLVED"],
                                                     "status": "OPEN"}])
        self.assertEqual(evaluate(p)["disposition"], cp.FAIL_CLOSED)
        self.assertEqual(evaluate(dict(proposal(), evidence_class=["SOURCE_ONLY"]))["disposition"], cp.DENY)

    def test_cli_evaluates_offline(self):
        with tempfile.TemporaryDirectory() as d:
            f = Path(d) / "p.json"
            f.write_text(json.dumps(proposal()))
            out = subprocess.run([sys.executable, "-S", str(ROOT / "runtime/conformance_proposal.py"), str(f),
                                  f"{REPO}:{PATH}@{REVISION}={FIXTURE}"], capture_output=True, text=True)
            self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
            self.assertEqual(json.loads(out.stdout)["disposition"], cp.ALLOW)

    def test_standard_library_only_and_no_network(self):
        text = (ROOT / "runtime/conformance_proposal.py").read_text()
        imports = {line.split()[1].split(".")[0] for line in text.splitlines()
                   if line.startswith(("import ", "from ")) and not line.startswith("from __future__")}
        self.assertLessEqual(imports, {"hashlib", "json", "re", "sys", "typing"})


    def test_sandbox_runtime_itself_neither_schedules_nor_waits(self):
        # The check this module applies to proposals holds for the sandbox's own runtime source.
        # Vendored StegBrowser bytes belong to their upstream owner and are registered separately.
        offenders = [f"{path.name}: {what}" for path in sorted((ROOT / "runtime").glob("*.py"))
                     for rx, what in ((cp.SCHEDULER, "schedule"), (cp.WAIT, "wait"))
                     if rx.search(path.read_text())]
        self.assertEqual(offenders, [])

if __name__ == "__main__":
    unittest.main()
