"""Sandbox + vendored StegBrowser llm.v1: synthetic integration (no network, injected Playwright).

Run: SV_LLM_DOTGITHUB_ROOT=<SV-LLM/.github checkout> python -B tests/test_stegbrowser_tool.py
"""
from __future__ import annotations
import copy, hashlib, json, sys, unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import MagicMock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests"))
from test_sandbox_runtime import Harness, ALLOW, DENY  # noqa: E402
from stegbrowser_tool import StegBrowserTool, VENDOR, MANIFEST, TOOL_REPAIRS, STEGBROWSER_NEXT_ATTEMPT  # noqa: E402
from sandbox import OWNING_EXISTING_GOAL  # noqa: E402

WORK = "fixture-work-001"
MARKER = "SVLLM_MARK_7Q"


def invocation(**changes):
    inv = {"invocation_id": "inv-1", "tool": "StegBrowser", "profile": "llm.v1",
           "prompt": f"Reply with {MARKER} and one sentence.", "response_marker": MARKER,
           "secure_url": "https://space.example.test/chat", "allowed_origins": ["space.example.test"],
           "browser_actions": [], "provider": "label-only-provider", "model": "label-only-model"}
    inv["browser_actions"] = [{"op": "fill", "selector": "textarea", "value": inv["prompt"]},
                              {"op": "press", "selector": "textarea", "key": "Enter"},
                              {"op": "wait_for", "selector": "[data-answer]"},
                              {"op": "read_text", "selector": "[data-answer]"}]
    inv.update(changes)
    return inv


def factory(*, text=f"{MARKER}: a reply.", fail_launch=False, status=200):
    playwright = MagicMock()
    p = playwright.return_value.__enter__.return_value
    browser = p.chromium.launch.return_value
    context = browser.new_context.return_value
    page = context.new_page.return_value
    page.goto.return_value.status = status
    page.locator.return_value.inner_text.return_value = text
    if fail_launch:
        p.chromium.launch.side_effect = RuntimeError("synthetic launch failure")
    return playwright


SIX_FIELDS = ("failure_code", "failed_predicate", "required_evidence_or_repair", "retry_entrypoint",
              "owning_existing_goal", "next_attempt")


def assert_six_fields(tc: unittest.TestCase, e: dict) -> None:
    """Every non-ALLOW tool observation carries the six conformance fields."""
    tc.assertNotEqual(e["disposition"], ALLOW)
    for field in SIX_FIELDS:
        tc.assertTrue(isinstance(e.get(field), str) and e[field], (e["failed_predicate"], field))
    tc.assertEqual(e["owning_existing_goal"], OWNING_EXISTING_GOAL)
    if e["decided_by"] == "STEGBROWSER":
        tc.assertEqual(e["next_attempt"], STEGBROWSER_NEXT_ATTEMPT)
    else:
        predicate = e["failed_predicate"]
        tc.assertIn(predicate, TOOL_REPAIRS)  # a specific repair, not the generic fallback
        tc.assertEqual(e["failure_code"], f"SANDBOX_TOOL_{e['disposition']}_{predicate}")
        tc.assertEqual(e["retry_entrypoint"], "runtime.stegbrowser_tool.StegBrowserTool.invoke")
        tc.assertEqual((e["required_evidence_or_repair"], e["next_attempt"]), TOOL_REPAIRS[predicate])


class Base(unittest.TestCase):
    def setUp(self, invocations=None, propagate_fails=False):
        self.h = Harness()
        if propagate_fails:
            self.fail_org = True
            original = self.h.sandbox.propagate

            def flaky(receipt, cls):
                if self.fail_org:
                    raise OSError("organization ledger unavailable")
                return original(receipt, cls)
            self.h.sandbox.propagate = flaky
        self.s = self.h.sandbox
        work = self.h.work(manifested_request={"manifest_id": "fixture-manifest-001",
                                               "tool_invocations": invocations or [invocation()]})
        admitted = self.h.admit(work)
        self.assertEqual(admitted.get("recorded_disposition", admitted["disposition"]), ALLOW)
        self.tool = StegBrowserTool(self.s)

    def obs(self, result):
        return next(r for r in self.s.ledger.chain() if r["receipt_sha256"] == result["repo_receipt_sha256"])["evidence"]


class Vendoring(Base):
    def test_AT01_vendored_bytes_match_manifest_and_upstream_commit(self):
        self.assertEqual(MANIFEST["source_commit"], "7353176612f4590d0d8220153869cd6e95e241d8")
        self.s.registration.verify_vendor(VENDOR)
        for rel, digest in MANIFEST["upstream_tests"].items():
            self.assertEqual("sha256:" + hashlib.sha256((ROOT / rel).read_bytes()).hexdigest(), digest, rel)

    def test_AT02_entrypoint_importable(self):
        self.assertTrue(callable(self.tool.transition.execute_manifested_llm_browser_transition))

    def test_AT12_no_llm_adapter_or_intr_in_path(self):
        sources = [(ROOT / "runtime/stegbrowser_tool.py").read_text()] + [
            (VENDOR / f).read_text() for f in MANIFEST["files"]]
        for text in sources:
            for forbidden in ("llm_adapter", "LLMAdapter", "import crossing", "interlock", "publish_packet"):
                self.assertNotIn(forbidden, text)


class Roundtrip(Base):
    def test_AT03_AT08_AT09_success_is_recorded_as_tool_observation(self):
        pw = factory()
        out = self.tool.invoke(WORK, "inv-1", playwright_factory=pw)
        self.assertEqual(out["disposition"], ALLOW, out)
        self.assertIn("org_receipt_sha256", out)
        e = self.obs(out)
        self.assertEqual((e["tool"], e["tool_profile"], e["decided_by"]), ("StegBrowser", "llm.v1", "STEGBROWSER"))
        self.assertEqual(e["observed_origin"], "space.example.test")
        self.assertIn(MARKER, e["result"]["response_text"])
        self.assertTrue(e["terminal_receipt"]["session_state_destroyed"])
        self.assertFalse(e["terminal_receipt"]["cookies_retained"])
        context = pw.return_value.__enter__.return_value.chromium.launch.return_value.new_context.return_value
        context.close.assert_called_once()
        pw.return_value.__enter__.return_value.chromium.launch.return_value.close.assert_called_once()
        # AT-09: Sandbox's own canonical digests; StegBrowser commitments kept as evidence.
        body = {k: v for k, v in e.items() if k not in ("observation_digest", "authority_effect")}
        self.assertEqual(e["observation_digest"], self.s.canon.digest(body))
        self.assertTrue(e["request_commitment"].startswith("sha256:"))
        self.assertTrue(e["sandbox_request_digest"].startswith("sha256:"))
        inv, _ = self.tool._invocation(self.s._work(WORK), "inv-1")
        rebuilt = self.tool.request(inv, self.tool.journey(WORK, inv, e["attempt"], e["observation_id"]))
        self.assertEqual(e["sandbox_request_digest"], self.s.canon.digest(rebuilt))  # recomputed by Sandbox under V1

    def test_AT10_AT16_labels_are_not_attestation_and_no_contribution_is_made(self):
        e = self.obs(self.tool.invoke(WORK, "inv-1", playwright_factory=factory()))
        self.assertEqual(e["result"]["provider_label"], "label-only-provider")
        self.assertFalse(e["result"]["labels_are_attestation"])
        self.assertEqual(self.s.contributions(WORK), [])
        self.assertNotIn("entity", e)

    def test_AT11_endpoint_receipts_stay_opaque(self):
        self.tool.invoke(WORK, "inv-1", playwright_factory=factory())
        for r in self.s.ledger.chain():
            blob = json.dumps(r["evidence"])
            self.assertNotIn("endpoint_receipts\"", blob)
            self.assertNotIn("stegverse.repo-transition-receipt/v1", blob)

    def test_G4_journey_is_deterministic_from_admitted_data(self):
        work = self.s._work(WORK)
        inv, _ = self.tool._invocation(work, "inv-1")
        a = self.tool.journey(WORK, inv, 1, "obs-x")
        self.assertEqual(a, self.tool.journey(WORK, inv, 1, "obs-x"))
        self.assertEqual(a["return_predecessor_manifest_sha256"], a["outbound_manifest_sha256"])
        self.assertNotEqual(a["outbound_manifest_sha256"], self.tool.journey(WORK, inv, 2, "obs-x")["outbound_manifest_sha256"])


class NonAllow(Base):
    def test_AT06_expired_lease_fails_before_launch(self):
        pw = factory()
        out = self.tool.invoke(WORK, "inv-1", playwright_factory=pw, now=datetime.now(timezone.utc) - timedelta(hours=1))
        e = self.obs(out)
        self.assertEqual((e["disposition"], e["evaluation_stage"]), ("FAIL_CLOSED", "LEASE_ADMISSION"))
        self.assertIsNone(e["terminal_receipt"])
        assert_six_fields(self, e)
        pw.return_value.__enter__.return_value.chromium.launch.assert_not_called()

    def test_AT07_browser_failures_fail_closed_with_retry(self):
        cases = [(dict(fail_launch=True), None, "BROWSER_LAUNCH"),
                 (dict(text="no marker here"), None, "RESULT_BINDING"),
                 (dict(status=503), None, "BROWSER_NAVIGATION")]
        for kwargs, _, stage in cases:
            e = self.obs(self.tool.invoke(WORK, "inv-1", playwright_factory=factory(**kwargs)))
            self.assertEqual((e["disposition"], e["evaluation_stage"]), ("FAIL_CLOSED", stage), stage)
            self.assertTrue(e["failed_predicate"])
            self.assertEqual(e["retry_entrypoint"], "src.stegbrowser.llm_transition.execute_manifested_llm_browser_transition")
            self.assertTrue(e["terminal_receipt"]["session_state_destroyed"])
            assert_six_fields(self, e)
        stages = [r["evidence"]["attempt"] for r in self.s.observations(WORK)]
        self.assertEqual(stages, [1, 2, 3])


class RuntimeCheck(Base):
    @unittest.skipIf(__import__("importlib.util").util.find_spec("playwright") is not None,
                     "Playwright installed here; the no-runtime path is exercised where it is absent")
    def test_AT20_missing_browser_runtime_fails_closed_immediately(self):
        e = self.obs(self.tool.invoke(WORK, "inv-1"))
        self.assertEqual((e["disposition"], e["failed_predicate"], e["decided_by"]),
                         ("FAIL_CLOSED", "SANDBOX_ENVIRONMENT_PYTHON_PLAYWRIGHT_CHROMIUM_AVAILABLE", "SANDBOX_RUNTIME_CHECK"))
        self.assertFalse(e["stegbrowser_invoked"])
        assert_six_fields(self, e)


class PreInvocation(Base):
    def setUp(self):
        super().setUp(invocations=[invocation(),
                                   invocation(invocation_id="inv-off-origin", secure_url="https://elsewhere.test/chat"),
                                   invocation(invocation_id="inv-bad-fill", browser_actions=[
                                       {"op": "fill", "selector": "textarea", "value": "something else"},
                                       {"op": "read_text", "selector": "body"}])])
        self.pw = factory()

    def denied(self, out, predicate):
        e = self.obs(out)
        self.assertEqual((e["disposition"], e["failed_predicate"], e["decided_by"]),
                         ("DENY", predicate, "SANDBOX_PRE_INVOCATION"))
        self.assertFalse(e["stegbrowser_invoked"])
        self.pw.return_value.__enter__.assert_not_called()
        assert_six_fields(self, e)
        return e

    def test_AT05_AT21_origin_outside_lease(self):
        self.denied(self.tool.invoke(WORK, "inv-off-origin", playwright_factory=self.pw), "SECURE_URL_ORIGIN_ALLOWED_BY_LEASE")
        self.denied(self.tool.invoke(WORK, "inv-1", playwright_factory=self.pw,
                                     proposed={"secure_url": "https://elsewhere.test/chat"}),
                    "SECURE_URL_ORIGIN_ALLOWED_BY_LEASE")

    def test_AT21_lease_and_prompt_binding(self):
        self.denied(self.tool.invoke(WORK, "inv-1", playwright_factory=self.pw,
                                     proposed={"lease": {"task_id": "other-work", "allowed_origins": ["space.example.test"]}}),
                    "LEASE_TASK_ID_EQUALS_WORK_ID")
        self.denied(self.tool.invoke(WORK, "inv-1", playwright_factory=self.pw,
                                     proposed={"lease": {"task_id": WORK, "allowed_origins": ["*.test"]}}),
                    "LEASE_ORIGINS_EQUAL_ADMITTED_ORIGINS")
        self.denied(self.tool.invoke(WORK, "inv-1", playwright_factory=self.pw, proposed={"prompt": "substituted"}),
                    "LLM_PROMPT_BOUND_TO_MANIFESTED_REQUEST")
        self.denied(self.tool.invoke(WORK, "inv-bad-fill", playwright_factory=self.pw),
                    "LLM_PROMPT_BOUND_TO_MANIFESTED_REQUEST")

    def test_AT21_work_and_invocation_must_be_admitted(self):
        self.denied(self.tool.invoke("not-admitted", "inv-1", playwright_factory=self.pw), "WORK_ID_IS_ADMITTED")
        self.denied(self.tool.invoke(WORK, "inv-undeclared", playwright_factory=self.pw), "TOOL_INVOCATION_DECLARED")

    def test_malformed_invocation_denied_with_six_fields(self):
        h = Harness()
        self.addCleanup(h.tmp.cleanup)
        work = h.work(manifested_request={"manifest_id": "fixture-manifest-001",
                                          "tool_invocations": [invocation(lease_seconds=0)]})
        h.admit(work)
        out = StegBrowserTool(h.sandbox).invoke(WORK, "inv-1", playwright_factory=self.pw)
        e = next(r for r in h.sandbox.ledger.chain() if r["receipt_sha256"] == out["repo_receipt_sha256"])["evidence"]
        self.assertEqual((e["disposition"], e["failed_predicate"]), ("DENY", "TOOL_INVOCATION_WELL_FORMED"))
        assert_six_fields(self, e)

    def test_matching_proposal_is_allowed(self):
        out = self.tool.invoke(WORK, "inv-1", playwright_factory=factory(),
                               proposed={"prompt": invocation()["prompt"], "secure_url": "https://space.example.test/chat",
                                         "lease": {"task_id": WORK, "allowed_origins": ["space.example.test"]}})
        self.assertEqual(out["disposition"], ALLOW)


class Synthesis(Base):
    def test_AT15_observation_only_work_synthesizes_and_completes(self):
        ok = self.tool.invoke(WORK, "inv-1", playwright_factory=factory())
        bad = self.tool.invoke(WORK, "inv-1", playwright_factory=factory(fail_launch=True))
        ids = [ok["observation_id"], bad["observation_id"]]
        omitted = self.s.synthesize(WORK, ids[:1], {"summary": "drops the failure"})
        self.assertEqual((omitted["disposition"], omitted["failed_predicate"]), (DENY, "SYNTHESIS_BINDS_EVERY_RECORDED_INPUT"))
        self.assertEqual(self.s.synthesize(WORK, ids, {"summary": "one answer, one launch failure"})["disposition"], ALLOW)
        self.assertEqual(self.s.complete(WORK)["disposition"], ALLOW)  # AT-19: no Master Records predicate
        rebuilt = self.s.reconstruct(WORK)
        self.assertEqual(sorted(rebuilt["observations"]), sorted(ids))
        self.assertEqual(rebuilt["contributions"], [])

    def test_pre_invocation_deny_is_a_synthesis_input(self):
        d = self.tool.invoke(WORK, "inv-undeclared", playwright_factory=factory())
        self.assertEqual(d["disposition"], DENY)
        self.assertEqual(self.s.synthesize(WORK, [d["observation_id"]], {"summary": "denied"})["disposition"], ALLOW)


class PropagationFailure(Base):
    def setUp(self):
        super().setUp(propagate_fails=True)

    def test_AT18_failure_is_recorded_and_blocks_completion_until_recovered(self):
        self.fail_org = False
        # admission happened in Base.setUp with fail_org True -> it is pending
        pending = self.s.pending_propagation(WORK)
        self.assertEqual(len(pending), 1)
        failure = next(r for r in self.s.ledger.chain() if r["transition_class"] == "ORGANIZATION_PROPAGATION_FAILED")
        self.assertEqual(failure["evidence"]["disposition"], "FAIL_CLOSED")
        self.assertEqual(failure["evidence"]["failed_predicate"], "ORGANIZATION_PROPAGATION_SUCCEEDED")
        self.assertEqual(failure["evidence"]["retry_entrypoint"], "runtime.sandbox.Sandbox.repropagate")
        obs = self.tool.invoke(WORK, "inv-1", playwright_factory=factory())
        self.assertEqual(self.s.synthesize(WORK, [obs["observation_id"]], {"s": 1})["disposition"], ALLOW)
        blocked = self.s.complete(WORK)
        self.assertEqual((blocked["disposition"], blocked["failed_predicate"]), (DENY, "ORGANIZATION_PROPAGATION_COMPLETE"))
        recovered = self.s.repropagate(pending[0])
        self.assertEqual(recovered["disposition"], ALLOW)
        self.assertIn("org_receipt_sha256", recovered)
        self.assertEqual(self.s.pending_propagation(WORK), [])
        self.assertEqual(self.s.complete(WORK)["disposition"], ALLOW)

    def test_AT18_failed_call_returns_fail_closed_without_org_receipt(self):
        self.fail_org = True
        out = self.tool.invoke(WORK, "inv-1", playwright_factory=factory())
        self.assertEqual((out["disposition"], out["failed_predicate"]), ("FAIL_CLOSED", "ORGANIZATION_PROPAGATION_SUCCEEDED"))
        self.assertEqual(out["recorded_disposition"], ALLOW)
        self.assertNotIn("org_receipt_sha256", out)
        self.assertEqual(self.s.repropagate("sha256:" + "0" * 64)["failed_predicate"], "RECEIPT_PROPAGATION_PENDING")


if __name__ == "__main__":
    unittest.main(verbosity=2)
