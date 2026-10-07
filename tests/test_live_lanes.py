"""AT-04 Stage 1 live lanes: conformance vs authentic organization-ledger evidence (no network).

Conformance: workflow-local ledger, fixture parent, never authoritative.

Authentic (SV-LLM-ORGANIZATION-ROLE-EXACT-STEGVERSE-ORG-DUPLICATION-001): the
organization ledger is bound exactly as the StegVerse-org reference binds it,
PosixLedgerStore(ledger_root()), inside SV-LLM organization execution only
(GITHUB_REPOSITORY). These tests reproduce the organization workflow's single
run offline: one ledger root, crossing.open_organization_ledger (explicit
GENESIS), crossing.record (authentic parent), then the lane. They also check
each refusal in its fixed order and the red exit on every non-ALLOW. The
browser is an injected Playwright mock.

Run: SV_LLM_DOTGITHUB_ROOT=<SV-LLM/.github checkout> python -B tests/test_live_lanes.py
"""
from __future__ import annotations
import contextlib, importlib.util, io, json, os, sys, tempfile, unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests"))
sys.path.insert(0, str(ROOT / "live"))
from test_stegbrowser_tool import factory  # noqa: E402
import run_live_llm as live  # noqa: E402

DOTGITHUB = Path(os.environ["SV_LLM_DOTGITHUB_ROOT"]).resolve()
TARGET = json.loads((ROOT / "live/target.json").read_text())
REPLY = TARGET["response_marker"] + ": a reply."
ORG = "SV-LLM/.github"
LANE_OUTCOME = {"disposition": "ALLOW", "intended_action": "STEGBROWSER_LIVE_PATH_CONFORMANCE",
                "target_id": TARGET["target_id"]}


def load_crossing():
    sys.path.insert(0, str(DOTGITHUB / "org-runtime"))
    spec = importlib.util.spec_from_file_location("sv_llm_crossing", DOTGITHUB / "org-runtime/crossing.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class LaneCase(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.tmp = Path(tmp.name)
        self.evidence = self.tmp / "evidence"
        # One execution-scoped root for the whole simulated organization run.
        self.org_env = {"STEGVERSE_ORG_LEDGER_ROOT": str(self.tmp / "org-ledger"),
                        "STEGVERSE_REPO_LEDGER_ROOT": str(self.tmp / "dotgithub-repo-ledger")}

    def run_lane(self, lane, *, parent=None, argv=(), playwright=None, repository=ORG):
        env = {"SV_LLM_DOTGITHUB_ROOT": str(DOTGITHUB), "EVIDENCE_DIR": str(self.evidence), "LIVE_LANE": lane,
               "STEGVERSE_ORG_LEDGER_ROOT": self.org_env["STEGVERSE_ORG_LEDGER_ROOT"]}
        with mock.patch.dict(os.environ, env), contextlib.redirect_stdout(io.StringIO()):
            os.environ.pop("GITHUB_REPOSITORY", None)
            os.environ.pop("PARENT_ORG_RECEIPT_SHA256", None)
            if repository is not None:
                os.environ["GITHUB_REPOSITORY"] = repository
            if parent is not None:
                os.environ["PARENT_ORG_RECEIPT_SHA256"] = parent
            code = live.main(list(argv), playwright_factory=playwright or factory(text=REPLY))
        report = json.loads((self.evidence / "report.json").read_text())
        digests = json.loads((self.evidence / "digests.json").read_text())
        return code, report, digests

    def organization(self, *, outcome=LANE_OUTCOME, open_ledger=True, parent=True):
        """The organization workflow's steps before the lane, in the same ledger root."""
        with mock.patch.dict(os.environ, self.org_env), contextlib.redirect_stdout(io.StringIO()):
            crossing = load_crossing()
            opened = crossing.open_organization_ledger(DOTGITHUB) if open_ledger else None
            recorded = crossing.record("ORGANIZATION_INGRESS_MATERIALIZED", subject={"intended_action": "AUTHENTIC_PARENT"},
                                       outcome=outcome, root=DOTGITHUB) if parent else None
        agg = live.load_dotgithub(DOTGITHUB)
        return agg, agg.PosixLedgerStore(Path(self.org_env["STEGVERSE_ORG_LEDGER_ROOT"])), opened, recorded

    def assertRefused(self, predicate, detail=None, **kw):
        with mock.patch.object(live.subprocess, "run", side_effect=AssertionError("emit.py must not run")):
            code, report, digests = self.run_lane(live.AUTHENTIC, **kw)
        self.assertEqual(code, 1)
        self.assertEqual((report["disposition"], report["failed_predicate"]), ("FAIL_CLOSED", predicate))
        self.assertEqual(report.get("detail"), detail)
        self.assertEqual(report["retry_entrypoint"], live.RETRY_ENTRYPOINT)
        self.assertTrue(report["required_evidence_or_repair"] and report["next_attempt"])
        self.assertIs(digests["authoritative_organization_runtime_reality"], False)
        self.assertEqual(report["evidence_class"], "AUTHENTIC_SV_LLM_ORGANIZATION_LEDGER_RUNTIME_EVIDENCE")
        self.assertEqual(report["ledger_persistence"], "EXECUTION_SCOPED_SAME_AS_REFERENCE")
        self.assertFalse((self.evidence / "sv-llm-org-ledger").exists())
        self.assertFalse((self.evidence / "dotgithub-fixture-ledger").exists())
        self.assertFalse(report["live_path_exercised"])
        return report


class Conformance(LaneCase):
    def test_labels_genesis_from_head_and_keyed_readback(self):
        code, report, digests = self.run_lane(live.CONFORMANCE)
        self.assertEqual(code, 0, report)
        self.assertEqual((report["disposition"], report["completion"]), ("ALLOW", "ALLOW"))
        for doc in (report, digests):
            self.assertEqual(doc["evidence_class"], "WORKFLOW_LOCAL_ORGANIZATION_LEDGER_CONFORMANCE")
            self.assertIs(doc["authoritative_organization_runtime_reality"], False)
            self.assertEqual(doc["retention_class"], "LIVE_RUN_EVIDENCE_RETENTION_NOT_PERMANENT_CUSTODY")
            self.assertEqual(doc["lane"], "conformance")
        self.assertEqual(report["ledger_persistence"], "WORKFLOW_LOCAL_CONFORMANCE_ONLY")
        self.assertEqual(report["parent_transition_basis"], "WORKFLOW_LOCAL_SV_LLM_DOTGITHUB_EMIT_FIXTURE")
        self.assertEqual(report["authority_effect"], "NONE")
        self.assertEqual(report["org_readback"], "EXACT_KEYED_READBACK_PASS")
        agg = live.load_dotgithub(DOTGITHUB)
        store = agg.PosixLedgerStore(self.evidence / "sv-llm-org-ledger")
        receipts = [store.get(agg.receipt_key(d)) for d in report["org_receipts"]]
        self.assertIs(receipts[0]["chain_genesis"], True)
        for previous, receipt in zip(receipts, receipts[1:]):
            self.assertNotIn("chain_genesis", receipt)
            self.assertEqual(receipt["predecessor_org_state_sha256"], previous["receipt_sha256"])
        self.assertEqual(len(store.list_prefix(agg.SOURCE_PREFIX)), len(receipts))

    def test_keyed_readback_detects_tampering(self):
        self.run_lane(live.CONFORMANCE)
        agg = live.load_dotgithub(DOTGITHUB)
        store = agg.PosixLedgerStore(self.evidence / "sv-llm-org-ledger")
        digest = json.loads((self.evidence / "report.json").read_text())["org_receipts"][-1]
        org = store.get(agg.receipt_key(digest))
        source = store.get(agg.source_key(org["source_transition_sha256"]))
        self.assertIsNone(live.keyed_readback(agg, store, org, source))
        self.assertEqual(live.keyed_readback(agg, store, {**org, "authority_effect": "X"}, source), "ORG_RECEIPT_EXACT_READBACK")
        self.assertEqual(live.keyed_readback(agg, store, org, {**source, "evidence": {}}), "SOURCE_RECEIPT_RETAINED")

    def test_failed_browser_run_is_red(self):
        code, report, _ = self.run_lane(live.CONFORMANCE, playwright=factory(fail_launch=True))
        self.assertEqual(code, 1)
        self.assertNotEqual(report["disposition"], "ALLOW")
        self.assertIs(report["authoritative_organization_runtime_reality"], False)

    def test_undeclared_lane_fails_closed(self):
        code, report, _ = self.run_lane("other")
        self.assertEqual((code, report["disposition"], report["failed_predicate"]), (1, "FAIL_CLOSED", "LIVE_LANE_DECLARED"))


class AuthenticRefusals(LaneCase):
    def test_outside_organization_execution_is_refused_first(self):
        for repository in (None, "SV-LLM/sandbox", "StegVerse-org/.github"):
            report = self.assertRefused("AUTHENTIC_LANE_NOT_ORGANIZATION_EXECUTION", repository=repository)
            self.assertEqual(report["executed_by"], repository)
        self.assertFalse(Path(self.org_env["STEGVERSE_ORG_LEDGER_ROOT"]).exists())

    def test_unopened_ledger_is_reported_before_the_parent(self):
        report = self.assertRefused("ORG_LEDGER_GENESIS_NOT_DECLARED", parent="sha256:" + "a" * 64)
        self.assertIn("open_organization_ledger", report["required_evidence_or_repair"])
        self.assertEqual(report["executed_by"], ORG)

    def test_missing_or_malformed_parent_claim(self):
        self.organization(parent=False)
        self.assertRefused("AUTHENTIC_PARENT_TRANSITION_NOT_IN_AUTHORITATIVE_STORE", "PARENT_DIGEST_MISSING_OR_MALFORMED")
        self.assertRefused("AUTHENTIC_PARENT_TRANSITION_NOT_IN_AUTHORITATIVE_STORE",
                           "PARENT_DIGEST_MISSING_OR_MALFORMED", parent="not-a-digest")

    def test_parent_not_in_ledger(self):
        self.organization(parent=False)
        self.assertRefused("AUTHENTIC_PARENT_TRANSITION_NOT_IN_AUTHORITATIVE_STORE", "ORG_RECEIPT_NOT_PRESENT",
                           parent="sha256:" + "b" * 64)

    def test_parent_without_retained_source(self):
        agg, store, _, recorded = self.organization()
        org = store.get(agg.receipt_key(recorded["org_receipt_sha256"]))
        (store.root / agg.source_key(org["source_transition_sha256"])).unlink()
        self.assertRefused("AUTHENTIC_PARENT_TRANSITION_NOT_IN_AUTHORITATIVE_STORE", "SOURCE_RECEIPT_NOT_PRESENT",
                           parent=recorded["org_receipt_sha256"])

    def test_parent_with_malformed_retained_source(self):
        agg, store, _, recorded = self.organization()
        org = store.get(agg.receipt_key(recorded["org_receipt_sha256"]))
        store.put(agg.source_key(org["source_transition_sha256"]), {"schema": "not-a-receipt"})
        self.assertRefused("AUTHENTIC_PARENT_TRANSITION_NOT_IN_AUTHORITATIVE_STORE", "SOURCE_RECEIPT_NOT_PRESENT",
                           parent=recorded["org_receipt_sha256"])

    def test_parent_subject_must_name_this_lane(self):
        for change in ({"target_id": "another.target"}, {"intended_action": "SOMETHING_ELSE"}, {"disposition": "DENY"}):
            with self.subTest(change=change):
                self.setUp()
                _, _, _, recorded = self.organization(outcome={**LANE_OUTCOME, **change})
                self.assertRefused("AUTHENTIC_PARENT_SUBJECT_MISMATCH", parent=recorded["org_receipt_sha256"])

    def test_sandbox_workflow_offers_conformance_only(self):
        text = (ROOT / ".github/workflows/sandbox-live-llm.yml").read_text()
        triggers = text.split("\non:\n", 1)[1].split("\npermissions:", 1)[0]
        self.assertEqual(triggers.strip(), "workflow_dispatch:")  # no lane or parent inputs
        self.assertIn("      LIVE_LANE: conformance\n", text)
        self.assertNotIn("PARENT_ORG_RECEIPT_SHA256:", text)
        self.assertNotIn("--preflight", text)


class SingleOrganizationRun(LaneCase):
    def test_preflight_passes_inside_the_organization_run(self):
        _, _, _, recorded = self.organization()
        code, report, _ = self.run_lane(live.AUTHENTIC, parent=recorded["org_receipt_sha256"], argv=["--preflight"])
        self.assertEqual((code, report["disposition"], report["preflight"]),
                         (0, "ALLOW", "ORGANIZATION_EXECUTION_LEDGER_OPENED_PARENT_AND_SUBJECT_PRESENT"))
        self.assertIs(report["authoritative_organization_runtime_reality"], False)

    def test_open_ledger_record_parent_then_lane_in_one_root(self):
        agg, store, opened, recorded = self.organization()
        calls = []
        real = agg.aggregate_transition

        def spy(*a, **kw):
            calls.append(kw.get("genesis", False))
            return real(*a, **kw)
        with mock.patch.object(live, "load_dotgithub", return_value=agg), \
                mock.patch.object(agg, "aggregate_transition", side_effect=spy), \
                mock.patch.object(live.subprocess, "run", side_effect=AssertionError("emit.py must not run")):
            code, report, digests = self.run_lane(live.AUTHENTIC, parent=recorded["org_receipt_sha256"])
        self.assertEqual(code, 0, report)
        self.assertEqual((report["admitted"], report["disposition"], report["synthesis"], report["completion"]),
                         ("ALLOW", "ALLOW", "ALLOW", "ALLOW"))
        self.assertTrue(calls and not any(calls), calls)
        self.assertEqual(report["org_readback"], "EXACT_KEYED_READBACK_PASS")
        self.assertEqual((report["executed_by"], report["ledger_persistence"]), (ORG, "EXECUTION_SCOPED_SAME_AS_REFERENCE"))
        self.assertEqual(report["parent_transition_basis"], "AUTHORITATIVE_STORE_EXACT_KEYED_READBACK")
        self.assertIs(digests["authoritative_organization_runtime_reality"], True)
        self.assertFalse((self.evidence / "sv-llm-org-ledger").exists())
        genesis = store.get(agg.receipt_key(opened["org_receipt_sha256"]))
        self.assertIs(genesis["chain_genesis"], True)
        first = store.get(agg.receipt_key(report["org_receipts"][0]))
        self.assertEqual(first["predecessor_org_state_sha256"], recorded["org_receipt_sha256"])
        self.assertEqual(store.get(agg.HEAD_KEY)["receipt_sha256"], report["org_receipts"][-1])
        self.assertEqual(len(store.list_prefix(agg.RECEIPT_PREFIX)), 2 + len(report["org_receipts"]))


if __name__ == "__main__":
    unittest.main()
