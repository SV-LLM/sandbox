"""AT-04 Stage 1 live lanes: conformance vs authentic organization-ledger evidence (no network).

SV-LLM-LIVE-LEDGER-EVIDENCE-SPLIT-001, P1-P6 with C1-C3: evidence labels per
lane, exact keyed readback, the three authentic refusals in their fixed order,
red exit on every non-ALLOW, and no fixture parent or workflow-local ledger in
the authentic lane. The browser is an injected Playwright mock.

Run: SV_LLM_DOTGITHUB_ROOT=<SV-LLM/.github checkout> python -B tests/test_live_lanes.py
"""
from __future__ import annotations
import contextlib, io, json, os, shutil, subprocess, sys, tempfile, unittest
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
TEST_KIND = "test-durable-store"  # test-only binder; production STORE_BINDERS is empty


class LaneCase(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.tmp = Path(tmp.name)
        self.evidence = self.tmp / "evidence"
        self.dotgithub = DOTGITHUB
        self.binders = mock.patch.dict(live.STORE_BINDERS, {}, clear=True)
        self.binders.start()
        self.addCleanup(self.binders.stop)

    def run_lane(self, lane, *, parent=None, argv=(), playwright=None):
        env = {"SV_LLM_DOTGITHUB_ROOT": str(self.dotgithub), "EVIDENCE_DIR": str(self.evidence), "LIVE_LANE": lane}
        if parent is not None:
            env["PARENT_ORG_RECEIPT_SHA256"] = parent
        with mock.patch.dict(os.environ, env), contextlib.redirect_stdout(io.StringIO()):
            code = live.main(list(argv), playwright_factory=playwright or factory(text=REPLY))
        report = json.loads((self.evidence / "report.json").read_text())
        digests = json.loads((self.evidence / "digests.json").read_text())
        return code, report, digests

    def declare(self, declaration):
        """A private SV-LLM/.github copy whose org-contract declares the given store."""
        copy = self.tmp / "dotgithub"
        shutil.copytree(DOTGITHUB, copy, ignore=shutil.ignore_patterns(".git", "__pycache__"))
        path = copy / ".stegverse/transition-ledger/org-contract.json"
        contract = json.loads(path.read_text())
        contract["authoritative_ledger_store"] = declaration
        path.write_text(json.dumps(contract, indent=2))
        self.dotgithub = copy
        return copy

    def bindable_store(self):
        root = self.tmp / "authoritative-store"
        self.declare({"kind": TEST_KIND, "locator": "test://authoritative"})
        agg = live.load_dotgithub(self.dotgithub)
        live.STORE_BINDERS[TEST_KIND] = lambda locator: agg.PosixLedgerStore(root)
        return agg, agg.PosixLedgerStore(root)

    def authentic_parent_for_target(self):
        """An SV-LLM/.github repo receipt for this target's subject (test parent; never used by the runner)."""
        subject = {"intended_action": "STEGBROWSER_LIVE_PATH_CONFORMANCE", "target_id": TARGET["target_id"]}
        sys.path.insert(0, str(ROOT / "runtime"))
        from ledger import sha
        out = subprocess.run([sys.executable, str(self.dotgithub / ".stegverse/transition-ledger/emit.py"),
                              "--transition-id", "AUTHENTIC_PARENT_FIXTURE", "--transition-class", "ORGANIZATION_INGRESS_MATERIALIZED",
                              "--predecessor-state-sha256", sha({"p": 1}), "--successor-state-sha256", sha(subject),
                              "--evidence-json", json.dumps({"disposition": "ALLOW"})],
                             capture_output=True, text=True, check=True,
                             env=dict(os.environ, STEGVERSE_REPO_LEDGER_ROOT=str(self.tmp / "parent-repo-ledger")))
        return json.loads(out.stdout)


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


class AuthenticBinding(LaneCase):
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
        self.assertFalse((self.evidence / "sv-llm-org-ledger").exists())
        self.assertFalse((self.evidence / "dotgithub-fixture-ledger").exists())
        self.assertFalse(report["live_path_exercised"])
        return report

    def test_current_contract_declares_no_store(self):
        contract = json.loads((DOTGITHUB / ".stegverse/transition-ledger/org-contract.json").read_text())
        self.assertNotIn("authoritative_ledger_store", contract)
        self.assertRefused("AUTHENTIC_ORGANIZATION_LEDGER_STORE_NOT_MATERIALIZED", "ABSENT")

    def test_environment_root_is_never_the_binding(self):
        with mock.patch.dict(os.environ, {"STEGVERSE_ORG_LEDGER_ROOT": str(self.tmp / "env-root")}):
            report = self.assertRefused("AUTHENTIC_ORGANIZATION_LEDGER_STORE_NOT_MATERIALIZED", "ABSENT")
        self.assertFalse((self.tmp / "env-root").exists(), report)

    def test_malformed_declaration(self):
        self.declare({"kind": TEST_KIND})
        self.assertRefused("AUTHENTIC_ORGANIZATION_LEDGER_STORE_NOT_MATERIALIZED", "MALFORMED")

    def test_posix_root_rejected(self):
        self.declare({"kind": "posix", "locator": str(self.tmp / "posix")})
        self.assertRefused("AUTHENTIC_ORGANIZATION_LEDGER_STORE_NOT_MATERIALIZED", "POSIX_ROOT_REJECTED")

    def test_kind_not_implemented(self):
        self.declare({"kind": "some-durable-store", "locator": "store://sv-llm"})
        self.assertRefused("AUTHENTIC_ORGANIZATION_LEDGER_STORE_NOT_MATERIALIZED", "KIND_NOT_IMPLEMENTED")


class AuthenticOrder(LaneCase):
    def test_unopened_ledger_is_reported_before_the_parent(self):
        self.bindable_store()
        report = AuthenticBinding.assertRefused(self, "ORG_LEDGER_GENESIS_NOT_DECLARED", parent="sha256:" + "a" * 64)
        self.assertIn("open_organization_ledger", report["required_evidence_or_repair"])

    def opened(self):
        agg, store = self.bindable_store()
        repo = self.authentic_parent_for_target()
        parent = agg.aggregate_transition(repo, org_transition_class="ORGANIZATION_INGRESS_MATERIALIZED", genesis=True, store=store)
        return agg, store, parent

    def test_missing_or_malformed_parent_claim(self):
        self.opened()
        AuthenticBinding.assertRefused(self, "AUTHENTIC_PARENT_TRANSITION_NOT_IN_AUTHORITATIVE_STORE", "PARENT_DIGEST_MISSING_OR_MALFORMED")
        AuthenticBinding.assertRefused(self, "AUTHENTIC_PARENT_TRANSITION_NOT_IN_AUTHORITATIVE_STORE",
                                       "PARENT_DIGEST_MISSING_OR_MALFORMED", parent="not-a-digest")

    def test_parent_not_in_store(self):
        self.opened()
        AuthenticBinding.assertRefused(self, "AUTHENTIC_PARENT_TRANSITION_NOT_IN_AUTHORITATIVE_STORE",
                                       "ORG_RECEIPT_NOT_PRESENT", parent="sha256:" + "b" * 64)

    def test_parent_without_retained_source(self):
        agg, store, parent = self.opened()
        (store.root / agg.source_key(parent["source_transition_sha256"])).unlink()
        AuthenticBinding.assertRefused(self, "AUTHENTIC_PARENT_TRANSITION_NOT_IN_AUTHORITATIVE_STORE",
                                       "SOURCE_RECEIPT_NOT_PRESENT", parent=parent["receipt_sha256"])

    def test_parent_with_malformed_retained_source(self):
        agg, store, parent = self.opened()
        store.put(agg.source_key(parent["source_transition_sha256"]), {"schema": "not-a-receipt"})
        AuthenticBinding.assertRefused(self, "AUTHENTIC_PARENT_TRANSITION_NOT_IN_AUTHORITATIVE_STORE",
                                       "SOURCE_RECEIPT_NOT_PRESENT", parent=parent["receipt_sha256"])

    def test_preflight_passes_when_bound_opened_and_parent_present(self):
        _, _, parent = self.opened()
        code, report, _ = self.run_lane(live.AUTHENTIC, parent=parent["receipt_sha256"], argv=["--preflight"])
        self.assertEqual((code, report["disposition"], report["preflight"]),
                         (0, "ALLOW", "AUTHENTIC_STORE_BOUND_AND_PARENT_PRESENT"))
        self.assertIs(report["authoritative_organization_runtime_reality"], False)

    def test_full_authentic_run_uses_from_head_and_no_fixture(self):
        agg, store, parent = self.opened()
        calls = []
        real = agg.aggregate_transition

        def spy(*a, **kw):
            calls.append(kw.get("genesis", False))
            return real(*a, **kw)
        with mock.patch.object(live, "load_dotgithub", return_value=agg), \
                mock.patch.object(agg, "aggregate_transition", side_effect=spy), \
                mock.patch.object(live.subprocess, "run", side_effect=AssertionError("emit.py must not run")):
            code, report, digests = self.run_lane(live.AUTHENTIC, parent=parent["receipt_sha256"])
        self.assertEqual(code, 0, report)
        self.assertTrue(calls and not any(calls), calls)
        self.assertEqual(report["org_readback"], "EXACT_KEYED_READBACK_PASS")
        self.assertEqual(report["parent_transition_basis"], "AUTHORITATIVE_STORE_EXACT_KEYED_READBACK")
        self.assertIs(digests["authoritative_organization_runtime_reality"], True)
        self.assertFalse((self.evidence / "sv-llm-org-ledger").exists())
        head = store.get(agg.HEAD_KEY)["receipt_sha256"]
        self.assertEqual(head, report["org_receipts"][-1])
        first = store.get(agg.receipt_key(report["org_receipts"][0]))
        self.assertEqual(first["predecessor_org_state_sha256"], parent["receipt_sha256"])


if __name__ == "__main__":
    unittest.main()
