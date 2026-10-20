"""G4 / NWI-S1: a Sandbox receipt carries the supplied epoch, never the wall clock.

SV_LLM_LEDGER_APPEND_CLOCK_FALLBACK, SUBMISSION_CARRIES_THE_SUPPLIED_HB_EPOCH,
owning_existing_goal SVORG-LLM-ORG-FOUNDATION-001 W04. runtime/ledger.py wrote
`observed_at` from datetime.now(), and WorkCycle._propagate passed no epoch to
the organization ledger. A missing or invalid epoch is now a six-field
FAIL_CLOSED from the vendored shared rule (sha256 726248a5); nothing is written.

Run: SV_LLM_DOTGITHUB_ROOT=<SV-LLM/.github checkout> python -B tests/test_ledger_supplied_epoch.py
"""
from __future__ import annotations
import ast, contextlib, hashlib, importlib.util, io, json, os, subprocess, sys, tempfile, unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
DOTGITHUB = Path(os.environ["SV_LLM_DOTGITHUB_ROOT"]).resolve()
sys.path.insert(0, str(ROOT / "runtime"))
import ledger  # noqa: E402
from work_cycle import WorkCycle  # noqa: E402

SIX = ("failure_code", "failed_predicate", "required_evidence_or_repair", "retry_entrypoint",
       "owning_existing_goal", "next_attempt")
MALFORMED = ("+33", " 33", "33 ", "3_3", "31", "0", "", "x", "٣٣", 31, -40, 33.0, True)
SUCCESSOR = "sha256:" + "b" * 64
PREDECESSOR = "sha256:" + "a" * 64


def files(root):
    return sorted(str(p.relative_to(root)) for p in Path(root).rglob("*") if p.is_file()) if Path(root).exists() else []


class SharedRule(unittest.TestCase):
    def test_the_vendored_rule_is_the_shared_segment(self):
        text = (ROOT / "runtime/ledger.py").read_text()
        [node] = [n for n in ast.parse(text).body if getattr(n, "name", None) == "supplied_epoch_failure"]
        segment = "\n".join(text.splitlines()[node.lineno - 1:node.end_lineno]).rstrip()
        self.assertEqual(hashlib.sha256(segment.encode()).hexdigest(), ledger.SHARED_RULE_SHA256)
        self.assertTrue(ledger.SHARED_RULE_SHA256.startswith("726248a5"))

    def test_the_ledger_reads_no_clock(self):
        text = (ROOT / "runtime/ledger.py").read_text()
        for clock in ("datetime", "time.time", "time_ns", "monotonic"):
            self.assertNotIn(clock, text)


class SandboxLedgerAppend(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name) / "ledger"

    def refused(self, epoch, code, **kw):
        with mock.patch("time.time", side_effect=AssertionError("clock read")):
            with self.assertRaises(ledger.LedgerEpochRefused) as caught:
                ledger.Ledger(self.root, **kw).append("SANDBOX_WORK_ADMITTED", predecessor=PREDECESSOR,
                                                      successor=SUCCESSOR, evidence={}, hb_epoch=epoch)
        refusal = caught.exception.refusal
        self.assertEqual(refusal["disposition"], "FAIL_CLOSED")
        self.assertTrue(all(refusal.get(field) for field in SIX), refusal)
        self.assertEqual((refusal["failure_code"], refusal["failed_predicate"], refusal["failure_class"]),
                         (code, "SUBMISSION_CARRIES_THE_SUPPLIED_HB_EPOCH", "SV_LLM_LEDGER_APPEND_CLOCK_FALLBACK"))
        self.assertEqual(refusal["owning_existing_goal"], "SVORG-LLM-ORG-FOUNDATION-001 W04")
        self.assertIn("WorkCycle._propagate", refusal["retry_entrypoint"])
        self.assertEqual(files(self.root), [])

    def test_a_missing_epoch_is_refused_and_nothing_is_written(self):
        self.refused(None, "HB_EPOCH_NOT_SUPPLIED")

    def test_a_malformed_or_pre_anchor_epoch_is_refused(self):
        for epoch in MALFORMED:
            with self.subTest(epoch=epoch):
                self.refused(epoch, "HB_EPOCH_INVALID")
                self.refused(None, "HB_EPOCH_INVALID", hb_epoch=epoch)  # supplied to the ledger instead

    def test_a_moving_clock_does_not_move_the_receipt(self):
        receipts = []
        for index, clock in enumerate((1_000.0, 9_999_999.0)):
            with mock.patch("time.time", return_value=clock), mock.patch("time.time_ns", return_value=int(clock * 1e9)):
                receipts.append(ledger.Ledger(self.root / str(index), hb_epoch="4000").append(
                    "SANDBOX_WORK_ADMITTED", predecessor=PREDECESSOR, successor=SUCCESSOR, evidence={}))
        self.assertEqual(receipts[0], receipts[1])
        self.assertEqual(receipts[0]["observed_at"], "SUPPLIED_HB_EPOCH:4000")
        self.assertEqual(receipts[0]["hb_reference"]["epoch"], 4000)
        self.assertIs(receipts[0]["hb_reference"]["derived_from_clock"], False)


class WorkCycleCarriesTheEpoch(unittest.TestCase):
    def cycle(self, tmp, epoch):
        return WorkCycle(dotgithub=DOTGITHUB, sandbox_ledger=Path(tmp) / "sandbox-ledger",
                         node_state_root=Path(tmp) / "node-state", hb_epoch=epoch)

    def test_propagate_passes_the_supplied_epoch(self):
        with tempfile.TemporaryDirectory() as tmp:
            cycle = self.cycle(tmp, "4000")
            cycle.agg = mock.Mock()
            cycle._propagate({"receipt_sha256": "sha256:" + "c" * 64}, "SANDBOX_WORK_ADMITTED")
            self.assertEqual(cycle.agg.aggregate_transition.call_args.kwargs["hb_epoch"], "4000")

    def test_propagate_without_an_epoch_is_refused_by_the_organization_ledger(self):
        with tempfile.TemporaryDirectory() as tmp, mock.patch.dict(os.environ, {
                "STEGVERSE_ORG_LEDGER_ROOT": str(Path(tmp) / "org"),
                "STEGVERSE_REPO_LEDGER_ROOT": str(Path(tmp) / "repo")}):
            cycle = self.cycle(tmp, None)
            receipt = ledger.Ledger(Path(tmp) / "source", hb_epoch=4000).append(
                "SANDBOX_WORK_ADMITTED", predecessor=PREDECESSOR, successor=SUCCESSOR, evidence={})
            with self.assertRaises(cycle.agg.OrgLedgerEpochRefused) as caught:
                cycle._propagate(receipt, "SANDBOX_WORK_ADMITTED")
            self.assertEqual(caught.exception.refusal["failure_code"], "HB_EPOCH_NOT_SUPPLIED")
            self.assertEqual(files(Path(tmp) / "org"), [])

    def test_the_cli_refuses_six_field(self):
        with tempfile.TemporaryDirectory() as tmp:
            for extra, code in (([], "HB_EPOCH_NOT_SUPPLIED"), (["--hb-epoch", "3_3"], "HB_EPOCH_INVALID")):
                with self.subTest(extra=extra):
                    run = subprocess.run([sys.executable, "-B", str(ROOT / "runtime/work_cycle.py"),
                                          "--dotgithub", str(DOTGITHUB), "--mesh-root", tmp + "/mesh",
                                          "--node-state-root", tmp + "/node", "--sandbox-ledger", tmp + "/ledger",
                                          "--standing", tmp + "/standing.json", *extra],
                                         capture_output=True, text=True)
                    self.assertEqual(run.returncode, 1, run.stderr)
                    refusal = json.loads(run.stdout)
                    self.assertEqual(refusal["failure_code"], code)
                    self.assertTrue(all(refusal.get(field) for field in SIX))
                    self.assertEqual(files(tmp), [])


class LiveRunnerRequiresTheEpoch(unittest.TestCase):
    def test_a_live_run_without_hb_epoch_is_refused_before_any_ledger(self):
        spec = importlib.util.spec_from_file_location("g4_live", ROOT / "live/run_live_llm.py")
        live = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(live)
        with tempfile.TemporaryDirectory() as tmp:
            env = {"SV_LLM_DOTGITHUB_ROOT": str(DOTGITHUB), "EVIDENCE_DIR": tmp + "/evidence", "HB_EPOCH": "+33"}
            with mock.patch.dict(os.environ, env), contextlib.redirect_stdout(io.StringIO()), \
                    mock.patch.object(live.subprocess, "run", side_effect=AssertionError("emit.py must not run")):
                os.environ.pop("LIVE_LANE", None)
                code = live.main([])
            report = json.loads((Path(tmp) / "evidence/report.json").read_text())
            self.assertEqual((code, report["disposition"], report["failure_code"]), (1, "FAIL_CLOSED", "HB_EPOCH_INVALID"))
            self.assertTrue(all(report.get(field) for field in SIX))
            self.assertFalse((Path(tmp) / "evidence/sandbox-repo-ledger").exists())


if __name__ == "__main__":
    unittest.main()
