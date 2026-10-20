"""Lease time from the supplied hb_epoch: no clock read anywhere on the lease path (NWI-S1).

Covers runtime/stegbrowser_tool.py (issue), runtime/page_load_tool.py (issue and
open), and the vendored runtime/vendor/stegbrowser_llm/ecosystem_ephemeral.py
fallbacks (validate/open/authorize/close), whose bytes stay the pinned upstream
bytes. A missing or invalid epoch is a six-field FAIL_CLOSED before any lease or
browser; with a supplied epoch every clock may move and the observation is
byte-identical.

Run: SV_LLM_DOTGITHUB_ROOT=<SV-LLM/.github checkout> python -B tests/test_lease_time_supplied_epoch.py
"""
from __future__ import annotations
import ast, datetime as _dt, hashlib, json, sys, time, unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests"))
import test_stegbrowser_tool as sbt  # noqa: E402
import test_page_load_tool as plt  # noqa: E402
import lease_time  # noqa: E402

EPOCH = "4000"
VENDORED = ROOT / "runtime/vendor/stegbrowser_llm/ecosystem_ephemeral.py"


class _MovedClock(_dt.datetime):
    @classmethod
    def now(cls, tz=None):
        return _dt.datetime(2099, 1, 1, tzinfo=tz)

    @classmethod
    def utcnow(cls):
        return _dt.datetime(2099, 1, 1)


def moved_clocks():
    return [mock.patch.object(time, "time", return_value=4_102_444_800.0),
            mock.patch.object(time, "time_ns", return_value=4_102_444_800 * 10**9),
            mock.patch.object(_dt, "datetime", _MovedClock)]


def strip_ids(obs):
    return json.dumps(obs, sort_keys=True)


class LeaseTimeSource(unittest.TestCase):
    def test_the_instant_is_the_hb32_lattice_and_needs_no_clock(self):
        self.assertEqual(lease_time.instant("32"), lease_time.instant(32))
        self.assertEqual(lease_time.instant(132) - lease_time.instant(32), _dt.timedelta(seconds=1))
        self.assertEqual(lease_time.instant(32).timestamp() * 10**9, lease_time.HB_ANCHOR_UNIX_NS)

    def test_missing_or_invalid_epochs_refuse_with_six_fields(self):
        for epoch, code in ((None, "HB_EPOCH_NOT_SUPPLIED"), ("31", "HB_EPOCH_INVALID"), ("+40", "HB_EPOCH_INVALID"),
                            (True, "HB_EPOCH_INVALID"), ("٤٠", "HB_EPOCH_INVALID")):
            with self.subTest(epoch=epoch), self.assertRaises(lease_time.LeaseTimeRefused) as cm:
                lease_time.instant(epoch)
            r = cm.exception.refusal
            self.assertEqual((r["disposition"], r["failure_code"]), ("FAIL_CLOSED", code))
            for f in ("failure_code", "failed_predicate", "required_evidence_or_repair", "retry_entrypoint",
                      "owning_existing_goal", "next_attempt"):
                self.assertTrue(r[f], f)

    def test_the_vendored_fallback_reads_the_supplied_instant_and_refuses_outside_a_call(self):
        sbt.Base.setUp(self)
        ephemeral = sys.modules["stegbrowser_llm.ecosystem_ephemeral"]
        self.assertIs(ephemeral.datetime, lease_time.SuppliedDatetime)
        with self.assertRaises(lease_time.LeaseTimeRefused):
            ephemeral.datetime.now(_dt.timezone.utc)
        at = lease_time.instant(EPOCH)
        with lease_time.supplied(at):
            self.assertEqual(ephemeral.datetime.now(_dt.timezone.utc), at)

    def test_the_vendored_bytes_are_still_the_pinned_upstream_bytes(self):
        manifest = json.loads((VENDORED.parent / "vendor-manifest.json").read_text())
        self.assertEqual("sha256:" + hashlib.sha256(VENDORED.read_bytes()).hexdigest(),
                         manifest["files"]["ecosystem_ephemeral.py"])

    def test_the_tools_call_no_clock(self):
        for name in ("stegbrowser_tool.py", "page_load_tool.py", "lease_time.py"):
            tree = ast.parse((ROOT / "runtime" / name).read_text())
            calls = [n for n in ast.walk(tree) if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
                     and n.func.attr in ("now", "utcnow", "today", "time", "time_ns")
                     and not (isinstance(n.func.value, ast.Name) and n.func.value.id in ("cls", "_current"))]
            self.assertEqual([ast.unparse(c) for c in calls], [], name)


class StegBrowserTool(sbt.Base):
    def test_no_epoch_is_six_field_fail_closed_before_any_lease_or_browser(self):
        for epoch in (None, "31", "x"):
            pw = sbt.factory()
            e = self.obs(self.tool.invoke(sbt.WORK, "inv-1", playwright_factory=pw, hb_epoch=epoch))
            self.assertEqual((e["disposition"], e["failed_predicate"]), ("FAIL_CLOSED", lease_time.LEASE_TIME_PREDICATE))
            self.assertIsNone(e["lease_id"])
            self.assertFalse(e["stegbrowser_invoked"])
            sbt.assert_six_fields(self, e)
            pw.return_value.__enter__.return_value.chromium.launch.assert_not_called()

    def test_an_invalid_issued_epoch_is_refused(self):
        e = self.obs(self.tool.invoke(sbt.WORK, "inv-1", playwright_factory=sbt.factory(), hb_epoch=EPOCH,
                                      issued_epoch="7"))
        self.assertEqual(e["failed_predicate"], lease_time.LEASE_TIME_PREDICATE)

    def test_a_supplied_epoch_gives_the_same_observation_whatever_the_clocks_read(self):
        first = self.obs(self.tool.invoke(sbt.WORK, "inv-1", playwright_factory=sbt.factory(), hb_epoch=EPOCH))
        self.assertEqual(first["disposition"], "ALLOW")
        sbt.Base.setUp(self)
        patches = moved_clocks()
        for p in patches:
            p.start()
        try:
            second = self.obs(self.tool.invoke(sbt.WORK, "inv-1", playwright_factory=sbt.factory(), hb_epoch=EPOCH))
        finally:
            for p in reversed(patches):
                p.stop()
        self.assertEqual(strip_ids(first), strip_ids(second))
        self.assertEqual(first["terminal_receipt"]["closed_at"], lease_time.instant(EPOCH).isoformat().replace("+00:00", "Z"))


class PageLoadTool(plt.Base):
    def test_no_epoch_is_six_field_fail_closed_before_any_lease_or_browser(self):
        pw = plt.factory()
        e = self.obs(self.tool.invoke(plt.WORK, "load-1", playwright_factory=pw))
        self.assertEqual((e["disposition"], e["failed_predicate"]), ("FAIL_CLOSED", lease_time.LEASE_TIME_PREDICATE))
        self.assertIsNone(e["lease_id"])
        for f in ("failure_code", "failed_predicate", "required_evidence_or_repair", "retry_entrypoint",
                  "owning_existing_goal", "next_attempt"):
            self.assertTrue(e[f], f)
        pw.return_value.__enter__.return_value.chromium.launch.assert_not_called()

    def test_a_supplied_epoch_gives_the_same_observation_whatever_the_clocks_read(self):
        first = self.obs(self.tool.invoke(plt.WORK, "load-1", playwright_factory=plt.factory(), hb_epoch=EPOCH))
        self.assertEqual(first["disposition"], "ALLOW")
        plt.Base.setUp(self)
        patches = moved_clocks()
        for p in patches:
            p.start()
        try:
            second = self.obs(self.tool.invoke(plt.WORK, "load-1", playwright_factory=plt.factory(), hb_epoch=EPOCH))
        finally:
            for p in reversed(patches):
                p.stop()
        self.assertEqual(strip_ids(first), strip_ids(second))


if __name__ == "__main__":
    unittest.main()
