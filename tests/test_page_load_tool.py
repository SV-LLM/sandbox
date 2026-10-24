"""Sandbox + vendored StegBrowser ephemeral session, page_load.v1 (AT-04 Stage 2 first test).

Synthetic: no network, injected Playwright. Covers pre-invocation refusals, the lease (navigate and
read_public only, no persistence), refusal of navigations outside the lease, screenshot capture,
and recording of every attempt.

Run: SV_LLM_DOTGITHUB_ROOT=<SV-LLM/.github checkout> python -B tests/test_page_load_tool.py
"""
from __future__ import annotations
import hashlib, json, os, sys, tempfile, unittest
from pathlib import Path
from unittest.mock import MagicMock
EPOCH = "4000"  # the supplied hb_epoch: every lease time is its HB32 instant

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests"))
from test_sandbox_runtime import Harness, ALLOW, DENY  # noqa: E402
from page_load_tool import StegBrowserPageLoadTool, TOOL_REPAIRS, INTERACTION_FIELDS  # noqa: E402
from sandbox import OWNING_EXISTING_GOAL  # noqa: E402

WORK = "fixture-work-001"
PNG = b"\x89PNG\r\n\x1a\nfixture"


def invocation(**changes):
    inv = {"invocation_id": "load-1", "tool": "StegBrowser", "profile": "page_load.v1", "repository": "FixtureLLM",
           "secure_url": "https://chat.fixture.test/", "allowed_origins": ["*.fixture.test"]}
    inv.update(changes)
    return inv


def factory(*, status=200, final_url="https://chat.fixture.test/", title="Fixture chat", fail_launch=False,
            fail_goto=False):
    playwright = MagicMock()
    p = playwright.return_value.__enter__.return_value
    page = p.chromium.launch.return_value.new_context.return_value.new_page.return_value
    page.goto.return_value.status = status
    page.url = final_url
    page.title.return_value = title
    page.screenshot.return_value = PNG
    if fail_launch:
        p.chromium.launch.side_effect = RuntimeError("synthetic launch failure")
    if fail_goto:
        page.goto.side_effect = TimeoutError("synthetic navigation timeout")
    return playwright


def page_of(pw):
    return pw.return_value.__enter__.return_value.chromium.launch.return_value.new_context.return_value.new_page.return_value


class Base(unittest.TestCase):
    def setUp(self, invocations=None):
        self.h = Harness()
        self.addCleanup(self.h.tmp.cleanup)
        self.s = self.h.sandbox
        self.h.admit(self.h.work(manifested_request={"manifest_id": "fixture-manifest-001",
                                                     "tool_invocations": invocations or [invocation()]}))
        self.out = Path(self.h.tmp.name) / "results"
        self.tool = StegBrowserPageLoadTool(self.s, artifacts_dir=self.out)

    def obs(self, result):
        return next(r for r in self.s.ledger.chain() if r["receipt_sha256"] == result["repo_receipt_sha256"])["evidence"]

    def six(self, e):
        self.assertNotEqual(e["disposition"], ALLOW)
        for f in ("failure_code", "failed_predicate", "required_evidence_or_repair", "retry_entrypoint",
                  "owning_existing_goal", "next_attempt"):
            self.assertTrue(isinstance(e.get(f), str) and e[f], f)
        self.assertEqual(e["owning_existing_goal"], OWNING_EXISTING_GOAL)
        self.assertEqual(e["retry_entrypoint"], "runtime.page_load_tool.StegBrowserPageLoadTool.invoke")
        self.assertIn(e["failed_predicate"], TOOL_REPAIRS)


class Allowed(Base):
    def test_page_load_is_recorded_with_screenshot_and_lease_receipt(self):
        pw = factory(status=403, title="Just a moment...")
        e = self.obs(self.tool.invoke(WORK, "load-1", hb_epoch=EPOCH, playwright_factory=pw))
        self.assertEqual((e["disposition"], e["decided_by"], e["tool_profile"]),
                         (ALLOW, "STEGBROWSER_EPHEMERAL_SESSION", "page_load.v1"))
        self.assertEqual((e["http_status"], e["title"]), (403, "Just a moment..."))  # observed, not judged
        self.assertEqual((e["interaction"], e["credentials"]), ("NONE", "NONE"))
        self.assertEqual(e["screenshot_sha256"], "sha256:" + hashlib.sha256(PNG).hexdigest())
        self.assertEqual((self.out / "FixtureLLM" / "screenshot.png").read_bytes(), PNG)
        t = e["terminal_receipt"]
        self.assertTrue(t["session_state_destroyed"])
        self.assertFalse(t["cookies_retained"] or t["history_retained"] or t["credential_material_retained"]
                         or t["persistent_profile_retained"])
        self.assertEqual(t["navigation_count"], 0)  # the injected browser never routed a navigation
        self.assertEqual({a["artifact_type"] for a in t["retained_artifacts"]}, {"content_commitment", "navigation_receipt"})

    def test_no_typing_clicking_or_credentials_reach_the_browser(self):
        pw = factory()
        self.tool.invoke(WORK, "load-1", hb_epoch=EPOCH, playwright_factory=pw)
        page = page_of(pw)
        for method in ("fill", "type", "click", "press", "locator", "keyboard", "mouse"):
            self.assertFalse(getattr(page, method).called, method)
        ctx_kwargs = pw.return_value.__enter__.return_value.chromium.launch.return_value.new_context.call_args.kwargs
        self.assertNotIn("storage_state", ctx_kwargs)
        self.assertEqual(ctx_kwargs["service_workers"], "block")

    def test_nothing_waits_on_the_provider_after_delivery(self):
        pw = factory()
        e = self.obs(self.tool.invoke(WORK, "load-1", hb_epoch=EPOCH, playwright_factory=pw))
        self.assertEqual(e["disposition"], ALLOW)
        page = page_of(pw)
        for method in ("wait_for_timeout", "wait_for_load_state", "wait_for_event", "wait_for_function"):
            self.assertFalse(getattr(page, method).called, method)
        self.assertEqual(page.goto.call_args.kwargs["wait_until"], "domcontentloaded")

    def test_navigation_outside_the_lease_is_aborted(self):
        pw = factory()
        page = page_of(pw)
        routes = {}

        def goto(url, **_):  # navigations the page attempts while the lease is open
            guard = page.route.call_args.args[1]
            for target in ("https://chat.fixture.test/next", "https://evil.example/"):
                route, request = MagicMock(), MagicMock()
                request.is_navigation_request.return_value = True
                request.frame = page.main_frame
                request.url = target
                guard(route, request)
                routes[target] = route
            return MagicMock(status=200)
        page.goto.side_effect = goto
        e = self.obs(self.tool.invoke(WORK, "load-1", hb_epoch=EPOCH, playwright_factory=pw))
        self.assertEqual(e["disposition"], ALLOW)
        self.assertTrue(routes["https://chat.fixture.test/next"].continue_.called)
        self.assertTrue(routes["https://evil.example/"].abort.called)
        self.assertEqual([d["url"] for d in e["denied_navigations"]], ["https://evil.example/"])
        self.assertEqual(e["terminal_receipt"]["navigation_count"], 1)


class Refused(Base):
    def setUp(self):
        super().setUp(invocations=[invocation(), invocation(invocation_id="off", secure_url="https://other.test/"),
                                   invocation(invocation_id="typing", prompt="hello"),
                                   invocation(invocation_id="creds", credential_mode="SESSION"),
                                   invocation(invocation_id="bad", lease_seconds=0)])

    def denied(self, out, predicate, disposition=DENY):
        e = self.obs(out)
        self.assertEqual((e["disposition"], e["failed_predicate"]), (disposition, predicate))
        self.six(e)
        return e

    def test_pre_invocation_refusals_never_start_a_browser(self):
        pw = factory()
        for work, inv, predicate in (("not-admitted", "load-1", "WORK_ID_IS_ADMITTED"),
                                     (WORK, "undeclared", "TOOL_INVOCATION_DECLARED"),
                                     (WORK, "bad", "TOOL_INVOCATION_WELL_FORMED"),
                                     (WORK, "typing", "PAGE_LOAD_HAS_NO_INTERACTION"),
                                     (WORK, "creds", "PAGE_LOAD_HAS_NO_INTERACTION"),
                                     (WORK, "off", "SECURE_URL_ORIGIN_ALLOWED_BY_LEASE")):
            e = self.denied(self.tool.invoke(work, inv, hb_epoch=EPOCH, playwright_factory=pw), predicate)
            self.assertFalse(e["stegbrowser_invoked"])
        pw.return_value.__enter__.assert_not_called()
        self.assertIn("prompt", INTERACTION_FIELDS)

    def test_final_host_outside_lease_fails_closed(self):
        e = self.denied(self.tool.invoke(WORK, "load-1", hb_epoch=EPOCH, playwright_factory=factory(final_url="https://evil.example/")),
                        "FINAL_ORIGIN_WITHIN_LEASE", "FAIL_CLOSED")
        self.assertTrue(e["stegbrowser_invoked"])
        self.assertTrue(e["terminal_receipt"]["session_state_destroyed"])

    def test_navigation_and_launch_failures_fail_closed(self):
        e = self.denied(self.tool.invoke(WORK, "load-1", hb_epoch=EPOCH, playwright_factory=factory(fail_goto=True)),
                        "PAGE_NAVIGATION_COMPLETED", "FAIL_CLOSED")
        self.assertIn("TimeoutError", e["detail"])
        e = self.denied(self.tool.invoke(WORK, "load-1", hb_epoch=EPOCH, playwright_factory=factory(fail_launch=True)),
                        "PAGE_NAVIGATION_COMPLETED", "FAIL_CLOSED")
        self.assertIsNone(e["screenshot_sha256"])

    def test_every_attempt_is_a_synthesis_input(self):
        ids = [self.tool.invoke(WORK, i, hb_epoch=EPOCH, playwright_factory=factory())["observation_id"] for i in ("load-1", "off")]
        self.assertEqual(self.s.synthesize(WORK, ids[:1], {"s": "drops one"})["failed_predicate"],
                         "SYNTHESIS_BINDS_EVERY_RECORDED_INPUT")
        self.assertEqual(self.s.synthesize(WORK, ids, {"s": "both"})["disposition"], ALLOW)
        self.assertEqual(self.s.complete(WORK)["disposition"], ALLOW)


if __name__ == "__main__":
    unittest.main(verbosity=2)
