import contextlib
import unittest
from unittest.mock import MagicMock, patch

from src.stegbrowser.llm_profile import validate_llm_profile_request
from src.stegbrowser.llm_browser_execution import execute_manifested_llm_browser_operation

JOURNEY = {
    "schema": "stegverse.packet-carried-endpoint-receipt-journey/v1",
    "journey_id": "test5-a", "origin_endpoint": "worker-a", "ephemeral_endpoint": "stegbrowser",
    "outbound_manifest_sha256": "sha256:out", "return_manifest_sha256": "sha256:return",
    "return_predecessor_manifest_sha256": "sha256:out",
}


def request(actions):
    return {
        "schema": "stegbrowser.llm-profile-request.v1", "profile": "llm.v1",
        "prompt": "Return TEST5_A", "response_marker": "TEST5_A",
        "provider": "free-browser-model", "model": "manifest-selected",
        "secure_url": "https://example.test/chat", "browser_actions": actions, "journey": JOURNEY,
    }


SUBMIT_AND_READ = [
    {"op": "fill", "selector": "textarea", "value": "Return TEST5_A"},
    {"op": "press", "selector": "textarea", "key": "Enter"},
    {"op": "read_text", "selector": "[data-answer]"},
]


class FakePage:
    """Records every call; any wait or timeout-bearing read fails the test."""

    def __init__(self, present, answers):
        self.present, self.answers, self.calls = present, answers, []

    def goto(self, url, **kwargs):
        self.calls.append(("goto", url))
        return MagicMock(status=200)

    def locator(self, selector):
        page = self

        class Loc:
            def count(self):
                return 1 if selector in page.present else 0

            def fill(self, value):
                page.calls.append(("fill", selector))

            def press(self, key):
                page.calls.append(("press", selector))

            def click(self):
                page.calls.append(("click", selector))

            def all_inner_texts(self):
                page.calls.append(("all_inner_texts", selector))
                return list(page.answers.get(selector, []))

            def wait_for(self, *a, **k):
                raise AssertionError("llm.v1 must never wait on the provider")

            def inner_text(self, *a, **k):
                raise AssertionError("llm.v1 must read without a waiting timeout")

        return Loc()

    def wait_for_timeout(self, *a, **k):
        raise AssertionError("llm.v1 must never sleep")


def factory(page):
    browser = MagicMock()
    browser.new_context.return_value.new_page.return_value = page
    pw = MagicMock()
    pw.chromium.launch.return_value = browser
    return lambda: contextlib.nullcontext(pw)


class FakeSession:
    def __init__(self):
        self.closed = []

    def authorize(self, **kwargs):
        return {"decision_commitment": "sha256:nav"}

    def close(self, reason):
        self.closed.append(reason)
        return {"reason": reason}


def run(actions, page):
    session = FakeSession()
    with patch("src.stegbrowser.llm_browser_execution.EphemeralBrowserSession.open", return_value=session):
        try:
            return execute_manifested_llm_browser_operation(
                request(actions), lease={}, playwright_factory=factory(page)), session
        except Exception as exc:
            exc.session = session
            raise


class LLMManifestedBrowserExecutionTests(unittest.TestCase):
    def test_llm_v1_accepts_manifested_credential_free_https_browser_actions(self):
        req = validate_llm_profile_request(request(SUBMIT_AND_READ))
        self.assertEqual(req["secure_url"], "https://example.test/chat")
        self.assertEqual(req["browser_actions"][-1]["op"], "read_text")

    def test_llm_v1_rejects_non_https_endpoint(self):
        with self.assertRaisesRegex(ValueError, "secure_url must use https"):
            validate_llm_profile_request({**request([{"op": "read_text", "selector": "body"}]),
                                          "secure_url": "http://example.test"})

    def test_llm_authorization_refusal_finalizes_ephemeral_lease(self):
        """Denied navigation must not leave an opened session unfinalized."""
        session = MagicMock()
        session.authorize.side_effect = PermissionError("origin is outside the lease")
        with patch("src.stegbrowser.llm_browser_execution.EphemeralBrowserSession.open", return_value=session):
            with self.assertRaisesRegex(PermissionError, "origin is outside the lease"):
                execute_manifested_llm_browser_operation(
                    request([{"op": "read_text", "selector": "body"}]), lease={})
        session.close.assert_called_once_with(reason="error")

    def test_answer_present_at_read_is_bound_without_waiting(self):
        page = FakePage({"textarea"}, {"[data-answer]": ["TEST5_A 43"]})
        out, session = run(SUBMIT_AND_READ, page)
        self.assertEqual(session.closed, ["completed"])
        self.assertIn(("all_inner_texts", "[data-answer]"), page.calls)
        self.assertEqual(out["schema"], "stegbrowser.llm-manifested-browser-execution.v1")

    def test_absent_answer_is_a_recorded_non_success_not_a_wait(self):
        page = FakePage({"textarea"}, {})
        with self.assertRaisesRegex(RuntimeError, "result text not observed") as ctx:
            run(SUBMIT_AND_READ, page)
        self.assertEqual(ctx.exception.session.closed, ["error"])

    def test_wait_for_is_refused_and_the_lease_is_finalized(self):
        page = FakePage({"textarea", "[data-answer]"}, {"[data-answer]": ["x"]})
        actions = SUBMIT_AND_READ[:2] + [{"op": "wait_for", "selector": "[data-answer]"}] + SUBMIT_AND_READ[2:]
        with self.assertRaisesRegex(ValueError, "wait_for is refused") as ctx:
            run(actions, page)
        self.assertEqual(ctx.exception.session.closed, ["error"])

    def test_absent_action_target_fails_without_waiting_for_it(self):
        page = FakePage(set(), {})
        with self.assertRaisesRegex(RuntimeError, "fill target not present") as ctx:
            run(SUBMIT_AND_READ, page)
        self.assertNotIn(("fill", "textarea"), page.calls)
        self.assertEqual(ctx.exception.session.closed, ["error"])


if __name__ == "__main__":
    unittest.main()
