"""Unit tests for the non-authorizing manifested LLM browser outcome contract."""
import unittest
from unittest.mock import MagicMock, patch

from src.stegbrowser.llm_transition import execute_manifested_llm_browser_transition


def request(actions=None):
    return {
        "schema": "stegbrowser.llm-profile-request.v1",
        "profile": "llm.v1",
        "prompt": "Return TEST5_A",
        "response_marker": "TEST5_A",
        "provider": "test-provider",
        "model": "test-model",
        "secure_url": "https://example.test/chat",
        "browser_actions": actions or [{"op": "read_text", "selector": "body"}],
        "journey": {
            "schema": "stegverse.packet-carried-endpoint-receipt-journey/v1",
            "journey_id": "evidence-43",
            "origin_endpoint": "sandbox",
            "ephemeral_endpoint": "stegbrowser",
            "outbound_manifest_sha256": "sha256:out",
            "return_manifest_sha256": "sha256:return",
            "return_predecessor_manifest_sha256": "sha256:out",
        },
    }


def ephemeral():
    session = MagicMock()
    session.authorize.return_value = {"decision_commitment": "sha256:navigation"}
    session.close.return_value = {"schema": "stegbrowser.ecosystem-ephemeral-terminal-receipt.v1", "session_state_destroyed": True}
    return session


def factory(*, fail_launch=False):
    playwright = MagicMock()
    p = playwright.return_value.__enter__.return_value
    browser = p.chromium.launch.return_value
    context = browser.new_context.return_value
    page = context.new_page.return_value
    page.goto.return_value.status = 200
    page.locator.return_value.inner_text.return_value = "TEST5_A"
    if fail_launch:
        p.chromium.launch.side_effect = RuntimeError("synthetic launch failure")
    return playwright


class ManifestedBrowserTransitionTests(unittest.TestCase):
    def _run(self, req, session=None, playwright=None):
        session = session or ephemeral()
        with patch("src.stegbrowser.llm_browser_execution.EphemeralBrowserSession.open", return_value=session):
            outcome = execute_manifested_llm_browser_transition(
                req, {"task_id": "task-43", "lease_id": "lease-43"},
                playwright_factory=playwright or factory(),
            )
        return outcome, session

    def test_success_result_and_local_receipt(self):
        result, session = self._run(request())
        self.assertEqual(result["disposition"], "ALLOW")
        self.assertEqual(result["receipt"]["evaluation_stage"], "RETURN_COMPLETE")
        self.assertEqual(result["receipt"]["outbound_manifest_sha256"], "sha256:out")
        self.assertEqual(result["receipt"]["terminal_receipt"]["session_state_destroyed"], True)
        self.assertFalse(result["receipt"]["organization_receipt_claimed"])
        self.assertIsNotNone(result["execution_result"]["result"]["response_commitment"])
        session.close.assert_called_once_with(reason="completed")

    def test_navigation_scope_denial(self):
        session = ephemeral()
        session.authorize.side_effect = PermissionError("origin out of scope")
        result, session = self._run(request(), session=session)
        self.assertEqual(result["disposition"], "DENY")
        self.assertEqual(result["receipt"]["evaluation_stage"], "NAVIGATION_ADMISSION")
        self.assertIsNone(result["execution_result"])
        self.assertIsNotNone(result["receipt"]["retry_entrypoint"])
        session.close.assert_called_once_with(reason="error")

    def test_malformed_dom_operation(self):
        result, session = self._run(request([{"op": "unsupported", "selector": "body"}]))
        self.assertEqual(result["disposition"], "FAIL_CLOSED")
        self.assertEqual(result["receipt"]["evaluation_stage"], "BROWSER_ACTION")
        session.close.assert_called_once_with(reason="error")

    def test_browser_launch_failure(self):
        result, session = self._run(request(), playwright=factory(fail_launch=True))
        self.assertEqual(result["disposition"], "FAIL_CLOSED")
        self.assertEqual(result["receipt"]["evaluation_stage"], "BROWSER_LAUNCH")
        session.close.assert_called_once_with(reason="error")

    def test_expired_lease(self):
        lease = {
            "schema": "stegbrowser.ecosystem-ephemeral-lease.v1",
            "lease_id": "expired-43", "task_id": "task-43",
            "requester": "sandbox", "purpose": "llm test",
            "issued_at": "2020-01-01T00:00:00Z",
            "expires_at": "2020-01-01T00:01:00Z",
            "allowed_origins": ["example.test"],
            "allowed_actions": ["navigate"],
        }
        result = execute_manifested_llm_browser_transition(request(), lease, playwright_factory=factory())
        self.assertEqual(result["disposition"], "FAIL_CLOSED")
        self.assertEqual(result["receipt"]["evaluation_stage"], "LEASE_ADMISSION")
        self.assertIsNone(result["receipt"]["terminal_receipt"])

    def test_invalid_manifest(self):
        bad = request()
        bad["profile"] = "unknown"
        result = execute_manifested_llm_browser_transition(bad, {"task_id": "task-43"}, playwright_factory=factory())
        self.assertEqual(result["disposition"], "FAIL_CLOSED")
        self.assertEqual(result["receipt"]["evaluation_stage"], "MANIFEST_VALIDATION")
        self.assertIsNone(result["receipt"]["request_commitment"])


if __name__ == "__main__":
    unittest.main()
