"""AT-04 Stage 1 target: derivation of the Sandbox invocation from live/target.json (T3/T4).

Run: SV_LLM_DOTGITHUB_ROOT=<SV-LLM/.github checkout> python -B tests/test_live_target.py
"""
from __future__ import annotations
import copy, json, sys, unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests"))
sys.path.insert(0, str(ROOT / "live"))
from test_sandbox_runtime import Harness, ALLOW  # noqa: E402
from test_stegbrowser_tool import factory  # noqa: E402
from stegbrowser_tool import StegBrowserTool  # noqa: E402
from run_live_llm import derive_invocation  # noqa: E402

TARGET = json.loads((ROOT / "live/target.json").read_text())


def verified(**changes):
    t = copy.deepcopy(TARGET)
    t["verified"] = True
    t.update(changes)
    return t


class Derivation(unittest.TestCase):
    def test_unverified_target_fails_closed(self):
        self.assertEqual(derive_invocation(verified(verified=False)), (None, "LIVE_TARGET_SELECTED_AND_VERIFIED"))

    def test_committed_target_is_verified_with_passing_evidence(self):
        self.assertIs(TARGET["verified"], True)
        checks = {e["check"]: e["result"] for e in TARGET["verification_evidence"]}
        for required in ("current page reachable", "selectors validated", "automation permitted",
                         "response marker behavior validated"):
            self.assertEqual(checks.get(required), "PASS", required)
        self.assertEqual(derive_invocation(TARGET)[1], None)

    def test_target_is_stegverse_controlled_and_unattributed(self):
        self.assertEqual(TARGET["origin"], "https://stegverse.org")
        self.assertTrue(TARGET["secure_url"].startswith("https://stegverse.org/"))
        self.assertIsNone(TARGET["provider_entity"])
        self.assertIs(TARGET["provider_attribution_allowed"], False)

    def test_verified_target_derives_exact_invocation(self):
        inv, refused = derive_invocation(verified())
        self.assertIsNone(refused)
        self.assertEqual(inv["allowed_origins"], ["stegverse.org"])
        self.assertEqual(inv["secure_url"], TARGET["secure_url"])
        self.assertEqual([a["op"] for a in inv["browser_actions"]], ["fill", "click", "wait_for", "read_text"])
        self.assertEqual(inv["browser_actions"][0]["value"], TARGET["prompt"])
        self.assertIn(TARGET["response_marker"], inv["prompt"])
        self.assertNotIn("provider", inv)
        self.assertNotIn("model", inv)

    def test_T4_any_provider_attribution_fails_closed(self):
        for changes in ({"provider_entity": "Anthropic"}, {"provider_attribution_allowed": True},
                        {"provider": "OpenAI"}, {"model": "any"}):
            self.assertEqual(derive_invocation(verified(**changes)), (None, "LIVE_TARGET_HAS_NO_PROVIDER_ATTRIBUTION"), changes)

    def test_T3_malformed_target_fails_closed(self):
        bad = [{"origin": "http://stegverse.org"}, {"origin": "https://stegverse.org/path"},
               {"origin": "https://stegverse.org:8443"}, {"secure_url": "https://elsewhere.test/page"},
               {"secure_url": "http://stegverse.org/integration/llm-browser-test/v1/"},
               {"prompt": "no marker in this prompt"}, {"credential_mode": "SESSION"},
               {"automation_policy": None}, {"profile": "social.v1"}, {"schema": "other"},
               {"selectors": {"prompt_input": "#prompt", "submit": "#submit", "response": "#response"}}]
        for changes in bad:
            self.assertEqual(derive_invocation(verified(**changes)), (None, "LIVE_TARGET_WELL_FORMED"), changes)


class AdapterAcceptsDerivedInvocation(unittest.TestCase):
    def test_derived_invocation_passes_pre_invocation_checks(self):
        inv, _ = derive_invocation(verified())
        h = Harness()
        work = h.work(manifested_request={"manifest_id": "at04", "tool_invocations": [inv]})
        self.assertEqual(h.admit(work)["disposition"], ALLOW)
        pw = factory(text=f"STEGVERSE_CONFORMANCE_V1 {inv['prompt']}")
        out = StegBrowserTool(h.sandbox).invoke("fixture-work-001", inv["invocation_id"], playwright_factory=pw)
        self.assertEqual(out["disposition"], ALLOW, out)
        e = next(r for r in h.sandbox.ledger.chain() if r["receipt_sha256"] == out["repo_receipt_sha256"])["evidence"]
        self.assertEqual(e["observed_origin"], "stegverse.org")
        self.assertFalse(e["result"]["labels_are_attestation"])
        self.assertEqual(h.sandbox.contributions("fixture-work-001"), [])


class Repository(unittest.TestCase):
    def text_files(self):
        for p in ROOT.rglob("*"):
            if p.is_file() and ".git" not in p.parts and p.suffix in (".py", ".json", ".md", ".yml") \
                    and p.resolve() != Path(__file__).resolve():
                yield p, p.read_text(encoding="utf-8")

    def test_TARGET_AT01_no_hugging_face_dependency(self):
        for p, text in self.text_files():
            self.assertNotIn("hugging", text.lower(), str(p))

    def test_TARGET_AT07_no_provider_urls_or_selectors_in_sandbox_runtime(self):
        for p in (ROOT / "runtime").glob("*.py"):
            text = p.read_text().lower()
            for host in ("openai.com", "chatgpt.com", "anthropic.com", "claude.ai"):
                self.assertNotIn(host, text, str(p))


if __name__ == "__main__":
    unittest.main(verbosity=2)
