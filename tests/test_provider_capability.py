"""Shared provider capability contract (sv-llm.provider-capability/v0.1).

The JSON Schema fixes the structure; runtime/provider_capability.py is the offline
validator that SV-LLM provider repositories vendor byte-for-byte and that returns
ALLOW, DENY or FAIL_CLOSED. Negative fixtures cover malformed declarations, false
execution claims, unauthorized authority, credentials and live endpoints, missing
provenance, unavailable authentic interfaces and identity mismatch.
No network, no provider, no credentials.

Run: python -B tests/test_provider_capability.py
"""
from __future__ import annotations
import json, subprocess, sys, unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "runtime"))
import provider_capability as pc  # noqa: E402

FIXTURES = ROOT / "tests/fixtures/provider_capability"
SCHEMA = json.loads((ROOT / "runtime/contracts/provider-capability.schema.json").read_text())


def schema_evaluator():
    """The SV-LLM native schema evaluator from SV-LLM/.github's digest-verified vendored copy."""
    import importlib.util, os
    vendor = Path(os.environ["SV_LLM_DOTGITHUB_ROOT"]) / "org-runtime/vendor/sv-llm-schemas"
    manifest = json.loads((vendor / "vendor-manifest.json").read_text())
    path = vendor / "tools/sv_llm_schema.py"
    import hashlib
    assert "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest() == manifest["files"]["tools/sv_llm_schema.py"]
    spec = importlib.util.spec_from_file_location("sv_llm_schema", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module
VALID = json.loads((FIXTURES / "valid.json").read_text())
NEGATIVES = sorted((FIXTURES / "negative").glob("*.json"))


class ProviderCapabilityContract(unittest.TestCase):
    def test_valid_fixture_is_allowed_deterministically(self):
        first = pc.validate(VALID, "FixtureProvider")
        self.assertEqual(first, {"disposition": pc.ALLOW, "failed_predicates": []})
        self.assertEqual(pc.validate(json.loads(json.dumps(VALID)), "FixtureProvider"), first)

    def test_valid_fixture_satisfies_the_schema(self):
        evaluator = schema_evaluator()
        evaluator.check_schema(SCHEMA)
        self.assertEqual(list(evaluator.Validator(SCHEMA).iter_errors(VALID)), [])

    def test_every_negative_fixture_is_refused_with_its_predicate(self):
        self.assertGreaterEqual(len(NEGATIVES), 15)
        for path in NEGATIVES:
            case = json.loads(path.read_text())
            with self.subTest(path.stem):
                result = pc.validate(case["declaration"], "FixtureProvider")
                self.assertEqual(result["disposition"], case["expected_disposition"], result)
                self.assertIn(case["expected_predicate"], result["failed_predicates"])

    def test_structural_negatives_also_fail_the_schema(self):
        v = schema_evaluator().Validator(SCHEMA)
        for path in NEGATIVES:
            case = json.loads(path.read_text())
            if case["expected_predicate"] in {"PROVIDER_IDENTITY_BOUND", "NO_CREDENTIAL_MATERIAL",
                                              "NO_LIVE_ENDPOINT_DEPENDENCY", "INSTALLATION_TASK_BOUND",
                                              "AUTHENTIC_INTERFACE_EVIDENCED", "PROVENANCE_BOUND"}:
                continue  # policy predicates enforced by the validator, not the structural schema
            with self.subTest(path.stem):
                self.assertTrue(list(v.iter_errors(case["declaration"])), path.stem)

    def test_unhashable_capability_and_prohibition_values_fail_closed(self):
        for field, values in (
            ("capabilities", [["reasoning"]]),
            ("capabilities", [{"unexpected": "reasoning"}]),
            ("prohibited", [{"unexpected": "authority"}]),
            ("prohibited", [["LEDGER_AUTHORITY"]]),
        ):
            with self.subTest(field=field, values=values):
                d = json.loads(json.dumps(VALID))
                d[field] = values
                result = pc.validate(d, "FixtureProvider")
                self.assertEqual(result["disposition"], pc.FAIL_CLOSED)
                self.assertIn("FIELD_TYPES_VALID", result["failed_predicates"])

    def test_wrong_typed_values_never_raise(self):
        """Every field of the valid fixture, replaced by values of other JSON types, yields a disposition."""
        def paths(v, p=()):
            yield p
            if isinstance(v, dict):
                for k in v: yield from paths(v[k], p + (k,))
            elif isinstance(v, list):
                for i, x in enumerate(v[:2]): yield from paths(x, p + (i,))
        for path in list(paths(VALID))[1:]:
            for bad in (None, 1, True, [], {}, [1], [[1]], {"a": []}, "x", ["x"]):
                d = json.loads(json.dumps(VALID))
                o = d
                for k in path[:-1]: o = o[k]
                o[path[-1]] = bad
                with self.subTest(path=path, value=bad):
                    self.assertIn(pc.validate(d, "FixtureProvider")["disposition"], (pc.DENY, pc.FAIL_CLOSED, pc.ALLOW))

    def test_non_integer_numbers_fail_closed(self):
        d = json.loads(json.dumps(VALID)); d["confidence"] = 0.5
        self.assertEqual(pc.validate(d)["disposition"], pc.FAIL_CLOSED)

    def test_cli_exit_status_follows_disposition(self):
        ok = subprocess.run([sys.executable, str(ROOT / "runtime/provider_capability.py"),
                             str(FIXTURES / "valid.json"), "FixtureProvider"], capture_output=True, text=True)
        self.assertEqual(ok.returncode, 0, ok.stdout + ok.stderr)
        bad = subprocess.run([sys.executable, str(ROOT / "runtime/provider_capability.py"),
                              str(FIXTURES / "valid.json"), "OtherProvider"], capture_output=True, text=True)
        self.assertEqual(bad.returncode, 1)
        self.assertEqual(json.loads(bad.stdout)["disposition"], pc.DENY)

    def test_validator_performs_no_transport(self):
        text = (ROOT / "runtime/provider_capability.py").read_text()
        for forbidden in ("urllib", "requests", "http.client", "httpx", "socket"):
            self.assertNotIn(f"import {forbidden}", text)


if __name__ == "__main__":
    unittest.main(verbosity=2)
