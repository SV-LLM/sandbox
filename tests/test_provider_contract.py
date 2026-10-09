"""AT-04 Stage 2 contract layer: Sandbox resolution of provider interaction contracts.

Real Anthropic and OpenAI resolve their vendored contracts against the canonical
SV-LLM organization tree; both are NO_APPROVED_AUTOMATION_SURFACE and refuse with
FAIL_CLOSED. Synthetic fixture-entity contracts cover every other predicate.
No provider is contacted and no browser starts.

Run: SV_LLM_DOTGITHUB_ROOT=<registered SV-LLM/.github checkout> python -B tests/test_provider_contract.py
"""
from __future__ import annotations
import copy, hashlib, json, re, sys, tempfile, unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests"))
sys.path.insert(0, str(ROOT / "runtime"))
from test_sandbox_runtime import Harness, ALLOW, DENY, A, B  # noqa: E402
from provider_contract import ProviderInteraction, VENDOR, PROVIDER_REPAIRS  # noqa: E402
from sandbox import OWNING_EXISTING_GOAL  # noqa: E402

FAIL_CLOSED = "FAIL_CLOSED"
REAL = ROOT / "tests/real_entities"
WORK = "fixture-work-001"
APPROVED = {
    "schema": "sv-llm.provider-interaction-contract/v0.1", "contract_role": "PROVIDER_INTERACTION_CONTRACT",
    "authority_effect": "NONE", "surface_status": "APPROVED",
    "automation_permission": {"basis": "PROVIDER_EXPLICIT_WRITTEN_PERMISSION", "reference": "fixture permission",
                              "document_sha256": "sha256:" + "a" * 64},
    "surface": {"kind": "BROWSER_WEB_SURFACE", "profile": "llm.v1", "origin": "https://surface.fixture.example",
                "secure_url": "https://surface.fixture.example/automation/v1/"},
    "credential_mode": "NONE",
    "selectors": {"prompt_input": "#prompt", "submit": "#submit", "response_ready": "#response[data-complete='true']",
                  "response": "#response"},
    "result_extraction": {"response_marker_required": True},
    "evidence_requirements": ["response marker observed", "browser session destroyed"],
    "attribution": {"provider_attribution_allowed": True},
    "verified": True, "verification_evidence": [{"check": "fixture", "result": "PASS"}],
}


def vendor(contracts: dict[str, dict | bytes]) -> tempfile.TemporaryDirectory:
    """A vendored contract directory with its own digest manifest."""
    tmp = tempfile.TemporaryDirectory()
    files = {}
    for repo, contract in contracts.items():
        path = Path(tmp.name) / repo / "provider-interaction-contract.json"
        path.parent.mkdir(parents=True)
        data = contract if isinstance(contract, bytes) else json.dumps(contract, indent=2).encode()
        path.write_bytes(data)
        files[f"{repo}/provider-interaction-contract.json"] = "sha256:" + hashlib.sha256(data).hexdigest()
    (Path(tmp.name) / "vendor-manifest.json").write_text(json.dumps({"files": files}))
    return tmp


SIX_FIELDS = ("failure_code", "failed_predicate", "required_evidence_or_repair", "retry_entrypoint",
              "owning_existing_goal", "next_attempt")


def assert_six_fields(tc: unittest.TestCase, sandbox, out: dict) -> None:
    """Every PROVIDER_INTERACTION_REFUSED carries the six conformance fields, returned and in the ledger."""
    tc.assertEqual(out["transition_class"], "PROVIDER_INTERACTION_REFUSED")
    evidence = next(r for r in sandbox.ledger.chain() if r["receipt_sha256"] == out["repo_receipt_sha256"])["evidence"]
    predicate = out["failed_predicate"]
    tc.assertIn(predicate, PROVIDER_REPAIRS)  # a specific repair, not the generic fallback
    for record in (out, evidence):
        for field in SIX_FIELDS:
            tc.assertTrue(isinstance(record.get(field), str) and record[field], (predicate, field))
        tc.assertEqual(record["failure_code"], f"PROVIDER_INTERACTION_{out['disposition']}_{predicate}")
        tc.assertEqual(record["retry_entrypoint"], "runtime.provider_contract.ProviderInteraction.resolve")
        tc.assertEqual(record["owning_existing_goal"], OWNING_EXISTING_GOAL)
        tc.assertEqual((record["required_evidence_or_repair"], record["next_attempt"]), PROVIDER_REPAIRS[predicate])


def approved(entity: str, **changes) -> dict:
    c = copy.deepcopy(APPROVED)
    c.update(entity=entity, repository=entity, **changes)
    return c


class RealProviderContracts(unittest.TestCase):
    def setUp(self):
        self.h = Harness()
        self.addCleanup(self.h.tmp.cleanup)
        self.s = self.h.sandbox
        self.s.registration.verify_vendor(REAL)
        self.tree = self.s.registration.load_tree()
        self.assertEqual(self.h.admit()["disposition"], ALLOW)
        self.pi = ProviderInteraction(self.s)

    def test_both_real_providers_refuse_with_no_approved_surface(self):
        for entity in ("Anthropic", "OpenAI"):
            decl = (REAL / entity / "entity-capability.json").read_bytes()
            self.assertEqual(self.s.assign(WORK, entity, "synthesis", declaration=decl, tree=self.tree)["disposition"], ALLOW)
            before = len(self.s.ledger.chain())
            out = self.pi.resolve(WORK, entity, "synthesis")
            self.assertEqual(len(self.s.ledger.chain()), before + 1)  # exactly one receipt
            self.assertEqual(out["transition_class"], "PROVIDER_INTERACTION_REFUSED")
            self.assertEqual((out["disposition"], out["failed_predicate"]),
                             (FAIL_CLOSED, "PROVIDER_AUTOMATION_SURFACE_APPROVED"))
            self.assertEqual(out["surface_status"], "NO_APPROVED_AUTOMATION_SURFACE")
            assert_six_fields(self, self.s, out)
            self.assertEqual(out["repository"], entity)
            raw = (VENDOR / entity / "provider-interaction-contract.json").read_bytes()
            self.assertEqual(out["contract_sha256"], self.s.canon.digest(self.s.canon.parse(raw)))
            self.assertTrue(out["terms_basis"] and out["unblock_condition"])
            self.assertNotIn("resolved_surface", out)
            self.assertIn("org_receipt_sha256", out)

    def test_vendored_contracts_match_manifest(self):
        manifest = json.loads((VENDOR / "vendor-manifest.json").read_text())
        self.assertEqual(set(manifest["files"]), {"Anthropic/provider-interaction-contract.json",
                                                  "OpenAI/provider-interaction-contract.json"})
        self.s.registration.verify_vendor(VENDOR)


class ResolutionPredicates(unittest.TestCase):
    def setUp(self):
        self.h = Harness()
        self.addCleanup(self.h.tmp.cleanup)
        self.s = self.h.sandbox
        self.h.setup_assignments()

    def resolve(self, contracts, entity=A):
        tmp = vendor(contracts)
        self.addCleanup(tmp.cleanup)
        return ProviderInteraction(self.s, Path(tmp.name)).resolve(WORK, entity, "synthesis")

    def test_unassigned_entity_denied(self):
        tmp = vendor({A: approved(A)})
        self.addCleanup(tmp.cleanup)
        out = ProviderInteraction(self.s, Path(tmp.name)).resolve(WORK, A, "code_generation")
        self.assertEqual((out["disposition"], out["failed_predicate"]), (DENY, "CAPABILITY_ASSIGNED_FOR_ADMITTED_WORK"))
        assert_six_fields(self, self.s, out)
        out = ProviderInteraction(self.s, Path(tmp.name)).resolve("no-such-work", A, "synthesis")
        self.assertEqual((out["disposition"], out["failed_predicate"]), (DENY, "CAPABILITY_ASSIGNED_FOR_ADMITTED_WORK"))
        assert_six_fields(self, self.s, out)

    def test_missing_contract_fails_closed(self):
        out = self.resolve({B: approved(B)}, entity=A)
        self.assertEqual((out["disposition"], out["failed_predicate"]), (FAIL_CLOSED, "PROVIDER_INTERACTION_CONTRACT_PRESENT"))
        assert_six_fields(self, self.s, out)

    def test_invalid_contract_fails_closed(self):
        for bad in (approved(A, credential_mode="SESSION_COOKIE"), approved(A, surface_status="NO_APPROVED_AUTOMATION_SURFACE"),
                    b'{"schema": 1, "schema": 2}'):
            out = self.resolve({A: bad})
            self.assertEqual((out["disposition"], out["failed_predicate"]),
                             (FAIL_CLOSED, "PROVIDER_INTERACTION_CONTRACT_SCHEMA_VALID"), bad)
            assert_six_fields(self, self.s, out)

    def test_contract_for_another_entity_denied(self):
        out = self.resolve({A: approved(B)})
        self.assertEqual((out["disposition"], out["failed_predicate"]),
                         (DENY, "PROVIDER_INTERACTION_CONTRACT_BOUND_TO_ASSIGNED_ENTITY"))
        assert_six_fields(self, self.s, out)

    def test_unverified_approved_contract_fails_closed(self):
        out = self.resolve({A: approved(A, verified=False)})
        self.assertEqual((out["disposition"], out["failed_predicate"]), (FAIL_CLOSED, "PROVIDER_INTERACTION_CONTRACT_VERIFIED"))
        assert_six_fields(self, self.s, out)

    def test_approved_verified_contract_resolves_surface_without_invoking_anything(self):
        out = self.resolve({A: approved(A)})
        self.assertEqual((out["transition_class"], out["disposition"]), ("PROVIDER_INTERACTION_RESOLVED", ALLOW))
        surface = out["resolved_surface"]
        self.assertEqual(surface["allowed_origins"], ["surface.fixture.example"])
        self.assertEqual(surface["secure_url"], APPROVED["surface"]["secure_url"])
        self.assertEqual(surface["selectors"], APPROVED["selectors"])
        self.assertEqual(surface["automation_permission"]["basis"], "PROVIDER_EXPLICIT_WRITTEN_PERMISSION")
        self.assertFalse(any(r["transition_class"] == "SANDBOX_TOOL_OBSERVATION_RECORDED" for r in self.s.ledger.chain()))
        for field in SIX_FIELDS[:1] + SIX_FIELDS[2:]:
            self.assertNotIn(field, out)  # ALLOW carries no repair fields

    def test_every_documented_refusal_predicate_has_a_specific_repair(self):
        import provider_contract
        documented = set(re.findall(r"^  ([A-Z_]+)\s+(?:DENY|FAIL_CLOSED)$", provider_contract.__doc__, re.M))
        self.assertEqual(documented, set(PROVIDER_REPAIRS))

    def test_refusal_fields_are_deterministic(self):
        first = self.resolve({A: approved(A, verified=False)})
        second = self.resolve({A: approved(A, verified=False)})
        self.assertEqual({f: first[f] for f in SIX_FIELDS}, {f: second[f] for f in SIX_FIELDS})

    def test_tampered_vendored_bytes_refuse_construction(self):
        tmp = vendor({A: approved(A)})
        self.addCleanup(tmp.cleanup)
        (Path(tmp.name) / A / "provider-interaction-contract.json").write_text("{}")
        with self.assertRaisesRegex(RuntimeError, "VENDORED_CONTRACT_DIGEST_MISMATCH"):
            ProviderInteraction(self.s, Path(tmp.name))


class NoHardCodedProviderSurface(unittest.TestCase):
    def test_resolver_names_no_provider_url_or_selector(self):
        text = (ROOT / "runtime/provider_contract.py").read_text().lower()
        for needle in ("claude.ai", "chatgpt.com", "openai.com", "anthropic.com", "#prompt-textarea"):
            self.assertNotIn(needle, text)


if __name__ == "__main__":
    unittest.main()
