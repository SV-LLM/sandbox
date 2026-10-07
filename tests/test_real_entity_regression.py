"""Successor order 5: contract-level multi-entity regression with real SV-LLM entities.

Anthropic and OpenAI register against the canonical SV-LLM organization tree
(from the pinned SV-LLM/.github checkout), using their migrated
sv-llm.entity-capability/v0.1 declarations. Their own core.py produces the
contributions. No model is invoked: the entities package supplied content,
which is the contract level; live invocation is a later, separate step.

Run: SV_LLM_DOTGITHUB_ROOT=<path> python -B tests/test_real_entity_regression.py
"""
from __future__ import annotations
import importlib.util, json, sys, unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests"))
from test_sandbox_runtime import Harness, DOTGITHUB, ALLOW, DENY  # noqa: E402

REAL = ROOT / "tests/real_entities"
ENTITIES = ("Anthropic", "OpenAI")


def entity_core(entity: str):
    spec = importlib.util.spec_from_file_location(f"real_entity_{entity.lower()}_core", REAL / entity / "core.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class RealEntityRegression(unittest.TestCase):
    def setUp(self):
        self.h = Harness()
        self.s = self.h.sandbox
        self.s.registration.verify_vendor(REAL)
        self.tree = self.s.registration.load_tree()  # the canonical tree, not a fixture
        self.decl = {e: (REAL / e / "entity-capability.json").read_bytes() for e in ENTITIES}
        self.core = {e: entity_core(e) for e in ENTITIES}

    def test_canonical_tree_registers_both_entities(self):
        refs = {row["name"] for row in self.tree["repositories"] if "capability_declaration_ref" in row}
        self.assertTrue(set(ENTITIES) <= refs, refs)
        for e in ENTITIES:
            result = self.s.registration.register(e, declaration=self.decl[e])
            self.assertEqual(result["disposition"], ALLOW, result)
            self.assertEqual(self.core[e].ENTITY, e)
        swapped = self.s.registration.register("Anthropic", declaration=self.decl["OpenAI"])
        self.assertEqual((swapped["disposition"], swapped["failed_predicate"]), (DENY, "DECLARATION_DIGEST_MATCHES"))

    def test_same_bounded_work_two_real_entities_end_to_end(self):
        h, s = self.h, self.s
        self.assertEqual(h.admit()["disposition"], ALLOW)
        work = s._work("fixture-work-001")
        for e in ENTITIES:
            for cap in ("adversarial_review", "synthesis"):
                a = s.assign("fixture-work-001", e, cap, declaration=self.decl[e], tree=self.tree)
                self.assertEqual(a["disposition"], ALLOW, a)
                self.assertEqual(s.request("fixture-work-001", e, cap)["disposition"], ALLOW)
        a, o = self.core["Anthropic"], self.core["OpenAI"]
        envelopes = [
            a.contribution(work=work, capability="adversarial_review", epistemic_state="DERIVED",
                           content={"finding": "clause 7 contradicts clause 3"}, evidence_refs=["fixture-view-001"],
                           provenance=["anthropic-contract-level-run"], uncertainty="bounded to the supplied view"),
            o.contribution(work=work, capability="adversarial_review", epistemic_state="DERIVED",
                           content={"finding": "no contradiction found"}, evidence_refs=["fixture-view-001"],
                           provenance=["openai-contract-level-run"], uncertainty="bounded to the supplied view"),
            a.non_success(work=work, capability="synthesis", status="UNAVAILABLE",
                          reason_or_failed_predicate="NO_LIVE_INVOCATION_AT_CONTRACT_LEVEL"),
            o.non_success(work=work, capability="synthesis", status="REFUSED",
                          reason_or_failed_predicate="SYNTHESIS_IS_SANDBOX_RESPONSIBILITY"),
        ]
        recorded = [s.record(json.dumps(env).encode()) for env in envelopes]
        for r in recorded:
            self.assertEqual(r["disposition"], ALLOW, r)
        self.assertEqual({r["entity"] for r in recorded}, set(ENTITIES))
        ids = [r["contribution_id"] for r in recorded]
        synth = s.synthesize("fixture-work-001", ids, {"summary": "the two entities disagree on clause 7",
                                                       "disagreement": ids[:2]})
        self.assertEqual(synth["disposition"], ALLOW)
        self.assertEqual(s.complete("fixture-work-001")["disposition"], ALLOW)
        rebuilt = s.reconstruct("fixture-work-001")
        self.assertEqual(sorted(rebuilt["contributions"]), sorted(ids))
        self.assertEqual(rebuilt["parent_transition"]["org_receipt_sha256"], h.parent_org["receipt_sha256"])
        self.assertEqual(len(h.org_receipts), len(s.ledger.chain()))

    def test_entity_cannot_contribute_outside_its_assignment(self):
        h, s = self.h, self.s
        h.admit()
        work = s._work("fixture-work-001")
        s.assign("fixture-work-001", "Anthropic", "adversarial_review", declaration=self.decl["Anthropic"], tree=self.tree)
        s.request("fixture-work-001", "Anthropic", "adversarial_review")
        env = self.core["OpenAI"].contribution(work=work, capability="adversarial_review", epistemic_state="DERIVED",
                                               content={"x": 1})
        denied = s.record(json.dumps(env).encode())
        self.assertEqual((denied["disposition"], denied["failed_predicate"]), (DENY, "CONTRIBUTION_WAS_REQUESTED"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
