"""Deterministic capability routing from declarations (offline, stdlib)."""
from __future__ import annotations
import json, sys, unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "runtime"))
import capability_routing as cr  # noqa: E402

REAL = ROOT / "tests/real_entities"
SIX = ("failure_code", "failed_predicate", "required_evidence_or_repair", "retry_entrypoint",
       "owning_existing_goal", "next_attempt")


def decl(entity, caps):
    return json.dumps({"schema": cr.DECLARATION_SCHEMA, "entity": entity, "capabilities": caps}).encode()


class Routing(unittest.TestCase):
    def assertSix(self, r):
        self.assertEqual(r["disposition"], cr.FAIL_CLOSED, r)
        for k in SIX:
            self.assertTrue(isinstance(r.get(k), str) and r[k], (k, r))

    def test_routes_each_capability_to_the_first_declaring_entity_in_order(self):
        d = {"A": decl("A", ["reasoning"]), "B": decl("B", ["reasoning", "synthesis"]), "C": decl("C", ["synthesis"])}
        r = cr.derive_participants(["synthesis", "reasoning"], d, order=["C", "B", "A"])
        self.assertEqual(r["disposition"], cr.ALLOW, r)
        self.assertEqual(r["participants"], [{"entity": "C", "capability": "synthesis"},
                                             {"entity": "B", "capability": "reasoning"}])
        self.assertEqual(r["evidence"]["alternates"], {"synthesis": ["B"], "reasoning": ["A"]})
        self.assertEqual(r["authority_effect"], "NONE")
        # Default order is sorted names; duplicates in the request collapse.
        r2 = cr.derive_participants(["reasoning", "reasoning"], d)
        self.assertEqual(r2["participants"], [{"entity": "A", "capability": "reasoning"}])

    def test_deterministic_for_equal_inputs_regardless_of_dict_insertion(self):
        d1 = {"A": decl("A", ["reasoning"]), "B": decl("B", ["reasoning"])}
        d2 = {"B": decl("B", ["reasoning"]), "A": decl("A", ["reasoning"])}
        self.assertEqual(json.dumps(cr.derive_participants(["reasoning"], d1), sort_keys=True),
                         json.dumps(cr.derive_participants(["reasoning"], d2), sort_keys=True))

    def test_undeclared_capability_fails_closed_naming_it(self):
        r = cr.derive_participants(["reasoning", "candidate_repair"], {"A": decl("A", ["reasoning"])})
        self.assertSix(r)
        self.assertEqual(r["failed_predicate"], "EVERY_REQUESTED_CAPABILITY_DECLARED_BY_A_REGISTERED_ENTITY")
        self.assertEqual(r["evidence"]["not_declared_by_any_entity"], ["candidate_repair"])
        self.assertEqual(r["participants"], [])

    def test_malformed_requests_declarations_and_order_fail_closed(self):
        good = {"A": decl("A", ["reasoning"])}
        for bad_req in ([], None, "reasoning", [""], [1]):
            r = cr.derive_participants(bad_req, good)
            self.assertSix(r); self.assertEqual(r["failed_predicate"], "REQUESTED_CAPABILITIES_WELL_FORMED", bad_req)
        for bad_decl in (b"not json", b"[]", json.dumps({"schema": "x", "entity": "A", "capabilities": []}).encode(),
                         decl("B", ["reasoning"]), json.dumps({"schema": cr.DECLARATION_SCHEMA, "entity": "A",
                                                               "capabilities": "reasoning"}).encode()):
            r = cr.derive_participants(["reasoning"], {"A": bad_decl})
            self.assertSix(r); self.assertEqual(r["failed_predicate"], "ENTITY_DECLARATIONS_WELL_FORMED", bad_decl)
        for bad_order in (["A", "A"], ["A", "Z"], []):
            r = cr.derive_participants(["reasoning"], good, order=bad_order)
            self.assertSix(r); self.assertEqual(r["failed_predicate"], "ORDER_IS_A_PERMUTATION_OF_DECLARED_ENTITIES", bad_order)

    def test_routes_against_the_vendored_real_entity_declarations(self):
        d = {p.name: (p / "entity-capability.json").read_bytes() for p in REAL.iterdir() if p.is_dir()}
        r = cr.derive_participants(["adversarial_review"], d)
        self.assertEqual(r["disposition"], cr.ALLOW, r)
        self.assertEqual(r["participants"][0]["entity"], sorted(d)[0])
        self.assertIn("adversarial_review", json.loads(d[r["participants"][0]["entity"]])["capabilities"])

    def test_module_calls_no_model_and_no_network(self):
        text = (ROOT / "runtime/capability_routing.py").read_text()
        for banned in ("urllib", "requests", "http.client", "subprocess", "socket", "while True"):
            self.assertNotIn(banned, text)


if __name__ == "__main__":
    unittest.main()
