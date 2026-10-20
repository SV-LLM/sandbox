"""SV-LLM work cycle, end to end, offline: one manifest from a peer organization in, one result out.

A peer organization (StegVerse-Labs, materialized by SV-LLM/.github
org-runtime/tests/peer_organization.py with its own kernel and ledgers)
publishes a manifest addressed to SV-LLM/sandbox. One runtime/work_cycle.py
pass then runs: boundary ingress (materialization), Sandbox intake (manifest
selection, admission against the ingress receipts, assignment, request),
entity response (the real entity core packages, vendored in tests/real_entities,
answering UNAVAILABLE: no SV-LLM code invokes a model),
synthesis, completion and result egress to the peer, which consumes it.
Every step is on the organization ledger. No network, no external machine.
Source-level evidence only: CI-class, never SANDBOX_RUNTIME_OBSERVED.

Run: SV_LLM_DOTGITHUB_ROOT=<SV-LLM/.github checkout> python -B tests/test_work_cycle.py
"""
from __future__ import annotations
import importlib.util, json, os, sys, tempfile, unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOTGITHUB = Path(os.environ["SV_LLM_DOTGITHUB_ROOT"]).resolve()
sys.path.insert(0, str(ROOT / "runtime"))
sys.path.insert(0, str(ROOT / "tests"))
from work_cycle import WorkCycle, Entity, SERVICE, NO_INVOCATION  # noqa: E402

REAL = ROOT / "tests/real_entities"
VENDORED = tuple(json.loads((REAL / "vendor-manifest.json").read_text())["sources"])
STANDING = {"mode": "ESTABLISH_GENESIS", "node_ref": "sv-llm-work-cycle-test-node", "predecessor": None}
ROUTE = SERVICE["admits_processing"][0]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def manifest(manifest_id, *, processing=ROUTE, participants=None, work=True):
    m = {"manifest_id": manifest_id, "destination": {"organization": "SV-LLM", "repository": "sandbox"},
         "return_to": {"organization": "StegVerse-Labs"}, "payload": {}}
    if processing is not None:
        m["processing"] = dict(processing)
    if work:
        m["payload"]["work"] = {
            "intent": "review the supplied contract for internal contradictions",
            "requested_capabilities": ["adversarial_review"], "permitted_capabilities": ["adversarial_review"],
            "participation_policy": {"mode": "MULTIPLE"},
            "expected_output_or_handoff": {"output_schema": "sv-llm.sandbox-work-cycle-synthesis/v1"},
            "participants": participants if participants is not None else
            [{"entity": "Anthropic", "capability": "adversarial_review"},
             {"entity": "OpenAI", "capability": "adversarial_review"}]}
    return m


def chain(ledger: Path):
    head = json.loads((ledger / "HEAD.json").read_text())["receipt_sha256"]
    rows = []
    while head:
        r = json.loads((ledger / "receipts" / (head.split(":", 1)[1] + ".json")).read_text())
        rows.append(r)
        head = r["previous_receipt_sha256"]
    return rows[::-1]


class WorkCycleEndToEnd(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        base = Path(self.tmp.name)
        self.base = base
        os.environ["STEGVERSE_REPO_LEDGER_ROOT"] = str(base / "dotgithub-ledger")
        os.environ["STEGVERSE_ORG_LEDGER_ROOT"] = str(base / "org-ledger")
        self.mesh = base / "mesh"
        self.entities = {e: Entity(REAL / e / "core.py", REAL / e / "entity-capability.json")
                         for e in ("Anthropic", "OpenAI")}
        self.cycle = WorkCycle(dotgithub=DOTGITHUB, sandbox_ledger=base / "sandbox-ledger",
                               node_state_root=base / "node-state", entities=self.entities)
        self.cycle.crossing.open_organization_ledger(root=DOTGITHUB)
        peers = load("peer_organization", DOTGITHUB / "org-runtime/tests/peer_organization.py")
        self.labs = peers.materialize(base / "peers", "StegVerse-Labs",
                                      [{"service_id": "stegverse-labs.org-control", "repository": "StegVerse-Labs/.github",
                                        "boundary_role": "BOUNDARY_LOCAL_CONTROL"}])

    def tearDown(self):
        self.tmp.cleanup()

    def send(self, m):
        k = self.labs.kernel
        self.labs.publish(k.build_packet(origin_org="StegVerse-Labs", origin_service="stegverse-labs.org-control",
                                         destination_org="SV-LLM", destination_service="sv-llm.org-control",
                                         payload={"manifest": m}, standing=STANDING, packet_id="in-" + m["manifest_id"]),
                          mesh_root=self.mesh)

    def run_pass(self):
        return self.cycle.run(standing=STANDING, mesh_root=self.mesh)

    def test_one_manifest_runs_the_whole_cycle_and_returns_a_result(self):
        self.send(manifest("work-cycle-001"))
        out = self.run_pass()
        self.assertEqual([r["transition_class"] for r in out["ingress"]], ["ORGANIZATION_INGRESS_MATERIALIZED"])
        taken, = out["intake"]
        self.assertEqual(taken["admit"]["disposition"], "ALLOW", taken["admit"])
        self.assertEqual(taken["selection"]["processing_selection"], "MANIFEST_DECLARED")
        self.assertEqual([a["disposition"] for a in taken["assign"] + taken["request"]], ["ALLOW"] * 4)
        self.assertEqual([(r["disposition"], r["status"]) for r in out["respond"]], [("ALLOW", "UNAVAILABLE")] * 2)
        closed, = out["close"]
        self.assertEqual((closed["synthesize"]["disposition"], closed["complete"]["disposition"]), ("ALLOW", "ALLOW"))
        self.assertEqual(closed["egress"]["transition_class"], "ORGANIZATION_EGRESS_EMITTED")
        self.assertIs(closed["egress"]["awaits_receiver"], False)

        # The Sandbox's parent is the boundary's ingress receipt pair; every Sandbox step reached the org ledger.
        work = self.cycle.sandbox._work("work-cycle-001")
        self.assertEqual(work["parent_transition"]["org_receipt_sha256"], out["ingress"][0]["org_receipt_sha256"])
        self.assertEqual(self.cycle.sandbox.pending_propagation(), [])
        org = [r["org_transition_class"] for r in chain(self.base / "org-ledger")]
        self.assertEqual(org, ["ORGANIZATION_LEDGER_OPENED", "ORGANIZATION_INGRESS_MATERIALIZED", "SANDBOX_WORK_ADMITTED",
                               "CAPABILITY_ASSIGNMENT", "CONTRIBUTION_REQUESTED", "CAPABILITY_ASSIGNMENT",
                               "CONTRIBUTION_REQUESTED", "ENTITY_CONTRIBUTION_RECORDED", "ENTITY_CONTRIBUTION_RECORDED",
                               "SANDBOX_SYNTHESIS_RECORDED", "SANDBOX_WORK_COMPLETED", "ORGANIZATION_EGRESS_EMITTED"])
        rebuilt = self.cycle.sandbox.reconstruct("work-cycle-001")
        self.assertEqual(rebuilt["work_id"], "work-cycle-001")
        for r in self.cycle.sandbox.contributions("work-cycle-001"):
            self.assertEqual(r["evidence"]["envelope"]["non_success_status_record"]["reason_or_failed_predicate"],
                             NO_INVOCATION)

        # The peer consumes the result from the mesh, whenever it runs.
        got = self.labs.consume_addressed(mesh_root=self.mesh)
        self.assertEqual(len(got), 1)
        payload = got[0]["result"]["packet"]["payload"]["manifest"]["payload"]
        self.assertEqual((payload["schema"], payload["request_manifest_id"]),
                         ("sv-llm.sandbox-work-result/v1", "work-cycle-001"))
        self.assertEqual(payload["synthesis"]["non_success"], 2)

        # A second pass changes nothing: every step is taken once.
        again = self.run_pass()
        self.assertEqual((again["ingress"], again["intake"], again["respond"]), ([], [], []))
        self.assertEqual([c.get("egress") for c in again["close"]], [None])
        self.assertEqual(len(chain(self.base / "org-ledger")), len(org))

    def test_participants_derived_from_declarations_route_without_consulting_availability(self):
        self.send(manifest("work-cycle-derive-001", participants="DERIVE_FROM_DECLARATIONS"))
        out = self.run_pass()
        taken, = out["intake"]
        self.assertEqual(taken["admit"]["disposition"], "ALLOW", taken["admit"])
        self.assertEqual(taken["routing"]["disposition"], "ALLOW", taken["routing"])
        # The organization tree's row order decides precedence (OpenAI precedes Anthropic there), never the name.
        self.assertEqual(taken["routing"]["participants"], [{"entity": "OpenAI", "capability": "adversarial_review"}])
        self.assertEqual(taken["routing"]["evidence"]["alternates"], {"adversarial_review": ["Anthropic"]})
        self.assertEqual(taken["routing"]["evidence"]["order"], ["OpenAI", "Anthropic"])
        self.assertEqual([a["disposition"] for a in taken["assign"] + taken["request"]], ["ALLOW"] * 2)
        closed, = out["close"]
        self.assertEqual(closed["complete"]["disposition"], "ALLOW")
        self.assertIs(closed["egress"]["awaits_receiver"], False)

    def test_a_question_drives_the_cycle_from_the_entity_classifier_to_a_result(self):
        """question text -> Ecosystem_Chat classify.select -> requested capabilities -> participants derived from
        declarations in tree order -> request -> answer -> result. No model, no network, declarations only."""
        classify = load("sv_llm_ecosystem_chat_classify", REAL / "Ecosystem_Chat/classify.py")
        chat = Entity(REAL / "Ecosystem_Chat/core.py", REAL / "Ecosystem_Chat/entity-capability.json")
        declared = json.loads(chat.declaration)["capabilities"]
        selection = classify.select({"text": "Do the entity-capability contracts in SV-LLM/.github and "
                                              "Ecosystem_Chat agree on the binding?"}, declared)
        self.assertEqual(selection["disposition"], "ALLOW", selection)
        self.assertEqual(selection["selected"][0], "cross_repository_contract_analysis")
        self.cycle.entities = {**self.entities, "Ecosystem_Chat": chat}
        m = manifest("work-cycle-question-001", participants="DERIVE_FROM_DECLARATIONS")
        m["payload"]["work"]["requested_capabilities"] = selection["selected"][:1]
        m["payload"]["work"]["permitted_capabilities"] = selection["selected"][:1]
        self.send(m)
        out = self.run_pass()
        taken, = out["intake"]
        # Ecosystem_Chat precedes every provider on the tree and declares the capability, so it carries the request.
        self.assertEqual(taken["routing"]["participants"],
                         [{"entity": "Ecosystem_Chat", "capability": "cross_repository_contract_analysis"}])
        self.assertEqual(taken["routing"]["evidence"]["order"][0], "Ecosystem_Chat")
        self.assertEqual([a["disposition"] for a in taken["assign"] + taken["request"]], ["ALLOW", "ALLOW"])
        self.assertEqual([(r["disposition"], r["status"]) for r in out["respond"]], [("ALLOW", "UNAVAILABLE")])
        closed, = out["close"]
        self.assertEqual(closed["complete"]["disposition"], "ALLOW")
        self.assertIs(closed["egress"]["awaits_receiver"], False)

    def test_an_underivable_request_is_refused_with_six_fields_and_recorded(self):
        # Every vendored provider declares the whole vocabulary, so narrow the registered declarations
        # to one that lacks adversarial_review: routing must then refuse, consulting nothing else.
        from types import SimpleNamespace
        narrowed = {"schema": "sv-llm.entity-capability/v0.1", "capabilities": ["reasoning"]}
        self.cycle.entities = {n: SimpleNamespace(name=n, declaration=json.dumps({**narrowed, "entity": n}).encode())
                               for n in self.entities}
        self.send(manifest("work-cycle-derive-002", participants="DERIVE_FROM_DECLARATIONS"))
        taken, = self.run_pass()["intake"]
        self.assertEqual(taken["admit"]["disposition"], "ALLOW")
        self.assertEqual(taken["routing"]["disposition"], "FAIL_CLOSED")
        refused, = taken["assign"]
        self.assertEqual((refused["disposition"], refused["failed_predicate"]),
                         ("DENY", "PARTICIPANTS_DERIVABLE_FROM_DECLARATIONS"))
        six = refused["routing"]
        self.assertEqual(six["failed_predicate"], "EVERY_REQUESTED_CAPABILITY_DECLARED_BY_A_REGISTERED_ENTITY")
        self.assertEqual(sorted(six), ["failed_predicate", "failure_code", "next_attempt", "owning_existing_goal",
                                       "required_evidence_or_repair", "retry_entrypoint"])
        self.assertEqual(taken["request"], [])

    def test_a_request_without_an_entity_surface_stays_outstanding_and_nothing_waits(self):
        self.send(manifest("work-cycle-002"))
        c = self.cycle
        c.crossing.ingress(mesh_root=self.mesh, node_state_root=c.node_state_root, root=DOTGITHUB)
        taken, = c.intake()
        self.assertEqual(len(taken["request"]), 2)
        c.entities = {"Anthropic": self.entities["Anthropic"]}   # OpenAI's surface is not present on this pass
        self.assertEqual(len(c.respond()), 1)
        self.assertEqual(c.close(standing=STANDING, mesh_root=self.mesh), [])   # not closed; the pass returned
        self.assertEqual(c._outstanding("work-cycle-002"), [("OpenAI", "adversarial_review")])
        c.entities = self.entities                                 # a later pass with OpenAI's surface
        later = self.run_pass()
        self.assertEqual(len(later["respond"]), 1)
        self.assertEqual(later["close"][0]["complete"]["disposition"], "ALLOW")

    def test_processing_is_selected_only_by_an_admitted_manifest_declaration(self):
        cases = {"no-processing": manifest("no-processing", processing=None),
                 "wrong-route": manifest("wrong-route", processing={"capability": ROUTE["capability"],
                                                                   "route_id": "another.route"}),
                 "wrong-capability": manifest("wrong-capability", processing={"capability": "something-else",
                                                                             "route_id": ROUTE["route_id"]}),
                 "no-work": manifest("no-work", work=False)}
        for m in cases.values():
            self.send(m)
        out = self.run_pass()
        refused = {t["admit"]["failed_predicate"] for t in out["intake"]}
        self.assertEqual(refused, {"PROCESSING_SELECTED_BY_ADMITTED_MANIFEST", "WORK_DECLARED_BY_MANIFEST"})
        self.assertEqual(sum(t["admit"]["failed_predicate"] == "PROCESSING_SELECTED_BY_ADMITTED_MANIFEST"
                             for t in out["intake"]), 3)
        self.assertTrue(all(t["admit"]["disposition"] == "DENY" and t["admit"]["org_receipt_sha256"]
                            for t in out["intake"]))
        self.assertEqual((out["respond"], out["close"]), ([], []))

    def test_every_registered_intelligence_provider_answers_in_one_cycle(self):
        tree = json.loads((DOTGITHUB / "data/organization-tree.json").read_text())
        providers = {r["name"] for r in tree["repositories"] if r["class"] == "INTELLIGENCE_PROVIDER"}
        self.assertEqual(len(providers), 18)
        self.assertEqual(set(VENDORED), providers)
        self.cycle.entities = {e: Entity(REAL / e / "core.py", REAL / e / "entity-capability.json") for e in VENDORED}
        self.send(manifest("work-cycle-004", participants=[{"entity": e, "capability": "adversarial_review"}
                                                           for e in sorted(providers)]))
        out = self.run_pass()
        taken, = out["intake"]
        self.assertEqual(taken["admit"]["disposition"], "ALLOW", taken["admit"])
        self.assertEqual([a["disposition"] for a in taken["assign"]], ["ALLOW"] * 18, taken["assign"])
        self.assertEqual(len(taken["request"]), 18)
        self.assertEqual(sorted(r["evidence"]["entity"] for r in self.cycle.sandbox.contributions("work-cycle-004")),
                         sorted(providers))
        self.assertEqual({(r["disposition"], r["status"]) for r in out["respond"]}, {("ALLOW", "UNAVAILABLE")})
        closed, = out["close"]
        self.assertEqual(closed["complete"]["disposition"], "ALLOW")
        got = self.labs.consume_addressed(mesh_root=self.mesh)
        payload = got[0]["result"]["packet"]["payload"]["manifest"]["payload"]
        self.assertEqual((payload["synthesis"]["contributed"], payload["synthesis"]["non_success"]), (0, 18))

    def test_an_unregistered_participant_is_refused_and_recorded(self):
        self.send(manifest("work-cycle-003", participants=[{"entity": "NotAnSvLlmEntity",
                                                            "capability": "adversarial_review"}]))
        out = self.run_pass()
        taken, = out["intake"]
        self.assertEqual(taken["admit"]["disposition"], "ALLOW")
        assigned, = taken["assign"]
        self.assertEqual(assigned["disposition"], "DENY")
        self.assertTrue(assigned["org_receipt_sha256"])
        self.assertEqual((taken["request"], out["close"]), ([], []))


    def _proposal_round_trip(self, manifest_id, *, content):
        import base64
        import test_conformance_proposal as fixture
        m = manifest(manifest_id)
        m["payload"]["sdk_proposal"] = {
            "conformance_proposal": fixture.proposal(),
            "canonical_source_attachments": [{"repository": fixture.REPO, "path": fixture.PATH,
                                              "revision": fixture.REVISION,
                                              "content_base64": base64.b64encode(content).decode("ascii")}]}
        self.send(m)
        out = self.run_pass()
        closed, = out["close"]
        self.assertEqual(closed["egress"]["transition_class"], "ORGANIZATION_EGRESS_EMITTED")
        got = self.labs.consume_addressed(mesh_root=self.mesh)
        return got[0]["result"]["packet"]["payload"]["manifest"]["payload"]["sdk_proposal_conformance"], fixture

    def test_a_manifest_carried_sdk_proposal_is_evaluated_and_offered_only_on_allow(self):
        import test_conformance_proposal as fixture
        conformance, fixture = self._proposal_round_trip("work-cycle-004", content=fixture.CONTENT)
        self.assertEqual(conformance["evaluation"]["disposition"], "ALLOW", conformance["evaluation"])
        self.assertIs(conformance["proposal_offered_to_sdk"], True)
        self.assertEqual(conformance["proposal"], fixture.proposal())

    def test_canonical_bytes_that_do_not_match_the_cited_digest_are_not_offered(self):
        conformance, _ = self._proposal_round_trip("work-cycle-005", content=b'{"tampered": true}')
        self.assertEqual(conformance["evaluation"]["disposition"], "FAIL_CLOSED")
        self.assertIn("CANONICAL_SOURCE_BOUND", conformance["evaluation"]["failed_predicates"])
        self.assertIs(conformance["proposal_offered_to_sdk"], False)
        self.assertIsNone(conformance["proposal"])

if __name__ == "__main__":
    unittest.main()
