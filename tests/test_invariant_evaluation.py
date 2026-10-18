"""RT-INVARIANT-EVALUATION-001 tests (offline, standard library).

Subjects are byte-for-byte copies of canonical StegVerse-Labs/.github files at
the revision pinned in tests/fixtures/invariant_evaluation/vendor-manifest.json.
The DENY case needs a subject that contradicts a canonical value; no real
record does (the registry gate forbids it), so that subject is a clearly
labelled synthetic fixture built in the test.
Run: python -B tests/test_invariant_evaluation.py
"""
from __future__ import annotations
import hashlib, json, shutil, sys, tempfile, unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "runtime"))
import invariant_evaluation as ie  # noqa: E402

FIX = ROOT / "tests/fixtures/invariant_evaluation"
MANIFEST = json.loads((FIX / "vendor-manifest.json").read_text())
LABS = FIX / "StegVerse-Labs.github"
REPO = MANIFEST["source_repository"]
REV = MANIFEST["source_revision"]
CANON = "data/task-registry-global-invariants.json"
SPEAKS = "data/canonical-task-records/SDK-GENERIC-MANIFEST-ECOSYSTEM-INVARIANT-005.json"   # asserts the key
PROSE_ONLY = "data/canonical-task-records/STEGDB-ORGANIZATION-ROLE-VERSION-PROPAGATION-002.json"  # names it in prose only
SILENT = "data/canonical-task-records/ADMISSIBILITY-WIKI-PUBLIC-DOMAIN-001.json"
IID = "invariant:external_machine_awaiting_allowed"
SIX = ("failure_code", "failed_predicate", "required_evidence_or_repair", "retry_entrypoint",
       "owning_existing_goal", "next_attempt")


def src(path: str, content: bytes | None = None) -> dict:
    return {"repository": REPO, "path": path, "revision": REV,
            "content": content if content is not None else (LABS / path).read_bytes()}


def question(subject_path: str, iid: str = IID, qid: str = "q-1") -> dict:
    return {"schema": ie.QUESTION_SCHEMA, "question_id": qid, "invariant_id": iid,
            "owning_existing_goal": "SDK-GENERIC-MANIFEST-ECOSYSTEM-INVARIANT-005",
            "invariants_source": {"repository": REPO, "path": CANON, "revision": REV},
            "subject": {"repository": REPO, "path": subject_path, "revision": REV}}


class InvariantEvaluation(unittest.TestCase):
    def setUp(self):
        self.queue = Path(tempfile.mkdtemp(prefix="relay-queue-"))

    def tearDown(self):
        shutil.rmtree(self.queue, ignore_errors=True)

    def assertSixFields(self, r):
        for k in SIX:
            self.assertTrue(isinstance(r.get(k), str) and r[k].strip(), (k, r))
        self.assertTrue(r["evidence_refs"], r)

    def test_vendored_fixtures_match_manifest(self):
        for rel, digest in MANIFEST["files"].items():
            self.assertEqual("sha256:" + hashlib.sha256((LABS / rel).read_bytes()).hexdigest(), digest, rel)

    def test_positive_record_asserting_canonical_value_is_allowed_with_line_citations(self):
        r = ie.evaluate(question(SPEAKS), [src(CANON), src(SPEAKS)], self.queue)
        self.assertEqual(r["disposition"], ie.ALLOW, r)
        self.assertEqual(r["authority_effect"], "NONE")
        self.assertNotIn("failure_code", r)
        for c in r["citations"]:
            repo_rev, path, line = c.rsplit(":", 2)
            self.assertEqual(repo_rev, f"{REPO}@{REV}")
            text = (LABS / path).read_text(encoding="utf-8").splitlines()[int(line) - 1]
            self.assertTrue(any(t in text for t in ("external_machine_awaiting_allowed", '"schema"', "{")), (c, text))
        self.assertTrue([c for c in r["citations"] if SPEAKS in c and not c.endswith(":1")], r["citations"])
        self.assertEqual(list(self.queue.iterdir()), [])

    def test_negative_synthetic_subject_contradicting_canonical_false_is_denied(self):
        synthetic = json.dumps({"schema": "SYNTHETIC_FIXTURE_NOT_A_CANONICAL_RECORD",
                                "runtime": {"external_machine_awaiting_allowed": True}}, indent=2).encode()
        r = ie.evaluate(question("fixtures/synthetic-contradiction.json"),
                        [src(CANON), src("fixtures/synthetic-contradiction.json", synthetic)], self.queue)
        self.assertEqual(r["disposition"], ie.DENY, r)
        self.assertEqual(r["failed_predicate"], "INVARIANT_CONFORMS")
        self.assertSixFields(r)
        self.assertTrue(any(c.endswith("fixtures/synthetic-contradiction.json:4") for c in r["citations"]), r["citations"])
        self.assertEqual(list(self.queue.iterdir()), [])

    def test_undecidable_silent_record_routes_to_relay_queue_file(self):
        r = ie.evaluate(question(SILENT, qid="q-silent"), [src(CANON), src(SILENT)], self.queue)
        self.assertEqual(r["disposition"], ie.UNDECIDABLE, r)
        self.assertEqual(r["failed_predicate"], "SUBJECT_SPEAKS_TO_INVARIANT")
        self.assertSixFields(r)
        entry = Path(r["relay_queue_entry"])
        self.assertEqual(entry.parent, self.queue)
        data = json.loads(entry.read_text())
        self.assertEqual(data["schema"], ie.QUEUE_SCHEMA)
        self.assertIs(data["github_call_made"], False)
        self.assertEqual(data["result"]["disposition"], ie.UNDECIDABLE)
        # idempotent by question_id
        ie.evaluate(question(SILENT, qid="q-silent"), [src(CANON), src(SILENT)], self.queue)
        self.assertEqual(len(list(self.queue.iterdir())), 1)

    def test_prose_mention_only_is_not_an_assertion(self):
        r = ie.evaluate(question(PROSE_ONLY, qid="q-prose"), [src(CANON), src(PROSE_ONLY)], self.queue)
        self.assertEqual(r["disposition"], ie.UNDECIDABLE, r)

    def test_prohibition_id_resolves_and_silence_is_undecidable(self):
        r = ie.evaluate(question(SILENT, iid="prohibition:NO_EXTERNAL_MACHINE_AWAITING_AS_TRANSITION_PREDICATE", qid="q-p"),
                        [src(CANON), src(SILENT)], self.queue)
        self.assertEqual(r["disposition"], ie.UNDECIDABLE, r)
        self.assertTrue(any(CANON in c for c in r["citations"]))

    def test_unknown_invariant_id_fails_closed(self):
        r = ie.evaluate(question(SPEAKS, iid="invariant:not_a_real_key"), [src(CANON), src(SPEAKS)], self.queue)
        self.assertEqual((r["disposition"], r["failed_predicate"]), (ie.FAIL_CLOSED, "INVARIANT_ID_CANONICAL"), r)
        self.assertSixFields(r)

    def test_missing_or_digest_mismatched_source_fails_closed(self):
        r = ie.evaluate(question(SPEAKS), [src(CANON)], self.queue)
        self.assertEqual((r["disposition"], r["failed_predicate"]), (ie.FAIL_CLOSED, "SUBJECT_SOURCE_BOUND"), r)
        q = question(SPEAKS)
        q["invariants_source"]["digest"] = "sha256:" + "0" * 64
        r = ie.evaluate(q, [src(CANON), src(SPEAKS)], self.queue)
        self.assertEqual((r["disposition"], r["failed_predicate"]), (ie.FAIL_CLOSED, "CANONICAL_SOURCE_BOUND"), r)

    def test_truncated_subject_fails_closed_instead_of_crashing(self):
        for bad in (b'{"a": 1', b'[1, 2', b'{"a": [1,', b'{'):
            r = ie.evaluate(question("fixtures/truncated.json"), [src(CANON), src("fixtures/truncated.json", bad)], self.queue)
            self.assertEqual((r["disposition"], r["failed_predicate"]), (ie.FAIL_CLOSED, "SUBJECT_SOURCE_BOUND"), bad)
            self.assertSixFields(r)

    def test_authority_effect_must_be_a_NONE_variant(self):
        canon = json.loads((LABS / CANON).read_text())
        for value, expected in (("NONE_TEST_FIXTURE", ie.ALLOW), ("GRANTS_ADMISSION", ie.FAIL_CLOSED)):
            doc = dict(canon, authority_effect=value)
            r = ie.evaluate(question(SPEAKS), [src(CANON, json.dumps(doc, indent=2).encode()), src(SPEAKS)], self.queue)
            self.assertEqual(r["disposition"], expected, (value, r))

    def test_deeply_nested_subject_fails_closed_without_recursion_error(self):
        deep = ("[" * 5000).encode()
        r = ie.evaluate(question("fixtures/deep.json"), [src(CANON), src("fixtures/deep.json", deep)], self.queue)
        self.assertEqual((r["disposition"], r["failed_predicate"]), (ie.FAIL_CLOSED, "SUBJECT_SOURCE_BOUND"), r)

    def test_type_loose_assertions_are_not_conformance(self):
        for v in (0, 1, "false", None, 0.0):
            synthetic = json.dumps({"runtime": {"external_machine_awaiting_allowed": v}}).encode()
            r = ie.evaluate(question("fixtures/loose.json"), [src(CANON), src("fixtures/loose.json", synthetic)], self.queue)
            self.assertEqual(r["disposition"], ie.DENY, (v, r["disposition"]))

    def test_line_numbers_scale_linearly_enough(self):
        import time
        big = ("{" + ",".join(f'"k{i}": {i}' for i in range(80000)) + "}").encode()
        t0 = time.perf_counter()
        r = ie.evaluate(question("fixtures/big.json"), [src(CANON), src("fixtures/big.json", big)], self.queue)
        self.assertLess(time.perf_counter() - t0, 5.0)
        self.assertEqual(r["disposition"], ie.UNDECIDABLE)

    def test_queue_entries_do_not_collide_on_sanitised_ids(self):
        for qid in ("a/b", "a_b"):
            ie.evaluate(question(SILENT, qid=qid), [src(CANON), src(SILENT)], self.queue)
        self.assertEqual(len(list(self.queue.iterdir())), 2)

    def test_malformed_question_fails_closed(self):
        r = ie.evaluate({"schema": "nope"}, [], self.queue)
        self.assertEqual((r["disposition"], r["failed_predicate"]), (ie.FAIL_CLOSED, "QUESTION_WELL_FORMED"))
        self.assertSixFields(r)

    def test_component_never_fetches(self):
        text = (ROOT / "runtime/invariant_evaluation.py").read_text()
        for banned in ("urllib", "requests", "http.client", "subprocess", "socket"):
            self.assertNotIn(banned, text, banned)


if __name__ == "__main__":
    unittest.main()
