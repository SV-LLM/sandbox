"""Every GitHub Action this repository uses is pinned to a commit SHA (owner directive: no floating dependencies).

A floating tag or branch (actions/checkout@v4, @main) lets the action's bytes change under a workflow without
any change here; a 40-hex commit pins them. The resolved tag is kept as a trailing comment for readers.
"""
from __future__ import annotations
import re, unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
USES = re.compile(r"^\s*-?\s*uses:\s*([^\s#]+)", re.M)
PINNED = re.compile(r"^[^@]+@[0-9a-f]{40}$")


class WorkflowActionPins(unittest.TestCase):
    def test_every_uses_is_pinned_to_a_commit_sha(self):
        floating = []
        for wf in sorted((ROOT / ".github/workflows").glob("*.yml")):
            for ref in USES.findall(wf.read_text(encoding="utf-8")):
                if ref.startswith("./"):
                    continue  # a local composite action is this repository's own bytes
                if not PINNED.fullmatch(ref):
                    floating.append(f"{wf.name}: {ref}")
        self.assertEqual(floating, [], {"failure_code": "WORKFLOW_ACTION_NOT_PINNED",
                                        "failed_predicate": "EVERY_USES_PINNED_TO_COMMIT_SHA",
                                        "required_evidence_or_repair": "pin each listed uses: to a 40-hex commit with the tag as a comment",
                                        "retry_entrypoint": "python3 -B -m unittest tests.test_workflow_action_pins",
                                        "owning_existing_goal": "SVORG-LLM-ORG-FOUNDATION-001",
                                        "next_attempt": "after the pins are committed", "floating": floating})


if __name__ == "__main__":
    unittest.main()
