"""Every workflow in this repository runs only on repository events (C1): no manual workflow_dispatch entrypoint.

A run must be caused by an event on the repository (pull_request, push to main), so every result is bound to the
commit that triggered it. workflow_dispatch lets a run start with no change behind it, so it is refused here.
Parsed with the standard library only (no YAML dependency): the top-level `on:` block of each workflow.
"""
from __future__ import annotations
import re, unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EVENT_DRIVEN = {"pull_request", "push"}
FORBIDDEN = {"workflow_dispatch"}


def triggers(text: str) -> set[str]:
    """Event names under the top-level `on:` key (block mapping, flow list, or scalar form)."""
    m = re.search(r"^(?:on|\"on\"|'on'):[ \t]*(.*)$", text, re.M)
    if not m:
        return set()
    inline = m.group(1).split("#", 1)[0].strip()
    if inline:
        return {t.strip(" '\"") for t in inline.strip("[]").split(",") if t.strip(" '\"")}
    events = set()
    for line in text[m.end():].splitlines():
        if line.strip() == "" or line.lstrip().startswith("#"):
            continue
        if not line.startswith((" ", "\t")):
            break  # next top-level key
        k = re.match(r"^ {2}([A-Za-z_]+)\s*:", line) or re.match(r"^ {2}-\s*([A-Za-z_]+)\s*$", line)
        if k:
            events.add(k.group(1))
    return events


def six(code, predicate, detail):
    return {"failure_code": code, "failed_predicate": predicate,
            "required_evidence_or_repair": "trigger each listed workflow only on pull_request / push events",
            "retry_entrypoint": "python3 -B -m unittest tests.test_workflow_triggers",
            "owning_existing_goal": "SVORG-LLM-ORG-FOUNDATION-001",
            "next_attempt": "after the workflow triggers are committed", "detail": detail}


class WorkflowTriggers(unittest.TestCase):
    def workflows(self):
        wfs = sorted((ROOT / ".github/workflows").glob("*.y*ml"))
        self.assertTrue(wfs, "no workflows found")
        return wfs

    def test_no_workflow_is_manually_dispatchable(self):
        bad = []
        for wf in self.workflows():
            text = wf.read_text(encoding="utf-8")
            if triggers(text) & FORBIDDEN or re.search(r"^\s*-?\s*workflow_dispatch\b", text, re.M):
                bad.append(wf.name)
        self.assertEqual(bad, [], six("WORKFLOW_MANUAL_DISPATCH_PRESENT", "WORKFLOWS_ARE_EVENT_DRIVEN_ONLY", bad))

    def test_every_workflow_keeps_an_event_driven_trigger(self):
        missing = {wf.name: sorted(triggers(wf.read_text(encoding="utf-8"))) for wf in self.workflows()
                   if not triggers(wf.read_text(encoding="utf-8")) & EVENT_DRIVEN}
        self.assertEqual(missing, {}, six("WORKFLOW_EVENT_TRIGGER_ABSENT", "WORKFLOWS_ARE_EVENT_DRIVEN_ONLY", missing))

    def test_sandbox_runtime_triggers_are_pull_request_and_push(self):
        self.assertEqual(triggers((ROOT / ".github/workflows/sandbox-runtime.yml").read_text(encoding="utf-8")),
                         {"pull_request", "push"})

    def test_parser_sees_dispatch_in_every_form(self):
        for form in ("on:\n  push:\n  workflow_dispatch:\njobs: {}\n", "on: [push, workflow_dispatch]\n",
                     "on:\n  - push\n  - workflow_dispatch\n", "on: workflow_dispatch\n"):
            self.assertIn("workflow_dispatch", triggers(form), form)
        self.assertEqual(triggers("on:\n  pull_request:\n    branches: [main]\njobs:\n  a: {}\n"), {"pull_request"})


if __name__ == "__main__":
    unittest.main()
