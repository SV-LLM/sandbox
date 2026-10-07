"""AT-04 live credential-free llm.v1 call (manual workflow only; disabled until live/target.json is verified).

Evidence goes to EVIDENCE_DIR (repo ledger, org ledger, report, digest manifest),
which the workflow uploads as a 90-day artifact: live-run evidence retention,
not permanent custody. The parent transition is a workflow-local SV-LLM/.github
emit.py fixture, labeled as such in the report.
"""
from __future__ import annotations
import hashlib, importlib.util, json, os, subprocess, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOTGITHUB = Path(os.environ["SV_LLM_DOTGITHUB_ROOT"]).resolve()
EVIDENCE = Path(os.environ["EVIDENCE_DIR"]).resolve()
sys.path.insert(0, str(ROOT / "runtime"))


def write(path: Path, value) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def digest_manifest() -> None:
    files = {str(p.relative_to(EVIDENCE)): "sha256:" + hashlib.sha256(p.read_bytes()).hexdigest()
             for p in sorted(EVIDENCE.rglob("*")) if p.is_file() and p.name != "digests.json"}
    write(EVIDENCE / "digests.json", {"schema": "sv-llm.live-run-evidence-digests/v1",
                                      "retention_class": "LIVE_RUN_EVIDENCE_RETENTION_NOT_PERMANENT_CUSTODY",
                                      "files": files})


def main() -> int:
    target = json.loads((ROOT / "live/target.json").read_text())
    report = {"schema": "sv-llm.sandbox-live-llm-report/v1", "target_status": target.get("status"),
              "selected_space": target.get("selected_space"), "live_path_exercised": False,
              "successful_live_response_observed": False,
              "retention_class": "LIVE_RUN_EVIDENCE_RETENTION_NOT_PERMANENT_CUSTODY",
              "parent_transition_basis": "WORKFLOW_LOCAL_SV_LLM_DOTGITHUB_EMIT_FIXTURE",
              "authority_effect": "NONE"}
    if target.get("verified") is not True or not target.get("invocation"):
        report.update(disposition="FAIL_CLOSED", failed_predicate="LIVE_TARGET_SELECTED_AND_VERIFIED")
        write(EVIDENCE / "report.json", report)
        digest_manifest()
        print(json.dumps(report, indent=2))
        return 1

    os.environ["STEGVERSE_REPO_LEDGER_ROOT"] = str(EVIDENCE / "sandbox-repo-ledger")
    os.environ["STEGVERSE_ORG_LEDGER_ROOT"] = str(EVIDENCE / "sv-llm-org-ledger")
    from ledger import Ledger, sha
    from sandbox import Sandbox
    from stegbrowser_tool import StegBrowserTool
    spec = importlib.util.spec_from_file_location("agg", DOTGITHUB / "resident-runtime/aggregate_repo_transition.py")
    agg = importlib.util.module_from_spec(spec); spec.loader.exec_module(agg)
    propagate = lambda r, c: agg.aggregate_transition(r, org_transition_class=c, boundary_evidence={"source": "SV-LLM/sandbox"},
                                                      authority_effect="NONE")
    sb = Sandbox(dotgithub_root=DOTGITHUB, ledger=Ledger(EVIDENCE / "sandbox-repo-ledger"), propagate=propagate)
    subject = {"intended_action": "LIVE_LLM_V1_PROOF", "selected_space": target["selected_space"]}
    run = subprocess.run([sys.executable, str(DOTGITHUB / ".stegverse/transition-ledger/emit.py"),
                          "--transition-id", "LIVE_FIXTURE_PARENT:" + sha(subject)[7:31],
                          "--transition-class", "ORGANIZATION_INGRESS_MATERIALIZED",
                          "--predecessor-state-sha256", sha({"live": "predecessor"}),
                          "--successor-state-sha256", sha(subject), "--evidence-json", json.dumps({"disposition": "ALLOW"})],
                         capture_output=True, text=True, check=True,
                         env=dict(os.environ, STEGVERSE_REPO_LEDGER_ROOT=str(EVIDENCE / "dotgithub-fixture-ledger")))
    parent_repo = json.loads(run.stdout)
    parent_org = agg.aggregate_transition(parent_repo, org_transition_class="ORGANIZATION_INGRESS_MATERIALIZED", authority_effect="NONE")
    inv = dict(target["invocation"])
    work = {"schema": "sv-llm.sandbox-work/v0.1", "work_id": "live-llm-" + sha(inv)[7:19],
            "manifested_request": {"manifest_id": "live-llm-proof", "tool_invocations": [inv]},
            "parent_transition": {"transition_class": "ORGANIZATION_INGRESS_MATERIALIZED",
                                  "repo_receipt_sha256": parent_repo["receipt_sha256"],
                                  "org_receipt_sha256": parent_org["receipt_sha256"],
                                  "subject_or_artifact_digest": sha(subject)},
            "canonical_context_refs": [], "requested_capabilities": ["reasoning"], "permitted_capabilities": ["reasoning"],
            "participation_policy": {"mode": "SINGLE"},
            "expected_output_or_handoff": {"successor_transition_class": "SANDBOX_SYNTHESIS_RECORDED"}}
    admitted = sb.admit(json.dumps(work).encode(), parent_repo_receipt=parent_repo, parent_org_receipt=parent_org, subject=subject)
    obs = StegBrowserTool(sb).invoke(work["work_id"], inv["invocation_id"])
    synth = sb.synthesize(work["work_id"], [obs["observation_id"]], {"summary": "AT-04 live credential-free llm.v1 proof"})
    done = sb.complete(work["work_id"])
    report.update(work_id=work["work_id"], admitted=admitted["disposition"], observation_id=obs["observation_id"],
                  disposition=obs["disposition"], failed_predicate=obs.get("failed_predicate"),
                  evaluation_stage=obs.get("evaluation_stage"),
                  live_path_exercised=bool(obs.get("stegbrowser_invoked")),
                  successful_live_response_observed=obs["disposition"] == "ALLOW",
                  synthesis=synth["disposition"], completion=done["disposition"],
                  org_readback=[r["repo_receipt_sha256"] for r in
                                (json.loads(p.read_text()) for p in sorted((EVIDENCE / "sv-llm-org-ledger/receipts").glob("*.json")))
                                if r.get("source_repository") == "SV-LLM/sandbox"],
                  repo_receipts=[r["receipt_sha256"] for r in sb.ledger.chain()])
    write(EVIDENCE / "report.json", report)
    digest_manifest()
    print(json.dumps(report, indent=2))
    return 0 if report["successful_live_response_observed"] and done["disposition"] == "ALLOW" else 1


if __name__ == "__main__":
    sys.exit(main())
