"""AT-04 Stage 2, first test: load each provider's public LLM URL in an ephemeral StegBrowser session and screenshot it.

Manual workflow only (.github/workflows/sandbox-stage2-page-load.yml). Conformance lane:
WORKFLOW_LOCAL_ORGANIZATION_LEDGER_CONFORMANCE, as AT-04 Stage 1 runs it (live/run_live_llm.py):
a fresh workflow-local organization ledger opened with a declared GENESIS and a workflow-local
SV-LLM/.github emit.py fixture parent; never authoritative organization runtime reality.

One admitted work item declares one page_load.v1 invocation per target in live/page_load_targets.json
(PAGE_LOAD_REPOSITORIES, comma-separated, narrows the set). Each invocation runs through
runtime/page_load_tool.py and is recorded as SANDBOX_TOOL_OBSERVATION_RECORDED; the work item is then
synthesized over every observation and completed. Nothing is typed, clicked or submitted.

EVIDENCE_DIR receives report.json, digests.json, both ledgers, and test-results/<Repository>/
{screenshot.png, page-load.json} for each target. The calling workflow uploads it as a 90-day artifact
(live-run evidence retention, not permanent custody). Exit 0 only when every observation is ALLOW and
the work item completes; an ALLOW observation can still show an HTTP 403 or a bot challenge, which is
what the browser saw, recorded as such.
"""
from __future__ import annotations
import json, os, subprocess, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "runtime"))
sys.path.insert(0, str(ROOT / "live"))
import run_live_llm as stage1  # noqa: E402  shared ledger and evidence helpers

INTENDED_ACTION = "STEGBROWSER_STAGE2_PAGE_LOAD"
EVIDENCE_CLASS = stage1.EVIDENCE_CLASS[stage1.CONFORMANCE]


def targets(selected: str | None) -> list[dict]:
    doc = json.loads((ROOT / "live/page_load_targets.json").read_text())
    rows = doc["targets"]
    if selected:
        wanted = [s.strip() for s in selected.split(",") if s.strip()]
        unknown = sorted(set(wanted) - {t["repository"] for t in rows})
        if unknown:
            raise SystemExit(f"unknown repositories: {unknown}")
        rows = [t for t in rows if t["repository"] in wanted]
    return rows


def main(argv=None, *, playwright_factory=None) -> int:
    DOTGITHUB = Path(os.environ["SV_LLM_DOTGITHUB_ROOT"]).resolve()
    EVIDENCE = Path(os.environ["EVIDENCE_DIR"]).resolve()
    rows = targets(os.environ.get("PAGE_LOAD_REPOSITORIES"))
    invocations = [{"invocation_id": "page-load-" + t["repository"], "tool": "StegBrowser", "profile": "page_load.v1",
                    "repository": t["repository"], "secure_url": t["secure_url"],
                    "allowed_origins": t["allowed_origins"], "lease_seconds": 300} for t in rows]
    report = {"schema": "sv-llm.sandbox-stage2-page-load-report/v1", "stage": INTENDED_ACTION,
              "lane": stage1.CONFORMANCE, "evidence_class": EVIDENCE_CLASS, "executed_by": stage1.organization_execution(),
              "authoritative_organization_runtime_reality": False, "interaction": "NONE", "credentials": "NONE",
              "proves_provider_integration": False, "retention_class": stage1.RETENTION, "authority_effect": "NONE",
              "parent_transition_basis": stage1.PARENT_BASIS[stage1.CONFORMANCE]}

    os.environ["STEGVERSE_REPO_LEDGER_ROOT"] = str(EVIDENCE / "sandbox-repo-ledger")
    from ledger import Ledger, sha
    from sandbox import Sandbox
    from page_load_tool import StegBrowserPageLoadTool
    subject = {"intended_action": INTENDED_ACTION, "repositories": [t["repository"] for t in rows]}
    agg = stage1.load_dotgithub(DOTGITHUB)
    store = stage1.store_opener(agg)(EVIDENCE / "sv-llm-org-ledger")
    run = subprocess.run([sys.executable, str(DOTGITHUB / ".stegverse/transition-ledger/emit.py"),
                          "--transition-id", "STAGE2_PAGE_LOAD_FIXTURE_PARENT:" + sha(subject)[7:31],
                          "--transition-class", "ORGANIZATION_INGRESS_MATERIALIZED",
                          "--predecessor-state-sha256", sha({"live": "predecessor"}),
                          "--successor-state-sha256", sha(subject), "--evidence-json", json.dumps({"disposition": "ALLOW"})],
                         capture_output=True, text=True, check=True,
                         env=dict(os.environ, STEGVERSE_REPO_LEDGER_ROOT=str(EVIDENCE / "dotgithub-fixture-ledger")))
    parent_repo = json.loads(run.stdout)
    parent_org = agg.aggregate_transition(parent_repo, org_transition_class="ORGANIZATION_INGRESS_MATERIALIZED",
                                          authority_effect="NONE", genesis=True, store=store)
    appended = [(parent_org, parent_repo)]

    def propagate(receipt, transition_class):
        org = agg.aggregate_transition(receipt, org_transition_class=transition_class,
                                       boundary_evidence={"source": "SV-LLM/sandbox"}, authority_effect="NONE", store=store)
        appended.append((org, receipt))
        return org

    ledger = Ledger(EVIDENCE / "sandbox-repo-ledger")
    sb = Sandbox(dotgithub_root=DOTGITHUB, ledger=ledger, propagate=propagate)
    work = {"schema": "sv-llm.sandbox-work/v0.1",
            "work_id": "stage2-page-load-" + sha({"invocations": invocations,
                                                  "parent_org_receipt_sha256": parent_org["receipt_sha256"]})[7:19],
            "manifested_request": {"manifest_id": "at04-stage2-page-load", "tool_invocations": invocations},
            "parent_transition": {"transition_class": parent_repo.get("transition_class"),
                                  "repo_receipt_sha256": parent_repo["receipt_sha256"],
                                  "org_receipt_sha256": parent_org["receipt_sha256"],
                                  "subject_or_artifact_digest": sha(subject)},
            "canonical_context_refs": [], "requested_capabilities": ["reasoning"], "permitted_capabilities": ["reasoning"],
            "participation_policy": {"mode": "SINGLE"},
            "expected_output_or_handoff": {"successor_transition_class": "SANDBOX_SYNTHESIS_RECORDED"}}
    admitted = sb.admit(json.dumps(work).encode(), parent_repo_receipt=parent_repo, parent_org_receipt=parent_org,
                        subject=subject)
    results_dir = EVIDENCE / "test-results"
    tool = StegBrowserPageLoadTool(sb, artifacts_dir=results_dir)
    observations = []
    for inv in invocations:
        obs = tool.invoke(work["work_id"], inv["invocation_id"], playwright_factory=playwright_factory)
        observations.append(obs)
        record = {k: obs.get(k) for k in ("observation_id", "repository", "requested_url", "final_url", "http_status",
                                          "title", "disposition", "failed_predicate", "detail", "screenshot_file",
                                          "screenshot_sha256", "denied_navigations", "lease_id", "lease_commitment",
                                          "terminal_receipt", "interaction", "credentials", "repo_receipt_sha256",
                                          "org_receipt_sha256")}
        record.update(schema="sv-llm.stage2-page-load-result/v1", work_id=work["work_id"], tool=obs.get("tool"),
                      tool_profile=obs.get("tool_profile"), stegbrowser_source_commit=obs.get("source_commit"),
                      executed_by=report["executed_by"], evidence_class=EVIDENCE_CLASS,
                      epistemic_state="OBSERVED", authority_effect="NONE")
        stage1.write(results_dir / inv["repository"] / "page-load.json", record)
        print(f"{inv['repository']}: {obs['disposition']} {obs.get('http_status')} {obs.get('final_url')} "
              f"| {obs.get('title') or obs.get('failed_predicate')}")
    synth = sb.synthesize(work["work_id"], [o["observation_id"] for o in observations],
                          {"summary": "AT-04 Stage 2 first test: public LLM URL page loads with screenshots; no interaction"})
    done = sb.complete(work["work_id"])
    readback = [stage1.keyed_readback(agg, store, org, source) for org, source in appended]
    failed_readback = next((f for f in readback if f), None)
    all_allow = all(o["disposition"] == "ALLOW" for o in observations)
    report.update(work_id=work["work_id"], admitted=admitted["disposition"], synthesis=synth["disposition"],
                  completion=done["disposition"],
                  observations=[{k: o.get(k) for k in ("repository", "disposition", "failed_predicate", "http_status",
                                                       "final_url", "screenshot_sha256", "observation_id")}
                                for o in observations],
                  org_receipts=[org["receipt_sha256"] for org, _ in appended],
                  org_readback="EXACT_KEYED_READBACK_PASS" if not failed_readback else "EXACT_KEYED_READBACK_FAIL",
                  repository_chain_length=len(sb.ledger.chain()))
    allowed = admitted["disposition"] == "ALLOW" and all_allow and done["disposition"] == "ALLOW" and not failed_readback
    report["disposition"] = "ALLOW" if allowed else "FAIL_CLOSED"
    if not allowed:
        report["failed_predicate"] = (failed_readback or ("STAGE2_PAGE_LOAD_ALL_OBSERVATIONS_ALLOW" if not all_allow
                                                          else "SANDBOX_COMPLETION_ALLOW"))
    return stage1.finish(EVIDENCE, report, 0 if allowed else 1)


if __name__ == "__main__":
    sys.exit(main())
