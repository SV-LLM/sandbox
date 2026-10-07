"""AT-04 Stage 1: live StegBrowser llm.v1 path conformance against the StegVerse.org fixture page.

Manual workflow only; fails closed until live/target.json is verified. The
target is a StegVerse-controlled conformance surface, never a provider: no
provider attribution, no provider/model labels, and a pass proves only the
live browser path, not OpenAI/Anthropic integration.

Evidence goes to EVIDENCE_DIR (repo ledger, org ledger, report, digest manifest),
which the workflow uploads as a 90-day artifact: live-run evidence retention,
not permanent custody. The parent transition is a workflow-local SV-LLM/.github
emit.py fixture, labeled as such in the report.
"""
from __future__ import annotations
import hashlib, importlib.util, json, os, subprocess, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "runtime"))


def write(path: Path, value) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def digest_manifest(EVIDENCE: Path) -> None:
    files = {str(p.relative_to(EVIDENCE)): "sha256:" + hashlib.sha256(p.read_bytes()).hexdigest()
             for p in sorted(EVIDENCE.rglob("*")) if p.is_file() and p.name != "digests.json"}
    write(EVIDENCE / "digests.json", {"schema": "sv-llm.live-run-evidence-digests/v1",
                                      "retention_class": "LIVE_RUN_EVIDENCE_RETENTION_NOT_PERMANENT_CUSTODY",
                                      "files": files})


REQUIRED_SELECTORS = ("prompt_input", "submit", "response_ready", "response")


def derive_invocation(target: dict):
    """T3/T4: derive the Sandbox tool invocation from live/target.json, or name the failed predicate.

    Order: provider attribution, then shape, then verification. Nothing here
    reaches StegBrowser; the caller records the refusal.
    """
    from urllib.parse import urlsplit
    if target.get("provider_entity") is not None or target.get("provider_attribution_allowed") is not False:
        return None, "LIVE_TARGET_HAS_NO_PROVIDER_ATTRIBUTION"
    if any(k in target for k in ("provider", "model")):
        return None, "LIVE_TARGET_HAS_NO_PROVIDER_ATTRIBUTION"
    origin, url, sel = target.get("origin"), target.get("secure_url"), target.get("selectors")
    o = urlsplit(origin) if isinstance(origin, str) else None
    u = urlsplit(url) if isinstance(url, str) else None
    ok = (target.get("schema") == "sv-llm.stegbrowser-live-target/v1" and target.get("profile") == "llm.v1"
          and target.get("credential_mode") == "NONE" and target.get("automation_policy") == "PERMITTED_BY_OWNER"
          and o is not None and o.scheme == "https" and o.hostname and o.path in ("", "/") and not o.port
          and u is not None and u.scheme == "https" and u.hostname == o.hostname and not u.port
          and isinstance(sel, dict) and all(isinstance(sel.get(k), str) and sel[k] for k in REQUIRED_SELECTORS)
          and isinstance(target.get("response_marker"), str) and target["response_marker"].strip()
          and isinstance(target.get("prompt"), str) and target["response_marker"] in target["prompt"]
          and isinstance(target.get("target_id"), str) and target["target_id"])
    if not ok:
        return None, "LIVE_TARGET_WELL_FORMED"
    if target.get("verified") is not True:
        return None, "LIVE_TARGET_SELECTED_AND_VERIFIED"
    prompt = target["prompt"]
    return {"invocation_id": "at04-" + target["target_id"], "tool": "StegBrowser", "profile": "llm.v1",
            "prompt": prompt, "response_marker": target["response_marker"], "secure_url": url,
            "allowed_origins": [o.hostname.lower().rstrip(".")],
            "browser_actions": [{"op": "fill", "selector": sel["prompt_input"], "value": prompt},
                                {"op": "click", "selector": sel["submit"]},
                                {"op": "wait_for", "selector": sel["response_ready"]},
                                {"op": "read_text", "selector": sel["response"]}]}, None


def main() -> int:
    DOTGITHUB = Path(os.environ["SV_LLM_DOTGITHUB_ROOT"]).resolve()
    EVIDENCE = Path(os.environ["EVIDENCE_DIR"]).resolve()
    target = json.loads((ROOT / "live/target.json").read_text())
    report = {"schema": "sv-llm.sandbox-live-llm-report/v1", "stage": "STEGBROWSER_LIVE_PATH_CONFORMANCE",
              "target_id": target.get("target_id"), "secure_url": target.get("secure_url"),
              "provider_attribution": "NONE", "proves_provider_integration": False,
              "live_path_exercised": False, "successful_live_response_observed": False,
              "retention_class": "LIVE_RUN_EVIDENCE_RETENTION_NOT_PERMANENT_CUSTODY",
              "parent_transition_basis": "WORKFLOW_LOCAL_SV_LLM_DOTGITHUB_EMIT_FIXTURE",
              "authority_effect": "NONE"}
    inv, refused = derive_invocation(target)
    if refused:
        report.update(disposition="FAIL_CLOSED", failed_predicate=refused)
        write(EVIDENCE / "report.json", report)
        digest_manifest(EVIDENCE)
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
    subject = {"intended_action": "STEGBROWSER_LIVE_PATH_CONFORMANCE", "target_id": target["target_id"]}
    run = subprocess.run([sys.executable, str(DOTGITHUB / ".stegverse/transition-ledger/emit.py"),
                          "--transition-id", "LIVE_FIXTURE_PARENT:" + sha(subject)[7:31],
                          "--transition-class", "ORGANIZATION_INGRESS_MATERIALIZED",
                          "--predecessor-state-sha256", sha({"live": "predecessor"}),
                          "--successor-state-sha256", sha(subject), "--evidence-json", json.dumps({"disposition": "ALLOW"})],
                         capture_output=True, text=True, check=True,
                         env=dict(os.environ, STEGVERSE_REPO_LEDGER_ROOT=str(EVIDENCE / "dotgithub-fixture-ledger")))
    parent_repo = json.loads(run.stdout)
    # First append on this run's fresh organization ledger: genesis is declared, never defaulted.
    parent_org = agg.aggregate_transition(parent_repo, org_transition_class="ORGANIZATION_INGRESS_MATERIALIZED", authority_effect="NONE",
                                          genesis=True)
    work = {"schema": "sv-llm.sandbox-work/v0.1", "work_id": "live-llm-" + sha(inv)[7:19],
            "manifested_request": {"manifest_id": "at04-stage1-live-path-conformance", "tool_invocations": [inv]},
            "parent_transition": {"transition_class": "ORGANIZATION_INGRESS_MATERIALIZED",
                                  "repo_receipt_sha256": parent_repo["receipt_sha256"],
                                  "org_receipt_sha256": parent_org["receipt_sha256"],
                                  "subject_or_artifact_digest": sha(subject)},
            "canonical_context_refs": [], "requested_capabilities": ["reasoning"], "permitted_capabilities": ["reasoning"],
            "participation_policy": {"mode": "SINGLE"},
            "expected_output_or_handoff": {"successor_transition_class": "SANDBOX_SYNTHESIS_RECORDED"}}
    admitted = sb.admit(json.dumps(work).encode(), parent_repo_receipt=parent_repo, parent_org_receipt=parent_org, subject=subject)
    obs = StegBrowserTool(sb).invoke(work["work_id"], inv["invocation_id"])
    synth = sb.synthesize(work["work_id"], [obs["observation_id"]], {"summary": "AT-04 Stage 1 StegBrowser live-path conformance; no provider attribution"})
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
    digest_manifest(EVIDENCE)
    print(json.dumps(report, indent=2))
    return 0 if report["successful_live_response_observed"] and done["disposition"] == "ALLOW" else 1


if __name__ == "__main__":
    sys.exit(main())
