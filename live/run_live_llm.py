"""AT-04 Stage 1: live StegBrowser llm.v1 path conformance against the StegVerse.org fixture page.

Manual workflow only; fails closed until live/target.json is verified. The
target is a StegVerse-controlled conformance surface, never a provider: no
provider attribution, no provider/model labels, and a pass proves only the
live browser path, not OpenAI/Anthropic integration.

Two lanes (LIVE_LANE):

  conformance  WORKFLOW_LOCAL_ORGANIZATION_LEDGER_CONFORMANCE, run by this
               repository's own workflow. A fresh workflow-local organization
               ledger opened with a declared GENESIS and a workflow-local
               SV-LLM/.github emit.py fixture parent. Never authoritative
               organization runtime reality.
  authentic    AUTHENTIC_SV_LLM_ORGANIZATION_LEDGER_RUNTIME_EVIDENCE
               (SV-LLM-ORGANIZATION-ROLE-EXACT-STEGVERSE-ORG-DUPLICATION-001).
               Runs only inside the SV-LLM organization's own .github workflow
               (executed_by is GITHUB_REPOSITORY, set by the runner). It binds
               the organization ledger exactly as the StegVerse-org reference
               does, PosixLedgerStore(ledger_root()) from the adopted
               SV-LLM/.github module: execution-scoped, the same as the
               reference, with no durability claimed beyond the run. It never
               passes GENESIS and never synthesizes its parent: the parent is
               the PARENT_ORG_RECEIPT_SHA256 claim, proven by exact keyed
               readback, and the work subject is that parent's own recorded
               outcome. Refusals, in order: not organization execution, ledger
               not opened, parent not present, parent subject mismatch.

Both lanes prove each organization receipt and its retained source receipt by
exact keyed whole-document readback. Evidence goes to EVIDENCE_DIR, which the
calling workflow uploads as a 90-day artifact: live-run evidence retention, not
permanent custody. Every non-ALLOW result exits 1; report.json is the
disposition record.
"""
from __future__ import annotations
import hashlib, importlib.util, json, os, re, subprocess, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "runtime"))

CONFORMANCE, AUTHENTIC = "conformance", "authentic"
EVIDENCE_CLASS = {CONFORMANCE: "WORKFLOW_LOCAL_ORGANIZATION_LEDGER_CONFORMANCE",
                  AUTHENTIC: "AUTHENTIC_SV_LLM_ORGANIZATION_LEDGER_RUNTIME_EVIDENCE"}
PARENT_BASIS = {CONFORMANCE: "WORKFLOW_LOCAL_SV_LLM_DOTGITHUB_EMIT_FIXTURE",
                AUTHENTIC: "AUTHORITATIVE_STORE_EXACT_KEYED_READBACK"}
RETENTION = "LIVE_RUN_EVIDENCE_RETENTION_NOT_PERMANENT_CUSTODY"
ORGANIZATION_EXECUTION = "SV-LLM/.github"
LEDGER_PERSISTENCE = {CONFORMANCE: "WORKFLOW_LOCAL_CONFORMANCE_ONLY", AUTHENTIC: "EXECUTION_SCOPED_SAME_AS_REFERENCE"}
INTENDED_ACTION = "STEGBROWSER_LIVE_PATH_CONFORMANCE"
RETRY_ENTRYPOINT = ("SV-LLM/.github:.github/workflows/organization-authentic-live-lane.yml (workflow_dispatch)"
                    " -> SV-LLM/sandbox live/run_live_llm.py::main")
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")

REFUSALS = {
    "AUTHENTIC_LANE_NOT_ORGANIZATION_EXECUTION": (
        "Run the authentic lane from the SV-LLM organization's own workflow, which opens the execution-scoped "
        "ledger and appends the authentic parent in the same run.",
        "Dispatch the organization workflow; nothing else qualifies."),
    "ORG_LEDGER_GENESIS_NOT_DECLARED": (
        "Run the separately manifested SV-LLM organization ledger opening transition "
        "(SV-LLM/.github org-runtime/crossing.py::open_organization_ledger) earlier in the same organization execution.",
        "Retry the organization workflow, which opens the ledger before running this lane."),
    "AUTHENTIC_PARENT_TRANSITION_NOT_IN_AUTHORITATIVE_STORE": (
        "Append the authentic parent through crossing.record earlier in the same organization execution and pass "
        "its organization receipt digest as PARENT_ORG_RECEIPT_SHA256.",
        "Retry the organization workflow after the named parent is present by exact keyed readback."),
    "AUTHENTIC_PARENT_SUBJECT_MISMATCH": (
        "Append a parent whose recorded outcome is {disposition: ALLOW, intended_action: "
        "STEGBROWSER_LIVE_PATH_CONFORMANCE, target_id: <this lane's live/target.json target_id>}.",
        "Retry the organization workflow with a parent whose outcome names this lane's intended action and target."),
}


class Refused(Exception):
    def __init__(self, failed_predicate: str, detail: str | None = None):
        super().__init__(failed_predicate)
        self.failed_predicate, self.detail = failed_predicate, detail


def write(path: Path, value) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def digest_manifest(EVIDENCE: Path, report: dict) -> None:
    files = {str(p.relative_to(EVIDENCE)): "sha256:" + hashlib.sha256(p.read_bytes()).hexdigest()
             for p in sorted(EVIDENCE.rglob("*")) if p.is_file() and p.name != "digests.json"}
    write(EVIDENCE / "digests.json", {"schema": "sv-llm.live-run-evidence-digests/v1", "lane": report["lane"],
                                      "evidence_class": report["evidence_class"],
                                      "authoritative_organization_runtime_reality":
                                          report["authoritative_organization_runtime_reality"],
                                      "retention_class": RETENTION, "files": files})


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


def load_dotgithub(dotgithub: Path):
    spec = importlib.util.spec_from_file_location("agg", dotgithub / "resident-runtime/aggregate_repo_transition.py")
    agg = importlib.util.module_from_spec(spec); spec.loader.exec_module(agg)
    return agg


def organization_execution() -> str | None:
    """X2: the repository whose workflow is running, as the runner reports it."""
    return os.environ.get("GITHUB_REPOSITORY") or None


def reference_store(agg):
    """D7: the organization ledger exactly as the StegVerse-org reference binds it."""
    return agg.PosixLedgerStore(agg.ledger_root())


def keyed_readback(agg, store, org_receipt: dict, source_receipt: dict) -> str | None:
    """Exact keyed whole-document readback; returns the failed predicate or None."""
    if store.get(agg.receipt_key(org_receipt["receipt_sha256"])) != org_receipt:
        return "ORG_RECEIPT_EXACT_READBACK"
    if store.get(agg.source_key(org_receipt["source_transition_sha256"])) != source_receipt:
        return "SOURCE_RECEIPT_RETAINED"
    return None


def authentic_parent(agg, store, claimed) -> tuple[dict, dict]:
    """The reference ledger is opened, then the claimed parent is present by exact keyed readback."""
    if store.get(agg.HEAD_KEY) is None:
        raise Refused("ORG_LEDGER_GENESIS_NOT_DECLARED")
    if not (isinstance(claimed, str) and DIGEST.match(claimed)):
        raise Refused("AUTHENTIC_PARENT_TRANSITION_NOT_IN_AUTHORITATIVE_STORE", "PARENT_DIGEST_MISSING_OR_MALFORMED")
    org = store.get(agg.receipt_key(claimed))
    body = dict(org or {}); body.pop("receipt_sha256", None)
    if not org or org.get("receipt_sha256") != claimed or agg.sha(body) != claimed:
        raise Refused("AUTHENTIC_PARENT_TRANSITION_NOT_IN_AUTHORITATIVE_STORE", "ORG_RECEIPT_NOT_PRESENT")
    source = store.get(agg.source_key(org.get("source_transition_sha256") or ""))
    try:
        retained = source is not None and \
            agg.verify_source(source)["source_transition_sha256"] == org["source_transition_sha256"]
    except (SystemExit, ValueError, KeyError, TypeError):  # verify_source refuses a malformed receipt
        retained = False
    if not retained:
        raise Refused("AUTHENTIC_PARENT_TRANSITION_NOT_IN_AUTHORITATIVE_STORE", "SOURCE_RECEIPT_NOT_PRESENT")
    return org, source


def parent_subject(source: dict, target: dict) -> dict:
    """D11: the work subject is the parent's own recorded outcome, and it must name this lane."""
    from ledger import sha
    subject = source.get("evidence")
    if not (isinstance(subject, dict) and sha(subject) == source.get("successor_state_sha256")
            and subject.get("disposition") == "ALLOW" and subject.get("intended_action") == INTENDED_ACTION
            and subject.get("target_id") == target.get("target_id")):
        raise Refused("AUTHENTIC_PARENT_SUBJECT_MISMATCH")
    return subject


def preflight(dotgithub: Path, claimed_parent, target: dict):
    """Authentic-lane gate, run before any browser is installed. Order: organization execution, opened, parent, subject."""
    if organization_execution() != ORGANIZATION_EXECUTION:
        raise Refused("AUTHENTIC_LANE_NOT_ORGANIZATION_EXECUTION")
    agg = load_dotgithub(dotgithub)
    store = reference_store(agg)
    org, source = authentic_parent(agg, store, claimed_parent)
    return agg, store, org, source, parent_subject(source, target)


def new_report(lane: str, target: dict) -> dict:
    return {"schema": "sv-llm.sandbox-live-llm-report/v1", "stage": "STEGBROWSER_LIVE_PATH_CONFORMANCE",
            "lane": lane, "evidence_class": EVIDENCE_CLASS.get(lane),
            "executed_by": organization_execution(), "ledger_persistence": LEDGER_PERSISTENCE.get(lane),
            "authoritative_organization_runtime_reality": False,
            "target_id": target.get("target_id"), "secure_url": target.get("secure_url"),
            "provider_attribution": "NONE", "proves_provider_integration": False,
            "live_path_exercised": False, "successful_live_response_observed": False,
            "retention_class": RETENTION, "parent_transition_basis": PARENT_BASIS.get(lane),
            "authority_effect": "NONE"}


def refuse(report: dict, refused: Refused) -> None:
    report.update(disposition="FAIL_CLOSED", failed_predicate=refused.failed_predicate)
    if refused.detail:
        report["detail"] = refused.detail
    if refused.failed_predicate in REFUSALS:
        repair, next_attempt = REFUSALS[refused.failed_predicate]
        report.update(required_evidence_or_repair=repair, retry_entrypoint=RETRY_ENTRYPOINT, next_attempt=next_attempt)


def finish(EVIDENCE: Path, report: dict, code: int) -> int:
    write(EVIDENCE / "report.json", report)
    digest_manifest(EVIDENCE, report)
    print(json.dumps(report, indent=2))
    return code


def main(argv=None, *, playwright_factory=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    DOTGITHUB = Path(os.environ["SV_LLM_DOTGITHUB_ROOT"]).resolve()
    EVIDENCE = Path(os.environ["EVIDENCE_DIR"]).resolve()
    lane = os.environ.get("LIVE_LANE") or CONFORMANCE
    claimed_parent = os.environ.get("PARENT_ORG_RECEIPT_SHA256") or None
    target = json.loads((ROOT / "live/target.json").read_text())
    report = new_report(lane, target)
    if lane not in EVIDENCE_CLASS:
        refuse(report, Refused("LIVE_LANE_DECLARED"))
        return finish(EVIDENCE, report, 1)
    if lane == AUTHENTIC:
        try:
            agg, store, parent_org, parent_repo, subject = preflight(DOTGITHUB, claimed_parent, target)
        except Refused as refused:
            refuse(report, refused)
            return finish(EVIDENCE, report, 1)
        if "--preflight" in argv:
            report.update(disposition="ALLOW", preflight="ORGANIZATION_EXECUTION_LEDGER_OPENED_PARENT_AND_SUBJECT_PRESENT")
            return finish(EVIDENCE, report, 0)
    inv, refused = derive_invocation(target)
    if refused:
        refuse(report, Refused(refused))
        return finish(EVIDENCE, report, 1)

    os.environ["STEGVERSE_REPO_LEDGER_ROOT"] = str(EVIDENCE / "sandbox-repo-ledger")
    from ledger import Ledger, sha
    from sandbox import Sandbox
    from stegbrowser_tool import StegBrowserTool
    appended = []  # (organization receipt, exact source receipt) for keyed readback
    if lane == CONFORMANCE:
        subject = {"intended_action": INTENDED_ACTION, "target_id": target["target_id"]}
        agg = load_dotgithub(DOTGITHUB)
        store = agg.PosixLedgerStore(EVIDENCE / "sv-llm-org-ledger")
        run = subprocess.run([sys.executable, str(DOTGITHUB / ".stegverse/transition-ledger/emit.py"),
                              "--transition-id", "LIVE_FIXTURE_PARENT:" + sha(subject)[7:31],
                              "--transition-class", "ORGANIZATION_INGRESS_MATERIALIZED",
                              "--predecessor-state-sha256", sha({"live": "predecessor"}),
                              "--successor-state-sha256", sha(subject), "--evidence-json", json.dumps({"disposition": "ALLOW"})],
                             capture_output=True, text=True, check=True,
                             env=dict(os.environ, STEGVERSE_REPO_LEDGER_ROOT=str(EVIDENCE / "dotgithub-fixture-ledger")))
        parent_repo = json.loads(run.stdout)
        # First append on this run's fresh workflow-local ledger: genesis is declared, never defaulted.
        parent_org = agg.aggregate_transition(parent_repo, org_transition_class="ORGANIZATION_INGRESS_MATERIALIZED",
                                              authority_effect="NONE", genesis=True, store=store)
        appended.append((parent_org, parent_repo))

    def propagate(receipt, transition_class):
        # FROM_HEAD only; GENESIS is never passed here.
        org = agg.aggregate_transition(receipt, org_transition_class=transition_class,
                                       boundary_evidence={"source": "SV-LLM/sandbox"}, authority_effect="NONE", store=store)
        appended.append((org, receipt))
        return org

    sb = Sandbox(dotgithub_root=DOTGITHUB, ledger=Ledger(EVIDENCE / "sandbox-repo-ledger"), propagate=propagate)
    work = {"schema": "sv-llm.sandbox-work/v0.1", "work_id": "live-llm-" + sha(inv)[7:19],
            "manifested_request": {"manifest_id": "at04-stage1-live-path-conformance", "tool_invocations": [inv]},
            "parent_transition": {"transition_class": parent_repo.get("transition_class"),
                                  "repo_receipt_sha256": parent_repo["receipt_sha256"],
                                  "org_receipt_sha256": parent_org["receipt_sha256"],
                                  "subject_or_artifact_digest": sha(subject)},
            "canonical_context_refs": [], "requested_capabilities": ["reasoning"], "permitted_capabilities": ["reasoning"],
            "participation_policy": {"mode": "SINGLE"},
            "expected_output_or_handoff": {"successor_transition_class": "SANDBOX_SYNTHESIS_RECORDED"}}
    admitted = sb.admit(json.dumps(work).encode(), parent_repo_receipt=parent_repo, parent_org_receipt=parent_org, subject=subject)
    obs = StegBrowserTool(sb).invoke(work["work_id"], inv["invocation_id"], playwright_factory=playwright_factory)
    synth = sb.synthesize(work["work_id"], [obs["observation_id"]], {"summary": "AT-04 Stage 1 StegBrowser live-path conformance; no provider attribution"})
    done = sb.complete(work["work_id"])
    readback = [keyed_readback(agg, store, org, source) for org, source in appended]
    failed_readback = next((f for f in readback if f), None)
    report.update(work_id=work["work_id"], admitted=admitted["disposition"], observation_id=obs["observation_id"],
                  disposition=obs["disposition"], failed_predicate=obs.get("failed_predicate"),
                  evaluation_stage=obs.get("evaluation_stage"),
                  live_path_exercised=bool(obs.get("stegbrowser_invoked")),
                  successful_live_response_observed=obs["disposition"] == "ALLOW",
                  synthesis=synth["disposition"], completion=done["disposition"],
                  org_receipts=[org["receipt_sha256"] for org, _ in appended],
                  org_readback="EXACT_KEYED_READBACK_PASS" if not failed_readback else "EXACT_KEYED_READBACK_FAIL",
                  repo_receipts=[r["receipt_sha256"] for r in sb.ledger.chain()])
    allowed = obs["disposition"] == "ALLOW" and done["disposition"] == "ALLOW" and not failed_readback \
        and admitted["disposition"] == "ALLOW"
    if failed_readback and obs["disposition"] == "ALLOW":
        report.update(disposition="FAIL_CLOSED", failed_predicate=failed_readback)
    elif obs["disposition"] == "ALLOW" and not allowed:
        report.update(disposition="FAIL_CLOSED", failed_predicate="SANDBOX_COMPLETION_ALLOW")
    report["authoritative_organization_runtime_reality"] = lane == AUTHENTIC and allowed
    return finish(EVIDENCE, report, 0 if allowed else 1)


if __name__ == "__main__":
    sys.exit(main())
