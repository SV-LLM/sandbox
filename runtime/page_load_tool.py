"""Sandbox adapter: StegBrowser ephemeral page load (profile page_load.v1).

AT-04 Stage 2, first test: load a provider's public URL in an ephemeral
StegBrowser session and capture a screenshot. Nothing is typed, clicked or
submitted; there is no prompt, no selector and no credential.

Path: admitted Sandbox work -> pre-invocation checks -> vendored StegBrowser
EphemeralBrowserSession lease (navigate + read_public, no persistent profile,
cookies, history or credentials) -> fresh Chromium context, main-frame
navigations outside the lease aborted -> screenshot -> session closed ->
SANDBOX_TOOL_OBSERVATION_RECORDED. Every attempt is recorded, including a
Sandbox-side DENY before any browser starts.

The invocation is admitted data at manifested_request.tool_invocations[]:
  {invocation_id, tool: "StegBrowser", profile: "page_load.v1", repository,
   secure_url, allowed_origins: [hostname | "*.suffix"], lease_seconds?: 1..900}

An observation records what the browser saw (HTTP status, final URL, title,
screenshot digest, refused navigations, the lease's terminal receipt). ALLOW
means the page was loaded inside the lease and a screenshot was taken; an HTTP
403 or a bot challenge is a recorded observation, not a tool failure. Nothing
here is provider interaction, a provider contribution or a runtime-observed
provider operation.
"""
from __future__ import annotations
import hashlib, importlib, importlib.util, json, sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Mapping

VENDOR = Path(__file__).resolve().parent / "vendor" / "stegbrowser_llm"
sys.path.insert(0, str(VENDOR.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from sandbox import deny_fields, OWNING_EXISTING_GOAL  # noqa: E402
from stegbrowser_tool import _host, _host_allowed, _iso  # noqa: E402
MANIFEST = json.loads((VENDOR / "vendor-manifest.json").read_text())
TOOL, PROFILE = "StegBrowser", "page_load.v1"
LEASE_SCHEMA = "stegbrowser.ecosystem-ephemeral-lease.v1"
MAX_LEASE_SECONDS = 900
MAX_NAVIGATIONS = 10
VIEWPORT = {"width": 1280, "height": 800}
INTERACTION_FIELDS = ("prompt", "browser_actions", "selectors", "response_marker", "credential_mode",
                      "credentials", "cookies", "storage_state")
RETRY_PREFIX = "runtime.page_load_tool.StegBrowserPageLoadTool."
ENVIRONMENT_PREDICATE = "SANDBOX_ENVIRONMENT_PYTHON_PLAYWRIGHT_CHROMIUM_AVAILABLE"
TOOL_REPAIRS = {
    "WORK_ID_IS_ADMITTED": (
        "Admit the work item first (a SANDBOX_WORK_ADMITTED receipt for this work_id).",
        "Call Sandbox.admit, then call invoke again for the same work_id."),
    "TOOL_INVOCATION_DECLARED": (
        "Declare exactly one manifested_request.tool_invocations[] entry with this invocation_id in admitted work.",
        "Call invoke with a declared invocation_id, or admit work that declares it."),
    "TOOL_INVOCATION_WELL_FORMED": (
        "Make the declared invocation a well-formed StegBrowser page_load.v1 invocation (tool, profile, repository, "
        "https secure_url, allowed_origins, lease_seconds 1..900).",
        "Admit work carrying the corrected invocation, then call invoke again."),
    "PAGE_LOAD_HAS_NO_INTERACTION": (
        "Remove prompt, browser_actions, selectors, response_marker and any credential or session field: "
        "page_load.v1 only loads and captures a public page.",
        "Admit work whose invocation carries no interaction or credential field, then call invoke again."),
    "SECURE_URL_ORIGIN_ALLOWED_BY_LEASE": (
        "Use an https secure_url whose host is inside the admitted allowed_origins.",
        "Admit work whose secure_url host is allowed, then call invoke again."),
    "FINAL_ORIGIN_WITHIN_LEASE": (
        "The page settled on a host outside the lease; widen allowed_origins only to hosts the provider owns.",
        "Admit work with the corrected allowed_origins, then call invoke again."),
    "PAGE_NAVIGATION_COMPLETED": (
        "The browser could not load the page (timeout, network or navigation error); see detail.",
        "Call invoke again (a new attempt is recorded)."),
    ENVIRONMENT_PREDICATE: (
        "Install Python Playwright and its Chromium in this environment (or pass a playwright_factory).",
        "Call invoke again where Playwright and Chromium are available."),
}


def _sha(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


class StegBrowserPageLoadTool:
    def __init__(self, sandbox, artifacts_dir: Path | None = None):
        self.sandbox = sandbox
        self.canon = sandbox.canon
        self.artifacts_dir = Path(artifacts_dir) if artifacts_dir else None
        sandbox.registration.verify_vendor(VENDOR)  # executed bytes match the manifest
        self.ephemeral = importlib.import_module("stegbrowser_llm.ecosystem_ephemeral")

    def _invocation(self, work: Mapping[str, Any], invocation_id: str) -> tuple[dict[str, Any] | None, str | None]:
        rows = [i for i in (work["manifested_request"].get("tool_invocations") or [])
                if isinstance(i, Mapping) and i.get("invocation_id") == invocation_id]
        if len(rows) != 1:
            return None, "TOOL_INVOCATION_DECLARED"
        inv = dict(rows[0])
        ok = (inv.get("tool") == TOOL and inv.get("profile") == PROFILE
              and isinstance(inv.get("repository"), str) and inv["repository"]
              and isinstance(inv.get("secure_url"), str) and _host(inv["secure_url"]) is not None
              and isinstance(inv.get("allowed_origins"), list) and inv["allowed_origins"]
              and all(isinstance(o, str) and o for o in inv["allowed_origins"])
              and isinstance(inv.get("lease_seconds", 300), int) and not isinstance(inv.get("lease_seconds"), bool)
              and 1 <= inv.get("lease_seconds", 300) <= MAX_LEASE_SECONDS)
        if not ok:
            return None, "TOOL_INVOCATION_WELL_FORMED"
        if any(k in inv for k in INTERACTION_FIELDS):
            return None, "PAGE_LOAD_HAS_NO_INTERACTION"
        return inv, None

    def _ids(self, work_id: str, invocation_id: str) -> tuple[int, str]:
        attempt = 1 + sum(1 for r in self.sandbox.observations(work_id)
                          if r["evidence"].get("invocation_id") == invocation_id)
        oid = "obs-" + self.canon.digest({"work_id": work_id, "invocation_id": invocation_id, "attempt": attempt,
                                          "profile": PROFILE})[7:31]
        return attempt, oid

    def lease(self, work_id: str, inv: Mapping[str, Any], observation_id: str, issued: datetime) -> dict[str, Any]:
        return {"schema": LEASE_SCHEMA, "lease_id": "lease-" + observation_id, "task_id": work_id,
                "requester": "SV-LLM/sandbox", "purpose": "page_load.v1 " + inv["invocation_id"],
                "issued_at": _iso(issued),
                "expires_at": _iso(issued + timedelta(seconds=inv.get("lease_seconds", 300))),
                "allowed_origins": list(inv["allowed_origins"]), "allowed_actions": ["navigate", "read_public"],
                "retain_artifacts": ["content_commitment", "error_receipt", "navigation_receipt"],
                "max_navigations": MAX_NAVIGATIONS, "persistent_profile": False, "persist_cookies": False,
                "persist_history": False}

    def invoke(self, work_id: str, invocation_id: str, *, playwright_factory=None,
               now: datetime | None = None) -> dict[str, Any]:
        attempt, oid = self._ids(work_id, invocation_id)
        base = {"observation_id": oid, "work_id": work_id, "invocation_id": invocation_id, "attempt": attempt,
                "tool": TOOL, "tool_profile": PROFILE, "source_commit": MANIFEST["source_commit"],
                "interaction": "NONE", "credentials": "NONE", "evidence_refs": []}
        empty = {"stegbrowser_invoked": False, "lease_id": None, "lease_commitment": None, "allowed_origins": None,
                 "repository": None, "requested_url": None, "final_url": None, "http_status": None, "title": None,
                 "screenshot_file": None, "screenshot_sha256": None, "denied_navigations": [],
                 "terminal_receipt": None}

        def deny(predicate: str, disposition: str = "DENY", decided_by: str = "SANDBOX_PRE_INVOCATION", **known):
            obs = {**base, **empty, **deny_fields("invoke", predicate, disposition=disposition, repairs=TOOL_REPAIRS,
                                                   retry_prefix=RETRY_PREFIX, code_prefix="SANDBOX_TOOL"),
                   "decided_by": decided_by, **known}
            return self.sandbox.record_tool_observation(obs)

        work = self.sandbox._work(work_id)
        if work is None:
            return deny("WORK_ID_IS_ADMITTED")
        inv, problem = self._invocation(work, invocation_id)
        if problem:
            return deny(problem)
        known = {"repository": inv["repository"], "requested_url": inv["secure_url"],
                 "allowed_origins": list(inv["allowed_origins"])}
        if not _host_allowed(_host(inv["secure_url"]), inv["allowed_origins"]):
            return deny("SECURE_URL_ORIGIN_ALLOWED_BY_LEASE", **known)
        if playwright_factory is None:
            if importlib.util.find_spec("playwright") is None:
                return deny(ENVIRONMENT_PREDICATE, disposition="FAIL_CLOSED", decided_by="SANDBOX_RUNTIME_CHECK",
                            **known)
            from playwright.sync_api import sync_playwright
            playwright_factory = sync_playwright

        session = self.ephemeral.EphemeralBrowserSession.open(
            self.lease(work_id, inv, oid, now or datetime.now(timezone.utc)), now=now)
        known.update(stegbrowser_invoked=True, lease_id=session.lease["lease_id"],
                     lease_commitment=session.lease["lease_commitment"])
        denied: list[dict[str, Any]] = []
        seen: dict[str, Any] = {}
        failure: tuple[str, str] | None = None
        png: bytes | None = None
        try:
            with playwright_factory() as pw:
                browser = pw.chromium.launch(headless=True)
                try:
                    context = browser.new_context(viewport=VIEWPORT, locale="en-US", accept_downloads=False,
                                                  service_workers="block")
                    page = context.new_page()

                    def guard(route, request):
                        if request.is_navigation_request() and request.frame == page.main_frame:
                            try:
                                session.authorize(action="navigate", url=request.url)
                            except (PermissionError, RuntimeError, ValueError) as exc:
                                denied.append({"url": request.url[:300], "reason": str(exc)})
                                return route.abort("blockedbyclient")
                        return route.continue_()

                    page.route("**/*", guard)
                    try:
                        # The observation is the page as delivered: nothing waits for the provider to
                        # go idle or settle. Waiting on an external machine is not a transition predicate.
                        resp = page.goto(inv["secure_url"], wait_until="domcontentloaded", timeout=45000)
                        seen = {"http_status": resp.status if resp else None, "final_url": page.url,
                                "title": (page.title() or "")[:200]}
                        try:
                            session.authorize(action="read_public", url=page.url)
                        except (PermissionError, RuntimeError, ValueError) as exc:
                            failure = ("FINAL_ORIGIN_WITHIN_LEASE", str(exc))
                    except Exception as exc:
                        failure = ("PAGE_NAVIGATION_COMPLETED", f"{type(exc).__name__}: {str(exc).splitlines()[0][:300]}")
                        seen.setdefault("final_url", page.url if page.url != "about:blank" else None)
                    try:
                        png = page.screenshot(full_page=False)
                    except Exception:
                        png = None
                    context.close()
                finally:
                    browser.close()
        except Exception as exc:  # launch failure
            failure = failure or ("PAGE_NAVIGATION_COMPLETED", f"{type(exc).__name__}: {str(exc).splitlines()[0][:300]}")

        if png is not None:
            known.update(screenshot_file="screenshot.png", screenshot_sha256=_sha(png))
            if self.artifacts_dir is not None:
                out = self.artifacts_dir / inv["repository"]
                out.mkdir(parents=True, exist_ok=True)
                (out / "screenshot.png").write_bytes(png)
            session.retain(artifact_type="content_commitment", artifact={"screenshot_sha256": known["screenshot_sha256"]})
        if seen:
            session.retain(artifact_type="navigation_receipt",
                           artifact={"requested_url": inv["secure_url"], "final_url": seen.get("final_url"),
                                     "http_status": seen.get("http_status")})
        if failure:
            session.retain(artifact_type="error_receipt", artifact={"failed_predicate": failure[0], "detail": failure[1]})
        known.update(http_status=seen.get("http_status"), final_url=seen.get("final_url"), title=seen.get("title"),
                     denied_navigations=denied, terminal_receipt=session.close(reason="failed" if failure else "completed"))
        if failure:
            return deny(failure[0], disposition="FAIL_CLOSED", decided_by="STEGBROWSER_EPHEMERAL_SESSION",
                        detail=failure[1], **known)
        obs = {**base, **empty, **known, "disposition": "ALLOW", "decided_by": "STEGBROWSER_EPHEMERAL_SESSION",
               "failed_predicate": None, "failure_code": None, "required_evidence_or_repair": None,
               "retry_entrypoint": None, "owning_existing_goal": None, "next_attempt": None}
        return self.sandbox.record_tool_observation(obs)
