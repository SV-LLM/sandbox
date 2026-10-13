from __future__ import annotations

from typing import Any, Mapping

from .ecosystem_ephemeral import EphemeralBrowserSession
from .llm_profile import validate_llm_profile_request, begin_llm_profile_packet, bind_llm_profile_result, complete_llm_profile_packet

_ALLOWED_ACTIONS = {"fill", "click", "press", "read_text"}
# wait_for is refused: holding the lease until a provider renders an answer awaits
# an external machine, which is never a transition predicate (StegVerse-Labs/.github
# data/task-registry-global-invariants.json, actions_by_manifest). read_text reads
# what the page holds at that moment; an absent answer is a recorded non-success
# that a later manifest may retry, never a wait.
_REFUSED_ACTIONS = {"wait_for"}

def execute_manifested_llm_browser_operation(
    request: Mapping[str, Any],
    lease: Mapping[str, Any],
    *,
    playwright_factory=None,
    attempt_evidence: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Execute llm.v1 as a credential-free manifested browser operation.

    The manifest supplies the HTTPS endpoint and bounded DOM actions. This owner
    does not infer provider credentials, API routes, selectors, or successor
    authority. Raw page/session state is destroyed with the ephemeral context.
    """
    if attempt_evidence is not None:
        attempt_evidence["stage"] = "MANIFEST_VALIDATION"
    normalized = validate_llm_profile_request(request)
    if attempt_evidence is not None:
        attempt_evidence["request_commitment"] = normalized["request_commitment"]
    endpoint = normalized.get("secure_url")
    actions = normalized.get("browser_actions")
    if not isinstance(endpoint, str) or not endpoint.startswith("https://"):
        raise ValueError("llm.v1 secure_url must be https")
    if not isinstance(actions, list) or not actions:
        raise ValueError("llm.v1 browser_actions required")

    if attempt_evidence is not None:
        attempt_evidence["stage"] = "LEASE_ADMISSION"
    session = EphemeralBrowserSession.open(lease)
    close_reason = "completed"
    result_text = None
    try:
        # Every admitted lease must be finalized, including an authorization
        # refusal or a failed packet construction before Chromium is launched.
        if attempt_evidence is not None:
            attempt_evidence["stage"] = "NAVIGATION_ADMISSION"
        nav = session.authorize(action="navigate", url=endpoint)
        if attempt_evidence is not None:
            attempt_evidence["stage"] = "PACKET_BUILD"
        journey = begin_llm_profile_packet(normalized)
        factory = playwright_factory
        if factory is None:
            from playwright.sync_api import sync_playwright
            factory = sync_playwright
        if attempt_evidence is not None:
            attempt_evidence["stage"] = "BROWSER_LAUNCH"
        with factory() as p:
            browser = p.chromium.launch(headless=True)
            context = browser.new_context()
            try:
                page = context.new_page()
                if attempt_evidence is not None:
                    attempt_evidence["stage"] = "BROWSER_NAVIGATION"
                response = page.goto(endpoint, wait_until="domcontentloaded", timeout=30000)
                if response is not None and int(response.status) >= 400:
                    raise RuntimeError(f"llm.v1 endpoint status {response.status}")
                for step in actions:
                    if attempt_evidence is not None:
                        attempt_evidence["stage"] = "BROWSER_ACTION"
                    if not isinstance(step, Mapping):
                        raise ValueError("llm.v1 browser action must be an object")
                    op = step.get("op")
                    selector = step.get("selector")
                    if op in _REFUSED_ACTIONS:
                        raise ValueError("llm.v1 wait_for is refused: the browser never waits on the provider")
                    if op not in _ALLOWED_ACTIONS or not isinstance(selector, str) or not selector:
                        raise ValueError("unsupported llm.v1 browser action")
                    frame_selector = step.get("frame_selector")
                    loc = (page.frame_locator(str(frame_selector)).locator(selector)
                           if isinstance(frame_selector, str) and frame_selector else page.locator(selector))
                    if op != "read_text" and loc.count() == 0:
                        # Act only on what the delivered page holds; never wait for it to appear.
                        raise RuntimeError(f"llm.v1 {op} target not present: {selector}")
                    if op == "fill":
                        value = step.get("value")
                        if value != normalized["prompt"]:
                            raise ValueError("fill value must equal manifested prompt")
                        loc.fill(value)
                    elif op == "click":
                        loc.click()
                    elif op == "press":
                        loc.press(str(step.get("key") or "Enter"))
                    elif op == "read_text":
                        # all_inner_texts() returns what is present now; it never waits.
                        result_text = "\n".join(loc.all_inner_texts())
                if attempt_evidence is not None:
                    attempt_evidence["stage"] = "RESULT_OBSERVATION"
                if not isinstance(result_text, str) or not result_text.strip():
                    raise RuntimeError("llm.v1 manifested result text not observed")
            finally:
                context.close()
                browser.close()
    except Exception:
        close_reason = "error"
        raise
    finally:
        terminal = session.close(reason=close_reason)
        if attempt_evidence is not None:
            attempt_evidence["terminal_receipt"] = terminal

    provider = normalized.get("provider") or "credential-free-browser-model"
    model = normalized.get("model") or "manifest-selected-free-model"
    # The browser observes page text only: provider/model are manifest-declared
    # labels (or defaults when undeclared), never attested provider identity, and
    # the DOM path exposes no provider usage. Say so, so no consumer can count this
    # result as provider-attested or usage-attributed evidence.
    attribution = {
        "provider": provider,
        "model": model,
        "provider_source": "MANIFEST_DECLARED" if normalized.get("provider") else "DEFAULT_LABEL_UNDECLARED",
        "model_source": "MANIFEST_DECLARED" if normalized.get("model") else "DEFAULT_LABEL_UNDECLARED",
        "provider_identity_attested": False,
        "usage_observed": False,
        "usage_unavailable_reason": "BROWSER_DOM_PATH_EXPOSES_NO_PROVIDER_USAGE",
    }
    if attempt_evidence is not None:
        attempt_evidence["stage"] = "RESULT_BINDING"
    bound = bind_llm_profile_result(
        packet=journey, response_text=result_text, provider=provider, model=model,
    )
    completed = complete_llm_profile_packet({**bound, "request": normalized})
    if attempt_evidence is not None:
        attempt_evidence["stage"] = "RETURN_COMPLETE"
    return {
        "schema": "stegbrowser.llm-manifested-browser-execution.v1",
        "request_commitment": normalized["request_commitment"],
        "secure_url": endpoint,
        "credential_required": False,
        "credential_used": False,
        "navigation_decision_commitment": nav["decision_commitment"],
        "terminal_receipt": terminal,
        "result": completed["result"],
        "endpoint_receipts": completed["endpoint_receipts"],
        "attribution": attribution,
        "authority_effect": "NONE_MANIFEST_BOUND_BROWSER_EXECUTION",
    }
