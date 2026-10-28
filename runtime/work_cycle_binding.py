"""Native StegNode/InTr binding for the Sandbox work cycle (StegVerse-org/.github#163).

WorkCycle._take() calls evaluate_take() after manifest selection and the parent
ingress readback and BEFORE Sandbox.admit; WorkCycle._return() calls
evaluate_return() BEFORE crossing.egress. Neither creates authority: every
outcome is a Sandbox receipt carrying authority_effect NONE, and a refusal
carries the six fields (failure_code, failed_predicate,
required_evidence_or_repair, retry_entrypoint, owning_existing_goal,
next_attempt).

Protected work requires, in order:
  1. the existing StegNode/InTr posture predicates (runtime/stegnode_capability_binding.py);
  2. the NATIVE posture verifier: StegOS stegos/intr_security_posture_resolution.py
     verify_task_security_posture_instance, vendored byte-for-byte under
     runtime/vendor/stegos_intr and digest-checked against its vendor-manifest.json.
     It is resolved here, never injected: a caller-supplied callable is not native
     authentication. Absent or digest-mismatched, protected work FAILS CLOSED;
  3. a capability floor the caller does not control: the max of the service's declared
     minimum_security_tier (runtime/contracts/sandbox-service.json), the verified instance's
     automatic_tier, and the native data-class/channel minimums for the instance's digested
     data_class/channel. A manifest's binding.required_tier may only RAISE that floor. The
     effective tier compared against it is the verified instance's digested effective_tier;
     an undigested resolution wrapper that disagrees with the instance is refused;
  4. non-replay: the posture instance's digest was never bound before on this
     Sandbox ledger chain (the self-digest alone proves neither issuance nor non-replay).
     This guard is scoped to this one ledger chain: a second Sandbox instance or a reset
     ledger would accept the same instance and claim again. Cross-instance non-replay is
     the WorkerCoordinator fence's job, which is why step 5 is mandatory;
  5. a task-bound WorkerCoordinator claim/fence (worker_claim.authority = WORKERCOORDINATOR).
     The admitted claim set is not yet supplied by any Registry/WorkerCoordinator
     surface, so main() supplies none and every protected take FAILS CLOSED with
     AUTHENTIC_WORKERCOORDINATOR_CLAIM_FENCE_NOT_OBSERVED. It never ALLOWs without one.

Public retrieval keeps its exemption: a manifest that declares binding.public and
requests only public-retrieval capabilities needs no node, posture or claim.

Nothing here confers governance authority.
"""
from __future__ import annotations
import hashlib, importlib.util, json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable

from ledger import sha
from stegnode_capability_binding import TIERS, evaluate_binding

SCHEMA = "sv-llm.sandbox-work-cycle-binding/v1"
OWNING_EXISTING_GOAL = "StegVerse-org/.github#163"
TAKE_ENTRYPOINT = "SV-LLM/sandbox runtime/work_cycle.py::_take"
RETURN_ENTRYPOINT = "SV-LLM/sandbox runtime/work_cycle.py::_return"
CLAIM_AUTHORITY = "WORKERCOORDINATOR"
CLAIM_SCHEMA = "stegverse.workercoordinator-claim-fence/v1"
NO_CLAIM_FENCE = "AUTHENTIC_WORKERCOORDINATOR_CLAIM_FENCE_NOT_OBSERVED"
# The only public-read surface the Sandbox carries is page_load.v1 (navigate + read_public).
PUBLIC_RETRIEVAL_CAPABILITIES = frozenset({"page_load.v1"})
VENDOR = Path(__file__).resolve().parent / "vendor/stegos_intr"
SERVICE_CONTRACT = Path(__file__).resolve().parent / "contracts/sandbox-service.json"
NATIVE_MODULE = "intr_security_posture_resolution.py"
NATIVE_FUNCTION = "verify_task_security_posture_instance"

REPAIRS: dict[str, tuple[str, str]] = {
    "AUTHENTIC_INTR_POSTURE_VERIFIER_NOT_BOUND": (
        "vendor StegOS stegos/intr_security_posture_resolution.py byte-for-byte under runtime/vendor/stegos_intr "
        "with its sha256 pinned in vendor-manifest.json",
        "a new manifest for the same work once the native verifier is vendored and its digest verifies"),
    NO_CLAIM_FENCE: (
        "an authentic WorkerCoordinator claim/fence (claim_ref and fence_ref non-null, projection_only false) "
        "admitted by the Registry/WorkerCoordinator surface for this task",
        "a new manifest for the same work carrying the admitted claim/fence; this intake is terminal and nothing waits"),
}


def _six(disposition: str, predicate: str, entrypoint: str, **extra) -> dict[str, Any]:
    repair, next_attempt = REPAIRS.get(predicate, (
        f"satisfy {predicate} with authentic evidence bound to this task",
        f"a new manifest for the same work whose binding satisfies {predicate}; this attempt is terminal"))
    return {"schema": SCHEMA, "disposition": disposition, "failure_code": predicate,
            "failed_predicate": predicate, "required_evidence_or_repair": repair, "retry_entrypoint": entrypoint,
            "owning_existing_goal": OWNING_EXISTING_GOAL, "next_attempt": next_attempt,
            "authority_effect": "NONE", **extra}


def _file_sha256(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def _native_module():
    """The vendored StegOS module, or None when it is absent or its bytes do not match the pinned digest."""
    manifest_path, module_path = VENDOR / "vendor-manifest.json", VENDOR / NATIVE_MODULE
    if not (manifest_path.is_file() and module_path.is_file()):
        return None
    try:
        pinned = json.loads(manifest_path.read_text(encoding="utf-8"))["files"][NATIVE_MODULE]
    except (ValueError, KeyError, TypeError):
        return None
    if pinned != _file_sha256(module_path):
        return None
    spec = importlib.util.spec_from_file_location("sv_llm_vendored_stegos_intr_posture", module_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def native_posture_verifier() -> Callable[..., Any] | None:
    """The vendored StegOS verifier, or None when it is absent or its bytes do not match the pinned digest."""
    fn = getattr(_native_module(), NATIVE_FUNCTION, None)
    return fn if callable(fn) else None


def capability_floor(binding: dict[str, Any], instance: Any) -> tuple[str | None, str | None]:
    """(floor tier, None) or (None, refusing predicate). The floor is never lowered by the manifest being gated:
    it is the service's declared minimum raised by the instance's automatic/data-class/channel floors, and the
    manifest's binding.required_tier only counts when it is higher."""
    try:
        service = json.loads(SERVICE_CONTRACT.read_text(encoding="utf-8")).get("minimum_security_tier")
    except (OSError, ValueError, AttributeError):
        service = None
    if service not in TIERS:
        return None, "SERVICE_MINIMUM_SECURITY_TIER_DECLARED"
    candidates = [service]
    requested = binding.get("required_tier")
    if requested is not None:
        if requested not in TIERS:
            return None, "UNRECOGNIZED_REQUIRED_SECURITY_TIER"
        candidates.append(requested)
    if isinstance(instance, dict):
        native = _native_module()
        candidates += [t for t in (instance.get("automatic_tier"),
                                   getattr(native, "DATA_CLASS_MINIMUM", {}).get(instance.get("data_class")),
                                   getattr(native, "CHANNEL_MINIMUM", {}).get(instance.get("channel")))
                       if t in TIERS]
    return max(candidates, key=TIERS.__getitem__), None


def observed_at(hb_epoch: int) -> str:
    """The supplied heartbeat epoch as the UTC instant the native verifier observes at. No clock is read."""
    return datetime.fromtimestamp(hb_epoch, timezone.utc).isoformat().replace("+00:00", "Z")


def _native_verdict(verifier, instance, task_id, payload_sha256, transition_request_sha256,
                    hb_epoch: int) -> tuple[bool, str | None]:
    """(verified, native refusal reason). The StegOS verifier returns None on success and raises on any failure."""
    if not isinstance(instance, dict):
        return False, "posture_instance_not_supplied"
    try:
        verifier(instance, task_id=task_id, payload_sha256=payload_sha256,
                 transition_request_sha256=transition_request_sha256, observed_at=observed_at(hb_epoch))
    except Exception as exc:
        return False, str(exc) or type(exc).__name__
    return True, None


def request_digests(manifest: dict[str, Any]) -> dict[str, str]:
    """The digests a posture instance and a claim bind to: the declared work, and the manifest without its binding."""
    payload = dict(manifest.get("payload") or {})
    binding_free = {**manifest, "payload": {k: v for k, v in payload.items() if k != "binding"}}
    return {"payload_sha256": sha(payload.get("work")), "transition_request_sha256": sha(binding_free)}


def claim_digest(claim: dict[str, Any]) -> str:
    return sha({k: v for k, v in claim.items() if k != "claim_sha256"})


def _epoch(hb_epoch: Any) -> int | None:
    """The supplied heartbeat epoch as an int (the CLI supplies ASCII digits), or None."""
    if isinstance(hb_epoch, str) and hb_epoch.isascii() and hb_epoch.isdigit():
        return int(hb_epoch)
    return hb_epoch if isinstance(hb_epoch, int) and not isinstance(hb_epoch, bool) else None


def _is_public(binding: dict[str, Any], work: dict[str, Any]) -> bool:
    requested = work.get("requested_capabilities")
    permitted = work.get("permitted_capabilities")
    return (binding.get("public") is True and isinstance(requested, list) and isinstance(permitted, list)
            and bool(requested) and set(requested) | set(permitted) <= PUBLIC_RETRIEVAL_CAPABILITIES)


def _claim_predicate(declared: Any, admitted: dict[str, dict[str, Any]], *, task_id: str,
                     digests: dict[str, str], hb_epoch: int, used_claims: set[str]) -> tuple[str, str] | None:
    """(disposition, predicate) refusing the declared claim/fence, or None when it is the admitted one for this task."""
    if (not isinstance(declared, dict) or declared.get("claim_ref") is None or declared.get("fence_ref") is None
            or declared.get("projection_only") is not False or not admitted):
        return "FAIL_CLOSED", NO_CLAIM_FENCE
    if declared.get("claim_sha256") != claim_digest(declared):
        return "DENY", "WORKERCOORDINATOR_CLAIM_SELF_DIGEST_MATCHES"
    held = admitted.get(declared["claim_sha256"])
    if held is None or held != declared:
        return "DENY", "WORKERCOORDINATOR_CLAIM_ADMITTED"
    if declared.get("schema") != CLAIM_SCHEMA or declared.get("authority") != CLAIM_AUTHORITY:
        return "DENY", "WORKERCOORDINATOR_IS_CLAIM_AUTHORITY"
    if declared.get("task_id") != task_id:
        return "DENY", "WORKERCOORDINATOR_CLAIM_TASK_BINDING"
    if declared.get("transition_request_sha256") != digests["transition_request_sha256"]:
        return "DENY", "WORKERCOORDINATOR_FENCE_HEAD_BINDING"
    valid_until = declared.get("valid_until_epoch")
    if not isinstance(valid_until, int) or isinstance(valid_until, bool) or hb_epoch > valid_until:
        return "DENY", "WORKERCOORDINATOR_CLAIM_NOT_STALE"
    if declared["claim_sha256"] in used_claims:
        return "DENY", "WORKERCOORDINATOR_CLAIM_NOT_REPLAYED"
    return None


def evaluate_take(manifest: dict[str, Any], *, task_id: str, hb_epoch: Any,
                  admitted_claims: Iterable[dict[str, Any]], bound: Iterable[dict[str, Any]],
                  verifier: Callable[..., Any] | None) -> dict[str, Any]:
    """The binding verdict for taking `manifest` in. `bound` is every earlier ALLOW binding on this ledger chain."""
    payload = manifest.get("payload") or {}
    binding = payload.get("binding") if isinstance(payload.get("binding"), dict) else {}
    work = payload.get("work") if isinstance(payload.get("work"), dict) else {}
    digests = request_digests(manifest)
    lineage = {"task_id": task_id, **digests}
    if _is_public(binding, work):
        base = evaluate_binding(public=True)
        return {"schema": SCHEMA, "disposition": "ALLOW", "predicate": base["predicate"], "public": True,
                "authority_effect": "NONE", **lineage}
    hb_epoch = _epoch(hb_epoch)
    if hb_epoch is None:
        return _six("FAIL_CLOSED", "SUPPLIED_EPOCH_FOR_BINDING_OBSERVATION", TAKE_ENTRYPOINT, **lineage)
    posture = binding.get("posture")
    instance = posture.get("posture_instance") if isinstance(posture, dict) else None
    native: dict[str, Any] = {}

    def natively(inst, _manifest) -> bool:
        ok, native["reason"] = _native_verdict(verifier, inst, task_id, digests["payload_sha256"],
                                               digests["transition_request_sha256"], hb_epoch)
        return ok
    floor, refused = capability_floor(binding, instance)
    if refused is not None:
        return _six("FAIL_CLOSED", refused, TAKE_ENTRYPOINT, **lineage)
    # The manifest's admission is the boundary ingress receipt pair the caller already read back.
    base = evaluate_binding(public=False, node=binding.get("node"), posture=posture,
                            manifest={"task_id": task_id, "disposition": "ALLOW", "authenticated": True},
                            required_tier=floor,
                            posture_verifier=natively if callable(verifier) else None)
    if base["disposition"] != "ALLOW":
        return _six(base["disposition"], base["predicate"], TAKE_ENTRYPOINT, native_reason=native.get("reason"),
                    **lineage)
    bound = list(bound)
    instance_sha256 = sha(instance)
    if instance_sha256 in {b.get("posture_instance_sha256") for b in bound}:
        return _six("DENY", "POSTURE_INSTANCE_NOT_REPLAYED", TAKE_ENTRYPOINT, **lineage)
    admitted = {c.get("claim_sha256"): c for c in admitted_claims if isinstance(c, dict)}
    declared = binding.get("worker_claim")
    refused = _claim_predicate(declared, admitted, task_id=task_id, digests=digests, hb_epoch=hb_epoch,
                               used_claims={b.get("claim_sha256") for b in bound})
    if refused is not None:
        return _six(*refused, TAKE_ENTRYPOINT, claim_ref=(declared or {}).get("claim_ref") if isinstance(declared, dict) else None,
                    fence_ref=(declared or {}).get("fence_ref") if isinstance(declared, dict) else None,
                    projection_only=not isinstance(declared, dict) or declared.get("projection_only") is not False,
                    **lineage)
    return {"schema": SCHEMA, "disposition": "ALLOW", "predicate": base["predicate"], "public": False,
            "node_id": base["node_id"], "security_tier": base["security_tier"], "capability_floor": floor,
            "posture_instance_sha256": instance_sha256, "claim_sha256": declared["claim_sha256"],
            "claim_ref": declared["claim_ref"], "fence_ref": declared["fence_ref"],
            "return_organization": (manifest.get("return_to") or {}).get("organization"),
            "execution_authorized_by_binding": False, "authority_effect": "NONE", **lineage}


def evaluate_return(manifest: dict[str, Any], take_binding: dict[str, Any] | None, *, task_id: str,
                    hb_epoch: Any, admitted_claims: Iterable[dict[str, Any]],
                    verifier: Callable[..., Any] | None) -> dict[str, Any]:
    """Revalidate, before egress, that the return crossing is the one the take-time binding bound."""
    digests = request_digests(manifest)
    lineage = {"task_id": task_id, **digests}
    if not isinstance(take_binding, dict) or take_binding.get("disposition") != "ALLOW":
        return _six("FAIL_CLOSED", "TAKE_BINDING_RECEIPT_PRESENT", RETURN_ENTRYPOINT, **lineage)
    lineage["take_binding_receipt_sha256"] = take_binding.get("repo_receipt_sha256")
    if take_binding.get("task_id") != task_id or any(take_binding.get(k) != v for k, v in digests.items()):
        return _six("DENY", "RETURN_BOUND_TO_TAKEN_REQUEST", RETURN_ENTRYPOINT, **lineage)
    if take_binding.get("public") is True:
        return {"schema": SCHEMA, "disposition": "ALLOW", "predicate": "PUBLIC_INFORMATION_NODE_NOT_REQUIRED",
                "public": True, "authority_effect": "NONE", **lineage}
    if (manifest.get("return_to") or {}).get("organization") != take_binding.get("return_organization"):
        return _six("DENY", "RETURN_ORGANIZATION_IS_BOUND_ORGANIZATION", RETURN_ENTRYPOINT, **lineage)
    hb_epoch = _epoch(hb_epoch)
    if hb_epoch is None:
        return _six("FAIL_CLOSED", "SUPPLIED_EPOCH_FOR_BINDING_OBSERVATION", RETURN_ENTRYPOINT, **lineage)
    if not callable(verifier):
        return _six("FAIL_CLOSED", "AUTHENTIC_INTR_POSTURE_VERIFIER_NOT_BOUND", RETURN_ENTRYPOINT, **lineage)
    binding = (manifest.get("payload") or {}).get("binding") or {}
    instance = (binding.get("posture") or {}).get("posture_instance")
    if sha(instance) != take_binding.get("posture_instance_sha256"):
        return _six("DENY", "RETURN_POSTURE_INSTANCE_IS_BOUND_INSTANCE", RETURN_ENTRYPOINT, **lineage)
    ok, reason = _native_verdict(verifier, instance, task_id, digests["payload_sha256"],
                                 digests["transition_request_sha256"], hb_epoch)
    if not ok:
        return _six("FAIL_CLOSED", "POSTURE_INSTANCE_CRYPTOGRAPHIC_VERIFICATION_NOT_OBSERVED", RETURN_ENTRYPOINT,
                    native_reason=reason, **lineage)
    admitted = {c.get("claim_sha256"): c for c in admitted_claims if isinstance(c, dict)}
    held = admitted.get(take_binding.get("claim_sha256"))
    if held is None:
        return _six("FAIL_CLOSED", NO_CLAIM_FENCE, RETURN_ENTRYPOINT, **lineage)
    if held.get("fence_ref") != take_binding.get("fence_ref") or hb_epoch > held.get("valid_until_epoch", -1):
        return _six("DENY", "WORKERCOORDINATOR_FENCE_STILL_HELD", RETURN_ENTRYPOINT, **lineage)
    return {"schema": SCHEMA, "disposition": "ALLOW", "predicate": "RETURN_CROSSING_REVALIDATED", "public": False,
            "claim_sha256": take_binding["claim_sha256"], "fence_ref": held["fence_ref"],
            "authority_effect": "NONE", **lineage}
