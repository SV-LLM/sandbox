"""Test-only fixture binding for runtime/work_cycle_binding.py: a fixture StegNode observation, a posture instance
minted by the vendored StegOS resolver at the supplied epoch, and a fixture WorkerCoordinator claim/fence.

None of it is authentic: the claim is admitted only by the test that builds the WorkCycle with it. Production
(work_cycle.py main()) admits no claim, so every protected take there fails closed.
"""
from __future__ import annotations
import copy, importlib.util, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "runtime"))
import work_cycle_binding as wcb  # noqa: E402
from ledger import sha  # noqa: E402

_spec = importlib.util.spec_from_file_location("sv_llm_test_stegos_intr_resolver",
                                               wcb.VENDOR / wcb.NATIVE_MODULE)
STEGOS = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(STEGOS)

NODE = {"node_id": "stegnode-fixture", "continuity_established": True, "class_established": True}


def claim(manifest: dict, *, valid_until_epoch: int, task_id: str | None = None, posture_instance: dict | None = None,
          **overrides) -> dict:
    """A fixture claim/fence bound to the manifest's request and to `posture_instance` (default: the manifest's own)."""
    digests = wcb.request_digests(manifest)
    if posture_instance is None:
        posture_instance = ((manifest["payload"].get("binding") or {}).get("posture") or {}).get("posture_instance")
    c = {"schema": wcb.CLAIM_SCHEMA, "authority": wcb.CLAIM_AUTHORITY,
         "task_id": task_id or manifest["manifest_id"], "claim_ref": "wc-claim:" + manifest["manifest_id"],
         "fence_ref": "wc-fence:1", "projection_only": False,
         "transition_request_sha256": digests["transition_request_sha256"],
         "posture_instance_sha256": sha(posture_instance), "valid_until_epoch": valid_until_epoch}
    c.update(overrides)
    c["claim_sha256"] = wcb.claim_digest(c)
    return c


def bind(manifest: dict, hb_epoch: int, *, tier: str = "HIGH", required_tier: str = "SECURE",
         claim_overrides: dict | None = None, valid_for: int = 600) -> tuple[dict, dict]:
    """(manifest carrying a binding valid at hb_epoch, the claim a test must admit for it)."""
    m = copy.deepcopy(manifest)
    m["payload"].pop("binding", None)
    digests = wcb.request_digests(m)
    posture = STEGOS.resolve_task_security_posture(
        request={"schema": STEGOS.REQUEST_SCHEMA, "authority_effect": "NONE_REQUEST_INPUT_ONLY",
                 "task_id": m["manifest_id"], "selected_tier": tier},
        task_id=m["manifest_id"], payload_sha256=digests["payload_sha256"],
        transition_request_sha256=digests["transition_request_sha256"], observed_at=wcb.observed_at(hb_epoch))
    c = claim(m, valid_until_epoch=hb_epoch + valid_for, posture_instance=posture["posture_instance"],
              **(claim_overrides or {}))
    m["payload"]["binding"] = {"node": dict(NODE), "posture": posture, "required_tier": required_tier,
                               "worker_claim": c}
    return m, c

# Offline predicate evidence only. These patches are installed by tests, never
# imported by runtime code, and do not provide an admission producer to WorkCycle.
RAW_TAKE = wcb.evaluate_take
RAW_RETURN = wcb.evaluate_return


def admission(manifest):
    return {"task_id": manifest["manifest_id"], "authenticated": True,
            "disposition": "ALLOW", **wcb.request_digests(manifest)}


def install_admission_fixture(case):
    from unittest.mock import patch
    def take(manifest, *args, **kwargs):
        kwargs.setdefault("manifest_admission", admission(manifest))
        return RAW_TAKE(manifest, *args, **kwargs)
    def returned(manifest, *args, **kwargs):
        kwargs.setdefault("manifest_admission", admission(manifest))
        return RAW_RETURN(manifest, *args, **kwargs)
    patches = [patch.object(wcb, "evaluate_take", side_effect=take),
               patch.object(wcb, "evaluate_return", side_effect=returned)]
    for item in patches:
        item.start()
        case.addCleanup(item.stop)
    return patches
