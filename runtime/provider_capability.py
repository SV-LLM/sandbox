"""Offline validator for sv-llm.provider-capability/v0.1 declarations.

Canonical copy: SV-LLM/sandbox runtime/provider_capability.py. Provider
repositories vendor this file byte-for-byte; each records the sha256 of the
copy it vendors.

The validator reads one declaration and returns a disposition:

- FAIL_CLOSED: the declaration cannot be evaluated (malformed, missing fields,
  unbound provenance).
- DENY: the declaration is well-formed but claims something it may not
  (authority, credentials, live endpoints, execution or runtime observation,
  an authentic interface without a receipt, a foreign identity).
- ALLOW: neither.

It performs no network access and calls no provider. A disposition is
evidence about a source file; it is not a governance transition.
"""
from __future__ import annotations

import json
import re
import sys
from typing import Any

SCHEMA = "sv-llm.provider-capability/v0.1"
ALLOW, DENY, FAIL_CLOSED = "ALLOW", "DENY", "FAIL_CLOSED"
MAX_SAFE = 9007199254740991

REQUIRED = ("schema", "entity", "repository", "provider_family", "role", "authority_effect", "installation",
            "lifecycle_claim", "capabilities", "interfaces", "operations", "provenance", "runtime_observations",
            "crossing", "prohibited")
CAPABILITY_VOCABULARY = frozenset({
    "reasoning", "synthesis", "code_analysis", "code_generation", "document_analysis",
    "cross_repository_contract_analysis", "adversarial_review", "candidate_repair",
    "forward_disposition_inference"})
REQUIRED_PROHIBITIONS = frozenset({
    "GOVERNANCE_DISPOSITION", "TASK_REGISTRY_AUTHORITY", "WORKER_CLAIM_AUTHORITY", "TRANSITION_AUTHORITY",
    "CREDENTIAL_AUTHORITY", "PUBLISHER_AUTHORITY", "LEDGER_AUTHORITY", "DIRECT_CONSEQUENCE_EXECUTION",
    "MODEL_CONSENSUS_AS_TRUTH", "TRANSPORT_OUTSIDE_ORGANIZATION_INTR_BOUNDARY"})
LIFECYCLE_CLAIMS = frozenset({"SOURCE_IMPLEMENTED"})
INTERFACE_KINDS = frozenset({"PROVIDER_API", "CONSUMER_PRODUCT", "OPEN_WEIGHTS"})
INTERFACE_STATUSES = frozenset({"DOCUMENTED_NOT_INVOKED", "NO_APPROVED_AUTOMATION_SURFACE",
                                "AUTHENTIC_INTERFACE_AVAILABLE"})
OPERATION_STATUSES = frozenset({"DOCUMENTED", "UNVERIFIED", "UNSUPPORTED"})
REGISTRY_PENDING = "REGISTRY_RECONCILIATION_PENDING"
SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
TIMESTAMP = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
CREDENTIAL_KEY = re.compile(r"(api_?key|secret|password|passwd|bearer|access_?token|auth_?token|private_?key)", re.I)
CREDENTIAL_VALUE = re.compile(r"(\bsk-[A-Za-z0-9_-]{16,}|\bAKIA[0-9A-Z]{16}\b|\bAIza[0-9A-Za-z_-]{30,}|"
                              r"-----BEGIN [A-Z ]*PRIVATE KEY-----|\bxai-[A-Za-z0-9]{20,}|\bBearer\s+[A-Za-z0-9._-]{16,})")
ENDPOINT_KEY = re.compile(r"^(endpoint|base_url|api_base|host|invoke_url)$", re.I)
AUTHORITY_ROLE = "INTELLIGENCE_CAPABILITY"


class _Result:
    def __init__(self) -> None:
        self.fail_closed: list[str] = []
        self.deny: list[str] = []

    def disposition(self) -> dict[str, Any]:
        if self.fail_closed:
            d = FAIL_CLOSED
        elif self.deny:
            d = DENY
        else:
            d = ALLOW
        return {"disposition": d, "failed_predicates": sorted(set(self.fail_closed)) + sorted(set(self.deny))}


def _canonical_domain(value: Any) -> bool:
    if value is None or isinstance(value, (bool, str)):
        return True
    if isinstance(value, int):
        return -MAX_SAFE <= value <= MAX_SAFE
    if isinstance(value, list):
        return all(_canonical_domain(v) for v in value)
    if isinstance(value, dict):
        return all(isinstance(k, str) and _canonical_domain(v) for k, v in value.items())
    return False


def _walk(value: Any, path: str = "$"):
    yield path, None, value
    if isinstance(value, dict):
        for k, v in value.items():
            yield path, k, v
            yield from _walk(v, f"{path}.{k}")
    elif isinstance(value, list):
        for i, v in enumerate(value):
            yield from _walk(v, f"{path}[{i}]")


def _is_https(url: Any) -> bool:
    return isinstance(url, str) and url.startswith("https://") and len(url) > len("https://")


def validate(decl: Any, expected_repository: str | None = None) -> dict[str, Any]:
    r = _Result()
    if not isinstance(decl, dict):
        r.fail_closed.append("DECLARATION_IS_OBJECT")
        return r.disposition()
    if decl.get("schema") != SCHEMA:
        r.fail_closed.append("SCHEMA_DECLARED")
    missing = [k for k in REQUIRED if k not in decl]
    if missing:
        r.fail_closed.append("REQUIRED_FIELDS_PRESENT")
        return r.disposition()
    if not _canonical_domain(decl):
        r.fail_closed.append("CANONICAL_JSON_DOMAIN")

    _identity(decl, expected_repository, r)
    _authority(decl, r)
    _installation(decl, r)
    sources = _provenance(decl, r)
    interface_ids = _interfaces(decl, r)
    _operations(decl, sources, interface_ids, r)
    _execution_claims(decl, r)
    _secrets_and_endpoints(decl, r)
    return r.disposition()


def _identity(decl: dict, expected: str | None, r: _Result) -> None:
    for k in ("entity", "repository", "provider_family"):
        if not isinstance(decl[k], str) or not decl[k]:
            r.fail_closed.append("FIELD_TYPES_VALID")
            return
    if decl["entity"] != decl["repository"]:
        r.deny.append("PROVIDER_IDENTITY_BOUND")
    if expected is not None and decl["repository"] != expected:
        r.deny.append("PROVIDER_IDENTITY_BOUND")


def _authority(decl: dict, r: _Result) -> None:
    if decl["authority_effect"] != "NONE":
        r.deny.append("AUTHORITY_EFFECT_NONE")
    if decl["role"] != AUTHORITY_ROLE:
        r.deny.append("NO_ALTERNATE_GOVERNANCE_AUTHORITY")
    caps = decl["capabilities"]
    if not isinstance(caps, list) or not caps or len(caps) != len(set(map(str, caps))):
        r.fail_closed.append("FIELD_TYPES_VALID")
    elif not set(caps) <= CAPABILITY_VOCABULARY:
        r.deny.append("NO_ALTERNATE_GOVERNANCE_AUTHORITY")
    prohibited = decl["prohibited"]
    if not isinstance(prohibited, list) or not REQUIRED_PROHIBITIONS <= set(prohibited):
        r.deny.append("NO_ALTERNATE_GOVERNANCE_AUTHORITY")
    crossing = decl["crossing"]
    if not isinstance(crossing, dict):
        r.fail_closed.append("FIELD_TYPES_VALID")
        return
    expected = {"boundary": "SV-LLM/.github", "transition_authority": "Interlock/InTr",
                "credential_authority": "TV/TVC", "transport_in_this_repository": False,
                "credential_material_in_this_repository": False, "live_invocation": False}
    if any(crossing.get(k) != v for k, v in expected.items()):
        r.deny.append("NO_ALTERNATE_GOVERNANCE_AUTHORITY")


def _installation(decl: dict, r: _Result) -> None:
    inst = decl["installation"]
    if not isinstance(inst, dict) or not {"task_id", "cosv", "registry_status"} <= set(inst):
        r.fail_closed.append("INSTALLATION_TASK_BOUND")
        return
    if inst["task_id"] is None or inst["cosv"] is None:
        if inst["registry_status"] != REGISTRY_PENDING:
            r.fail_closed.append("INSTALLATION_TASK_BOUND")
    elif not (isinstance(inst["task_id"], str) and isinstance(inst["cosv"], str) and inst["cosv"].isdigit()):
        r.fail_closed.append("INSTALLATION_TASK_BOUND")
    if decl["lifecycle_claim"] not in LIFECYCLE_CLAIMS:
        r.deny.append("NO_UNEVIDENCED_EXECUTION_CLAIM")


def _provenance(decl: dict, r: _Result) -> list[dict]:
    prov = decl["provenance"]
    if not isinstance(prov, dict) or not isinstance(prov.get("sources"), list) or not prov["sources"]:
        r.fail_closed.append("PROVENANCE_BOUND")
        return []
    if prov.get("epistemic_state") != "DERIVED" or not prov.get("method"):
        r.fail_closed.append("PROVENANCE_BOUND")
    for s in prov["sources"]:
        if not isinstance(s, dict) or not _is_https(s.get("url")) or not TIMESTAMP.match(str(s.get("observed_at"))):
            r.fail_closed.append("PROVENANCE_BOUND")
            continue
        if s.get("http_status") == 200:
            if not SHA256.match(str(s.get("body_sha256"))) or not _is_https(s.get("final_url")):
                r.fail_closed.append("PROVENANCE_BOUND")
        elif not s.get("fetch_error"):
            r.fail_closed.append("PROVENANCE_BOUND")
    return prov["sources"]


def _interfaces(decl: dict, r: _Result) -> set[str]:
    ifaces = decl["interfaces"]
    if not isinstance(ifaces, list) or not ifaces:
        r.fail_closed.append("FIELD_TYPES_VALID")
        return set()
    ids: set[str] = set()
    for i in ifaces:
        if not isinstance(i, dict) or not isinstance(i.get("interface_id"), str):
            r.fail_closed.append("FIELD_TYPES_VALID")
            continue
        ids.add(i["interface_id"])
        if i.get("kind") not in INTERFACE_KINDS or i.get("status") not in INTERFACE_STATUSES:
            r.fail_closed.append("FIELD_TYPES_VALID")
            continue
        if i.get("live_invocation") is not False or i.get("credential_material_in_repository") is not False:
            r.deny.append("NO_UNEVIDENCED_EXECUTION_CLAIM")
        if i["status"] == "AUTHENTIC_INTERFACE_AVAILABLE":
            # v0.1 has no admissible receipt form for an authentic interface; every such claim is refused.
            r.deny.append("AUTHENTIC_INTERFACE_EVIDENCED")
        if i["kind"] == "CONSUMER_PRODUCT" and i["status"] != "NO_APPROVED_AUTOMATION_SURFACE":
            r.deny.append("AUTHENTIC_INTERFACE_EVIDENCED")
    if len(ids) != len(ifaces):
        r.fail_closed.append("FIELD_TYPES_VALID")
    return ids


def _operations(decl: dict, sources: list[dict], interface_ids: set[str], r: _Result) -> None:
    ops = decl["operations"]
    if not isinstance(ops, list) or not ops:
        r.fail_closed.append("FIELD_TYPES_VALID")
        return
    for op in ops:
        if not isinstance(op, dict) or not isinstance(op.get("operation"), str):
            r.fail_closed.append("FIELD_TYPES_VALID")
            continue
        status = op.get("status")
        if status not in OPERATION_STATUSES:
            r.deny.append("NO_UNEVIDENCED_EXECUTION_CLAIM")
            continue
        if op.get("interface_id") not in interface_ids:
            r.fail_closed.append("FIELD_TYPES_VALID")
        if status == "DOCUMENTED":
            ev = op.get("evidence")
            idx = ev.get("source_index") if isinstance(ev, dict) else None
            if (not isinstance(idx, int) or isinstance(idx, bool) or not 0 <= idx < len(sources)
                    or not isinstance(sources[idx], dict) or sources[idx].get("http_status") != 200
                    or not isinstance(ev.get("excerpt"), str) or not ev["excerpt"].strip()):
                r.fail_closed.append("PROVENANCE_BOUND")


def _execution_claims(decl: dict, r: _Result) -> None:
    if decl["runtime_observations"] != []:
        r.deny.append("NO_UNEVIDENCED_EXECUTION_CLAIM")


def _secrets_and_endpoints(decl: dict, r: _Result) -> None:
    for _path, key, value in _walk(decl):
        if key is not None:
            if CREDENTIAL_KEY.search(key):
                r.deny.append("NO_CREDENTIAL_MATERIAL")
            if ENDPOINT_KEY.match(key):
                r.deny.append("NO_LIVE_ENDPOINT_DEPENDENCY")
        elif isinstance(value, str) and CREDENTIAL_VALUE.search(value):
            r.deny.append("NO_CREDENTIAL_MATERIAL")


def main(argv: list[str]) -> int:
    if len(argv) not in (2, 3):
        print("usage: python -m sv_llm_provider_capability.validator <capability.json> [expected-repository]",
              file=sys.stderr)
        return 2
    try:
        with open(argv[1], encoding="utf-8") as fh:
            decl = json.load(fh, parse_float=lambda s: float(s))
    except (OSError, ValueError) as exc:
        print(json.dumps({"disposition": FAIL_CLOSED, "failed_predicates": ["DECLARATION_READABLE"],
                          "detail": str(exc)}))
        return 1
    result = validate(decl, argv[2] if len(argv) == 3 else None)
    print(json.dumps(result, sort_keys=True))
    return 0 if result["disposition"] == ALLOW else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
