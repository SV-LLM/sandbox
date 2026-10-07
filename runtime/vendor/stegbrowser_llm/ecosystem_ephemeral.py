"""Governed ephemeral StegBrowser sessions for ecosystem callers.

This module does not create browser execution authority. It validates a bounded
lease issued by an external governance/admission layer and tracks only the
minimal in-memory lifecycle needed to prevent use outside that lease.

No cookies, credentials, browser history, page bodies, form contents, or other
session data are persisted here. Durable output is limited to terminal receipts
and explicitly allow-listed governed artifacts supplied by the caller.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
import json
from typing import Any, Iterable, Mapping
from urllib.parse import urlsplit

LEASE_SCHEMA = "stegbrowser.ecosystem-ephemeral-lease.v1"
RECEIPT_SCHEMA = "stegbrowser.ecosystem-ephemeral-terminal-receipt.v1"
MAX_TTL_SECONDS = 900
_ALLOWED_ACTIONS = {
    "navigate",
    "read_public",
    "read_authenticated",
    "submit_form",
    "download",
    "upload",
}
_ALLOWED_RETAINED_ARTIFACTS = {
    "navigation_receipt",
    "content_commitment",
    "governance_receipt",
    "publication_receipt",
    "error_receipt",
}


def _parse_time(value: str) -> datetime:
    if not isinstance(value, str) or not value:
        raise ValueError("timestamp is required")
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    parsed = datetime.fromisoformat(normalized)
    if parsed.tzinfo is None:
        raise ValueError("timestamp must include timezone")
    return parsed.astimezone(timezone.utc)


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _commit(value: Any) -> str:
    return "sha256:" + hashlib.sha256(_canonical(value)).hexdigest()


def _host_for(url: str) -> str:
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("only http(s) URLs with a hostname are allowed")
    return parsed.hostname.lower().rstrip(".")


def _origin_allowed(host: str, allowed_origins: Iterable[str]) -> bool:
    for origin in allowed_origins:
        candidate = str(origin).lower().rstrip(".")
        if candidate.startswith("*."):
            suffix = candidate[2:]
            if host == suffix or host.endswith("." + suffix):
                return True
        elif host == candidate:
            return True
    return False


def validate_ephemeral_lease(lease: Mapping[str, Any], *, now: datetime | None = None) -> dict[str, Any]:
    """Validate and normalize an externally admitted ephemeral browser lease."""
    if lease.get("schema") != LEASE_SCHEMA:
        raise ValueError("unsupported ephemeral lease schema")

    required_strings = ("lease_id", "task_id", "requester", "purpose", "issued_at", "expires_at")
    for key in required_strings:
        if not isinstance(lease.get(key), str) or not lease.get(key):
            raise ValueError(f"{key} is required")

    issued = _parse_time(str(lease["issued_at"]))
    expires = _parse_time(str(lease["expires_at"]))
    if expires <= issued:
        raise ValueError("lease must expire after issuance")
    if (expires - issued).total_seconds() > MAX_TTL_SECONDS:
        raise ValueError("lease exceeds maximum ephemeral TTL")

    current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    if current < issued:
        raise ValueError("lease is not active yet")
    if current >= expires:
        raise ValueError("lease has expired")

    origins = lease.get("allowed_origins")
    if not isinstance(origins, list) or not origins or not all(isinstance(v, str) and v for v in origins):
        raise ValueError("allowed_origins must be a non-empty string list")

    actions = lease.get("allowed_actions")
    if not isinstance(actions, list) or not actions:
        raise ValueError("allowed_actions must be a non-empty list")
    normalized_actions = sorted(set(str(v) for v in actions))
    unknown_actions = set(normalized_actions) - _ALLOWED_ACTIONS
    if unknown_actions:
        raise ValueError(f"unsupported actions: {sorted(unknown_actions)}")

    retained = lease.get("retain_artifacts", [])
    if not isinstance(retained, list):
        raise ValueError("retain_artifacts must be a list")
    normalized_retained = sorted(set(str(v) for v in retained))
    unknown_retained = set(normalized_retained) - _ALLOWED_RETAINED_ARTIFACTS
    if unknown_retained:
        raise ValueError(f"unsupported retained artifacts: {sorted(unknown_retained)}")

    max_navigations = lease.get("max_navigations", 1)
    if not isinstance(max_navigations, int) or isinstance(max_navigations, bool) or max_navigations < 1 or max_navigations > 100:
        raise ValueError("max_navigations must be an integer from 1 through 100")

    if lease.get("persistent_profile") not in (None, False):
        raise ValueError("persistent browser profiles are prohibited")
    if lease.get("persist_cookies") not in (None, False):
        raise ValueError("cookie persistence is prohibited")
    if lease.get("persist_history") not in (None, False):
        raise ValueError("history persistence is prohibited")
    if lease.get("credential_material") is not None:
        raise ValueError("credential material must not be embedded in the lease")

    normalized = {
        "schema": LEASE_SCHEMA,
        "lease_id": str(lease["lease_id"]),
        "task_id": str(lease["task_id"]),
        "requester": str(lease["requester"]),
        "purpose": str(lease["purpose"]),
        "issued_at": issued.isoformat().replace("+00:00", "Z"),
        "expires_at": expires.isoformat().replace("+00:00", "Z"),
        "allowed_origins": sorted(set(str(v).lower().rstrip(".") for v in origins)),
        "allowed_actions": normalized_actions,
        "retain_artifacts": normalized_retained,
        "max_navigations": max_navigations,
        "persistent_profile": False,
        "persist_cookies": False,
        "persist_history": False,
    }
    normalized["lease_commitment"] = _commit(normalized)
    return normalized


@dataclass
class EphemeralBrowserSession:
    """In-memory, single-lease lifecycle guard for an ecosystem browser session."""

    lease: dict[str, Any]
    opened_at: str
    navigation_count: int = 0
    closed: bool = False
    close_reason: str | None = None
    retained_artifacts: list[dict[str, Any]] = field(default_factory=list)

    @classmethod
    def open(cls, lease: Mapping[str, Any], *, now: datetime | None = None) -> "EphemeralBrowserSession":
        current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
        normalized = validate_ephemeral_lease(lease, now=current)
        return cls(lease=normalized, opened_at=current.isoformat().replace("+00:00", "Z"))

    def authorize(self, *, action: str, url: str, now: datetime | None = None) -> dict[str, Any]:
        if self.closed:
            raise RuntimeError("ephemeral browser session is closed")
        current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
        expires = _parse_time(self.lease["expires_at"])
        if current >= expires:
            self.closed = True
            self.close_reason = "expired"
            raise RuntimeError("ephemeral browser lease expired")
        if action not in self.lease["allowed_actions"]:
            raise PermissionError("action is outside the lease")

        host = _host_for(url)
        if not _origin_allowed(host, self.lease["allowed_origins"]):
            raise PermissionError("origin is outside the lease")

        if action == "navigate":
            if self.navigation_count >= self.lease["max_navigations"]:
                raise PermissionError("navigation limit exhausted")
            self.navigation_count += 1

        decision = {
            "lease_id": self.lease["lease_id"],
            "task_id": self.lease["task_id"],
            "action": action,
            "host": host,
            "authorized_at": current.isoformat().replace("+00:00", "Z"),
            "navigation_count": self.navigation_count,
            "authority_effect": "LEASE_SCOPE_ONLY",
        }
        decision["decision_commitment"] = _commit(decision)
        return decision

    def retain(self, *, artifact_type: str, artifact: Mapping[str, Any]) -> dict[str, Any]:
        if self.closed:
            raise RuntimeError("ephemeral browser session is closed")
        if artifact_type not in self.lease["retain_artifacts"]:
            raise PermissionError("artifact type is not retained by this lease")
        record = {
            "artifact_type": artifact_type,
            "artifact_commitment": _commit(dict(artifact)),
        }
        self.retained_artifacts.append(record)
        return dict(record)

    def close(self, *, reason: str = "completed", now: datetime | None = None) -> dict[str, Any]:
        if self.closed and self.close_reason != "expired":
            raise RuntimeError("ephemeral browser session already closed")
        current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
        if not self.closed:
            self.closed = True
            self.close_reason = reason
        receipt = {
            "schema": RECEIPT_SCHEMA,
            "lease_id": self.lease["lease_id"],
            "task_id": self.lease["task_id"],
            "lease_commitment": self.lease["lease_commitment"],
            "opened_at": self.opened_at,
            "closed_at": current.isoformat().replace("+00:00", "Z"),
            "close_reason": self.close_reason,
            "navigation_count": self.navigation_count,
            "retained_artifacts": list(self.retained_artifacts),
            "persistent_profile_retained": False,
            "cookies_retained": False,
            "history_retained": False,
            "credential_material_retained": False,
            "session_state_destroyed": True,
            "authority_effect": "NONE",
        }
        receipt["receipt_commitment"] = _commit(receipt)
        return receipt
