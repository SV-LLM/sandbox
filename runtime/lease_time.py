"""Lease time from the supplied hb_epoch: the browser lease never reads a clock (NWI-S1).

StegVerse-org/.github#162 (NWI-S1). The StegBrowser lease is issued, opened,
authorized and closed at the instant of a supplied hb_epoch: the HB32 lattice
instant HB_ANCHOR_UNIX_NS + (epoch - 32) * HB_PERIOD_NS (the org kernel's
oscillator, 100 Hz), as UTC. Nothing here, nor in the code this binds, reads a
clock.

The vendored StegVerse-Labs/StegBrowser module ecosystem_ephemeral.py (bytes
pinned by vendor-manifest.json, so they are not edited) falls back to
datetime.now(timezone.utc) at validate_ephemeral_lease, open, authorize and close
when no `now` is passed -- and its own caller, llm_browser_execution.py, passes
none. bind() replaces that module's `datetime` name with SuppliedDatetime, whose
now() is the instant of the epoch supplied for the current call (a ContextVar
set by supplied()) and which refuses, six-field FAIL_CLOSED, when no epoch was
supplied. The clock fallback is unreachable in a process that has bound it.

The tools refuse before any of this when the epoch is absent or invalid
(lease_time_refusal). Live behaviour changes only through admission.
"""
from __future__ import annotations

import contextvars
import datetime as _dt
from contextlib import contextmanager
from typing import Any, Iterator

from ledger import supplied_epoch_failure  # noqa: E402  the vendored shared rule

OWNING_EXISTING_GOAL = "StegVerse-org/.github#162 / INTERLOCK-INTR-RUNTIME-INDEPENDENT-PROTOCOL-001 (NWI-S1)"

HB_ANCHOR_EPOCH = 32
HB_ANCHOR_UNIX_NS = 1_787_511_600_000_000_000
HB_PERIOD_NS = 10_000_000
LEASE_TIME_PREDICATE = "LEASE_TIME_IS_THE_SUPPLIED_HB_EPOCH"
_UNIX_EPOCH = _dt.datetime(1970, 1, 1, tzinfo=_dt.timezone.utc)
_CURRENT: contextvars.ContextVar[_dt.datetime | None] = contextvars.ContextVar("sv_llm_lease_instant", default=None)


def lease_time_refusal(hb_epoch: Any, *, field: str = "hb_epoch") -> dict[str, Any] | None:
    """The six-field FAIL_CLOSED refusal of a lease time source, or None when the epoch is a supplied one."""
    failure = supplied_epoch_failure(hb_epoch)
    if failure is None:
        return None
    code, detail = failure
    return {"disposition": "FAIL_CLOSED", "failure_code": code, "failed_predicate": LEASE_TIME_PREDICATE,
            "detail": field + ": " + detail,
            "required_evidence_or_repair": "supply " + field + " (ASCII digits >= " + str(HB_ANCHOR_EPOCH)
                                           + "); the lease time is the supplied epoch's HB32 instant, never a clock",
            "retry_entrypoint": "runtime.stegbrowser_tool.StegBrowserTool.invoke(..., hb_epoch=<supplied>) / "
                                "runtime.page_load_tool.StegBrowserPageLoadTool.invoke(..., hb_epoch=<supplied>)",
            "owning_existing_goal": OWNING_EXISTING_GOAL,
            "next_attempt": "invoke again with the supplied epoch; no lease was issued and no browser launched"}


class LeaseTimeRefused(RuntimeError):
    def __init__(self, refusal: dict[str, Any]):
        super().__init__(refusal["failure_code"] + ":" + refusal["detail"])
        self.refusal = dict(refusal)


def instant(hb_epoch: Any, *, field: str = "hb_epoch") -> _dt.datetime:
    """The UTC instant of a supplied epoch on the HB32 lattice; refuses otherwise."""
    refusal = lease_time_refusal(hb_epoch, field=field)
    if refusal is not None:
        raise LeaseTimeRefused(refusal)
    ns = HB_ANCHOR_UNIX_NS + (int(str(hb_epoch)) - HB_ANCHOR_EPOCH) * HB_PERIOD_NS
    return _UNIX_EPOCH + _dt.timedelta(microseconds=ns // 1000)


def _current() -> _dt.datetime:
    current = _CURRENT.get()
    if current is None:
        raise LeaseTimeRefused(lease_time_refusal(None))
    return current


class SuppliedDatetime(_dt.datetime):
    """datetime whose now() is the supplied epoch's instant for the current call, and never a clock."""

    @classmethod
    def now(cls, tz=None):  # noqa: D102
        current = _current()
        return current if tz is None else current.astimezone(tz)

    @classmethod
    def utcnow(cls):  # noqa: D102
        return _current().replace(tzinfo=None)

    @classmethod
    def today(cls):  # noqa: D102
        return _current().replace(tzinfo=None)


def bind(module: Any) -> Any:
    """Route `module`'s datetime.now() to the supplied epoch (idempotent); returns the module."""
    present = getattr(module, "datetime", None)
    if present is not SuppliedDatetime:
        if present is not _dt.datetime:
            raise RuntimeError("lease_time.bind: " + module.__name__ + ".datetime is not datetime.datetime")
        module.datetime = SuppliedDatetime
    return module


@contextmanager
def supplied(at: _dt.datetime) -> Iterator[_dt.datetime]:
    """Within this block a bound module's now() is `at` (the supplied epoch's instant)."""
    token = _CURRENT.set(at)
    try:
        yield at
    finally:
        _CURRENT.reset(token)
