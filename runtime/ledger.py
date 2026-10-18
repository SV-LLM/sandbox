"""SV-LLM/sandbox repository transition ledger.

Receipts use stegverse.repo-transition-receipt/v1, the same shape as
SV-LLM/.github .stegverse/transition-ledger/emit.py, so the SV-LLM
organization ledger aggregates them unchanged. Evidence is passed in-process
and written as a file; it never travels as a command-line argument, so its
size is bounded only by storage.

A ledger is a POSIX root by default. Given a `store` -- the adopted
SV-LLM/.github reference's ledger store, opened at the location the
materializer supplies -- it keeps the same layout (`HEAD.json`,
`receipts/<hex>.json`) in that store instead, and publishes each append by the
store's own compare-and-swap. A store opened on the repository's declared
subtree of the organization ledger ref (`repository_ledger_location` in
`.stegverse/transition-ledger/contract.json`) is durable: the next run
continues the chain from the published HEAD rather than starting a new one.

Every receipt carries the supplied heartbeat epoch (G4 / NWI-S1,
SV_LLM_LEDGER_APPEND_CLOCK_FALLBACK): `observed_at` used to be the host's
wall clock, so two runs of the same work wrote different receipts. It is now
`SUPPLIED_HB_EPOCH:<epoch>`, and an append without a supplied epoch, or with an
invalid one, is refused six-field FAIL_CLOSED before anything is written. No
clock is read.
"""
from __future__ import annotations
import fcntl, hashlib, json, os, tempfile
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
CONTRACT = json.loads((ROOT / ".stegverse/transition-ledger/contract.json").read_text())
REPOSITORY = CONTRACT["repository"]


#: The shared supplied-epoch rule (SUBMISSION_CARRIES_THE_SUPPLIED_HB_EPOCH),
#: vendored byte-identical (function segment sha256 SHARED_RULE_SHA256) from
#: the organization kernel, as StegVerse-org/.github 40a5d235 vendors it.
HB_EPOCH_PREDICATE = "SUBMISSION_CARRIES_THE_SUPPLIED_HB_EPOCH"
HB_ANCHOR_EPOCH = 32
SHARED_RULE_SHA256 = "726248a585904b52cfe2eec1754e7ce582f67d6b501bd664bb7bee80bce9b7ef"
LEDGER_APPEND_CLOCK_FALLBACK = "SV_LLM_LEDGER_APPEND_CLOCK_FALLBACK"
OWNING_EXISTING_GOAL = "SVORG-LLM-ORG-FOUNDATION-001 W04"
EPOCH_RETRY_ENTRYPOINT = ("runtime/work_cycle.py::WorkCycle._propagate (WorkCycle(hb_epoch=<supplied>) -> "
                          "runtime/ledger.py::Ledger.append)")


def supplied_epoch_failure(hb_epoch: Any, reference: Any = None) -> tuple[str, str] | None:
    """The shared supplied-epoch rule (SUBMISSION_CARRIES_THE_SUPPLIED_HB_EPOCH).

    Byte-identical in StegVerse-org/.github#185 and StegVerse-Labs/.github#3212
    and #3213. `hb_epoch` absent (None) is HB_EPOCH_NOT_SUPPLIED. Otherwise it
    must be ASCII [0-9]+ only -- an int is read as its decimal text; a bool, a
    float or anything coerced ('+33', ' 33', '3_3', '33.0') is refused -- with
    integer value >= 32 (the HB32 anchor). `reference`, the carrier frame's
    heartbeat reference when there is one, must be an object, and a
    `derived_from_clock` it carries must be exactly false. Any failure is
    HB_EPOCH_INVALID. Returns (failure_code, detail), or None when the epoch is
    supplied. No clock is read.
    """
    if reference is not None and not isinstance(reference, dict):
        return "HB_EPOCH_INVALID", "the carrier's heartbeat reference is not an object"
    if hb_epoch is None:
        return "HB_EPOCH_NOT_SUPPLIED", "no hb_epoch was supplied and no clock is read"
    if isinstance(hb_epoch, bool):
        text = None
    elif isinstance(hb_epoch, int):
        text = str(hb_epoch)
    elif isinstance(hb_epoch, str):
        text = hb_epoch
    else:
        text = None
    if text is None or not text.isascii() or not text.isdigit():
        return "HB_EPOCH_INVALID", "hb_epoch " + repr(hb_epoch) + " is not ASCII [0-9]+"
    if int(text) < 32:
        return "HB_EPOCH_INVALID", "hb_epoch " + text + " is below the HB32 anchor (32)"
    if reference is not None and "derived_from_clock" in reference \
            and reference["derived_from_clock"] is not False:
        return "HB_EPOCH_INVALID", ("the carrier's derived_from_clock is not exactly false; "
                                    "a clock-derived epoch is not a supplied one")
    return None


class LedgerEpochRefused(ValueError):
    """An append refused because its epoch was not supplied or is invalid; `refusal` is six-field."""

    def __init__(self, refusal: dict[str, Any]):
        super().__init__(refusal["failure_code"] + ":" + refusal["detail"])
        self.refusal = dict(refusal)


def epoch_refusal(hb_epoch: Any) -> dict[str, Any] | None:
    """The six-field FAIL_CLOSED refusal of a repository ledger append's epoch, or None."""
    failure = supplied_epoch_failure(hb_epoch)
    if failure is None:
        return None
    code, detail = failure
    return {"disposition": "FAIL_CLOSED", "failure_code": code, "failure_class": LEDGER_APPEND_CLOCK_FALLBACK,
            "failed_predicate": HB_EPOCH_PREDICATE, "detail": detail,
            "required_evidence_or_repair": ("supply hb_epoch (WorkCycle(hb_epoch=...) / --hb-epoch / HB_EPOCH): "
                                            "ASCII digits with value >= " + str(HB_ANCHOR_EPOCH)
                                            + "; it is never derived from a clock"),
            "retry_entrypoint": EPOCH_RETRY_ENTRYPOINT, "owning_existing_goal": OWNING_EXISTING_GOAL,
            "next_attempt": "append again with the supplied epoch; nothing was written",
            "authority_effect": "NONE"}


def require_supplied_epoch(hb_epoch: Any) -> int:
    refusal = epoch_refusal(hb_epoch)
    if refusal is not None:
        raise LedgerEpochRefused(refusal)
    return int(str(hb_epoch))


def canon(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def sha(value: Any) -> str:
    data = value if isinstance(value, (bytes, bytearray)) else canon(value)
    return "sha256:" + hashlib.sha256(data).hexdigest()


def default_root() -> Path:
    override = os.getenv("STEGVERSE_REPO_LEDGER_ROOT")
    if override:
        return Path(override).expanduser().resolve()
    state = Path(os.getenv("XDG_STATE_HOME", str(Path.home() / ".local/state")))
    return (state / "stegverse/repo-ledgers" / REPOSITORY).resolve()


def _atomic_write(path: Path, value: Any) -> None:
    fd, name = tempfile.mkstemp(prefix=".tmp-", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


HEAD_KEY = "HEAD.json"
RECEIPT_PREFIX = "receipts/"
# A lost compare-and-swap re-reads HEAD and rebinds; another writer landing
# first this many times in a row is contention, not a race, and fails closed.
APPEND_ATTEMPTS = 128


def receipt_key(digest: str) -> str:
    return RECEIPT_PREFIX + digest[7:] + ".json"


class Ledger:
    def __init__(self, root: Path | None = None, *, store: Any = None, hb_epoch: Any = None):
        # The epoch is supplied by the caller and checked at each append, never read from a clock.
        self.hb_epoch = hb_epoch
        self.store = store
        if store is not None:
            store.initialize()
            self.root = None
            return
        self.root = Path(root) if root is not None else default_root()
        self.receipts_dir = self.root / "receipts"
        self.head = self.root / "HEAD.json"

    @property
    def kind(self) -> str:
        return getattr(self.store, "kind", "POSIX") if self.store is not None else "POSIX"

    def _body(self, transition_class: str, predecessor: str, successor: str, evidence: dict[str, Any],
              prev: str | None, epoch: int) -> dict[str, Any]:
        return {"schema": "stegverse.repo-transition-receipt/v1", "repository": REPOSITORY,
                "transition_id": transition_class + ":" + successor[7:31],
                "transition_class": transition_class,
                "predecessor_state_sha256": predecessor, "successor_state_sha256": successor,
                "evidence": evidence, "authority_effect": "NONE",
                "hb_reference": {"epoch": epoch, "heartbeat_id": "HB:" + str(epoch), "derived_from_clock": False,
                                 "progression_dependency": "OSCILLATOR_ONLY", "authority_effect": "NONE"},
                "observed_at": "SUPPLIED_HB_EPOCH:" + str(epoch),
                "previous_receipt_sha256": prev}

    def _append_to_store(self, transition_class: str, predecessor: str, successor: str,
                         evidence: dict[str, Any], epoch: int) -> dict[str, Any]:
        for _attempt in range(APPEND_ATTEMPTS):
            expected_head = self.store.get(HEAD_KEY)
            prev = (expected_head or {}).get("receipt_sha256")
            body = self._body(transition_class, predecessor, successor, evidence, prev, epoch)
            digest = sha(body)
            receipt = {**body, "receipt_sha256": digest}
            key = receipt_key(digest)
            if self.store.get(key) is not None:
                raise ValueError("receipt collision")
            new_head = {"repository": REPOSITORY, "receipt_sha256": digest, "receipt_path": self.store.locator(key)}
            if self.store.append_transaction(key, receipt, expected_head, new_head):
                return receipt
        raise ValueError("REPO_LEDGER_APPEND_CONTENTION_EXHAUSTED")

    def append(self, transition_class: str, *, predecessor: str, successor: str,
               evidence: dict[str, Any], hb_epoch: Any = None) -> dict[str, Any]:
        """Append one receipt at the supplied epoch (this call's, else the ledger's); refused six-field otherwise."""
        epoch = require_supplied_epoch(self.hb_epoch if hb_epoch is None else hb_epoch)  # before anything is written
        if self.store is not None:
            return self._append_to_store(transition_class, predecessor, successor, evidence, epoch)
        self.receipts_dir.mkdir(parents=True, exist_ok=True)
        with (self.root / ".append.lock").open("a+b") as lock:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
            prev = json.loads(self.head.read_text())["receipt_sha256"] if self.head.exists() else None
            body = self._body(transition_class, predecessor, successor, evidence, prev, epoch)
            digest = sha(body)
            receipt = {**body, "receipt_sha256": digest}
            path = self.receipts_dir / (digest[7:] + ".json")
            if path.exists():
                raise ValueError("receipt collision")
            _atomic_write(path, receipt)
            _atomic_write(self.head, {"repository": REPOSITORY, "receipt_sha256": digest, "receipt_path": str(path)})
            return receipt

    def _read_head(self) -> dict[str, Any] | None:
        if self.store is not None:
            return self.store.get(HEAD_KEY)
        return json.loads(self.head.read_text()) if self.head.exists() else None

    def _read_receipt(self, cursor: str) -> dict[str, Any]:
        if self.store is not None:
            receipt = self.store.get(receipt_key(cursor))
            if receipt is None:
                raise ValueError("RECEIPT_MISSING: " + cursor)
            return receipt
        return json.loads((self.receipts_dir / (cursor[7:] + ".json")).read_text())

    def _stored_receipt_count(self) -> int:
        if self.store is not None:
            return len(self.store.list_prefix(RECEIPT_PREFIX))
        return len(list(self.receipts_dir.glob("*.json")))

    def chain(self) -> list[dict[str, Any]]:
        """All receipts in append order, each hash and back-link verified."""
        head = self._read_head()
        if head is None:
            return []
        out, cursor = [], head["receipt_sha256"]
        while cursor is not None:
            receipt = self._read_receipt(cursor)
            body = dict(receipt)
            claimed = body.pop("receipt_sha256")
            if claimed != cursor or sha(body) != claimed:
                raise ValueError("RECEIPT_HASH_MISMATCH: " + cursor)
            out.append(receipt)
            cursor = receipt["previous_receipt_sha256"]
        out.reverse()
        if len(out) != self._stored_receipt_count():
            raise ValueError("RECEIPT_OUTSIDE_CHAIN")
        return out
