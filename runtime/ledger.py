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
"""
from __future__ import annotations
import fcntl, hashlib, json, os, tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
CONTRACT = json.loads((ROOT / ".stegverse/transition-ledger/contract.json").read_text())
REPOSITORY = CONTRACT["repository"]


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
    def __init__(self, root: Path | None = None, *, store: Any = None):
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
              prev: str | None) -> dict[str, Any]:
        return {"schema": "stegverse.repo-transition-receipt/v1", "repository": REPOSITORY,
                "transition_id": transition_class + ":" + successor[7:31],
                "transition_class": transition_class,
                "predecessor_state_sha256": predecessor, "successor_state_sha256": successor,
                "evidence": evidence, "authority_effect": "NONE", "hb_reference": None,
                "observed_at": datetime.now(timezone.utc).isoformat(),
                "previous_receipt_sha256": prev}

    def _append_to_store(self, transition_class: str, predecessor: str, successor: str,
                         evidence: dict[str, Any]) -> dict[str, Any]:
        for _attempt in range(APPEND_ATTEMPTS):
            expected_head = self.store.get(HEAD_KEY)
            prev = (expected_head or {}).get("receipt_sha256")
            body = self._body(transition_class, predecessor, successor, evidence, prev)
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
               evidence: dict[str, Any]) -> dict[str, Any]:
        if self.store is not None:
            return self._append_to_store(transition_class, predecessor, successor, evidence)
        self.receipts_dir.mkdir(parents=True, exist_ok=True)
        with (self.root / ".append.lock").open("a+b") as lock:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
            prev = json.loads(self.head.read_text())["receipt_sha256"] if self.head.exists() else None
            body = self._body(transition_class, predecessor, successor, evidence, prev)
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
