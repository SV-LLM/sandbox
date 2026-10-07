"""SV-LLM/sandbox repository transition ledger.

Receipts use stegverse.repo-transition-receipt/v1, the same shape as
SV-LLM/.github .stegverse/transition-ledger/emit.py, so the SV-LLM
organization ledger aggregates them unchanged. Evidence is passed in-process
and written as a file; it never travels as a command-line argument, so its
size is bounded only by storage.
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


class Ledger:
    def __init__(self, root: Path | None = None):
        self.root = Path(root) if root is not None else default_root()
        self.receipts_dir = self.root / "receipts"
        self.head = self.root / "HEAD.json"

    def append(self, transition_class: str, *, predecessor: str, successor: str,
               evidence: dict[str, Any]) -> dict[str, Any]:
        self.receipts_dir.mkdir(parents=True, exist_ok=True)
        with (self.root / ".append.lock").open("a+b") as lock:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
            prev = json.loads(self.head.read_text())["receipt_sha256"] if self.head.exists() else None
            body = {"schema": "stegverse.repo-transition-receipt/v1", "repository": REPOSITORY,
                    "transition_id": transition_class + ":" + successor[7:31],
                    "transition_class": transition_class,
                    "predecessor_state_sha256": predecessor, "successor_state_sha256": successor,
                    "evidence": evidence, "authority_effect": "NONE", "hb_reference": None,
                    "observed_at": datetime.now(timezone.utc).isoformat(),
                    "previous_receipt_sha256": prev}
            digest = sha(body)
            receipt = {**body, "receipt_sha256": digest}
            path = self.receipts_dir / (digest[7:] + ".json")
            if path.exists():
                raise ValueError("receipt collision")
            _atomic_write(path, receipt)
            _atomic_write(self.head, {"repository": REPOSITORY, "receipt_sha256": digest, "receipt_path": str(path)})
            return receipt

    def chain(self) -> list[dict[str, Any]]:
        """All receipts in append order, each hash and back-link verified."""
        if not self.head.exists():
            return []
        out, cursor = [], json.loads(self.head.read_text())["receipt_sha256"]
        while cursor is not None:
            receipt = json.loads((self.receipts_dir / (cursor[7:] + ".json")).read_text())
            body = dict(receipt)
            claimed = body.pop("receipt_sha256")
            if claimed != cursor or sha(body) != claimed:
                raise ValueError("RECEIPT_HASH_MISMATCH: " + cursor)
            out.append(receipt)
            cursor = receipt["previous_receipt_sha256"]
        out.reverse()
        if len(out) != len(list(self.receipts_dir.glob("*.json"))):
            raise ValueError("RECEIPT_OUTSIDE_CHAIN")
        return out
