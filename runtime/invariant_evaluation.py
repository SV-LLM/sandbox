#!/usr/bin/env python3
"""RT-INVARIANT-EVALUATION-001 (prototype): answer one structured invariant question.

Input is a question, not free text: an invariant_id resolved from
data/task-registry-global-invariants.json ("invariant:<key>" or
"prohibition:<NAME>"), one subject document, and evidence refs the caller has
already resolved to bytes (repository, path, revision). The component never
fetches, never calls GitHub, and never transitions anything.

Disposition:
  ALLOW        every assertion the subject makes about the invariant equals the
               canonical value.
  DENY         at least one assertion in the subject contradicts the canonical value.
  FAIL_CLOSED  the question cannot be evaluated (malformed question, unknown
               invariant_id, missing/unparseable/digest-mismatched source).
  UNDECIDABLE  the sources are sound but the subject does not speak to the
               invariant; a relay-queue entry file is written for a reader
               with more evidence. Silence is never read as conformance.

Every disposition carries citations of the form repo@revision:path:line.
Every non-ALLOW disposition carries the six fields required by
docs/ECOSYSTEM_STATE_TRANSITION_DISPOSITION_INVARIANT.md plus evidence_refs,
so scripts/validate_transition_disposition.non_allow_missing() accepts it.
authority_effect is NONE_ANSWER_ONLY: this answers; it does not transition.
"""
from __future__ import annotations

import bisect
import hashlib
import os
import json
import re
import sys
from pathlib import Path
from typing import Any

QUESTION_SCHEMA = "stegverse.invariant-question/v1"
ANSWER_SCHEMA = "stegverse.invariant-evaluation/v1"
QUEUE_SCHEMA = "stegverse.invariant-evaluation-relay-queue-entry/v1"
CANONICAL_SCHEMA = "stegverse.task-registry-global-invariants/v1"
CANONICAL_PATH = "data/task-registry-global-invariants.json"
COMPONENT_ID = "RT-INVARIANT-EVALUATION-001"
ALLOW, DENY, FAIL_CLOSED, UNDECIDABLE = "ALLOW", "DENY", "FAIL_CLOSED", "UNDECIDABLE"
MAX_DEPTH = 256  # bound on JSON nesting; deeper subjects fail closed instead of exhausting the stack
ANSWER_AUTHORITY_EFFECT = "NONE_ANSWER_ONLY"  # this component answers; it never transitions
ALLOWED_AUTHORITY_EFFECTS = frozenset({"NONE", "NONE_REGISTRY_INVARIANT_ONLY", "NONE_TEST_FIXTURE", "NONE_ANSWER_ONLY"})
RETRY_ENTRYPOINT = "python -B runtime/invariant_evaluation.py QUESTION.json QUEUE_DIR REPOSITORY:PATH@REVISION=FILE ..."

# Keys under which a subject may name prohibitions it honours or has violated.
PROHIBITION_HONOURED_KEYS = frozenset({"prohibitions", "honoured_prohibitions", "prohibitions_applied"})
PROHIBITION_VIOLATED_KEYS = frozenset({"violated_prohibitions", "violations", "prohibition_violations"})

_WS = re.compile(r"[ \t\n\r]*")
_NUM = re.compile(r"-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][-+]?\d+)?")


# --------------------------------------------------------------------------- position-aware JSON
def _parse_with_lines(text: str) -> tuple[Any, dict[str, int]]:
    """Parse JSON text; return (value, {json_path: 1-based line of the key or element})."""
    from json.decoder import scanstring

    lines: dict[str, int] = {}
    newline_offsets = [i for i, ch in enumerate(text) if ch == "\n"]

    def line_at(i: int) -> int:
        return bisect.bisect_right(newline_offsets, i - 1) + 1

    def skip(i: int) -> int:
        return _WS.match(text, i).end()

    def value(i: int, path: str, depth: int = 0) -> tuple[Any, int]:
        if depth > MAX_DEPTH:
            raise ValueError(f"nesting deeper than {MAX_DEPTH}")
        i = skip(i)
        c = text[i]
        if c == "{":
            obj: dict[str, Any] = {}
            i = skip(i + 1)
            if text[i] == "}":
                return obj, i + 1
            while i < len(text):  # bounded by the input; every member advances i
                i = skip(i)
                if text[i] != '"':
                    raise ValueError(f"expected key at offset {i}")
                key, i = scanstring(text, i + 1)
                if key in obj:
                    raise ValueError(f"duplicate key {key!r} at offset {i}")
                sub = f"{path}.{key}" if path else key
                lines[sub] = line_at(i)
                i = skip(i)
                if text[i] != ":":
                    raise ValueError(f"expected ':' at offset {i}")
                obj[key], i = value(i + 1, sub, depth + 1)
                i = skip(i)
                if text[i] == ",":
                    i += 1
                    continue
                if text[i] == "}":
                    return obj, i + 1
                raise ValueError(f"expected ',' or '}}' at offset {i}")
            raise ValueError("unterminated object")
        if c == "[":
            arr: list[Any] = []
            i = skip(i + 1)
            if text[i] == "]":
                return arr, i + 1
            while i < len(text):  # bounded by the input; every element advances i
                sub = f"{path}[{len(arr)}]"
                lines[sub] = line_at(skip(i))
                v, i = value(i, sub, depth + 1)
                arr.append(v)
                i = skip(i)
                if text[i] == ",":
                    i += 1
                    continue
                if text[i] == "]":
                    return arr, i + 1
                raise ValueError(f"expected ',' or ']' at offset {i}")
            raise ValueError("unterminated array")
        if c == '"':
            return scanstring(text, i + 1)
        for lit, val in (("true", True), ("false", False), ("null", None)):
            if text.startswith(lit, i):
                return val, i + len(lit)
        m = _NUM.match(text, i)
        if m:
            s = m.group()
            return (float(s) if any(ch in s for ch in ".eE") else int(s)), m.end()
        raise ValueError(f"unexpected character {c!r} at offset {i}")

    v, end = value(0, "")
    if text[skip(end):]:
        raise ValueError("trailing data after JSON document")
    return v, lines


def _same(a: Any, b: Any) -> bool:
    """Strict JSON equality: bool is never equal to int, int never to float."""
    if type(a) is not type(b):
        return False
    if isinstance(a, dict):
        return a.keys() == b.keys() and all(_same(a[k], b[k]) for k in a)
    if isinstance(a, list):
        return len(a) == len(b) and all(_same(x, y) for x, y in zip(a, b))
    return a == b


def _walk(value: Any, path: str = ""):
    if isinstance(value, dict):
        for k, v in value.items():
            p = f"{path}.{k}" if path else k
            yield p, k, v
            yield from _walk(v, p)
    elif isinstance(value, list):
        for i, v in enumerate(value):
            yield from _walk(v, f"{path}[{i}]")


# --------------------------------------------------------------------------- sources
class _Source:
    def __init__(self, ref: dict[str, Any], content: bytes):
        self.repository, self.path, self.revision = ref["repository"], ref["path"], ref["revision"]
        self.content = content
        self.digest = "sha256:" + hashlib.sha256(content).hexdigest()
        self.doc, self.lines = _parse_with_lines(content.decode("utf-8"))

    def cite(self, json_path: str | None = None) -> str:
        line = self.lines.get(json_path, 1) if json_path else 1
        return f"{self.repository}@{self.revision}:{self.path}:{line}"


def _str(v: Any) -> bool:
    return isinstance(v, str) and bool(v.strip())


def _load_source(ref: Any, sources: list[dict[str, Any]], problems: list[str]) -> _Source | None:
    if not isinstance(ref, dict) or not all(_str(ref.get(k)) for k in ("repository", "path", "revision")):
        problems.append("source ref lacks repository, path or revision")
        return None
    for s in sources:
        if (s.get("repository"), s.get("path"), s.get("revision")) == (ref["repository"], ref["path"], ref["revision"]):
            content = s.get("content")
            if not isinstance(content, (bytes, bytearray)):
                problems.append(f"{ref['repository']}:{ref['path']} supplied without bytes")
                return None
            # Digest first, parse second: bytes that do not match the cited digest are never parsed.
            digest = "sha256:" + hashlib.sha256(bytes(content)).hexdigest()
            if not _str(ref.get("digest")):
                problems.append(f"{ref['repository']}:{ref['path']} cited without a digest")
                return None
            if ref["digest"] != digest:
                problems.append(f"{ref['repository']}:{ref['path']} digest {ref['digest']} != evaluated {digest}")
                return None
            try:
                return _Source(ref, bytes(content))
            except (ValueError, IndexError, UnicodeDecodeError, RecursionError) as exc:
                problems.append(f"{ref['repository']}:{ref['path']} is not parseable JSON: {exc}")
                return None
    problems.append(f"{ref['repository']}:{ref['path']}@{ref['revision']} was cited but not supplied")
    return None


# --------------------------------------------------------------------------- evaluation
def evaluate(question: Any, sources: list[dict[str, Any]], queue_dir: str | Path | None = None) -> dict[str, Any]:
    """Answer one invariant question against caller-resolved sources.

    sources: [{"repository", "path", "revision", "content": bytes}].
    queue_dir: where an UNDECIDABLE answer writes its relay-queue entry file.
    """
    problems: list[str] = []
    citations: list[str] = []
    findings: list[dict[str, Any]] = []
    qid = question.get("question_id") if isinstance(question, dict) else None
    owning = question.get("owning_existing_goal") if isinstance(question, dict) else None

    def answer(disposition: str, failed_predicate: str, repair: str, next_attempt: str) -> dict[str, Any]:
        out: dict[str, Any] = {
            "schema": ANSWER_SCHEMA, "component_id": COMPONENT_ID, "question_id": qid,
            "invariant_id": question.get("invariant_id") if isinstance(question, dict) else None,
            "disposition": disposition, "citations": sorted(set(citations)), "findings": findings,
            "authority_effect": ANSWER_AUTHORITY_EFFECT,
        }
        if disposition != ALLOW:
            out.update({
                "failure_code": f"INVARIANT_EVALUATION_{disposition}_{failed_predicate}",
                "failed_predicate": failed_predicate,
                "required_evidence_or_repair": repair,
                "retry_entrypoint": RETRY_ENTRYPOINT,
                "owning_existing_goal": owning if _str(owning) else "UNRESOLVED_QUESTION_NAMES_NO_OWNER",
                "next_attempt": next_attempt,
                "evidence_refs": sorted(set(citations)) or [f"SOURCE_RECORD_ONLY:{qid}"],
            })
        if disposition == UNDECIDABLE and queue_dir is not None:
            out["relay_queue_entry"] = _write_queue_entry(Path(queue_dir), question, out, sources)
        return out

    # 1. question well-formed
    if not isinstance(question, dict) or question.get("schema") != QUESTION_SCHEMA:
        problems.append(f"question is not a {QUESTION_SCHEMA} object")
    else:
        for k in ("question_id", "invariant_id", "owning_existing_goal"):
            if not _str(question.get(k)):
                problems.append(f"question lacks {k}")
        if not isinstance(question.get("invariants_source"), dict):
            problems.append("question lacks invariants_source")
        if not isinstance(question.get("subject"), dict):
            problems.append("question lacks subject")
    if problems:
        findings.append({"predicate": "QUESTION_WELL_FORMED", "detail": "; ".join(problems)})
        return answer(FAIL_CLOSED, "QUESTION_WELL_FORMED", "Supply schema, question_id, invariant_id, "
                      "owning_existing_goal, invariants_source and subject.", "Repair the question and evaluate again.")

    # 2. canonical invariants resolved and sound
    canon = _load_source(question["invariants_source"], sources, problems)
    if canon is not None:
        if canon.path != CANONICAL_PATH or not isinstance(canon.doc, dict) or canon.doc.get("schema") != CANONICAL_SCHEMA:
            problems.append(f"invariants_source is not {CANONICAL_PATH} with schema {CANONICAL_SCHEMA}")
        else:
            effect = canon.doc.get("authority_effect")
            if not isinstance(effect, str) or effect not in ALLOWED_AUTHORITY_EFFECTS:
                problems.append("invariants document claims an authority effect")
    if problems:
        findings.append({"predicate": "CANONICAL_SOURCE_BOUND", "detail": "; ".join(problems)})
        return answer(FAIL_CLOSED, "CANONICAL_SOURCE_BOUND",
                      f"Resolve {CANONICAL_PATH} at an exact revision and pass its bytes.",
                      "Re-resolve the canonical invariants and evaluate again.")
    citations.append(canon.cite("schema"))

    # 3. invariant_id resolves inside the canonical document
    iid = question["invariant_id"]
    kind, _, name = iid.partition(":")
    invariants = canon.doc.get("invariants") if isinstance(canon.doc.get("invariants"), dict) else {}
    prohibitions = canon.doc.get("prohibitions") if isinstance(canon.doc.get("prohibitions"), list) else []
    if kind == "invariant" and name in invariants:
        canonical_value = invariants[name]
        citations.append(canon.cite(f"invariants.{name}"))
    elif kind == "prohibition" and name in prohibitions:
        canonical_value = True
        citations.append(canon.cite(f"prohibitions[{prohibitions.index(name)}]"))
    else:
        # Not declared in the supplied canonical bytes: undecidable here, not refused. A reader with more
        # evidence (another revision, a secondary canonical source) answers from the relay queue.
        findings.append({"predicate": "INVARIANT_ID_CANONICAL", "detail": f"{iid!r} is not declared in the supplied canonical document"})
        return answer(UNDECIDABLE, "INVARIANT_ID_CANONICAL",
                      "Ask about an id of the form invariant:<key> or prohibition:<NAME> declared in the canonical document "
                      "at the cited revision, or supply the canonical source that declares it.",
                      "Re-ask with the declaring canonical source, or consume the relay-queue entry.")

    # 4. subject resolved
    subject = _load_source(question["subject"], sources, problems)
    if subject is None:
        findings.append({"predicate": "SUBJECT_SOURCE_BOUND", "detail": "; ".join(problems)})
        return answer(FAIL_CLOSED, "SUBJECT_SOURCE_BOUND", "Resolve the subject at an exact revision and pass its bytes.",
                      "Re-resolve the subject and evaluate again.")
    citations.append(subject.cite())

    # 5. the predicate: what does the subject assert about this invariant?
    conforming: list[str] = []
    contradicting: list[str] = []
    if kind == "invariant":
        for path, key, value in _walk(subject.doc):
            if key != name:
                continue
            cite = subject.cite(path)
            if _same(value, canonical_value):
                conforming.append(cite)
            else:
                contradicting.append(cite)
                findings.append({"predicate": "INVARIANT_CONFORMS", "invariant_id": iid, "citation": cite,
                                 "detail": f"{path} asserts {json.dumps(value)}; canonical value is {json.dumps(canonical_value)}"})
    else:
        for path, key, value in _walk(subject.doc):
            if isinstance(value, list) and name in value:
                cite = subject.cite(f"{path}[{value.index(name)}]")
                if key in PROHIBITION_HONOURED_KEYS:
                    conforming.append(cite)
                elif key in PROHIBITION_VIOLATED_KEYS:
                    contradicting.append(cite)
                    findings.append({"predicate": "INVARIANT_CONFORMS", "invariant_id": iid, "citation": cite,
                                     "detail": f"{path} lists {name} as violated"})
    citations.extend(conforming + contradicting)

    if contradicting:
        return answer(DENY, "INVARIANT_CONFORMS",
                      f"Repair the subject so every assertion of {name} equals the canonical value, or register an exemption.",
                      "Repair the subject and evaluate the same question again.")
    if conforming:
        return answer(ALLOW, "", "", "")
    findings.append({"predicate": "SUBJECT_SPEAKS_TO_INVARIANT", "invariant_id": iid,
                     "detail": f"the subject makes no assertion about {name}; silence is not conformance"})
    return answer(UNDECIDABLE, "SUBJECT_SPEAKS_TO_INVARIANT",
                  f"Supply evidence in which the subject asserts {name}, or a reader with more evidence answers from the relay queue.",
                  "Re-ask with additional evidence refs, or consume the relay-queue entry.")


def _write_queue_entry(queue_dir: Path, question: dict[str, Any], result: dict[str, Any],
                       sources: list[dict[str, Any]]) -> dict[str, Any]:
    """Durable, local, non-GitHub: one write-once file per (question bytes, supplied source bindings).

    The same question over the same bytes is one entry ({"created": False} on repeat); the same question_id
    over different subject or source bytes is a different entry. An existing entry is never overwritten
    (DURABLE_QUEUE_OR_EVENT_EPHEMERAL_MATERIALIZATION: the reader with more evidence consumes it).
    """
    queue_dir.mkdir(parents=True, exist_ok=True)
    bindings = sorted(f"{s.get('repository')}:{s.get('path')}@{s.get('revision')}#sha256:"
                      f"{hashlib.sha256(bytes(s['content'])).hexdigest()}"
                      for s in sources if isinstance(s, dict) and isinstance(s.get("content"), (bytes, bytearray)))
    key = hashlib.sha256(json.dumps({"question": question, "source_bindings": bindings},
                                    sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", str(question["question_id"]))[:64]
    path = queue_dir / f"{safe}-{key[:16]}.json"
    if path.exists():
        return {"path": str(path), "created": False, "entry_key": key}
    entry = {"schema": QUEUE_SCHEMA, "entry_key": key, "question": question, "source_bindings": bindings,
             "result": {k: v for k, v in result.items() if k != "relay_queue_entry"},
             "routing": "DURABLE_QUEUE_OR_EVENT_EPHEMERAL_MATERIALIZATION", "github_call_made": False,
             "authority_effect": ANSWER_AUTHORITY_EFFECT}
    tmp = path.with_name(path.name + f".{os.getpid()}.tmp")
    tmp.write_text(json.dumps(entry, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    try:
        os.link(tmp, path)  # atomic create-if-absent; a concurrent writer of the same key loses harmlessly
        created = True
    except FileExistsError:
        created = False
    finally:
        tmp.unlink(missing_ok=True)
    return {"path": str(path), "created": created, "entry_key": key}


def main(argv: list[str]) -> int:
    """python3 -I invariant_evaluation.py QUESTION.json QUEUE_DIR REPOSITORY:PATH@REVISION=FILE ..."""
    if len(argv) < 3:
        print(main.__doc__, file=sys.stderr)
        return 2
    question = json.loads(Path(argv[0]).read_bytes())
    sources = []
    for spec in argv[2:]:
        ref, _, file = spec.rpartition("=")
        repo_path, _, revision = ref.rpartition("@")
        repo, _, path = repo_path.partition(":")
        sources.append({"repository": repo, "path": path, "revision": revision, "content": Path(file).read_bytes()})
    result = evaluate(question, sources, argv[1])
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["disposition"] == ALLOW else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
