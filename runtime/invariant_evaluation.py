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
MAX_DEPTH = 64  # spec max_json_nesting (RT-INVARIANT-EVALUATION-001, Labs#3278 B-P7); deeper sources fail closed
ANSWER_AUTHORITY_EFFECT = "NONE_ANSWER_ONLY"  # this component answers; it never transitions
ALLOWED_AUTHORITY_EFFECTS = frozenset({"NONE", "NONE_REGISTRY_INVARIANT_ONLY", "NONE_TEST_FIXTURE", "NONE_ANSWER_ONLY"})
RETRY_ENTRYPOINT = "python -B runtime/invariant_evaluation.py QUESTION.json QUEUE_DIR REPOSITORY:PATH@REVISION=FILE ..."

# Keys under which a subject may name prohibitions it honours or has violated.
PROHIBITION_HONOURED_KEYS = frozenset({"prohibitions", "honoured_prohibitions", "prohibitions_applied"})
PROHIBITION_VIOLATED_KEYS = frozenset({"violated_prohibitions", "violations", "prohibition_violations"})

_WS = re.compile(r"[ \t\n\r]*")
_NUM = re.compile(r"-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][-+]?\d+)?")


# --------------------------------------------------------------------------- position-aware JSON
class ParseRefusal(ValueError):
    """A refused parse: code names the spec refusal, offset is where parsing stopped."""

    def __init__(self, code: str, offset: int, detail: str = ""):
        super().__init__(detail or code)
        self.code, self.offset = code, offset


def _parse_with_lines(text: str) -> tuple[Any, dict[str, int]]:
    """Parse JSON text; return (value, {json_path: 1-based line of the key or element}).

    Bounded: at most MAX_DEPTH containers open at once (the next opening bracket is INPUT_DEPTH_EXCEEDED);
    duplicate object keys are JSON_DUPLICATE_KEY; running out of bytes is JSON_TRUNCATED; anything else
    malformed is JSON_SYNTAX. Every refusal carries the offset it stopped on.
    """
    from json.decoder import scanstring

    lines: dict[str, int] = {}
    newline_offsets = [i for i, ch in enumerate(text) if ch == "\n"]

    def line_at(i: int) -> int:
        return bisect.bisect_right(newline_offsets, i - 1) + 1

    def skip(i: int) -> int:
        return _WS.match(text, i).end()

    def value(i: int, path: str, open_containers: int) -> tuple[Any, int]:
        i = skip(i)
        c = text[i]
        if c in "{[":
            if open_containers + 1 > MAX_DEPTH:
                raise ParseRefusal("INPUT_DEPTH_EXCEEDED", i, f"more than {MAX_DEPTH} containers open at offset {i}")
        if c == "{":
            obj: dict[str, Any] = {}
            i = skip(i + 1)
            if text[i] == "}":
                return obj, i + 1
            while i < len(text):  # bounded by the input; every member advances i
                i = skip(i)
                if text[i] != '"':
                    raise ParseRefusal("JSON_SYNTAX", i, f"expected key at offset {i}")
                key_at = i
                key, i = scanstring(text, i + 1)
                if key in obj:
                    raise ParseRefusal("JSON_DUPLICATE_KEY", key_at, f"duplicate key {key!r} at offset {key_at}")
                sub = f"{path}.{key}" if path else key
                lines[sub] = line_at(key_at)
                i = skip(i)
                if text[i] != ":":
                    raise ParseRefusal("JSON_SYNTAX", i, f"expected ':' at offset {i}")
                obj[key], i = value(i + 1, sub, open_containers + 1)
                i = skip(i)
                if text[i] == ",":
                    i += 1
                    continue
                if text[i] == "}":
                    return obj, i + 1
                raise ParseRefusal("JSON_SYNTAX", i, f"expected ',' or '}}' at offset {i}")
            raise ParseRefusal("JSON_TRUNCATED", len(text), "unterminated object")
        if c == "[":
            arr: list[Any] = []
            i = skip(i + 1)
            if text[i] == "]":
                return arr, i + 1
            while i < len(text):  # bounded by the input; every element advances i
                sub = f"{path}[{len(arr)}]"
                lines[sub] = line_at(skip(i))
                v, i = value(i, sub, open_containers + 1)
                arr.append(v)
                i = skip(i)
                if text[i] == ",":
                    i += 1
                    continue
                if text[i] == "]":
                    return arr, i + 1
                raise ParseRefusal("JSON_SYNTAX", i, f"expected ',' or ']' at offset {i}")
            raise ParseRefusal("JSON_TRUNCATED", len(text), "unterminated array")
        if c == '"':
            return scanstring(text, i + 1)
        for lit, val in (("true", True), ("false", False), ("null", None)):
            if text.startswith(lit, i):
                return val, i + len(lit)
        m = _NUM.match(text, i)
        if m:
            n = m.group()
            return (float(n) if any(ch in n for ch in ".eE") else int(n)), m.end()
        raise ParseRefusal("JSON_SYNTAX", i, f"unexpected character {c!r} at offset {i}")

    try:
        v, end = value(0, "", 0)
        if text[skip(end):]:
            raise ParseRefusal("JSON_SYNTAX", skip(end), "trailing data after JSON document")
    except ParseRefusal:
        raise
    except IndexError:
        raise ParseRefusal("JSON_TRUNCATED", len(text), "input ends inside a value") from None
    except json.JSONDecodeError as exc:
        if "Unterminated" in str(exc):  # a string that runs off the end of the bytes is truncation, not syntax
            raise ParseRefusal("JSON_TRUNCATED", len(text), str(exc)) from None
        raise ParseRefusal("JSON_SYNTAX", exc.pos, str(exc)) from None
    except RecursionError:
        raise ParseRefusal("INPUT_DEPTH_EXCEEDED", 0, "recursion limit") from None
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


def _line_of(content: bytes, offset: int) -> int:
    return content[:max(0, min(offset, len(content)))].count(b"\n") + 1


def _refusal_cite(ref: dict[str, Any], content: bytes, exc: BaseException | None) -> str:
    """repo@revision:path:line for a refused source: the line parsing stopped on, else line 1."""
    line = _line_of(content, exc.offset) if isinstance(exc, ParseRefusal) else 1
    return f"{ref['repository']}@{ref['revision']}:{ref['path']}:{line}"


def _load_source(ref: Any, sources: list[dict[str, Any]], problems: list[str],
                 citations: list[str] | None = None, codes: list[str] | None = None) -> _Source | None:
    """Resolve one cited source: digest verified before any byte is parsed. codes receives the spec refusal code."""
    def refuse(code: str, detail: str, cite: str | None = None):
        problems.append(detail)
        if codes is not None:
            codes.append(code)
        if citations is not None and cite is not None:
            citations.append(cite)
        return None

    if not isinstance(ref, dict) or not all(_str(ref.get(k)) for k in ("repository", "path", "revision")):
        return refuse("SOURCE_REF_MALFORMED", "source ref lacks repository, path or revision")
    for src in sources:
        if (src.get("repository"), src.get("path"), src.get("revision")) == (ref["repository"], ref["path"], ref["revision"]):
            content = src.get("content")
            if not isinstance(content, (bytes, bytearray)):
                return refuse("SOURCE_BYTES_MISSING", f"{ref['repository']}:{ref['path']} supplied without bytes")
            content = bytes(content)
            digest = "sha256:" + hashlib.sha256(content).hexdigest()
            if not _str(ref.get("digest")):
                return refuse("SOURCE_DIGEST_MISSING", f"{ref['repository']}:{ref['path']} cited without a digest",
                              _refusal_cite(ref, content, None))
            if ref["digest"] != digest:
                return refuse("SOURCE_DIGEST_MISMATCH",
                              f"{ref['repository']}:{ref['path']} digest {ref['digest']} != evaluated {digest}",
                              _refusal_cite(ref, content, None))
            try:
                return _Source(ref, content)
            except ParseRefusal as exc:
                return refuse(exc.code, f"{ref['repository']}:{ref['path']} is not parseable JSON: {exc}",
                              _refusal_cite(ref, content, exc))
            except UnicodeDecodeError as exc:
                return refuse("SOURCE_NOT_UTF8", f"{ref['repository']}:{ref['path']} is not UTF-8: {exc}",
                              _refusal_cite(ref, content, None))
    return refuse("SOURCE_NOT_SUPPLIED", f"{ref['repository']}:{ref['path']}@{ref['revision']} was cited but not supplied",
                  f"{ref['repository']}@{ref['revision']}:{ref['path']}:1")

# --------------------------------------------------------------------------- evaluation
FIXED_OWNER = "STEGVERSE-CANONICAL-WORK-COORDINATION-001"  # owns the evaluator; carried before a question is well-formed
_TASK_ID = re.compile(r"[A-Z0-9][A-Z0-9-]{2,127}")


def _bindings(sources: list[dict[str, Any]]) -> list[str]:
    return sorted(f"{s.get('repository')}:{s.get('path')}@{s.get('revision')}#sha256:"
                  f"{hashlib.sha256(bytes(s['content'])).hexdigest()}"
                  for s in sources if isinstance(s, dict) and isinstance(s.get("content"), (bytes, bytearray)))


def _evaluation_key(question_sha256: str, bindings: list[str]) -> str:
    return hashlib.sha256(json.dumps({"question_sha256": question_sha256, "source_bindings": bindings},
                                     sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


def _compose(disposition: str, failed_predicate: str, repair: str, next_attempt: str, *, code: str | None,
             qid: Any, iid: Any, owner: str, citations: list[str], findings: list[dict[str, Any]],
             question_sha256: str, evaluation_key: str) -> dict[str, Any]:
    out: dict[str, Any] = {
        "schema": ANSWER_SCHEMA, "component_id": COMPONENT_ID, "question_id": qid, "invariant_id": iid,
        "question_sha256": question_sha256, "evaluation_key": evaluation_key,
        "disposition": disposition, "citations": sorted(set(citations)), "findings": findings,
        "authority_effect": ANSWER_AUTHORITY_EFFECT,
    }
    if disposition != ALLOW:
        refusal_code = code or failed_predicate
        out.update({
            "failure_code": f"INVARIANT_EVALUATION_{disposition}_{refusal_code}",
            "refusal_code": refusal_code,
            "failed_predicate": failed_predicate,
            "required_evidence_or_repair": repair,
            "retry_entrypoint": RETRY_ENTRYPOINT,
            "owning_existing_goal": owner,
            "next_attempt": next_attempt,
            "evidence_refs": sorted(set(citations)) or [f"SOURCE_RECORD_ONLY:{qid}"],
        })
    return out


def evaluate_bytes(question_bytes: bytes, sources: list[dict[str, Any]],
                   queue_dir: str | Path | None = None) -> dict[str, Any]:
    """Answer from the exact question bytes: the same bounded parser as every source (depth, duplicate keys,
    truncation), question_sha256 over those bytes, and the fixed owner on a refusal before well-formedness."""
    qsha = hashlib.sha256(question_bytes).hexdigest()
    try:
        question, _ = _parse_with_lines(question_bytes.decode("utf-8"))
    except (ParseRefusal, UnicodeDecodeError) as exc:
        code = exc.code if isinstance(exc, ParseRefusal) else "SOURCE_NOT_UTF8"
        line = _line_of(question_bytes, exc.offset) if isinstance(exc, ParseRefusal) else 1
        cite = f"question@{qsha}:question:{line}"
        return _compose(FAIL_CLOSED, "QUESTION_WELL_FORMED",
                        "Supply a well-formed stegverse.invariant-question/v1 object within the parser bounds.",
                        "Repair the question bytes and evaluate again.", code=code, qid=None, iid=None,
                        owner=FIXED_OWNER, citations=[cite],
                        findings=[{"predicate": "QUESTION_WELL_FORMED", "detail": f"question bytes refused: {code}: {exc}"}],
                        question_sha256=qsha, evaluation_key=_evaluation_key(qsha, _bindings(sources)))
    return evaluate(question, sources, queue_dir, question_bytes=question_bytes)


def evaluate(question: Any, sources: list[dict[str, Any]], queue_dir: str | Path | None = None, *,
             question_bytes: bytes | None = None) -> dict[str, Any]:
    """Answer one invariant question against caller-resolved sources.

    sources: [{"repository", "path", "revision", "content": bytes}].
    queue_dir: where an UNDECIDABLE answer writes its write-once relay-queue entry.
    question_bytes: the exact bytes the question came from (evaluate_bytes supplies them); a dict caller's
    question is bound by its canonical JSON bytes instead.
    """
    problems: list[str] = []
    citations: list[str] = []
    findings: list[dict[str, Any]] = []
    codes: list[str] = []
    if question_bytes is None:
        try:
            question_bytes = json.dumps(question, sort_keys=True, separators=(",", ":")).encode("utf-8")
        except (TypeError, ValueError):
            question_bytes = b""
    qsha = hashlib.sha256(question_bytes).hexdigest()
    bindings = _bindings(sources)
    ekey = _evaluation_key(qsha, bindings)
    qid = question.get("question_id") if isinstance(question, dict) else None
    iid_value = question.get("invariant_id") if isinstance(question, dict) else None
    owning = question.get("owning_existing_goal") if isinstance(question, dict) else None
    well_formed = False

    def answer(disposition: str, failed_predicate: str, repair: str, next_attempt: str,
               code: str | None = None) -> dict[str, Any]:
        owner = owning if well_formed else FIXED_OWNER
        if disposition != ALLOW and not citations:
            citations.append(f"question@{qsha}:question:1")  # SPEC:47: every answer cites a line
        out = _compose(disposition, failed_predicate, repair, next_attempt, code=code, qid=qid, iid=iid_value,
                       owner=owner, citations=citations, findings=findings, question_sha256=qsha, evaluation_key=ekey)
        if disposition == UNDECIDABLE and queue_dir is not None:
            out["relay_queue_entry"] = _write_queue_entry(Path(queue_dir), question, out, bindings, owner)
        return out

    # 1. question well-formed
    if not isinstance(question, dict) or question.get("schema") != QUESTION_SCHEMA:
        problems.append(f"question is not a {QUESTION_SCHEMA} object")
    else:
        for k in ("question_id", "invariant_id", "owning_existing_goal"):
            if not _str(question.get(k)):
                problems.append(f"question lacks {k}")
        if _str(owning) and not _TASK_ID.fullmatch(owning):
            problems.append("owning_existing_goal is not a canonical task id ([A-Z0-9][A-Z0-9-]{2,127})")
        if not isinstance(question.get("invariants_source"), dict):
            problems.append("question lacks invariants_source")
        if not isinstance(question.get("subject"), dict):
            problems.append("question lacks subject")
    if problems:
        citations.append(f"question@{qsha}:question:1")  # the question root: every answer cites a line (SPEC:47)
        findings.append({"predicate": "QUESTION_WELL_FORMED", "detail": "; ".join(problems)})
        return answer(FAIL_CLOSED, "QUESTION_WELL_FORMED", "Supply schema, question_id, invariant_id, "
                      "owning_existing_goal (canonical task id), invariants_source and subject.",
                      "Repair the question and evaluate again.")
    well_formed = True

    # 2. canonical invariants resolved and sound
    canon = _load_source(question["invariants_source"], sources, problems, citations, codes)
    if canon is not None:
        if canon.path != CANONICAL_PATH or not isinstance(canon.doc, dict) or canon.doc.get("schema") != CANONICAL_SCHEMA:
            problems.append(f"invariants_source is not {CANONICAL_PATH} with schema {CANONICAL_SCHEMA}")
            codes.append("CANONICAL_SCHEMA_MISMATCH")
            citations.append(canon.cite("schema") if "schema" in canon.lines else canon.cite())
        else:
            effect = canon.doc.get("authority_effect")
            if not isinstance(effect, str) or effect not in ALLOWED_AUTHORITY_EFFECTS:
                problems.append("invariants document claims an authority effect")
                codes.append("SOURCE_AUTHORITY_EFFECT_NOT_ALLOWED")
                citations.append(canon.cite("authority_effect") if "authority_effect" in canon.lines else canon.cite())
    if problems:
        findings.append({"predicate": "CANONICAL_SOURCE_BOUND", "detail": "; ".join(problems)})
        return answer(FAIL_CLOSED, "CANONICAL_SOURCE_BOUND",
                      f"Resolve {CANONICAL_PATH} at an exact revision and pass its bytes.",
                      "Re-resolve the canonical invariants and evaluate again.", codes[0] if codes else None)
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
        container = "invariants" if kind == "invariant" else "prohibitions"
        citations.append(canon.cite(container) if container in canon.lines else canon.cite())  # the declaring container
        findings.append({"predicate": "INVARIANT_ID_CANONICAL", "detail": f"{iid!r} is not declared in the supplied canonical document"})
        return answer(UNDECIDABLE, "INVARIANT_ID_CANONICAL",
                      "Ask about an id of the form invariant:<key> or prohibition:<NAME> declared in the canonical document "
                      "at the cited revision, or supply the canonical source that declares it.",
                      "Re-ask with the declaring canonical source, or consume the relay-queue entry.")

    # 4. subject resolved
    subject = _load_source(question["subject"], sources, problems, citations, codes)
    if subject is None:
        findings.append({"predicate": "SUBJECT_SOURCE_BOUND", "detail": "; ".join(problems)})
        return answer(FAIL_CLOSED, "SUBJECT_SOURCE_BOUND", "Resolve the subject at an exact revision and pass its bytes.",
                      "Re-resolve the subject and evaluate again.", codes[0] if codes else None)
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
                       bindings: list[str], relay_to: str) -> dict[str, Any]:
    """Durable, local, non-GitHub: one write-once file per evaluation_key (question bytes + source bindings).

    The same question bytes over the same sources is one entry ({"created": False} on repeat); different
    bytes or sources are a different entry. An existing entry is never overwritten
    (DURABLE_QUEUE_OR_EVENT_EPHEMERAL_MATERIALIZATION: the reader with more evidence consumes it).
    """
    queue_dir.mkdir(parents=True, exist_ok=True)
    key = result["evaluation_key"]
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", str(question.get("question_id")))[:64]
    path = queue_dir / f"{safe}-{key[:16]}.json"
    if path.exists():
        return {"path": str(path), "created": False, "evaluation_key": key}
    entry = {"schema": QUEUE_SCHEMA, "evaluation_key": key, "question_sha256": result["question_sha256"],
             "question": question, "source_bindings": bindings, "relay_to": relay_to,
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
    return {"path": str(path), "created": created, "evaluation_key": key}


def main(argv: list[str]) -> int:
    """python3 -I invariant_evaluation.py QUESTION.json QUEUE_DIR REPOSITORY:PATH@REVISION=FILE ..."""
    if len(argv) < 3:
        print(main.__doc__, file=sys.stderr)
        return 2
    sources = []
    for spec in argv[2:]:
        ref, _, file = spec.rpartition("=")
        repo_path, _, revision = ref.rpartition("@")
        repo, _, path = repo_path.partition(":")
        sources.append({"repository": repo, "path": path, "revision": revision, "content": Path(file).read_bytes()})
    result = evaluate_bytes(Path(argv[0]).read_bytes(), sources, argv[1])  # the question goes through the same bounded parser
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["disposition"] == ALLOW else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
