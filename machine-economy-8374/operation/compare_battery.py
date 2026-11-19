#!/usr/bin/env python3
"""Battery — /compare reference-result labels (COMPARE-CURE-01;
cohort separation added GEN 14, ChatGPT cycle-2 R03).

The compare page's labels must be DERIVED from the evidence each
row cites, and settlement is scored PER COHORT: the frozen cohort
(the frozen test's own references, PAIR-000049/PAIR-000054) and
the witness cohort (PAIR-000045/PAIR-000054) each carry their own
outcome line, and no label spans cohorts. This battery runs the
derivation (_compare_sections) against THROWAWAY copies of the
endpoint tree with synthetic receipt chains — never against
production:

  c1. missing-record state (empty chain): F3, F5, W5 and 5b do
      NOT print PASS, and neither cohort outcome is PASS;
  c2. PAIR-000049 born PENDING with only failed settlement
      attempts, PAIR-000054 settled once, PAIR-000045 absent:
      the frozen cohort FAILs (its evidence states PAIR-000049
      settled 0 times, never "settled by"), its outcome line
      states NOT SETTLED and names the correction record, and
      the witness cohort is UNVERIFIED (a witness is missing);
  c3. full witness arcs (PAIR-000045 born into the
      RPC-unreachable window, failed attempt, settled exactly
      once; PAIR-000054 settled exactly once) while
      PAIR-000049 never settles: the witness cohort PASSes with
      the settling records named, and the frozen cohort still
      FAILs — a witness PASS cannot relabel the frozen cohort;
  c4. PAIR-000054 settled by TWO distinct settlement records:
      both cohorts FAIL (settles more than once);
  c5. frozen-test record document absent: steps 1 and 4 fall to
      UNVERIFIED (their evidence is the record);
  c6. PAIR-000049 and PAIR-000054 each settled exactly once,
      PAIR-000045 absent: the frozen cohort PASSes on its own
      references while the witness cohort stays UNVERIFIED —
      independence in the other direction.
"""
import importlib.util, json, os, shutil, sys, tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
RESULTS = []
TX = "0x" + "9f" * 32
TX2 = "0x" + "8e" * 32


def check(name, ok, detail=""):
    RESULTS.append((name, bool(ok)))
    print(f"[{'PASS' if ok else 'FAIL'}] {name} -- {detail}")


def entry(i, content):
    return {"i": i, "prev": "x" * 64, "hash": "y" * 64,
            "content": content}


def pair(pid, kind0, kind1, **kw):
    c0 = {"pair_id": pid, "kind": kind0, "index_in_pair": 0, **kw}
    c1 = {"pair_id": pid, "kind": kind1, "index_in_pair": 1,
          "pair_anchor": "a" * 64, **kw}
    return [c0, c1]


def crossing(pid, settlement, disposition="ALLOW"):
    return pair(pid, "RECEIPT_ENDPOINT_SIDE",
                "RECEIPT_COUNTERPARTY_SIDE",
                disposition=disposition,
                ts="2026-11-19T00:00:00+00:00",
                settlement=settlement)


def settling(rec_pid, cross_pid, settlement, kind0=(
        "SETTLEMENT_ENDPOINT_SIDE")):
    return pair(rec_pid, kind0, "SETTLEMENT_PARENT_ANCHOR",
                disposition="SETTLEMENT_RESUBMISSION",
                settles_pair_id=cross_pid, settlement=settlement)


def write_chain(seg_dir, contents):
    os.makedirs(seg_dir, exist_ok=True)
    with open(os.path.join(seg_dir, "segment-0001.jsonl"),
              "w") as f:
        for i, c in enumerate(contents, 1):
            f.write(json.dumps(entry(i, c)) + "\n")


def load_endpoint(with_record=True):
    tmp = tempfile.mkdtemp(prefix="compare-battery-")
    for n in os.listdir(HERE):
        if n.endswith((".py", ".json")):
            shutil.copy(os.path.join(HERE, n), tmp)
    if with_record:
        shutil.copy(os.path.join(
            HERE, "FROZEN__TEST__PAIR__FIRST__OUTAGE__01.md"), tmp)
    sys.path.insert(0, tmp)
    try:
        spec = importlib.util.spec_from_file_location(
            "endpoint_throwaway", os.path.join(tmp, "endpoint.py"))
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
    finally:
        sys.path.remove(tmp)
    return mod, os.path.join(tmp, "receipts")


def rows_by_step(mod, seg_dir):
    s = mod._compare_sections(seg_dir)
    rows = {name: (label, ev) for name, label, ev
            in s["steps"] + s["frozen_rows"] + s["witness_rows"]}
    rows["__frozen_outcome__"] = s["frozen_outcome"]
    rows["__witness_outcome__"] = s["witness_outcome"]
    return rows


def arc45_settled_once():
    out = []
    out += crossing("PAIR-000045",
                    {"status": "FAIL_CLOSED",
                     "failure_code": "SETTLEMENT_RPC_UNREACHABLE"})
    out += settling("PAIR-000046", "PAIR-000045",
                    {"status": "FAIL_CLOSED"},
                    "SETTLEMENT_FAILURE_ENDPOINT_SIDE")
    out += settling("PAIR-000047", "PAIR-000045",
                    {"status": "SETTLED", "tx_hash": TX,
                     "block_number": 123, "value_micro_usdc": 100})
    return out


def main():
    F3 = "F3. Crossing presented offline (frozen references)"
    F5 = "F5. Network restored — settlement (frozen references)"
    W5 = "W5. Network restored — settlement (witness cohort)"

    # c1: missing-record state
    mod, seg = load_endpoint()
    rows = rows_by_step(mod, seg)
    check("c1: empty chain -- F3 not PASS",
          rows[F3][0] != "PASS", rows[F3][0])
    check("c1: empty chain -- F5 not PASS",
          rows[F5][0] != "PASS", rows[F5][0])
    check("c1: empty chain -- W5 not PASS",
          rows[W5][0] != "PASS", rows[W5][0])
    check("c1: empty chain -- step 5b not PASS (0 pairs)",
          rows["5b. Full record replay/recompute"][0] != "PASS",
          rows["5b. Full record replay/recompute"][0])
    check("c1: empty chain -- neither cohort outcome is PASS",
          rows["__frozen_outcome__"][0] != "PASS"
          and rows["__witness_outcome__"][0] != "PASS",
          f"frozen={rows['__frozen_outcome__'][0]}, "
          f"witness={rows['__witness_outcome__'][0]}")

    # c2: PAIR-000049 unsettled; PAIR-000045 absent
    mod, seg = load_endpoint()
    contents = []
    contents += crossing("PAIR-000049", {"status": "PENDING"})
    contents += settling("PAIR-000050", "PAIR-000049",
                         {"status": "FAIL_CLOSED"},
                         "SETTLEMENT_FAILURE_ENDPOINT_SIDE")
    contents += crossing("PAIR-000054", {"status": "PENDING"})
    contents += settling("PAIR-000055", "PAIR-000054",
                         {"status": "SETTLED", "tx_hash": TX,
                          "block_number": 124,
                          "value_micro_usdc": 200})
    write_chain(seg, contents)
    rows = rows_by_step(mod, seg)
    lab5, ev5 = rows[F5]
    check("c2: frozen F5 FAIL when PAIR-000049 never settles",
          lab5 == "FAIL", lab5)
    check("c2: frozen F5 evidence states PAIR-000049 settled 0 "
          "times, never 'settled by'",
          "PAIR-000049" in ev5 and "settled 0 times" in ev5
          and "PAIR-000049 settled by" not in ev5
          and "PAIR-000049: settlement record not found" not in ev5,
          ev5[:200])
    fo = rows["__frozen_outcome__"]
    check("c2: frozen outcome line states PAIR-000049 NOT "
          "SETTLED and names the correction record",
          fo[0] == "FAIL" and "NOT SETTLED" in fo[1]
          and "CORRECTION__RECORD__FROZEN__TEST__01" in fo[1]
          and "1mFCeEssHr7SwIdwzn7y1LeCRD9d8XD-6" in fo[1],
          fo[1][:240])
    check("c2: witness W5 UNVERIFIED (PAIR-000045 missing) and "
          "witness outcome UNVERIFIED",
          rows[W5][0] == "UNVERIFIED"
          and rows["__witness_outcome__"][0] == "UNVERIFIED",
          f"W5={rows[W5][0]}, "
          f"outcome={rows['__witness_outcome__'][0]}")
    check("c2: F3 PASS (both frozen crossings born PENDING)",
          rows[F3][0] == "PASS", rows[F3][0])

    # c3: full witness arcs; PAIR-000049 still never settles
    mod, seg = load_endpoint()
    contents = arc45_settled_once()
    contents += crossing("PAIR-000049", {"status": "PENDING"})
    contents += crossing("PAIR-000054", {"status": "PENDING"})
    contents += settling("PAIR-000055", "PAIR-000054",
                         {"status": "SETTLED", "tx_hash": TX2,
                          "block_number": 125,
                          "value_micro_usdc": 200})
    write_chain(seg, contents)
    rows = rows_by_step(mod, seg)
    check("c3: witness W5 PASS on exactly-once arcs",
          rows[W5][0] == "PASS", rows[W5][1][:200])
    check("c3: step 2 PASS (RPC-unreachable births on chain)",
          rows["2. Network cut"][0] == "PASS",
          rows["2. Network cut"][0])
    check("c3: witness W5 evidence names the settling records",
          "PAIR-000047" in rows[W5][1]
          and "PAIR-000055" in rows[W5][1],
          rows[W5][1][:200])
    check("c3: witness outcome PASS, frozen outcome still FAIL "
          "-- a witness PASS cannot relabel the frozen cohort",
          rows["__witness_outcome__"][0] == "PASS"
          and rows["__frozen_outcome__"][0] == "FAIL"
          and "NOT SETTLED" in rows["__frozen_outcome__"][1],
          f"witness={rows['__witness_outcome__'][0]}, "
          f"frozen={rows['__frozen_outcome__'][0]}")

    # c4: settled twice -> FAIL in both cohorts (PAIR-000054 is
    # a member of each)
    mod, seg = load_endpoint()
    contents = arc45_settled_once()
    contents += crossing("PAIR-000054", {"status": "PENDING"})
    contents += settling("PAIR-000055", "PAIR-000054",
                         {"status": "SETTLED", "tx_hash": TX,
                          "block_number": 125,
                          "value_micro_usdc": 200})
    contents += settling("PAIR-000056", "PAIR-000054",
                         {"status": "SETTLED", "tx_hash": TX2,
                          "block_number": 126,
                          "value_micro_usdc": 200})
    write_chain(seg, contents)
    rows = rows_by_step(mod, seg)
    check("c4: witness W5 FAIL when a crossing settles twice",
          rows[W5][0] == "FAIL", rows[W5][0])
    check("c4: frozen F5 FAIL on the same double settlement",
          rows[F5][0] == "FAIL", rows[F5][0])

    # c5: no frozen-test record document
    mod, seg = load_endpoint(with_record=False)
    contents = arc45_settled_once()
    contents += crossing("PAIR-000054", {"status": "PENDING"})
    contents += settling("PAIR-000055", "PAIR-000054",
                         {"status": "SETTLED", "tx_hash": TX,
                          "block_number": 125,
                          "value_micro_usdc": 200})
    write_chain(seg, contents)
    rows = rows_by_step(mod, seg)
    check("c5: step 4 UNVERIFIED without the record document",
          rows["4. Same authorization re-presented offline"][0]
          == "UNVERIFIED",
          rows["4. Same authorization re-presented offline"][0])
    check("c5: step 1 UNVERIFIED without the record document",
          rows["1. Authorization obtained"][0] == "UNVERIFIED",
          rows["1. Authorization obtained"][0])

    # c6: frozen references each settle exactly once; the
    # witness PAIR-000045 is absent -- frozen PASSes on its own
    # references, witness stays UNVERIFIED
    mod, seg = load_endpoint()
    contents = []
    contents += crossing("PAIR-000049", {"status": "PENDING"})
    contents += settling("PAIR-000052", "PAIR-000049",
                         {"status": "SETTLED", "tx_hash": TX,
                          "block_number": 130,
                          "value_micro_usdc": 100})
    contents += crossing("PAIR-000054", {"status": "PENDING"})
    contents += settling("PAIR-000055", "PAIR-000054",
                         {"status": "SETTLED", "tx_hash": TX2,
                          "block_number": 131,
                          "value_micro_usdc": 200})
    write_chain(seg, contents)
    rows = rows_by_step(mod, seg)
    F5 = "F5. Network restored — settlement (frozen references)"
    W5 = "W5. Network restored — settlement (witness cohort)"
    check("c6: frozen F5 + outcome PASS on its own references",
          rows[F5][0] == "PASS"
          and rows["__frozen_outcome__"][0] == "PASS",
          f"F5={rows[F5][0]}, "
          f"outcome={rows['__frozen_outcome__'][0]}")
    check("c6: witness W5 + outcome UNVERIFIED (PAIR-000045 "
          "absent) -- independence in the other direction",
          rows[W5][0] == "UNVERIFIED"
          and rows["__witness_outcome__"][0] == "UNVERIFIED",
          f"W5={rows[W5][0]}, "
          f"outcome={rows['__witness_outcome__'][0]}")

    passed = sum(1 for _n, ok in RESULTS if ok)
    print(f"\nBATTERY: {passed}/{len(RESULTS)} passed")
    return 0 if passed == len(RESULTS) else 1


if __name__ == "__main__":
    sys.exit(main())
