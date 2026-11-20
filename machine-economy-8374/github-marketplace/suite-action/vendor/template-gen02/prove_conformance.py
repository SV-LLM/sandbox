#!/usr/bin/env python3
"""Prove a suite's conformance to SUITE__TEMPLATE (GEN 01 or GEN 02).
Non-retroactivity rule (Spec 02 & E6):
  - Suites derived from SUITE__TEMPLATE GEN 01 continue grading against GEN 01
    elements E1..E5; installed GEN 01 proofs keep their bound template hash and
    are never retroactively failed on E6..E8.
  - Suites derived from SUITE__TEMPLATE GEN 02 are graded against E1..E5 plus:
      * E6_pricing_schedule (Spec 01: PRICING__AND__ACCESS__01.md populated + purchasable)
      * E7_compensation_basis (Spec 02: COMPENSATION__BASIS__01.md populated + own-generation
        integer meter row when accounts_for_errors=true)
      * E8_zero_placeholders_and_chained_ledger (KV__303 R-200-1 + KV__298: zero unpopulated
        slots/TODO stubs across ALL members incl. Charter/Spec/References, and valid SHA-256
        hash chain in LEDGER__01.json).
"""
import hashlib, json, os, re, subprocess, sys

HERE = os.path.dirname(os.path.abspath(__file__))
TMAN_PATH = os.path.join(HERE, "TEMPLATE__MANIFEST__02.json")
PROOF_NAME = "CONFORMANCE__PROOF__01.json"

ORDER_GEN01 = [
    "E1_manifest_members_verify",
    "E2_self_check_passes",
    "E2b_checker_carries_template_checks",
    "E3_face_carries_projectid_funding",
    "E4_funding_statement",
    "E5_proof_in_suite",
]
ORDER_GEN02 = ORDER_GEN01 + [
    "E6_pricing_schedule",
    "E7_compensation_basis",
    "E8_zero_placeholders_and_chained_ledger",
]

SLOT_RE = re.compile(r"\{\{[A-Z0-9_]+\}\}")
TODO_STUB_RE = re.compile(r"\bTODO\s*(?:—|--|:)\s*", re.IGNORECASE)

def sha(b):
    return hashlib.sha256(b).hexdigest()

def tman_sha():
    return sha(open(TMAN_PATH, "rb").read())

def find_manifest(suite):
    for n in sorted(os.listdir(suite)):
        if "MANIFEST" in n.upper() and n.endswith(".json"):
            try:
                return n, json.load(open(os.path.join(suite, n), encoding="utf-8"))
            except Exception:
                return n, None
    return None, None

def is_gen02_suite(manifest):
    if not manifest:
        return True
    tmpl = ((manifest.get("derived_from") or {}).get("template") or "").upper()
    if "GEN 01" in tmpl:
        return False
    return True

def member_entries(manifest):
    if not manifest:
        return None
    for key in ("members", "files", "inventory", "entries"):
        v = manifest.get(key)
        if isinstance(v, list):
            return v
        if isinstance(v, dict):
            return [dict({"file": k}, **(val if isinstance(val, dict) else {})) for k, val in v.items()]
    return None

def norm(m):
    return (
        m.get("file") or m.get("path") or m.get("name"),
        m.get("bytes", m.get("size")),
        m.get("sha256") or m.get("sha"),
    )

def find_checker(suite):
    for n in sorted(os.listdir(suite)):
        if "self" in n.lower() and "check" in n.lower() and n.endswith(".py"):
            return n
    return None

def run_checker(suite, checker):
    r = subprocess.run([sys.executable, os.path.join(suite, checker)], capture_output=True, text=True, cwd=suite)
    return r.returncode == 0, (r.stdout.strip().splitlines() or [""])[-1]

def assess(suite, tsha, skip_proof_member=False):
    el = {}
    man_name, manifest = find_manifest(suite)
    gen02 = is_gen02_suite(manifest)
    entries = member_entries(manifest)
    listed = set()
    if entries:
        bad = []
        for m in entries:
            rel, wb, ws = norm(m)
            listed.add(rel)
            if skip_proof_member and rel == PROOF_NAME:
                continue
            if not rel:
                bad.append("entry without a path")
                continue
            p = os.path.join(suite, rel)
            if not os.path.exists(p):
                bad.append(rel + " missing")
                continue
            d = open(p, "rb").read()
            if wb is not None and len(d) != wb:
                bad.append(rel + " size mismatch")
            elif ws and sha(d) != ws:
                bad.append(rel + " hash mismatch")
        el["E1_manifest_members_verify"] = {
            "pass": not bad,
            "detail": f"{len(entries)} members, {len(bad)} bad",
            "bad": bad[:5],
        }
    else:
        el["E1_manifest_members_verify"] = {"pass": False, "detail": "no manifest with member entries found"}

    checker = find_checker(suite)
    if checker:
        src = open(os.path.join(suite, checker), encoding="utf-8", errors="replace").read()
        ok_chk = ("FUNDING" in src and "ProjectID" in src)
        if gen02:
            ok_chk = ok_chk and ("COMPENSATION__BASIS__01.md" in src and "TODO_STUB_RE" in src and "LEDGER__01.json" in src)
        el["E2b_checker_carries_template_checks"] = {
            "pass": ok_chk,
            "detail": "checker carries GEN 02 template, compensation, placeholder, and ledger checks"
            if (ok_chk and gen02)
            else ("checker source names FUNDING + ProjectID" if ok_chk else "checker lacks required template checks"),
        }
    else:
        el["E2b_checker_carries_template_checks"] = {"pass": False, "detail": "no self-check file"}

    pid = (manifest or {}).get("project_id") or ""
    gen = (manifest or {}).get("generation") or ""

    readme = ""
    for n in sorted(os.listdir(suite)):
        if n.upper().startswith("README") and n.endswith(".md"):
            readme = open(os.path.join(suite, n), encoding="utf-8", errors="replace").read()
            break
    el["E3_face_carries_projectid_funding"] = {
        "pass": ("ProjectID" in readme and "Funding" in readme),
        "detail": "README names ProjectID + Funding"
        if ("ProjectID" in readme and "Funding" in readme)
        else "README lacks ProjectID and/or Funding lines",
    }

    e4 = {"pass": False, "detail": "no funding statement found"}
    cand = [n for n in os.listdir(suite) if "FUNDING" in n.upper() and n.endswith(".md")]
    if cand:
        t = open(os.path.join(suite, cand[0]), encoding="utf-8", errors="replace").read()
        ok = "ProjectID" in t and "Funding" in t and "commercial arrangement" in t.lower()
        e4 = {"pass": ok, "detail": f"{cand[0]} " + ("carries the three lines" if ok else "lacks required lines")}
    el["E4_funding_statement"] = e4

    ppath = os.path.join(suite, PROOF_NAME)
    if os.path.exists(ppath) and PROOF_NAME in listed:
        try:
            pj = json.load(open(ppath, encoding="utf-8"))
            if not gen02:
                # GEN 01 installed proofs keep grading against their recorded GEN 01 template hash
                expected_h = ((manifest or {}).get("derived_from") or {}).get("template_manifest_sha256")
                match = bool(expected_h and pj.get("template_manifest_sha256") == expected_h)
                el["E5_proof_in_suite"] = {
                    "pass": match,
                    "detail": "GEN 01 in-suite proof bound by manifest (not re-graded under GEN 02)"
                    if match
                    else "GEN 01 in-suite proof hash mismatch",
                }
            else:
                match = pj.get("template_manifest_sha256") == tsha
                el["E5_proof_in_suite"] = {
                    "pass": match,
                    "detail": "in-suite proof bound by manifest, names the current GEN 02 template hash"
                    if match
                    else "in-suite proof names a superseded template hash — re-proof required",
                }
        except Exception:
            el["E5_proof_in_suite"] = {"pass": False, "detail": "in-suite proof file unreadable"}
    else:
        el["E5_proof_in_suite"] = {
            "pass": False,
            "detail": "no in-suite proof (install: prove_conformance.py <suite> --install)",
        }

    if gen02:
        # E6: Pricing schedule member present, ProjectID consistent, >=8 purchase links, no unpopulated slots
        pr_path = os.path.join(suite, "PRICING__AND__ACCESS__01.md")
        if os.path.exists(pr_path) and "PRICING__AND__ACCESS__01.md" in listed:
            pr = open(pr_path, encoding="utf-8", errors="replace").read()
            links = re.findall(r"https://buy\.stripe\.com/[A-Za-z0-9]+", pr)
            ok6 = (
                f"SuiteProjectID: {pid}" in pr
                and len(links) >= 8
                and not SLOT_RE.search(pr)
                and not TODO_STUB_RE.search(pr)
            )
            el["E6_pricing_schedule"] = {
                "pass": ok6,
                "detail": f"PRICING__AND__ACCESS__01.md populated ({len(links)} purchase links, ProjectID={pid})"
                if ok6
                else "PRICING__AND__ACCESS__01.md unpopulated, lacks purchase links, or ProjectID mismatch",
            }
        else:
            el["E6_pricing_schedule"] = {"pass": False, "detail": "PRICING__AND__ACCESS__01.md missing or unlisted"}

        # E7: Compensation basis member present, populated, ProjectID consistent, own-generation row when true
        cb_path = os.path.join(suite, "COMPENSATION__BASIS__01.md")
        if os.path.exists(cb_path) and "COMPENSATION__BASIS__01.md" in listed:
            cb = open(cb_path, encoding="utf-8", errors="replace").read()
            m_acc = re.search(r"- `accounts_for_errors`:\s*(true|false)\b", cb)
            m_sub = re.search(r"- `subject`:\s*(.+)", cb)
            m_ins = re.search(r"- `meter_instruments`:\s*(.+)", cb)
            m_cls = re.search(r"- `error_classes`:\s*(.+)", cb)
            m_pid = re.search(r"- `suite_project_id`:\s*(.+)", cb)
            ok7 = bool(
                m_acc
                and m_pid
                and m_pid.group(1).strip() == pid
                and not SLOT_RE.search(cb)
                and not TODO_STUB_RE.search(cb)
            )
            detail7 = ""
            if ok7:
                if m_acc.group(1) == "true":
                    vals = [
                        m_sub.group(1).strip() if m_sub else "",
                        m_ins.group(1).strip() if m_ins else "",
                        m_cls.group(1).strip() if m_cls else "",
                    ]
                    if any(not v or v == "N/A (accounts_for_errors=false)" for v in vals):
                        ok7 = False
                        detail7 = "accounts_for_errors=true lacks populated subject/instruments/classes"
                    else:
                        rows = []
                        for line in cb.splitlines():
                            ls = line.strip()
                            if ls.startswith("|") and not ls.startswith("| Generation") and not ls.startswith("|---"):
                                cols = [c.strip() for c in ls.strip("|").split("|")]
                                if len(cols) == 5:
                                    rows.append(cols)
                        own_gen_ok = False
                        ints_ok = bool(rows)
                        for rg, rd, rj, rt, rl in rows:
                            if rg == gen:
                                own_gen_ok = True
                            try:
                                d = json.loads(rj)
                                tot = int(rt)
                                if not isinstance(d, dict) or not d or any((not isinstance(v, int) or isinstance(v, bool) or v < 0) for v in d.values()):
                                    ints_ok = False
                                if tot != sum(d.values()) or not rl:
                                    ints_ok = False
                            except Exception:
                                ints_ok = False
                        ok7 = own_gen_ok and ints_ok
                        detail7 = (
                            f"accounts_for_errors=true; {len(rows)} readings row(s) incl. generation {gen} verified"
                            if ok7
                            else f"readings table invalid or missing row for generation '{gen}'"
                        )
                else:
                    detail7 = "accounts_for_errors=false; N/A declaration verified"
            else:
                detail7 = "COMPENSATION__BASIS__01.md malformed, unpopulated, or ProjectID mismatch"
            el["E7_compensation_basis"] = {"pass": ok7, "detail": detail7}
        else:
            el["E7_compensation_basis"] = {"pass": False, "detail": "COMPENSATION__BASIS__01.md missing or unlisted"}

        # E8: Zero placeholders across ALL members + hash-chained LEDGER__01.json (KV__303 R-200-1 + KV__298)
        stub_hits = []
        for fn in sorted(listed):
            if fn and fn.endswith((".md", ".json", ".txt")) and fn != PROOF_NAME:
                fp = os.path.join(suite, fn)
                if os.path.exists(fp):
                    txt = open(fp, encoding="utf-8", errors="replace").read()
                    if SLOT_RE.search(txt) or TODO_STUB_RE.search(txt):
                        stub_hits.append(fn)
        led_path = os.path.join(suite, "LEDGER__01.json")
        led_ok = False
        led_detail = "LEDGER__01.json missing"
        if os.path.exists(led_path) and "LEDGER__01.json" in listed:
            try:
                led = json.load(open(led_path, encoding="utf-8"))
                ents = led.get("entries") or []
                prev = "GENESIS"
                led_ok = bool(ents) and bool(led.get("chaining_rule")) and led.get("project_id") == pid
                for idx, e in enumerate(ents, 1):
                    if e.get("seq") != idx or e.get("prev") != prev:
                        led_ok = False
                        break
                    nh = {k: v for k, v in e.items() if k != "hash"}
                    eh = hashlib.sha256((e["prev"] + json.dumps(nh, sort_keys=True)).encode("utf-8")).hexdigest()
                    if e.get("hash") != eh:
                        led_ok = False
                        break
                    prev = eh
                led_detail = f"LEDGER__01.json chain valid ({len(ents)} entries)" if led_ok else "LEDGER__01.json chain invalid"
            except Exception as exc:
                led_detail = f"LEDGER__01.json error: {exc}"
        ok8 = (not stub_hits) and led_ok
        el["E8_zero_placeholders_and_chained_ledger"] = {
            "pass": ok8,
            "detail": f"0 placeholder/TODO stubs across all members; {led_detail}"
            if ok8
            else f"stubs={stub_hits}; {led_detail}",
        }

    return el, gen02

def public(el, gen02):
    order = ORDER_GEN02 if gen02 else ORDER_GEN01
    return {k: el[k] for k in order if k in el}

def regen_manifest(suite, man_name, manifest):
    members = []
    for name in sorted(os.listdir(suite)):
        if name == man_name or name.startswith(".") or name == "__pycache__":
            continue
        p = os.path.join(suite, name)
        if os.path.isfile(p):
            d = open(p, "rb").read()
            members.append({"file": name, "bytes": len(d), "sha256": sha(d)})
    manifest["members"] = members
    with open(os.path.join(suite, man_name), "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)
    return members

def build_proof(suite, manifest, tsha, el, gen02):
    els = public(el, gen02)
    els["E5_proof_in_suite"] = {
        "pass": True,
        "detail": "this file — a member of the suite it proves, bound by the manifest hash",
    }
    order = ORDER_GEN02 if gen02 else ORDER_GEN01
    ordered = {k: els[k] for k in order if k in els}
    return {
        "proof_of": manifest.get("suite") or os.path.basename(os.path.abspath(suite)),
        "generation": manifest.get("generation"),
        "template": "SUITE__TEMPLATE GEN 02" if gen02 else "SUITE__TEMPLATE GEN 01",
        "template_manifest_sha256": tsha,
        "convention": "This proof lives inside the suite it proves, as a hashed member of the suite manifest. It is excluded from its own E1 enumeration; the manifest binds its bytes.",
        "elements": ordered,
        "verdict": "CONFORMANT" if all(v["pass"] for v in ordered.values()) else "NON_CONFORMANT",
    }

def install(suite):
    tsha = tman_sha()
    man_name, manifest = find_manifest(suite)
    if not manifest or not isinstance(manifest.get("members"), list):
        print("NON-ALLOW: suite manifest is not the template dialect ('members' list).")
        return 2
    if not is_gen02_suite(manifest):
        print("NON-ALLOW: installed GEN 01 suite proofs are never re-graded under GEN 02.")
        return 2
    checker = find_checker(suite)
    el, gen02 = assess(suite, tsha, skip_proof_member=True)
    if checker:
        ok, last = run_checker(suite, checker)
        el["E2_self_check_passes"] = {"pass": ok, "detail": last + " (pre-install run)"}
    with open(os.path.join(suite, PROOF_NAME), "w", encoding="utf-8") as f:
        json.dump(build_proof(suite, manifest, tsha, el, gen02), f, indent=2)
    regen_manifest(suite, man_name, manifest)
    if checker:
        ok, last = run_checker(suite, checker)
        el["E2_self_check_passes"] = {"pass": ok, "detail": last}
        el2, _ = assess(suite, tsha, skip_proof_member=True)
        el2["E2_self_check_passes"] = el["E2_self_check_passes"]
        el = el2
        with open(os.path.join(suite, PROOF_NAME), "w", encoding="utf-8") as f:
            json.dump(build_proof(suite, manifest, tsha, el, gen02), f, indent=2)
        regen_manifest(suite, man_name, manifest)
        ok2, last2 = run_checker(suite, checker)
        print(f"final self-check over installed bytes: {'PASS' if ok2 else 'FAIL'} — {last2}")
        if not ok2:
            return 1
    final = build_proof(suite, manifest, tsha, el, gen02)
    v = final["verdict"] == "CONFORMANT"
    print(f"proof installed in suite: {PROOF_NAME} — verdict {final['verdict']}")
    for k, val in final["elements"].items():
        print(f"  {k}: {'PASS' if val['pass'] else 'FAIL'} — {val['detail']}")
    return 0 if v else 1

def main():
    suite = sys.argv[1]
    if len(sys.argv) > 2 and sys.argv[2] == "--install":
        return install(suite)
    tsha = tman_sha()
    el, gen02 = assess(suite, tsha)
    checker = find_checker(suite)
    if checker:
        ok, last = run_checker(suite, checker)
        el["E2_self_check_passes"] = {"pass": ok, "detail": last}
    else:
        el["E2_self_check_passes"] = {"pass": False, "detail": "no self-check file"}
    pub = public(el, gen02)
    v = all(val["pass"] for val in pub.values())
    print(f"{os.path.basename(os.path.abspath(suite))} [{'GEN 02' if gen02 else 'GEN 01'}]: {'CONFORMANT' if v else 'NON_CONFORMANT'}")
    for k, val in pub.items():
        print(f"  {k}: {'PASS' if val['pass'] else 'FAIL'} — {val['detail']}")
    return 0 if v else 1

if __name__ == "__main__":
    sys.exit(main())
