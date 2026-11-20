#!/usr/bin/env python3
"""Instantiate a suite from SUITE__TEMPLATE GEN 02.
Enforces:
  - Hash + size verification of all TEMPLATE__MANIFEST__02.json components before derivation.
  - Spec 01 commercial schedule variables populated (refuses missing/zero prices or purchase URLs).
  - Spec 02 compensation basis variables populated (with accounts_for_errors=true, refuses missing
    subject, meter_instruments, error_classes, or non-integer readings, or ProjectID mismatch).
  - KV__303 R-200-1 universal placeholder refusal: refuses unpopulated '{{...}}' slot tokens or
    'TODO —' placeholders in ANY templated member (Charter, Spec Member, References, README,
    Funding, Pricing, Compensation, Ledger).
  - KV__298 hash-chained LEDGER__01.json genesis computation.
"""
import argparse, datetime, hashlib, json, os, re, subprocess, sys

HERE = os.path.dirname(os.path.abspath(__file__))
SLOT_RE = re.compile(r"\{\{[A-Z0-9_]+\}\}")
TODO_STUB_RE = re.compile(r"\bTODO\s*(?:—|--|:)\s*", re.IGNORECASE)
NA_TOKEN = "N/A (accounts_for_errors=false)"

def sha(b):
    return hashlib.sha256(b).hexdigest()

def fmt_dollars(cents):
    if cents % 100 == 0:
        return f"${cents // 100:,}"
    return f"${cents / 100:,.2f}"

def ledger_hash(entry_without_hash):
    return hashlib.sha256(
        (entry_without_hash["prev"] + json.dumps(entry_without_hash, sort_keys=True)).encode("utf-8")
    ).hexdigest()

def abort(msg):
    print(f"TEMPLATE INVALID: {msg}")
    return 1

def main():
    ap = argparse.ArgumentParser()
    for a in [
        "name", "generation", "project-id", "funding-line", "funder",
        "arrangement", "source", "purpose", "levels", "member-title",
        "body", "pointers", "accounts-for-errors", "out",
    ]:
        ap.add_argument("--" + a, required=True)
    ap.add_argument("--pricing-schedule-json", default=os.path.join(HERE, "price_schedule.json"))
    ap.add_argument("--suite-project-id", default=None, help="Optional explicit ProjectID for compensation basis consistency check")
    ap.add_argument("--subject", default="")
    ap.add_argument("--meter-instruments", default="")
    ap.add_argument("--error-classes", default="")
    ap.add_argument("--reading-date", default=str(datetime.date.today()))
    ap.add_argument("--reading-counts-json", default="")
    ap.add_argument("--compensation-line", default="")
    ap.add_argument("--prior-readings-rows", default="")
    args = ap.parse_args()

    tman_path = os.path.join(HERE, "TEMPLATE__MANIFEST__02.json")
    tman = json.load(open(tman_path, encoding="utf-8"))
    for m in tman["components"]:
        p = os.path.join(HERE, m["file"])
        if not os.path.exists(p):
            return abort(f"{m['file']} missing")
        data = open(p, "rb").read()
        if len(data) != m["bytes"] or sha(data) != m["sha256"]:
            return abort(f"{m['file']} hash/size mismatch")

    # KV__303 R-200-1 pre-derivation check on required prose arguments
    for field_name, val in [
        ("name", args.name), ("generation", args.generation), ("project_id", args.project_id),
        ("funding_line", args.funding_line), ("funder", args.funder), ("arrangement", args.arrangement),
        ("source", args.source), ("purpose", args.purpose), ("levels", args.levels),
        ("member_title", args.member_title), ("body", args.body), ("pointers", args.pointers),
    ]:
        s = (val or "").strip()
        if not s or SLOT_RE.search(s) or TODO_STUB_RE.search(s):
            return abort(f"unpopulated or placeholder value supplied for --{field_name.replace('_', '-')}")

    comp_pid = args.suite_project_id if args.suite_project_id is not None else args.project_id
    if comp_pid != args.project_id:
        return abort(f"suite_project_id '{comp_pid}' mismatches funding ProjectID '{args.project_id}'")

    # Spec 01 pricing validation
    if not os.path.exists(args.pricing_schedule_json):
        return abort(f"pricing schedule JSON missing: {args.pricing_schedule_json}")
    ps = json.load(open(args.pricing_schedule_json, encoding="utf-8"))
    try:
        classes = ps["classes"]
        sr = classes["scoped_run"]
        dr = classes["document_run"]
        seat = classes["participant_seat"]
        ep = classes["eval_package"]
        gc = classes["governance_continuity"]
        req_urls = [
            sr["per_use_purchase_url"], sr["subscription"]["plan_purchase_url"],
            dr["purchase_url"], seat["subscription"]["purchase_url"],
            ep["first_repo_purchase_url"], ep["additional_repo_purchase_url"],
            gc["subscription"]["first_repo_purchase_url"], gc["subscription"]["additional_repo_purchase_url"],
        ]
        req_cents = [
            sr["per_use_cents"], sr["subscription"]["monthly_cents"], dr["per_use_cents"],
            seat["subscription"]["monthly_cents"], ep["first_repo_cents"], ep["additional_repo_cents"],
            gc["subscription"]["first_repo_monthly_cents"], gc["subscription"]["additional_repo_monthly_cents"],
        ]
        if any(not str(u).startswith("https://buy.stripe.com/") for u in req_urls):
            return abort("pricing schedule lacks active Stripe purchase URLs")
        if any(not isinstance(c, int) or c <= 0 for c in req_cents):
            return abort("pricing schedule lacks positive integer cent amounts")
    except Exception as exc:
        return abort(f"unpopulated or malformed pricing schedule slots: {exc}")

    # Spec 02 compensation basis validation
    if args.accounts_for_errors not in ("true", "false"):
        return abort("--accounts-for-errors must be 'true' or 'false'")
    if args.accounts_for_errors == "true":
        for fn, fv in [
            ("subject", args.subject),
            ("meter_instruments", args.meter_instruments),
            ("error_classes", args.error_classes),
            ("reading_counts_json", args.reading_counts_json),
            ("compensation_line", args.compensation_line),
        ]:
            if not (fv or "").strip() or SLOT_RE.search(fv) or TODO_STUB_RE.search(fv):
                return abort(f"accounts_for_errors=true requires populated --{fn.replace('_', '-')}")
        try:
            counts = json.loads(args.reading_counts_json)
            if not isinstance(counts, dict) or not counts:
                return abort("reading_counts_json must be a non-empty JSON object of class->int")
            for k, v in counts.items():
                if not isinstance(v, int) or isinstance(v, bool) or v < 0:
                    return abort(f"meter count for '{k}' is not a non-negative integer")
        except Exception as exc:
            return abort(f"invalid --reading-counts-json: {exc}")
        comp_subject = args.subject.strip()
        comp_instr = args.meter_instruments.strip()
        comp_classes = args.error_classes.strip()
        total_cnt = sum(counts.values())
        own_row = f"| {args.generation} | {args.reading_date.strip()} | `{json.dumps(counts, sort_keys=True)}` | {total_cnt} | {args.compensation_line.strip()} |"
        # Strip backticks in JSON column? Wait: self_check parses cols[2] as JSON, so keep raw JSON without backticks!
        own_row = f"| {args.generation} | {args.reading_date.strip()} | {json.dumps(counts, sort_keys=True)} | {total_cnt} | {args.compensation_line.strip()} |"
        rows_list = [r for r in (args.prior_readings_rows or "").splitlines() if r.strip()]
        rows_list.append(own_row)
        readings_rows = "\n".join(rows_list)
    else:
        comp_subject = NA_TOKEN
        comp_instr = NA_TOKEN
        comp_classes = NA_TOKEN
        readings_rows = f"| {args.generation} | {args.reading_date.strip()} | N/A (accounts_for_errors=false) | N/A | No error-compensation compute owed (accounts_for_errors=false). |"

    genesis_detail = (
        f"Instantiated by SUITE__TEMPLATE GEN 02 instantiator ({len(tman['components'])}/{len(tman['components'])} "
        f"template components hash-verified against TEMPLATE__MANIFEST__02.json). ProjectID {args.project_id}; "
        f"accounts_for_errors={args.accounts_for_errors}."
    )
    genesis_no_hash = {
        "seq": 1,
        "kind": "GENESIS",
        "subject": "Derivation from SUITE__TEMPLATE GEN 02",
        "detail": genesis_detail,
        "prev": "GENESIS",
    }
    genesis_h = ledger_hash(genesis_no_hash)

    slots = {
        "{{SUITE_NAME}}": args.name,
        "{{GENERATION}}": args.generation,
        "{{PROJECT_ID}}": args.project_id,
        "{{FUNDING_LINE}}": args.funding_line,
        "{{FUNDER}}": args.funder,
        "{{ARRANGEMENT}}": args.arrangement,
        "{{SOURCE_LINE}}": args.source,
        "{{STATUS_LINE}}": f"FILED AS {args.generation} MEMBER (SUITE__TEMPLATE GEN 02 derivation).",
        "{{PURPOSE}}": args.purpose,
        "{{LEVELS}}": args.levels,
        "{{MEMBER_TITLE}}": args.member_title,
        "{{BODY}}": args.body,
        "{{POINTERS}}": args.pointers,
        "{{PRICE_SCHEDULE_VERSION}}": str(ps["version"]),
        "{{PRICE_ESTABLISHED_DATE}}": str(ps["established"]),
        "{{PRICE_ESTABLISHED_BY}}": str(ps["established_by"]),
        "{{PRICE_CURRENCY}}": str(ps["currency"]).upper(),
        "{{PRICE_SCOPED_RUN_DOLLARS}}": fmt_dollars(sr["per_use_cents"]),
        "{{URL_SCOPED_RUN}}": sr["per_use_purchase_url"],
        "{{PRICE_SCOPED_PLAN_DOLLARS}}": fmt_dollars(sr["subscription"]["monthly_cents"]),
        "{{URL_SCOPED_PLAN}}": sr["subscription"]["plan_purchase_url"],
        "{{PRICE_DOC_RUN_DOLLARS}}": fmt_dollars(dr["per_use_cents"]),
        "{{URL_DOC_RUN}}": dr["purchase_url"],
        "{{PRICE_SEAT_DOLLARS}}": fmt_dollars(seat["subscription"]["monthly_cents"]),
        "{{URL_SEAT}}": seat["subscription"]["purchase_url"],
        "{{PRICE_EVAL_FIRST_DOLLARS}}": fmt_dollars(ep["first_repo_cents"]),
        "{{URL_EVAL_FIRST}}": ep["first_repo_purchase_url"],
        "{{PRICE_EVAL_ADDL_DOLLARS}}": fmt_dollars(ep["additional_repo_cents"]),
        "{{URL_EVAL_ADDL}}": ep["additional_repo_purchase_url"],
        "{{PRICE_CONT_FIRST_DOLLARS}}": fmt_dollars(gc["subscription"]["first_repo_monthly_cents"]),
        "{{URL_CONT_FIRST}}": gc["subscription"]["first_repo_purchase_url"],
        "{{PRICE_CONT_ADDL_DOLLARS}}": fmt_dollars(gc["subscription"]["additional_repo_monthly_cents"]),
        "{{URL_CONT_ADDL}}": gc["subscription"]["additional_repo_purchase_url"],
        "{{ACCOUNTS_FOR_ERRORS}}": args.accounts_for_errors,
        "{{COMP_SUBJECT}}": comp_subject,
        "{{COMP_METER_INSTRUMENTS}}": comp_instr,
        "{{COMP_ERROR_CLASSES}}": comp_classes,
        "{{COMP_SUITE_PROJECT_ID}}": comp_pid,
        "{{COMP_READINGS_ROWS}}": readings_rows,
        "{{LEDGER_GENESIS_DETAIL}}": genesis_detail,
        "{{LEDGER_GENESIS_HASH}}": genesis_h,
    }

    os.makedirs(args.out, exist_ok=True)
    mapping = {
        "README.md.tmpl": "README.md",
        "SUITE__CHARTER__01.md.tmpl": "SUITE__CHARTER__01.md",
        "FUNDING__STATEMENT__01.md.tmpl": "FUNDING__STATEMENT__01.md",
        "PRICING__AND__ACCESS__01.md.tmpl": "PRICING__AND__ACCESS__01.md",
        "COMPENSATION__BASIS__01.md.tmpl": "COMPENSATION__BASIS__01.md",
        "SPEC__MEMBER__01.md.tmpl": "SPEC__MEMBER__01.md",
        "REFERENCES__01.md.tmpl": "REFERENCES__01.md",
        "LEDGER__01.json.tmpl": "LEDGER__01.json",
        "self_check.py.tmpl": "self_check.py",
    }
    for tmpl, out_name in mapping.items():
        text = open(os.path.join(HERE, tmpl), encoding="utf-8").read()
        if tmpl != "self_check.py.tmpl":
            if tmpl == "LEDGER__01.json.tmpl":
                for k, v in slots.items():
                    # JSON-escape string values when substituting inside JSON string literals
                    json_safe = json.dumps(v)[1:-1]
                    text = text.replace(k, json_safe)
            else:
                for k, v in slots.items():
                    text = text.replace(k, v)
            if SLOT_RE.search(text) or TODO_STUB_RE.search(text):
                return abort(f"unpopulated token remained in rendered {out_name}")
        with open(os.path.join(args.out, out_name), "w", encoding="utf-8") as f:
            f.write(text)

    tman_sha = sha(open(tman_path, "rb").read())
    sc_hash = sha(open(os.path.join(args.out, "self_check.py"), "rb").read())
    members = []
    for name in sorted(os.listdir(args.out)):
        if name == "PACKAGE__MANIFEST__01.json" or name.startswith("."):
            continue
        p = os.path.join(args.out, name)
        if os.path.isfile(p):
            d = open(p, "rb").read()
            members.append({"file": name, "bytes": len(d), "sha256": sha(d)})

    manifest = {
        "suite": args.name,
        "generation": args.generation,
        "project_id": args.project_id,
        "funding": args.funding_line,
        "accounts_for_errors": (args.accounts_for_errors == "true"),
        "source": args.source,
        "derived_from": {
            "template": "SUITE__TEMPLATE GEN 02",
            "template_manifest_sha256": tman_sha,
            "self_check_sha256": sc_hash,
        },
        "manifest_excludes": "PACKAGE__MANIFEST__01.json (this file)",
        "members": members,
    }
    with open(os.path.join(args.out, "PACKAGE__MANIFEST__01.json"), "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)

    r = subprocess.run(
        [sys.executable, os.path.join(HERE, "prove_conformance.py"), args.out, "--install"],
        capture_output=True,
        text=True,
    )
    print(r.stdout.strip())
    if r.returncode != 0:
        print(r.stderr.strip())
        return r.returncode
    final = json.load(open(os.path.join(args.out, "PACKAGE__MANIFEST__01.json"), encoding="utf-8"))
    print(f"instantiated GEN 02 suite: {args.out} ({len(final['members'])} members incl. in-suite proof)")
    return 0

if __name__ == "__main__":
    sys.exit(main())
