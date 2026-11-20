#!/usr/bin/env python3
"""Cleanroom test suite for SUITE__TEMPLATE GEN 02 (Spec 01 + Spec 02 + R-200-1)."""
import json, os, shutil, subprocess, sys, tempfile

HERE = os.path.dirname(os.path.abspath(__file__))

def run(cmd, cwd=None):
    return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)

def base_args(out_dir, accounts="false", extra=None):
    cmd = [
        sys.executable, os.path.join(HERE, "instantiate.py"),
        "--name", "TEST SUITE",
        "--generation", "GEN 02",
        "--project-id", "TEST-PROJ-001",
        "--funding-line", "UNFUNDED - cleanroom test specimen",
        "--funder", "None (test specimen)",
        "--arrangement", "no commercial arrangement; commercial_arrangement: false",
        "--source", "Cleanroom test against SUITE__TEMPLATE GEN 02",
        "--purpose", "Verify mechanical enforcement of Spec 01, Spec 02, and KV__303 R-200-1.",
        "--levels", "Separates template machinery from derived suite instances.",
        "--member-title", "Cleanroom Specification",
        "--body", "All required specification fields are populated with concrete test predicates.",
        "--pointers", "- SUITE__TEMPLATE__GEN02__SPEC__02.md (Drive 16FqoAHbR0iuajWFdkNKNvUjlJWuwSHhr)",
        "--accounts-for-errors", accounts,
        "--out", out_dir,
    ]
    if extra:
        cmd.extend(extra)
    return cmd

def main():
    tmp = tempfile.mkdtemp(prefix="tmpl_gen02_test_")
    try:
        # 1. Positive derivation: accounts_for_errors = false
        d_false = os.path.join(tmp, "suite_false")
        r1 = run(base_args(d_false, "false"))
        assert r1.returncode == 0, f"false derivation failed: {r1.stdout} {r1.stderr}"
        p1 = json.load(open(os.path.join(d_false, "CONFORMANCE__PROOF__01.json")))
        assert p1["verdict"] == "CONFORMANT" and all(v["pass"] for v in p1["elements"].values())

        # 2. Positive derivation: accounts_for_errors = true (Sovereign Veritas GEN 02 reference shape)
        d_true = os.path.join(tmp, "suite_true")
        r2 = run(base_args(d_true, "true", [
            "--subject", "holland202/sovereign-veritas @ 13c663b3a3b058b7170fd3628325c1361112d07d",
            "--meter-instruments", "execution_boundary_probe.py, eo1_probe.py, verify_transition.py,TransitionSink",
            "--error-classes", "duplicate_before_effect, x4_race, x5_write_failure_asymmetry, eo1_unattested_execution, unknown_executor_hold",
            "--reading-date", "2026-11-12",
            "--reading-counts-json", json.dumps({"duplicate_before_effect": 3, "x4_race": 1, "x5_write_failure_asymmetry": 1, "eo1_unattested_execution": 2, "unknown_executor_hold": 1}),
            "--compensation-line", "Operator covering absorbs 8 metered error-surface events across 5 registered classes (UNFUNDED specimen).",
        ]))
        assert r2.returncode == 0, f"true derivation failed: {r2.stdout} {r2.stderr}"
        p2 = json.load(open(os.path.join(d_true, "CONFORMANCE__PROOF__01.json")))
        assert p2["verdict"] == "CONFORMANT" and p2["elements"]["E7_compensation_basis"]["pass"] is True

        # 3. Negative: accounts_for_errors = true with unpopulated subject -> abort
        d_neg1 = os.path.join(tmp, "neg_missing_subject")
        r3 = run(base_args(d_neg1, "true", [
            "--meter-instruments", "probe",
            "--error-classes", "cls1",
            "--reading-counts-json", '{"cls1": 2}',
            "--compensation-line", "line",
        ]))
        assert r3.returncode != 0 and "TEMPLATE INVALID" in r3.stdout

        # 4. Negative (KV__303 R-200-1): TODO placeholder in Charter Purpose -> abort at instantiate.py!
        d_neg2 = os.path.join(tmp, "neg_todo_charter")
        cmd_todo = base_args(d_neg2, "false")
        idx_p = cmd_todo.index("--purpose")
        cmd_todo[idx_p + 1] = "TODO — the suite's purpose, stated by its author."
        r4 = run(cmd_todo)
        assert r4.returncode != 0 and "TEMPLATE INVALID" in r4.stdout

        # 5. Negative: ProjectID mismatch on compensation basis -> abort at instantiate.py!
        d_neg3 = os.path.join(tmp, "neg_pid_mismatch")
        r5 = run(base_args(d_neg3, "false", ["--suite-project-id", "WRONG-ID"]))
        assert r5.returncode != 0 and "TEMPLATE INVALID" in r5.stdout

        # 6. Post-derivation tamper: inject TODO into REFERENCES__01.md and rebind manifest -> E8 & self_check MUST FAIL
        d_tamper = os.path.join(tmp, "suite_tamper")
        shutil.copytree(d_true, d_tamper)
        ref_p = os.path.join(d_tamper, "REFERENCES__01.md")
        open(ref_p, "w").write("# References\n\nTODO — pointers to the surrounding record.\n")
        r6 = run([sys.executable, os.path.join(HERE, "prove_conformance.py"), d_tamper])
        assert r6.returncode != 0 and "NON_CONFORMANT" in r6.stdout

        # 7. Post-derivation tamper: bump manifest generation to GEN 03 without adding GEN 03 readings row -> E7 MUST FAIL
        d_gen_gap = os.path.join(tmp, "suite_gen_gap")
        shutil.copytree(d_true, d_gen_gap)
        mp = os.path.join(d_gen_gap, "PACKAGE__MANIFEST__01.json")
        mj = json.load(open(mp))
        mj["generation"] = "GEN 03"
        json.dump(mj, open(mp, "w"), indent=2)
        r7 = run([sys.executable, os.path.join(HERE, "prove_conformance.py"), d_gen_gap])
        assert r7.returncode != 0 and "E7_compensation_basis: FAIL" in r7.stdout

        # 8. Post-derivation tamper: corrupt LEDGER__01.json hash -> E8 & self_check MUST FAIL
        d_led_bad = os.path.join(tmp, "suite_led_bad")
        shutil.copytree(d_false, d_led_bad)
        lp = os.path.join(d_led_bad, "LEDGER__01.json")
        lj = json.load(open(lp))
        lj["entries"][0]["hash"] = "0" * 64
        json.dump(lj, open(lp, "w"), indent=2)
        r8 = run([sys.executable, os.path.join(HERE, "prove_conformance.py"), d_led_bad])
        assert r8.returncode != 0 and "E8_zero_placeholders_and_chained_ledger: FAIL" in r8.stdout

        print("TEMPLATE_GEN02_CLEANROOM_TESTS: 8/8 PASS")
        return 0
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

if __name__ == "__main__":
    sys.exit(main())
