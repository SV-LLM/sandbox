"""I7: one browser-lease contract (contracts/browser-lease/v1/contract.json) and this repo's implementation of it.

Offline and deterministic: no clock, network or credential. Lowest supported mode: E0.
"""
from __future__ import annotations

import hashlib
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "runtime"))

import lease_time  # noqa: E402

CONTRACT = ROOT / "contracts/browser-lease/v1/contract.json"
SIX = ("failure_code", "failed_predicate", "required_evidence_or_repair", "retry_entrypoint",
       "owning_existing_goal", "next_attempt")


class BrowserLeaseContract(unittest.TestCase):
    def setUp(self):
        self.c = json.loads(CONTRACT.read_text(encoding="utf-8"))

    def test_lattice_constants_are_the_contract(self):
        ts = self.c["time_source"]
        self.assertEqual(ts["hb_anchor_epoch"], lease_time.HB_ANCHOR_EPOCH)
        self.assertEqual(ts["hb_anchor_unix_ns"], lease_time.HB_ANCHOR_UNIX_NS)
        self.assertEqual(ts["hb_period_ns"], lease_time.HB_PERIOD_NS)
        self.assertEqual(self.c["predicate"], lease_time.LEASE_TIME_PREDICATE)
        self.assertEqual(self.c["non_allow_fields"], list(SIX))
        self.assertEqual(self.c["lowest_supported_mode"], "E0")

    def test_lease_schema_is_the_page_load_tools(self):
        src = (ROOT / "runtime/page_load_tool.py").read_text(encoding="utf-8")
        self.assertIn('LEASE_SCHEMA = "' + self.c["lease_schema"] + '"', src)

    def test_supplied_clock_is_the_lattice_instant_and_reads_no_clock(self):
        clock = lease_time.supplied_clock(4096)
        self.assertEqual(clock(), clock())
        self.assertEqual(clock(), (1_787_511_600_000_000_000 + (4096 - 32) * 10_000_000) / 1e9)
        self.assertEqual(lease_time.instant(4096).timestamp(), clock())

    def test_absent_or_invalid_epoch_refuses_six_field(self):
        for value, code in ((None, "HB_EPOCH_NOT_SUPPLIED"), ("31", "HB_EPOCH_INVALID"), ("3_3", "HB_EPOCH_INVALID")):
            with self.subTest(value=value):
                with self.assertRaises(lease_time.LeaseTimeRefused) as caught:
                    lease_time.supplied_clock(value)
                r = caught.exception.refusal
                self.assertEqual((r["disposition"], r["failure_code"]), ("FAIL_CLOSED", code))
                self.assertTrue(all(r[f] for f in SIX))
                self.assertIn(self.c["refusals"][code], ("FAIL_CLOSED",))

    def test_contract_digest_is_stable(self):
        # Consumers (StegApp) pin this digest; a change here moves their pin in the same change.
        print("BROWSER_LEASE_CONTRACT_SHA256", hashlib.sha256(CONTRACT.read_bytes()).hexdigest())


if __name__ == "__main__":
    unittest.main()
