import unittest

from src.stegbrowser.llm_profile import (
    begin_llm_profile_packet,
    bind_llm_profile_result,
    complete_llm_profile_packet,
    validate_llm_profile_request,
)


def request(marker="SESSION-A / ALPHA", journey_id="test5-worker-a"):
    return {
        "schema": "stegbrowser.llm-profile-request.v1",
        "profile": "llm.v1",
        "prompt": f"Before answering, state {marker}. What is 17 + 26?",
        "response_marker": marker,
        "provider": "openai",
        "journey": {
            "schema": "stegverse.packet-carried-endpoint-receipt-journey/v1",
            "journey_id": journey_id,
            "origin_endpoint": "STEGVERSE-ORG",
            "ephemeral_endpoint": "EPHEMERAL-STEGBROWSER",
            "outbound_manifest_sha256": "sha256:" + "a" * 64,
            "return_manifest_sha256": "sha256:" + "b" * 64,
            "return_predecessor_manifest_sha256": "sha256:" + "a" * 64,
        },
    }


class LLMProfileTest5Tests(unittest.TestCase):
    def test_profile_binds_distinguishable_response_and_four_receipts(self):
        outbound = begin_llm_profile_packet(request())
        returned = bind_llm_profile_result(
            packet=outbound,
            response_text="SESSION-A / ALPHA. 43",
            provider="openai",
            model="test-model",
        )
        returned["request"] = outbound["request"]
        completed = complete_llm_profile_packet(returned)
        self.assertEqual(completed["result"]["response_marker"], "SESSION-A / ALPHA")
        receipts = completed["endpoint_receipts"]
        self.assertEqual([(r["evidence"]["leg"], r["evidence"]["direction"]) for r in receipts],
                         [(1, "EGRESS"), (1, "INGRESS"), (2, "EGRESS"), (2, "INGRESS")])
        self.assertTrue(receipts[1]["evidence"]["manifest_read"])
        self.assertTrue(receipts[2]["evidence"]["next_leg_directed"])
        self.assertTrue(receipts[3]["evidence"]["returned_endpoint_receipts"])

    def test_two_workers_are_distinguished_by_manifest_only(self):
        a = validate_llm_profile_request(request("SESSION-A / ALPHA", "test5-worker-a"))
        b = validate_llm_profile_request(request("SESSION-B / BRAVO", "test5-worker-b"))
        self.assertNotEqual(a["request_commitment"], b["request_commitment"])
        self.assertNotEqual(a["response_marker"], b["response_marker"])
        self.assertNotEqual(a["journey"]["journey_id"], b["journey"]["journey_id"])

    def test_profile_rejects_cross_session_response(self):
        outbound = begin_llm_profile_packet(request())
        with self.assertRaisesRegex(ValueError, "response marker"):
            bind_llm_profile_result(
                packet=outbound,
                response_text="SESSION-B / BRAVO. Jupiter",
                provider="openai",
                model="test-model",
            )

    def test_return_manifest_must_predecessor_link_outbound(self):
        value = request()
        value["journey"]["return_predecessor_manifest_sha256"] = "sha256:" + "c" * 64
        with self.assertRaisesRegex(ValueError, "predecessor-link"):
            validate_llm_profile_request(value)


if __name__ == "__main__":
    unittest.main()
