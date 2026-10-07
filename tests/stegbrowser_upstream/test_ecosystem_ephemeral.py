import unittest
from datetime import datetime, timedelta, timezone

from src.stegbrowser.ecosystem_ephemeral import EphemeralBrowserSession, validate_ephemeral_lease


def lease(now: datetime) -> dict:
    return {
        "schema": "stegbrowser.ecosystem-ephemeral-lease.v1",
        "lease_id": "lease-001",
        "task_id": "STEG-BROWSER-ECOSYSTEM-EPHEMERAL-001",
        "requester": "StegSocials",
        "purpose": "verify a public publication surface",
        "issued_at": now.isoformat().replace("+00:00", "Z"),
        "expires_at": (now + timedelta(minutes=5)).isoformat().replace("+00:00", "Z"),
        "allowed_origins": ["facebook.com", "*.facebook.com", "stegverse.org"],
        "allowed_actions": ["navigate", "read_public"],
        "retain_artifacts": ["navigation_receipt", "content_commitment"],
        "max_navigations": 2,
        "persistent_profile": False,
        "persist_cookies": False,
        "persist_history": False,
    }


class EcosystemEphemeralTests(unittest.TestCase):
    def test_valid_lease_is_normalized_and_committed(self):
        now = datetime(2026, 9, 8, 23, 0, tzinfo=timezone.utc)
        normalized = validate_ephemeral_lease(lease(now), now=now)
        self.assertEqual(normalized["lease_id"], "lease-001")
        self.assertFalse(normalized["persistent_profile"])
        self.assertTrue(normalized["lease_commitment"].startswith("sha256:"))

    def test_expired_and_overlong_leases_fail_closed(self):
        now = datetime(2026, 9, 8, 23, 0, tzinfo=timezone.utc)
        expired = lease(now - timedelta(minutes=10))
        with self.assertRaisesRegex(ValueError, "expired"):
            validate_ephemeral_lease(expired, now=now)

        overlong = lease(now)
        overlong["expires_at"] = (now + timedelta(minutes=16)).isoformat().replace("+00:00", "Z")
        with self.assertRaisesRegex(ValueError, "maximum ephemeral TTL"):
            validate_ephemeral_lease(overlong, now=now)

    def test_persistent_state_and_embedded_credentials_are_rejected(self):
        now = datetime(2026, 9, 8, 23, 0, tzinfo=timezone.utc)
        bad = lease(now)
        bad["persist_cookies"] = True
        with self.assertRaisesRegex(ValueError, "cookie persistence"):
            validate_ephemeral_lease(bad, now=now)

        bad = lease(now)
        bad["credential_material"] = {"token": "secret"}
        with self.assertRaisesRegex(ValueError, "credential material"):
            validate_ephemeral_lease(bad, now=now)

    def test_origin_action_and_navigation_limits_are_enforced(self):
        now = datetime(2026, 9, 8, 23, 0, tzinfo=timezone.utc)
        session = EphemeralBrowserSession.open(lease(now), now=now)

        first = session.authorize(action="navigate", url="https://m.facebook.com/story.php?id=1", now=now)
        self.assertEqual(first["host"], "m.facebook.com")
        self.assertEqual(first["authority_effect"], "LEASE_SCOPE_ONLY")

        session.authorize(action="navigate", url="https://www.facebook.com/page", now=now)
        with self.assertRaisesRegex(PermissionError, "navigation limit"):
            session.authorize(action="navigate", url="https://facebook.com/third", now=now)

        with self.assertRaisesRegex(PermissionError, "outside the lease"):
            session.authorize(action="download", url="https://facebook.com/file", now=now)

        with self.assertRaisesRegex(PermissionError, "origin"):
            session.authorize(action="read_public", url="https://example.com", now=now)

    def test_only_allowlisted_artifact_commitments_survive_close(self):
        now = datetime(2026, 9, 8, 23, 0, tzinfo=timezone.utc)
        session = EphemeralBrowserSession.open(lease(now), now=now)
        record = session.retain(
            artifact_type="content_commitment",
            artifact={"surface": "facebook", "observed": True, "content": "not retained"},
        )
        self.assertEqual(set(record), {"artifact_type", "artifact_commitment"})

        with self.assertRaisesRegex(PermissionError, "not retained"):
            session.retain(artifact_type="page_body", artifact={"raw": "secret"})

        receipt = session.close(now=now + timedelta(seconds=5))
        self.assertTrue(receipt["session_state_destroyed"])
        self.assertFalse(receipt["cookies_retained"])
        self.assertFalse(receipt["history_retained"])
        self.assertFalse(receipt["credential_material_retained"])
        self.assertEqual(receipt["authority_effect"], "NONE")
        self.assertEqual(receipt["retained_artifacts"], [record])

        with self.assertRaisesRegex(RuntimeError, "closed"):
            session.authorize(action="read_public", url="https://facebook.com", now=now)

    def test_expiry_closes_session_and_terminal_receipt_records_expiration(self):
        now = datetime(2026, 9, 8, 23, 0, tzinfo=timezone.utc)
        current_lease = lease(now)
        current_lease["expires_at"] = (now + timedelta(seconds=10)).isoformat().replace("+00:00", "Z")
        session = EphemeralBrowserSession.open(current_lease, now=now)

        with self.assertRaisesRegex(RuntimeError, "expired"):
            session.authorize(
                action="read_public",
                url="https://facebook.com",
                now=now + timedelta(seconds=11),
            )

        receipt = session.close(now=now + timedelta(seconds=11))
        self.assertEqual(receipt["close_reason"], "expired")
        self.assertTrue(receipt["session_state_destroyed"])


if __name__ == "__main__":
    unittest.main()
