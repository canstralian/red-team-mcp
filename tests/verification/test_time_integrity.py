"""
Tests for TimeIntegrityChecker - time source validation and freshness checks.

These tests use fixtures to safely test time integrity logic without
requiring actual sdwdate or NTP configuration.
"""

import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from src.verification.time_integrity import (
    TimeIntegrityChecker,
    TimeSource,
    TimeIntegrityResult,
    host_has_sdwdate
)


class TestTimeIntegrityChecker(unittest.TestCase):
    """Test time integrity checking."""

    def test_sdwdate_high_confidence(self):
        """Test sdwdate with successful sync gives high confidence."""
        fixture_data = {
            "source": "sdwdate",
            "current_time": datetime.now(timezone.utc).isoformat(),
            "confidence": "high",
            "is_synchronized": True,
            "last_sync_time": datetime.now(timezone.utc).isoformat(),
            "warnings": [],
            "metadata": {"source_type": "sdwdate", "service_active": True}
        }

        checker = TimeIntegrityChecker(fixture_mode=True, fixture_data=fixture_data)
        result = checker.check_time_integrity()

        self.assertEqual(result.source, TimeSource.SDWDATE)
        self.assertEqual(result.confidence, "high")
        self.assertTrue(result.is_synchronized)
        self.assertEqual(len(result.warnings), 0)

    def test_ntp_verified_medium_confidence(self):
        """Test verified NTP gives medium confidence."""
        fixture_data = {
            "source": "ntp_verified",
            "current_time": datetime.now(timezone.utc).isoformat(),
            "confidence": "medium",
            "is_synchronized": True,
            "last_sync_time": datetime.now(timezone.utc).isoformat(),
            "warnings": ["Using NTP instead of sdwdate (less secure against time attacks)"],
            "metadata": {"source_type": "ntp"}
        }

        checker = TimeIntegrityChecker(fixture_mode=True, fixture_data=fixture_data)
        result = checker.check_time_integrity()

        self.assertEqual(result.source, TimeSource.NTP_VERIFIED)
        self.assertEqual(result.confidence, "medium")
        self.assertIn("Using NTP instead of sdwdate", result.warnings[0])

    def test_system_time_low_confidence(self):
        """Test fallback to system time gives low confidence."""
        fixture_data = {
            "source": "system_time",
            "current_time": datetime.now(timezone.utc).isoformat(),
            "confidence": "low",
            "is_synchronized": False,
            "last_sync_time": None,
            "warnings": [
                "No trusted time source detected (no sdwdate or synchronized NTP)",
                "System time may be vulnerable to manipulation"
            ],
            "metadata": {"source_type": "system_time"}
        }

        checker = TimeIntegrityChecker(fixture_mode=True, fixture_data=fixture_data)
        result = checker.check_time_integrity()

        self.assertEqual(result.source, TimeSource.SYSTEM_TIME)
        self.assertEqual(result.confidence, "low")
        self.assertFalse(result.is_synchronized)

    def test_freshness_validation_pass(self):
        """Test freshness validation with recent signature."""
        now = datetime.now(timezone.utc)
        signed_time = now - timedelta(hours=1)
        maximum_age = timedelta(days=7)

        fixture_data = {
            "source": "sdwdate",
            "current_time": now.isoformat(),
            "confidence": "high",
            "is_synchronized": True,
            "last_sync_time": now.isoformat(),
            "warnings": [],
            "metadata": {}
        }

        checker = TimeIntegrityChecker(fixture_mode=True, fixture_data=fixture_data)
        is_fresh, reason, time_result = checker.validate_freshness(
            signed_time,
            maximum_age,
            require_trusted_source=True
        )

        self.assertTrue(is_fresh)
        self.assertIn("passed", reason)

    def test_freshness_validation_future_timestamp(self):
        """Test detection of future timestamps (attack scenario)."""
        now = datetime.now(timezone.utc)
        signed_time = now + timedelta(hours=1)  # Future!
        maximum_age = timedelta(days=7)

        fixture_data = {
            "source": "sdwdate",
            "current_time": now.isoformat(),
            "confidence": "high",
            "is_synchronized": True,
            "last_sync_time": now.isoformat(),
            "warnings": [],
            "metadata": {}
        }

        checker = TimeIntegrityChecker(fixture_mode=True, fixture_data=fixture_data)
        is_fresh, reason, time_result = checker.validate_freshness(
            signed_time,
            maximum_age,
            require_trusted_source=True
        )

        self.assertFalse(is_fresh)
        self.assertIn("future", reason.lower())

    def test_freshness_validation_too_old(self):
        """Test detection of expired signatures."""
        now = datetime.now(timezone.utc)
        signed_time = now - timedelta(days=30)  # Too old
        maximum_age = timedelta(days=7)

        fixture_data = {
            "source": "sdwdate",
            "current_time": now.isoformat(),
            "confidence": "high",
            "is_synchronized": True,
            "last_sync_time": now.isoformat(),
            "warnings": [],
            "metadata": {}
        }

        checker = TimeIntegrityChecker(fixture_mode=True, fixture_data=fixture_data)
        is_fresh, reason, time_result = checker.validate_freshness(
            signed_time,
            maximum_age,
            require_trusted_source=True
        )

        self.assertFalse(is_fresh)
        self.assertIn("too old", reason.lower())

    def test_freshness_validation_low_confidence_time_source(self):
        """Test freshness validation fails with untrusted time source."""
        now = datetime.now(timezone.utc)
        signed_time = now - timedelta(hours=1)
        maximum_age = timedelta(days=7)

        fixture_data = {
            "source": "system_time",
            "current_time": now.isoformat(),
            "confidence": "low",
            "is_synchronized": False,
            "last_sync_time": None,
            "warnings": ["No trusted time source"],
            "metadata": {}
        }

        checker = TimeIntegrityChecker(fixture_mode=True, fixture_data=fixture_data)
        is_fresh, reason, time_result = checker.validate_freshness(
            signed_time,
            maximum_age,
            require_trusted_source=True
        )

        self.assertFalse(is_fresh)
        self.assertIn("confidence is low", reason)


if __name__ == '__main__':
    unittest.main()
