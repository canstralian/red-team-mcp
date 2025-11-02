"""
Tests for AptSecurityChecker - APT source security validation.

These tests use fixtures to safely test APT security logic without
requiring actual system APT configuration.
"""

import unittest
from src.verification.apt_security import (
    AptSecurityChecker,
    AptTransportSecurity,
    AptSourceInfo
)


class TestAptSecurityChecker(unittest.TestCase):
    """Test APT security checking."""

    def test_torified_apt_high_confidence(self):
        """Test torified APT gives high confidence."""
        fixture_data = {
            "sources": [
                {
                    "source_line": "deb tor+https://deb.debian.org/debian bullseye main",
                    "transport": "torified",
                    "uri": "tor+https://deb.debian.org/debian",
                    "distribution": "bullseye",
                    "components": ["main"],
                    "is_torified": True,
                    "is_pinned": False,
                    "line_number": 1,
                    "warnings": []
                }
            ],
            "has_torified_sources": True,
            "has_insecure_sources": False,
            "confidence": "high",
            "warnings": [],
            "recommendations": [],
            "metadata": {"total_sources": 1, "torified_count": 1}
        }

        checker = AptSecurityChecker(fixture_mode=True, fixture_data=fixture_data)
        result = checker.check_apt_security()

        self.assertTrue(result.has_torified_sources)
        self.assertFalse(result.has_insecure_sources)
        self.assertEqual(result.confidence, "high")

    def test_https_apt_medium_confidence(self):
        """Test HTTPS APT gives medium confidence."""
        fixture_data = {
            "sources": [
                {
                    "source_line": "deb https://deb.debian.org/debian bullseye main",
                    "transport": "https",
                    "uri": "https://deb.debian.org/debian",
                    "distribution": "bullseye",
                    "components": ["main"],
                    "is_torified": False,
                    "is_pinned": False,
                    "line_number": 1,
                    "warnings": []
                }
            ],
            "has_torified_sources": False,
            "has_insecure_sources": False,
            "confidence": "medium",
            "warnings": [],
            "recommendations": ["Consider using torified APT (apt-transport-tor) for enhanced security"],
            "metadata": {"total_sources": 1, "torified_count": 0}
        }

        checker = AptSecurityChecker(fixture_mode=True, fixture_data=fixture_data)
        result = checker.check_apt_security()

        self.assertFalse(result.has_torified_sources)
        self.assertFalse(result.has_insecure_sources)
        self.assertEqual(result.confidence, "medium")

    def test_http_apt_low_confidence(self):
        """Test HTTP APT gives low confidence (security risk)."""
        fixture_data = {
            "sources": [
                {
                    "source_line": "deb http://archive.ubuntu.com/ubuntu focal main",
                    "transport": "http",
                    "uri": "http://archive.ubuntu.com/ubuntu",
                    "distribution": "focal",
                    "components": ["main"],
                    "is_torified": False,
                    "is_pinned": False,
                    "line_number": 1,
                    "warnings": ["Insecure HTTP transport: http://archive.ubuntu.com/ubuntu"]
                }
            ],
            "has_torified_sources": False,
            "has_insecure_sources": True,
            "confidence": "low",
            "warnings": ["Insecure HTTP transport: http://archive.ubuntu.com/ubuntu"],
            "recommendations": ["Migrate HTTP sources to HTTPS or torified transport"],
            "metadata": {"total_sources": 1, "insecure_count": 1}
        }

        checker = AptSecurityChecker(fixture_mode=True, fixture_data=fixture_data)
        result = checker.check_apt_security()

        self.assertTrue(result.has_insecure_sources)
        self.assertEqual(result.confidence, "low")
        self.assertIn("HTTP", result.warnings[0])

    def test_script_apt_usage_not_torified(self):
        """Test detection of non-torified APT in scripts."""
        script_content = """
        #!/bin/bash
        apt-get update
        apt-get install -y nginx
        systemctl start nginx
        """

        checker = AptSecurityChecker()
        result = checker.check_script_apt_usage(script_content)

        self.assertTrue(result["uses_apt"])
        self.assertFalse(result["uses_tor"])
        self.assertGreaterEqual(len(result["apt_commands"]), 2)
        self.assertIn("apt-get", result["apt_commands"][0])
        self.assertGreater(len(result["warnings"]), 0)
        self.assertIn("torified transport", result["warnings"][0])

    def test_script_apt_usage_torified(self):
        """Test detection of torified APT in scripts."""
        script_content = """
        #!/bin/bash
        # Using apt-transport-tor
        torsocks apt-get update
        torsocks apt-get install -y nginx
        """

        checker = AptSecurityChecker()
        result = checker.check_script_apt_usage(script_content)

        self.assertTrue(result["uses_apt"])
        self.assertTrue(result["uses_tor"])
        self.assertEqual(len(result["warnings"]), 0)

    def test_script_no_apt_usage(self):
        """Test script without APT usage."""
        script_content = """
        #!/bin/bash
        echo "Hello world"
        ls -la
        """

        checker = AptSecurityChecker()
        result = checker.check_script_apt_usage(script_content)

        self.assertFalse(result["uses_apt"])
        self.assertEqual(len(result["apt_commands"]), 0)


if __name__ == '__main__':
    unittest.main()
