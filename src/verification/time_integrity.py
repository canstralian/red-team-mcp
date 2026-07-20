"""
Time Integrity Checker - Kicksecure-inspired time source validation.

This module implements trusted time source detection and freshness validation
following Kicksecure's approach to time integrity using sdwdate (Secure Distributed
Web Date) instead of unauthenticated NTP.

References:
- Kicksecure time integrity: https://www.kicksecure.com/wiki/Time_Attacks
- sdwdate: https://github.com/Kicksecure/sdwdate
"""

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import Optional, Dict, Any
import json

from .base import BaseVerificationChecker, SubprocessUtils, FileSystemUtils


class TimeSource(str, Enum):
    """Trusted time source types."""
    SDWDATE = "sdwdate"  # Kicksecure secure distributed web date
    NTP_VERIFIED = "ntp_verified"  # NTP with verified sync
    NTP_UNVERIFIED = "ntp_unverified"  # NTP without verification
    SYSTEM_TIME = "system_time"  # Fallback to system time
    UNKNOWN = "unknown"


@dataclass
class TimeIntegrityResult:
    """Result of time integrity check."""
    source: TimeSource
    current_time: datetime
    confidence: str  # "high", "medium", "low"
    is_synchronized: bool
    last_sync_time: Optional[datetime]
    warnings: list[str]
    metadata: Dict[str, Any]


class TimeIntegrityChecker(BaseVerificationChecker):
    """
    Check time source integrity following Kicksecure principles.

    This checker detects and validates trusted time sources to prevent
    timestamp manipulation attacks. It prioritizes sdwdate, falls back
    to verified NTP, and marks unverified sources as low confidence.
    """

    def check_time_integrity(self) -> TimeIntegrityResult:
        """
        Check the current time source and its integrity.

        Returns:
            TimeIntegrityResult with source type, confidence, and metadata
        """
        if self.fixture_mode:
            return self._check_fixture_time()

        # Priority 1: Check for sdwdate (Kicksecure's secure time)
        if self._has_sdwdate():
            return self._check_sdwdate()

        # Priority 2: Check for synchronized NTP
        ntp_result = self._check_ntp()
        if ntp_result:
            return ntp_result

        # Fallback: System time with low confidence
        return self._fallback_system_time()

    def _has_sdwdate(self) -> bool:
        """
        Detect if sdwdate is present on the system.

        Checks for:
        - /usr/sbin/sdwdate binary
        - /etc/sdwdate.d/ configuration directory
        - systemd service file

        Returns:
            True if sdwdate is detected
        """
        sdwdate_indicators = [
            Path("/usr/sbin/sdwdate"),
            Path("/etc/sdwdate.d"),
            Path("/lib/systemd/system/sdwdate.service"),
            Path("/usr/lib/systemd/system/sdwdate.service"),
        ]

        return any(path.exists() for path in sdwdate_indicators)

    def _check_sdwdate(self) -> TimeIntegrityResult:
        """
        Check sdwdate status and last sync time.

        Returns:
            TimeIntegrityResult with high confidence if sdwdate is active
        """
        warnings = []
        is_synchronized = False
        last_sync = None
        metadata = {"source_type": "sdwdate"}

        # Check if sdwdate service is running using utility
        result = SubprocessUtils.run_command(
            ["systemctl", "is-active", "sdwdate"],
            timeout=5
        )
        
        service_active = result is not None and result.returncode == 0
        metadata["service_active"] = service_active

        if not service_active:
            warnings.append("sdwdate service is not active")

        # Check sdwdate status file for last sync
        status_file = Path("/var/run/sdwdate/status")
        if FileSystemUtils.path_exists(status_file):
            status_content = FileSystemUtils.read_file_content(status_file)
            if status_content:
                status = status_content.strip()
                metadata["status"] = status
                is_synchronized = "success" in status.lower()
            else:
                warnings.append("Could not read sdwdate status")

        # Check last sync timestamp
        sync_file = Path("/var/run/sdwdate/last_sync")
        if FileSystemUtils.path_exists(sync_file):
            try:
                last_sync = datetime.fromtimestamp(
                    sync_file.stat().st_mtime,
                    tz=timezone.utc
                )
                metadata["last_sync"] = last_sync.isoformat()

                # Warn if last sync was too long ago (>24 hours)
                time_since_sync = datetime.now(timezone.utc) - last_sync
                if time_since_sync > timedelta(hours=24):
                    warnings.append(f"sdwdate last sync was {time_since_sync.total_seconds() / 3600:.1f} hours ago")

            except Exception as e:
                warnings.append(f"Could not read sdwdate last sync time: {e}")

        # Determine confidence
        if is_synchronized and not warnings:
            confidence = "high"
        elif is_synchronized:
            confidence = "medium"
        else:
            confidence = "low"

        return TimeIntegrityResult(
            source=TimeSource.SDWDATE,
            current_time=datetime.now(timezone.utc),
            confidence=confidence,
            is_synchronized=is_synchronized,
            last_sync_time=last_sync,
            warnings=warnings,
            metadata=metadata
        )

    def _check_ntp(self) -> Optional[TimeIntegrityResult]:
        """
        Check NTP synchronization status.

        Uses timedatectl or ntpq to verify NTP sync.

        Returns:
            TimeIntegrityResult if NTP is detected, None otherwise
        """
        warnings = []
        metadata = {"source_type": "ntp"}

        # Try timedatectl first (systemd-timesyncd)
        result = SubprocessUtils.run_command(
            ["timedatectl", "status"],
            timeout=5
        )

        if result and result.returncode == 0:
            output = result.stdout.lower()
            metadata["timedatectl_output"] = result.stdout

            # Check for NTP sync
            ntp_synchronized = "ntp synchronized: yes" in output or \
                               "system clock synchronized: yes" in output

            if ntp_synchronized:
                # NTP is synced, but not as trusted as sdwdate
                return TimeIntegrityResult(
                    source=TimeSource.NTP_VERIFIED,
                    current_time=datetime.now(timezone.utc),
                    confidence="medium",
                    is_synchronized=True,
                    last_sync_time=datetime.now(timezone.utc),
                    warnings=["Using NTP instead of sdwdate (less secure against time attacks)"],
                    metadata=metadata
                )
            else:
                warnings.append("NTP is not synchronized")

        # Try ntpq as fallback
        result = SubprocessUtils.run_command(
            ["ntpq", "-p"],
            timeout=5
        )

        if result and result.returncode == 0:
            metadata["ntpq_output"] = result.stdout
            # Check for synchronized peers (lines starting with *)
            if "*" in result.stdout:
                return TimeIntegrityResult(
                    source=TimeSource.NTP_VERIFIED,
                    current_time=datetime.now(timezone.utc),
                    confidence="medium",
                    is_synchronized=True,
                    last_sync_time=datetime.now(timezone.utc),
                    warnings=["Using NTP instead of sdwdate (less secure against time attacks)"],
                    metadata=metadata
                )

        return None

    def _fallback_system_time(self) -> TimeIntegrityResult:
        """
        Fallback to system time with low confidence.

        Returns:
            TimeIntegrityResult with low confidence warning
        """
        return TimeIntegrityResult(
            source=TimeSource.SYSTEM_TIME,
            current_time=datetime.now(timezone.utc),
            confidence="low",
            is_synchronized=False,
            last_sync_time=None,
            warnings=[
                "No trusted time source detected (no sdwdate or synchronized NTP)",
                "System time may be vulnerable to manipulation",
                "Freshness checks will be marked as low confidence"
            ],
            metadata={"source_type": "system_time"}
        )

    def _check_fixture_time(self) -> TimeIntegrityResult:
        """
        Return fixture time data for testing.

        Returns:
            TimeIntegrityResult from fixture data
        """
        fixture = self.fixture_data

        return TimeIntegrityResult(
            source=TimeSource(fixture.get("source", "system_time")),
            current_time=datetime.fromisoformat(
                fixture.get("current_time", datetime.now(timezone.utc).isoformat())
            ),
            confidence=fixture.get("confidence", "low"),
            is_synchronized=fixture.get("is_synchronized", False),
            last_sync_time=datetime.fromisoformat(fixture["last_sync_time"])
                if fixture.get("last_sync_time") else None,
            warnings=fixture.get("warnings", []),
            metadata=fixture.get("metadata", {})
        )

    def validate_freshness(
        self,
        signed_time: datetime,
        maximum_age: timedelta,
        require_trusted_source: bool = True
    ) -> tuple[bool, str, TimeIntegrityResult]:
        """
        Validate artifact freshness against trusted time source.

        Args:
            signed_time: Timestamp from artifact signature
            maximum_age: Maximum allowed age for artifact
            require_trusted_source: If True, require high-confidence time source

        Returns:
            Tuple of (is_fresh, reason, time_result)
        """
        time_result = self.check_time_integrity()
        now = time_result.current_time

        # Check if time source is trusted enough
        if require_trusted_source and time_result.confidence == "low":
            return (
                False,
                f"Cannot validate freshness: time source confidence is {time_result.confidence}",
                time_result
            )

        # Check for future timestamps (possible attack)
        if signed_time > now + timedelta(minutes=5):  # Allow 5min clock skew
            return (
                False,
                f"Signature timestamp is in the future (signed: {signed_time}, now: {now})",
                time_result
            )

        # Check age
        age = now - signed_time
        if age > maximum_age:
            return (
                False,
                f"Artifact is too old (age: {age}, maximum: {maximum_age})",
                time_result
            )

        return (True, "Freshness validation passed", time_result)


# Convenience function for quick checks
def host_has_sdwdate() -> bool:
    """
    Quick check if host has sdwdate (non-exec check for CI/fixture friendly).

    Returns:
        True if sdwdate is detected on the system
    """
    checker = TimeIntegrityChecker()
    return checker._has_sdwdate()
