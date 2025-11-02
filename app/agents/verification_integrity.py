#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
VerificationIntegrityAgent - Static analyzer for GPG verification scripts.

Performs read-only pattern detection to identify security controls and risks
in shell scripts that handle GPG signature verification.

Security Model:
- Read-only analysis (no script execution)
- Immutable findings via dataclasses
- Non-actionable risk cataloging
- Pattern-based control detection
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


# Maximum file size to analyze (10MB)
MAX_FILE_SIZE_BYTES = 10 * 1024 * 1024

# Restrict file analysis to within this directory (adjust as appropriate)
AUDITABLE_ROOT = Path("/srv/auditable_scripts").resolve()

@dataclass(frozen=True)
class ControlEvidence:
    """Evidence of a security control implementation."""

    control_name: str
    implemented: bool
    line_number: Optional[int] = None
    snippet: str = ""
    confidence: float = 0.0

    def __post_init__(self):
        """Validate confidence score."""
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError(f"confidence must be 0.0-1.0, got {self.confidence}")


@dataclass(frozen=True)
class Finding:
    """Immutable finding from verification script analysis."""

    file_path: str
    controls: tuple[ControlEvidence, ...] = field(default_factory=tuple)
    summary: str = ""
    risk_flags: tuple[str, ...] = field(default_factory=tuple)

    def __post_init__(self):
        """Convert mutable inputs to immutable types."""
        if isinstance(self.controls, list):
            object.__setattr__(self, "controls", tuple(self.controls))
        if isinstance(self.risk_flags, list):
            object.__setattr__(self, "risk_flags", tuple(self.risk_flags))


class VerificationIntegrityAgent:
    """
    Static analyzer for GPG signature verification scripts.

    Detects implementation of security controls:
    - status_fd: Use of --status-fd for machine-readable output
    - rollback: Freshness checks (maximum_age_in_seconds)
    - freeze: Timeout protection (verify_timeout_after, kill_after)
    - endless_data: Protection against endless data DoS
    - tampering: Filename verification via notations
    """

    def __init__(self):
        """Initialize pattern detection rules."""
        self.patterns = {
            "status_fd": re.compile(r"--status-fd\s+\d+", re.MULTILINE),
            "rollback_check": re.compile(
                r"gpg_bash_lib_(?:output_signed_on_unixtime|input_maximum_age_in_seconds)",
                re.MULTILINE
            ),
            "timeout_verify": re.compile(
                r"gpg_bash_lib_input_verify_timeout_after=\d+",
                re.MULTILINE
            ),
            "timeout_kill": re.compile(
                r"gpg_bash_lib_input_kill_after=\d+",
                re.MULTILINE
            ),
            "notation_filename": re.compile(
                r'notation\[["\'](file@name|filename)["\']]\s*=',
                re.MULTILINE
            ),
            "gpg_verify": re.compile(r"\bgpg\b.*--verify", re.MULTILINE),
        }

    def analyze_file(self, file_path: Path) -> Optional[Finding]:
        """
        Analyze a file for GPG verification security controls.

        Args:
            file_path: Path to script file

        Returns:
            Finding object or None if file unreadable/too large or out-of-bounds
        """
        try:
            # Restrict file access to under AUDITABLE_ROOT (mitigate path traversal)
            file_path_resolved = file_path.resolve()
            try:
                file_path_resolved.relative_to(AUDITABLE_ROOT)
            except ValueError:
                # Path escapes root, not allowed
                return None

            if not file_path_resolved.exists() or not file_path_resolved.is_file():
                return None

            if file_path_resolved.stat().st_size > MAX_FILE_SIZE_BYTES:
                return None

            content = file_path_resolved.read_text(encoding="utf-8", errors="ignore")
            return self.analyze_text(content, file_path=str(file_path_resolved))

        except (OSError, UnicodeDecodeError):
            return None

    def analyze_text(self, script_text: str, file_path: str = "<inline>") -> Finding:
        """
        Analyze script text for GPG verification security controls.

        Args:
            script_text: Shell script content
            file_path: Source identifier for reporting

        Returns:
            Finding with control evidence and risk flags
        """
        lines = script_text.split("\n")
        controls = []
        risk_flags = []

        # Check for GPG verification usage
        has_gpg_verify = bool(self.patterns["gpg_verify"].search(script_text))

        if not has_gpg_verify:
            # Not a GPG verification script - minimal analysis
            return Finding(
                file_path=file_path,
                controls=tuple(controls),
                summary="No GPG verification detected",
                risk_flags=tuple(risk_flags)
            )

        # Control 1: status-fd for machine-readable output
        status_fd_match = self.patterns["status_fd"].search(script_text)
        controls.append(ControlEvidence(
            control_name="status_fd",
            implemented=bool(status_fd_match),
            line_number=self._find_line_number(lines, status_fd_match) if status_fd_match else None,
            snippet=status_fd_match.group(0) if status_fd_match else "",
            confidence=1.0 if status_fd_match else 0.0
        ))

        # Control 2: Rollback protection (freshness checks)
        rollback_match = self.patterns["rollback_check"].search(script_text)
        controls.append(ControlEvidence(
            control_name="rollback",
            implemented=bool(rollback_match),
            line_number=self._find_line_number(lines, rollback_match) if rollback_match else None,
            snippet=rollback_match.group(0) if rollback_match else "",
            confidence=1.0 if rollback_match else 0.0
        ))

        if not rollback_match:
            risk_flags.append("possible_rollback_missing_freshness_check")

        # Control 3: Freeze protection (verify timeout)
        timeout_verify_match = self.patterns["timeout_verify"].search(script_text)
        controls.append(ControlEvidence(
            control_name="freeze",
            implemented=bool(timeout_verify_match),
            line_number=self._find_line_number(lines, timeout_verify_match) if timeout_verify_match else None,
            snippet=timeout_verify_match.group(0) if timeout_verify_match else "",
            confidence=1.0 if timeout_verify_match else 0.0
        ))

        # Control 4: Endless data DoS protection (kill timeout)
        timeout_kill_match = self.patterns["timeout_kill"].search(script_text)
        controls.append(ControlEvidence(
            control_name="endless_data",
            implemented=bool(timeout_kill_match),
            line_number=self._find_line_number(lines, timeout_kill_match) if timeout_kill_match else None,
            snippet=timeout_kill_match.group(0) if timeout_kill_match else "",
            confidence=1.0 if timeout_kill_match else 0.0
        ))

        if not (timeout_verify_match and timeout_kill_match):
            risk_flags.append("possible_endless_data_dos_no_timeouts")

        # Control 5: Filename tampering protection (notation checks)
        notation_match = self.patterns["notation_filename"].search(script_text)
        controls.append(ControlEvidence(
            control_name="tampering",
            implemented=bool(notation_match),
            line_number=self._find_line_number(lines, notation_match) if notation_match else None,
            snippet=notation_match.group(0) if notation_match else "",
            confidence=1.0 if notation_match else 0.0
        ))

        if not notation_match:
            risk_flags.append("possible_filename_tampering_risk")

        # Generate summary
        implemented_count = sum(1 for c in controls if c.implemented)
        summary = (
            f"GPG verification script analysis: "
            f"{implemented_count}/{len(controls)} security controls detected"
        )

        return Finding(
            file_path=file_path,
            controls=tuple(controls),
            summary=summary,
            risk_flags=tuple(risk_flags)
        )

    def _find_line_number(self, lines: list[str], match: re.Match) -> int:
        """Find line number of a regex match in source lines."""
        if not match:
            return 0

        # Count newlines before match position
        matched_text = match.string[:match.start()]
        return matched_text.count("\n") + 1
