"""
Base classes and utilities for verification modules.

This module provides shared functionality to reduce code duplication across
verification checkers (APT security, time integrity, provenance, etc.).
"""

from typing import Dict, Any, List, Optional, TypeVar
import subprocess
from pathlib import Path


class BaseVerificationChecker:
    """
    Base class for verification checkers with fixture support.

    All verification modules share common patterns:
    - Fixture mode for testing without system access
    - Common initialization and error handling
    """

    def __init__(self, fixture_mode: bool = False, fixture_data: Optional[Dict] = None):
        """
        Initialize verification checker.

        Args:
            fixture_mode: If True, use fixture data instead of system checks
            fixture_data: Test fixture data for CI/testing
        """
        self.fixture_mode = fixture_mode
        self.fixture_data = fixture_data or {}


# Type variable for subprocess utilities
T = TypeVar('T')


class SubprocessUtils:
    """Utilities for subprocess execution with consistent error handling."""

    @staticmethod
    def run_command(
        command: List[str],
        timeout: int = 30,
        capture_output: bool = True
    ) -> Optional[subprocess.CompletedProcess]:
        """
        Run subprocess command with consistent error handling.

        Args:
            command: Command and arguments as list
            timeout: Timeout in seconds
            capture_output: Whether to capture stdout/stderr

        Returns:
            CompletedProcess if successful, None if error/timeout
        """
        try:
            result = subprocess.run(
                command,
                capture_output=capture_output,
                text=True,
                timeout=timeout
            )
            return result
        except subprocess.TimeoutExpired:
            return None
        except (subprocess.SubprocessError, FileNotFoundError):
            return None

    @staticmethod
    def command_exists(command: str) -> bool:
        """
        Check if a command exists in PATH.

        Args:
            command: Command name to check

        Returns:
            True if command exists, False otherwise
        """
        result = SubprocessUtils.run_command(
            ["which", command],
            timeout=5,
            capture_output=True
        )
        return result is not None and result.returncode == 0


class FileSystemUtils:
    """Utilities for filesystem operations used by verification modules."""

    @staticmethod
    def path_exists(path: Path) -> bool:
        """
        Safely check if path exists.

        Args:
            path: Path to check

        Returns:
            True if path exists and is accessible
        """
        try:
            return path.exists()
        except (OSError, PermissionError):
            return False

    @staticmethod
    def read_file_lines(
        path: Path,
        skip_comments: bool = True,
        skip_empty: bool = True
    ) -> List[str]:
        """
        Read file lines with optional filtering.

        Args:
            path: Path to file
            skip_comments: Skip lines starting with #
            skip_empty: Skip empty lines

        Returns:
            List of file lines (filtered if requested)
        """
        try:
            with open(path, 'r') as f:
                lines = f.readlines()

            processed_lines = []
            for line in lines:
                line = line.strip()

                if skip_empty and not line:
                    continue
                if skip_comments and line.startswith('#'):
                    continue

                processed_lines.append(line)

            return processed_lines
        except (OSError, PermissionError, UnicodeDecodeError):
            return []


class ConfidenceCalculator:
    """Utilities for calculating confidence levels across verification modules."""

    @staticmethod
    def calculate_confidence(
        has_high_security: bool,
        has_medium_security: bool,
        has_low_security: bool,
        has_critical_warnings: bool = False
    ) -> str:
        """
        Calculate confidence level based on security indicators.

        Args:
            has_high_security: High security features present
            has_medium_security: Medium security features present
            has_low_security: Low security features present
            has_critical_warnings: Critical security warnings present

        Returns:
            Confidence level: "high", "medium", or "low"
        """
        if has_critical_warnings or has_low_security:
            return "low"
        elif has_high_security and not has_low_security:
            return "high"
        elif has_medium_security or has_high_security:
            return "medium"
        else:
            return "low"

    @staticmethod
    def merge_confidence_levels(levels: List[str]) -> str:
        """
        Merge multiple confidence levels to overall confidence.

        Takes the minimum confidence level (most conservative approach).

        Args:
            levels: List of confidence levels ("high", "medium", "low")

        Returns:
            Overall confidence level
        """
        if not levels:
            return "low"

        # Priority order: low < medium < high
        if "low" in levels:
            return "low"
        elif "medium" in levels:
            return "medium"
        else:
            return "high"
