"""
APT Security Checker - Update channel validation.

This module validates APT sources configuration following Kicksecure's approach
to torified APT updates and secure update channels.

References:
- Kicksecure APT security: https://www.kicksecure.com/wiki/Operating_System_Software_and_Updates
"""

from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import List, Dict, Any, Optional
import re

from .base import BaseVerificationChecker, FileSystemUtils


class AptTransportSecurity(str, Enum):
    """APT transport security levels."""
    TORIFIED = "torified"  # apt-transport-tor or tor-routed
    HTTPS = "https"  # Plain HTTPS
    HTTP = "http"  # Insecure HTTP
    UNKNOWN = "unknown"


@dataclass
class AptSourceInfo:
    """Information about an APT source."""
    source_line: str
    transport: AptTransportSecurity
    uri: str
    distribution: str
    components: List[str]
    is_torified: bool
    is_pinned: bool
    line_number: int
    warnings: List[str]


@dataclass
class AptSecurityResult:
    """Result of APT security check."""
    sources: List[AptSourceInfo]
    has_torified_sources: bool
    has_insecure_sources: bool
    confidence: str  # "high", "medium", "low"
    warnings: List[str]
    recommendations: List[str]
    metadata: Dict[str, Any]


class AptSecurityChecker(BaseVerificationChecker):
    """
    Check APT sources for security configuration.

    Validates:
    - Torified APT (apt-transport-tor)
    - Source pinning
    - HTTPS vs HTTP transport
    - Suspicious or untrusted sources
    """

    def check_apt_security(
        self,
        sources_path: Path = Path("/etc/apt/sources.list"),
        sources_d_path: Path = Path("/etc/apt/sources.list.d")
    ) -> AptSecurityResult:
        """
        Check APT sources for security configuration.

        Args:
            sources_path: Path to main sources.list
            sources_d_path: Path to sources.list.d directory

        Returns:
            AptSecurityResult with source analysis
        """
        if self.fixture_mode:
            return self._check_fixture_apt()

        warnings = []
        recommendations = []
        metadata = {}
        sources = []

        # Parse main sources.list
        if sources_path.exists():
            sources.extend(self._parse_sources_file(sources_path))

        # Parse sources.list.d/*.list files
        if sources_d_path.exists() and sources_d_path.is_dir():
            for list_file in sources_d_path.glob("*.list"):
                sources.extend(self._parse_sources_file(list_file))

        if not sources:
            warnings.append("No APT sources found")
            return AptSecurityResult(
                sources=[],
                has_torified_sources=False,
                has_insecure_sources=False,
                confidence="low",
                warnings=warnings,
                recommendations=["Configure APT sources in /etc/apt/sources.list"],
                metadata=metadata
            )

        # Analyze sources
        has_torified = any(s.is_torified for s in sources)
        has_insecure = any(
            s.transport in [AptTransportSecurity.HTTP, AptTransportSecurity.UNKNOWN]
            for s in sources
        )

        # Collect warnings
        for source in sources:
            warnings.extend(source.warnings)

        # Determine confidence
        if has_torified and not has_insecure:
            confidence = "high"
        elif not has_insecure:
            confidence = "medium"
            recommendations.append(
                "Consider using torified APT (apt-transport-tor) for enhanced security"
            )
        else:
            confidence = "low"
            recommendations.append("Migrate HTTP sources to HTTPS or torified transport")

        metadata["total_sources"] = len(sources)
        metadata["torified_count"] = sum(1 for s in sources if s.is_torified)
        metadata["insecure_count"] = sum(
            1 for s in sources
            if s.transport in [AptTransportSecurity.HTTP, AptTransportSecurity.UNKNOWN]
        )

        return AptSecurityResult(
            sources=sources,
            has_torified_sources=has_torified,
            has_insecure_sources=has_insecure,
            confidence=confidence,
            warnings=warnings,
            recommendations=recommendations,
            metadata=metadata
        )

    def check_script_apt_usage(self, script_content: str) -> Dict[str, Any]:
        """
        Check if script uses APT and whether it's configured securely.

        Args:
            script_content: Shell script or code content

        Returns:
            Dictionary with APT usage analysis
        """
        result = {
            "uses_apt": False,
            "apt_commands": [],
            "uses_tor": False,
            "uses_pinning": False,
            "warnings": [],
            "recommendations": []
        }

        # Detect APT usage
        apt_patterns = [
            r'\bapt\s+(?:install|update|upgrade)',
            r'\bapt-get\s+(?:install|update|upgrade)',
            r'\baptitude\s+(?:install|update|upgrade)',
        ]

        for pattern in apt_patterns:
            matches = re.finditer(pattern, script_content, re.IGNORECASE | re.MULTILINE)
            for match in matches:
                result["uses_apt"] = True
                result["apt_commands"].append(match.group(0))

        if not result["uses_apt"]:
            return result

        # Check for torified APT
        tor_patterns = [
            r'apt-transport-tor',
            r'tor\+https?://',
            r'torsocks\s+apt',
        ]

        for pattern in tor_patterns:
            if re.search(pattern, script_content, re.IGNORECASE):
                result["uses_tor"] = True
                break

        # Check for apt pinning
        if re.search(r'/etc/apt/preferences', script_content):
            result["uses_pinning"] = True

        # Generate warnings
        if result["uses_apt"] and not result["uses_tor"]:
            result["warnings"].append(
                "Script uses APT without torified transport (vulnerable to targeted update attacks)"
            )
            result["recommendations"].append(
                "Use apt-transport-tor or torsocks for APT operations"
            )

        if result["uses_apt"] and not result["uses_pinning"]:
            result["recommendations"].append(
                "Consider using APT pinning to lock package versions"
            )

        return result

    def _parse_sources_file(self, file_path: Path) -> List[AptSourceInfo]:
        """
        Parse APT sources list file.

        Args:
            file_path: Path to sources.list file

        Returns:
            List of AptSourceInfo objects
        """
        sources = []

        # Use utility for safe file reading
        lines = FileSystemUtils.read_file_lines(
            file_path,
            skip_comments=True,
            skip_empty=True
        )

        for line_num, line in enumerate(lines, 1):
            # Parse source line
            source_info = self._parse_source_line(line, line_num)
            if source_info:
                sources.append(source_info)

        return sources

    def _parse_source_line(self, line: str, line_number: int) -> Optional[AptSourceInfo]:
        """
        Parse a single APT source line.

        Format: deb|deb-src [options] uri distribution [components...]

        Args:
            line: Source line
            line_number: Line number in file

        Returns:
            AptSourceInfo or None if invalid
        """
        warnings = []

        # Match source line format
        match = re.match(
            r'^(deb(?:-src)?)\s+(?:\[([^\]]+)\]\s+)?(\S+)\s+(\S+)\s*(.*)',
            line
        )

        if not match:
            return None

        source_type, options, uri, distribution, components_str = match.groups()
        components = components_str.split() if components_str else []

        # Determine transport security
        transport = self._determine_transport(uri)
        is_torified = self._is_torified(uri, options)

        # Check for security issues
        if transport == AptTransportSecurity.HTTP:
            warnings.append(f"Insecure HTTP transport: {uri}")
        elif transport == AptTransportSecurity.UNKNOWN:
            warnings.append(f"Unknown transport: {uri}")

        # Check pinning (simplified - would need to check /etc/apt/preferences)
        is_pinned = False  # TODO: Check preferences files

        return AptSourceInfo(
            source_line=line,
            transport=transport,
            uri=uri,
            distribution=distribution,
            components=components,
            is_torified=is_torified,
            is_pinned=is_pinned,
            line_number=line_number,
            warnings=warnings
        )

    def _determine_transport(self, uri: str) -> AptTransportSecurity:
        """
        Determine transport security level from URI.

        Args:
            uri: APT source URI

        Returns:
            AptTransportSecurity level
        """
        uri_lower = uri.lower()

        if uri_lower.startswith("tor+https://") or uri_lower.startswith("tor+http://"):
            return AptTransportSecurity.TORIFIED
        elif uri_lower.startswith("https://"):
            return AptTransportSecurity.HTTPS
        elif uri_lower.startswith("http://"):
            return AptTransportSecurity.HTTP
        else:
            return AptTransportSecurity.UNKNOWN

    def _is_torified(self, uri: str, options: Optional[str]) -> bool:
        """
        Check if source uses torified transport.

        Args:
            uri: APT source URI
            options: APT source options string

        Returns:
            True if torified
        """
        # Check URI scheme
        if uri.lower().startswith("tor+"):
            return True

        # Check options for tor settings
        if options:
            if "tor" in options.lower():
                return True

        return False

    def _check_fixture_apt(self) -> AptSecurityResult:
        """
        Return fixture APT data for testing.

        Returns:
            AptSecurityResult from fixture data
        """
        fixture = self.fixture_data

        sources = []
        for source_data in fixture.get("sources", []):
            sources.append(AptSourceInfo(
                source_line=source_data.get("source_line", ""),
                transport=AptTransportSecurity(source_data.get("transport", "unknown")),
                uri=source_data.get("uri", ""),
                distribution=source_data.get("distribution", ""),
                components=source_data.get("components", []),
                is_torified=source_data.get("is_torified", False),
                is_pinned=source_data.get("is_pinned", False),
                line_number=source_data.get("line_number", 1),
                warnings=source_data.get("warnings", [])
            ))

        return AptSecurityResult(
            sources=sources,
            has_torified_sources=fixture.get("has_torified_sources", False),
            has_insecure_sources=fixture.get("has_insecure_sources", False),
            confidence=fixture.get("confidence", "low"),
            warnings=fixture.get("warnings", []),
            recommendations=fixture.get("recommendations", []),
            metadata=fixture.get("metadata", {})
        )
