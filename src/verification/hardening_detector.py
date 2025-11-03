"""
Hardening Detector - Environment security posture detection.

This module detects system hardening configurations following Kicksecure's
defense-in-depth approach with AppArmor, kernel hardening, and strict defaults.

References:
- Kicksecure hardening: https://www.kicksecure.com/wiki/System_Hardening_Checklist
"""

from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import List, Dict, Any, Optional
import re

from .base import BaseVerificationChecker, SubprocessUtils, FileSystemUtils


class HardeningLevel(str, Enum):
    """System hardening levels."""
    HARDENED = "hardened"  # Kicksecure-like hardening
    MODERATE = "moderate"  # Some hardening present
    MINIMAL = "minimal"  # Default/permissive configuration
    UNKNOWN = "unknown"


@dataclass
class HardeningFeature:
    """Information about a hardening feature."""
    name: str
    category: str  # "apparmor", "kernel", "services", "filesystem"
    is_enabled: bool
    confidence: str
    details: str
    warnings: List[str]


@dataclass
class HardeningResult:
    """Result of hardening detection."""
    level: HardeningLevel
    features: List[HardeningFeature]
    confidence: str  # "high", "medium", "low"
    warnings: List[str]
    recommendations: List[str]
    metadata: Dict[str, Any]


class HardeningDetector(BaseVerificationChecker):
    """
    Detect system hardening posture.

    Checks for:
    - AppArmor profiles and enforcement
    - Kernel hardening (sysctl settings)
    - Disabled unnecessary services
    - Filesystem mount options (noexec, nosuid)
    - SSH hardening
    """

    def check_hardening(self) -> HardeningResult:
        """
        Check system hardening posture.

        Returns:
            HardeningResult with detected hardening features
        """
        if self.fixture_mode:
            return self._check_fixture_hardening()

        warnings = []
        recommendations = []
        features = []

        # Check AppArmor
        apparmor_feature = self._check_apparmor()
        features.append(apparmor_feature)

        # Check kernel hardening
        features.extend(self._check_kernel_hardening())

        # Check services
        features.extend(self._check_services())

        # Check filesystem mounts
        features.extend(self._check_filesystem())

        # Check SSH hardening
        features.extend(self._check_ssh_hardening())

        # Collect warnings
        for feature in features:
            warnings.extend(feature.warnings)

        # Determine hardening level
        enabled_count = sum(1 for f in features if f.is_enabled)
        total_count = len(features)

        if enabled_count >= total_count * 0.8:
            level = HardeningLevel.HARDENED
            confidence = "high"
        elif enabled_count >= total_count * 0.5:
            level = HardeningLevel.MODERATE
            confidence = "medium"
            recommendations.append("Consider enabling additional hardening features")
        else:
            level = HardeningLevel.MINIMAL
            confidence = "low"
            recommendations.append("System uses permissive/default configuration")
            recommendations.append("Review Kicksecure hardening checklist")

        metadata = {
            "enabled_features": enabled_count,
            "total_features": total_count,
            "hardening_percentage": (enabled_count / total_count * 100) if total_count > 0 else 0
        }

        return HardeningResult(
            level=level,
            features=features,
            confidence=confidence,
            warnings=warnings,
            recommendations=recommendations,
            metadata=metadata
        )

    def check_script_assumptions(self, script_content: str) -> Dict[str, Any]:
        """
        Check if script makes assumptions incompatible with hardened hosts.

        Args:
            script_content: Shell script or code content

        Returns:
            Dictionary with assumption analysis
        """
        result = {
            "assumes_permissive": False,
            "assumptions": [],
            "warnings": [],
            "recommendations": []
        }

        # Detect assumptions about default ports
        if re.search(r'(?:ssh|sshd).*?22\b', script_content, re.IGNORECASE):
            result["assumes_permissive"] = True
            result["assumptions"].append("Assumes SSH on default port 22")
            result["warnings"].append("Hardened hosts may use non-standard SSH ports")

        # Detect assumptions about service installations
        service_patterns = [
            r'systemctl\s+(?:start|enable)\s+(\w+)',
            r'service\s+(\w+)\s+start',
        ]

        for pattern in service_patterns:
            matches = re.finditer(pattern, script_content)
            for match in matches:
                result["assumes_permissive"] = True
                result["assumptions"].append(f"Assumes ability to start service: {match.group(1)}")

        # Detect assumptions about filesystem permissions
        if re.search(r'chmod\s+777', script_content):
            result["assumes_permissive"] = True
            result["assumptions"].append("Sets world-writable permissions (777)")
            result["warnings"].append("Insecure permissions incompatible with hardened systems")

        # Detect assumptions about disabled features
        if re.search(r'setenforce\s+0', script_content, re.IGNORECASE):
            result["assumes_permissive"] = True
            result["assumptions"].append("Attempts to disable SELinux")
            result["warnings"].append("Disabling MAC is policy violation on hardened hosts")

        if re.search(r'aa-disable|apparmor.*disable', script_content, re.IGNORECASE):
            result["assumes_permissive"] = True
            result["assumptions"].append("Attempts to disable AppArmor")
            result["warnings"].append("Disabling AppArmor violates hardening policy")

        # Generate recommendations
        if result["assumes_permissive"]:
            result["recommendations"].append(
                "Test on Kicksecure-like host before deployment"
            )
            result["recommendations"].append(
                "Add environment checks before assuming permissive defaults"
            )

        return result

    def _check_apparmor(self) -> HardeningFeature:
        """Check AppArmor status."""
        warnings = []
        is_enabled = False
        details = "AppArmor not detected"

        # Check if AppArmor is enabled using utility
        result = SubprocessUtils.run_command(
            ["aa-status", "--enabled"],
            timeout=5
        )

        if result and result.returncode == 0:
            is_enabled = True

            # Get profile counts
            status_result = SubprocessUtils.run_command(
                ["aa-status", "--json"],
                timeout=5
            )

            if status_result and status_result.returncode == 0:
                try:
                    import json
                    status_data = json.loads(status_result.stdout)
                    enforce_count = len(status_data.get("profiles", {}).get("enforce", []))
                    complain_count = len(status_data.get("profiles", {}).get("complain", []))
                    details = f"AppArmor active: {enforce_count} enforcing, {complain_count} complain"

                    if complain_count > 0:
                        warnings.append(f"{complain_count} AppArmor profiles in complain mode")
                except (json.JSONDecodeError, ImportError):
                    details = "AppArmor enabled, but status details could not be parsed"
        else:
            warnings.append("AppArmor not enabled")

        return HardeningFeature(
            name="AppArmor",
            category="apparmor",
            is_enabled=is_enabled,
            confidence="high" if is_enabled else "low",
            details=details,
            warnings=warnings
        )

    def _check_kernel_hardening(self) -> List[HardeningFeature]:
        """Check kernel hardening via sysctl."""
        features = []

        # Key kernel hardening settings from Kicksecure
        hardening_settings = {
            "kernel.dmesg_restrict": ("1", "Restrict dmesg access"),
            "kernel.kptr_restrict": ("2", "Hide kernel pointers"),
            "kernel.yama.ptrace_scope": ("2", "Restrict ptrace"),
            "net.ipv4.conf.all.rp_filter": ("1", "Enable reverse path filtering"),
            "net.ipv4.conf.all.accept_source_route": ("0", "Disable source routing"),
            "net.ipv4.tcp_syncookies": ("1", "Enable SYN cookies"),
        }

        for setting, (expected_value, description) in hardening_settings.items():
            is_enabled = False
            warnings = []
            details = description

            result = SubprocessUtils.run_command(
                ["sysctl", "-n", setting],
                timeout=5
            )

            if result and result.returncode == 0:
                actual_value = result.stdout.strip()
                is_enabled = actual_value == expected_value
                details = f"{description}: {actual_value} (expected: {expected_value})"

                if not is_enabled:
                    warnings.append(f"Non-hardened value: {actual_value}")
            else:
                warnings.append(f"Could not read sysctl {setting}")

            features.append(HardeningFeature(
                name=f"Kernel: {setting}",
                category="kernel",
                is_enabled=is_enabled,
                confidence="medium",
                details=details,
                warnings=warnings
            ))

        return features

    def _check_services(self) -> List[HardeningFeature]:
        """Check for disabled unnecessary services."""
        features = []

        # Services that should be disabled on hardened systems
        unnecessary_services = [
            "avahi-daemon",
            "cups",
            "bluetooth",
            "telnet",
        ]

        for service in unnecessary_services:
            is_enabled = False  # For hardening, we want these disabled
            warnings = []
            details = f"Service {service} status"

            result = SubprocessUtils.run_command(
                ["systemctl", "is-enabled", service],
                timeout=5
            )

            if result:
                status = result.stdout.strip()

                # Service is hardened if disabled/masked
                is_enabled = status in ["disabled", "masked"]
                details = f"{service}: {status}"

                if not is_enabled and status == "enabled":
                    warnings.append(f"Unnecessary service {service} is enabled")
            else:
                # If service doesn't exist, that's good for hardening
                is_enabled = True
                details = f"{service}: not installed (good)"

            features.append(HardeningFeature(
                name=f"Service: {service} disabled",
                category="services",
                is_enabled=is_enabled,
                confidence="medium",
                details=details,
                warnings=warnings
            ))

        return features

    def _check_filesystem(self) -> List[HardeningFeature]:
        """Check filesystem mount options."""
        features = []
        warnings = []

        # Check /tmp mount options using utility
        mounts = FileSystemUtils.read_file_content(Path("/proc/mounts"))
        
        if mounts:
            # Check /tmp hardening
            tmp_match = re.search(r'/tmp\s+\S+\s+\S+\s+([^\s]+)', mounts)
            if tmp_match:
                options = tmp_match.group(1).split(',')
                has_noexec = 'noexec' in options
                has_nosuid = 'nosuid' in options
                has_nodev = 'nodev' in options

                feature_warnings = []
                if not has_noexec:
                    feature_warnings.append("/tmp not mounted with noexec")
                if not has_nosuid:
                    feature_warnings.append("/tmp not mounted with nosuid")

                features.append(HardeningFeature(
                    name="Filesystem: /tmp hardening",
                    category="filesystem",
                    is_enabled=has_noexec and has_nosuid and has_nodev,
                    confidence="high",
                    details=f"/tmp options: {', '.join(options)}",
                    warnings=feature_warnings
                ))
        else:
            features.append(HardeningFeature(
                name="Filesystem: /tmp hardening",
                category="filesystem",
                is_enabled=False,
                confidence="low",
                details="Could not read /proc/mounts",
                warnings=["Could not check filesystem mounts"]
            ))

        return features

    def _check_ssh_hardening(self) -> List[HardeningFeature]:
        """Check SSH hardening configuration."""
        features = []
        sshd_config = Path("/etc/ssh/sshd_config")

        if not FileSystemUtils.path_exists(sshd_config):
            return features

        config = FileSystemUtils.read_file_content(sshd_config)
        
        if config:
            # Check key hardening settings
            hardening_checks = {
                "PermitRootLogin no": ("Root login disabled", r'^\s*PermitRootLogin\s+no'),
                "PasswordAuthentication no": ("Password auth disabled", r'^\s*PasswordAuthentication\s+no'),
                "X11Forwarding no": ("X11 forwarding disabled", r'^\s*X11Forwarding\s+no'),
            }

            for check_name, (description, pattern) in hardening_checks.items():
                is_enabled = bool(re.search(pattern, config, re.MULTILINE | re.IGNORECASE))
                warnings = [] if is_enabled else [f"SSH: {description} not configured"]

                features.append(HardeningFeature(
                    name=f"SSH: {check_name}",
                    category="ssh",
                    is_enabled=is_enabled,
                    confidence="medium",
                    details=description,
                    warnings=warnings
                ))
        else:
            features.append(HardeningFeature(
                name="SSH: Config Read",
                category="ssh",
                is_enabled=False,
                confidence="low",
                details="Could not read sshd_config",
                warnings=["Failed to read /etc/ssh/sshd_config"]
            ))

        return features

    def _check_fixture_hardening(self) -> HardeningResult:
        """Return fixture hardening data for testing."""
        fixture = self.fixture_data

        features = []
        for feature_data in fixture.get("features", []):
            features.append(HardeningFeature(
                name=feature_data.get("name", ""),
                category=feature_data.get("category", "unknown"),
                is_enabled=feature_data.get("is_enabled", False),
                confidence=feature_data.get("confidence", "low"),
                details=feature_data.get("details", ""),
                warnings=feature_data.get("warnings", [])
            ))

        return HardeningResult(
            level=HardeningLevel(fixture.get("level", "unknown")),
            features=features,
            confidence=fixture.get("confidence", "low"),
            warnings=fixture.get("warnings", []),
            recommendations=fixture.get("recommendations", []),
            metadata=fixture.get("metadata", {})
        )
