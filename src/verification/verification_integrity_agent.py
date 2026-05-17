"""
Verification Integrity Agent - Kicksecure-inspired artifact verification.

This agent provides comprehensive security verification for artifacts, scripts,
and system configurations following Kicksecure's defense-in-depth principles.

Key capabilities:
- Trusted time source detection and freshness validation
- Artifact provenance and signature verification with notation binding
- APT source security checking (torified apt detection)
- System hardening posture detection
- Multi-factor confidence scoring

References:
- Kicksecure About: https://www.kicksecure.com/wiki/About
- Digital Signature Policy: https://www.kicksecure.com/wiki/Trust
- Time Integrity: https://www.kicksecure.com/wiki/Time_Attacks
"""

from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Dict, Any, Optional
import re

from .time_integrity import TimeIntegrityChecker, TimeIntegrityResult
from .provenance_checker import ProvenanceChecker, ProvenanceResult
from .apt_security import AptSecurityChecker, AptSecurityResult
from .hardening_detector import HardeningDetector, HardeningResult
from .confidence_model import ConfidenceModel, ConfidenceScore


@dataclass
class VerificationControl:
    """Security control detected in artifact."""
    control_name: str
    implemented: bool
    line_number: Optional[int]
    details: str
    severity: str  # "critical", "high", "medium", "low", "info"


@dataclass
class VerificationFinding:
    """Complete verification finding for an artifact."""
    file_path: str
    artifact_type: str  # "script", "artifact", "config"
    controls: List[VerificationControl]
    time_result: Optional[TimeIntegrityResult]
    provenance_result: Optional[ProvenanceResult]
    apt_result: Optional[AptSecurityResult]
    hardening_result: Optional[HardeningResult]
    confidence_score: ConfidenceScore
    summary: str
    risk_flags: List[str]
    recommendations: List[str]
    metadata: Dict[str, Any]


class VerificationIntegrityAgent:
    """
    Main agent for verification integrity analysis.

    This agent analyzes artifacts, scripts, and configurations to detect
    security controls and validate against Kicksecure-inspired best practices.
    """

    def __init__(self, fixture_mode: bool = False, strict_mode: bool = False):
        """
        Initialize verification integrity agent.

        Args:
            fixture_mode: If True, use fixture data for testing
            strict_mode: If True, apply stricter filtering and only scan actual verification scripts
        """
        self.fixture_mode = fixture_mode
        self.strict_mode = strict_mode
        self.time_checker = TimeIntegrityChecker(fixture_mode=fixture_mode)
        self.provenance_checker = ProvenanceChecker(fixture_mode=fixture_mode)
        self.apt_checker = AptSecurityChecker(fixture_mode=fixture_mode)
        self.hardening_detector = HardeningDetector(fixture_mode=fixture_mode)
        self.confidence_model = ConfidenceModel()

        # Paths to exclude from scanning
        self.exclusion_patterns = [
            'src/verification/',  # Don't scan the verification library itself
            'tests/',             # Don't scan tests
            'docs/',              # Don't scan documentation
            '.github/',           # Don't scan CI configs
            'tools/',             # Don't scan tooling
            'src/main.py',        # Don't scan red team offensive tools
            'src/models.py',
            'src/payloads',
            'src/advanced_attacks/',
            'src/stealth/',
            'src/resilience/',
            'README.md',
            'SECURITY.md',
            'LICENSE',
        ]

    def _should_exclude_file(self, file_path: Path) -> bool:
        """
        Check if file should be excluded from scanning.

        Args:
            file_path: Path to file

        Returns:
            True if file should be excluded
        """
        file_str = str(file_path)

        # Check exclusion patterns
        for pattern in self.exclusion_patterns:
            if pattern in file_str:
                return True

        # Don't scan the payloads module
        if 'payloads' in file_str.lower():
            return True

        return False

    def analyze_file(self, file_path: Path) -> Optional[VerificationFinding]:
        """
        Analyze a file for verification integrity controls.

        Args:
            file_path: Path to file to analyze

        Returns:
            VerificationFinding if relevant, None if file is not verification-related
        """
        if not file_path.exists():
            return None

        # Check exclusions first
        if self._should_exclude_file(file_path):
            return None

        # Read file content
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
        except Exception as e:
            # Consider adding a logging framework to report this error.
            print(f"Error reading file {file_path}: {e}", file=sys.stderr)
            return None

        # Determine artifact type
        artifact_type = self._determine_artifact_type(file_path, content)

        # Skip if not relevant
        if not self._is_verification_relevant(file_path, content):
            return None

        # Analyze controls
        controls = self._analyze_controls(content)

        # Check time integrity (always run for environment context)
        time_result = self.time_checker.check_time_integrity()

        # Check provenance if signature file exists
        provenance_result = None
        if self._looks_like_signed_artifact(file_path):
            provenance_result = self.provenance_checker.check_provenance(file_path)

        # Check APT usage
        apt_result = None
        apt_usage = self.apt_checker.check_script_apt_usage(content)
        if apt_usage["uses_apt"]:
            apt_result = self.apt_checker.check_apt_security()

        # Check hardening assumptions
        hardening_result = None
        hardening_assumptions = self.hardening_detector.check_script_assumptions(content)
        if hardening_assumptions["assumes_permissive"]:
            hardening_result = self.hardening_detector.check_hardening()

        # Calculate confidence
        confidence_score = self.confidence_model.calculate_confidence(
            time_result=time_result,
            provenance_result=provenance_result,
            apt_result=apt_result,
            hardening_result=hardening_result
        )

        # Generate risk flags
        risk_flags = self._generate_risk_flags(
            controls, time_result, provenance_result, apt_usage, hardening_assumptions
        )

        # Generate summary
        summary = self._generate_summary(file_path, controls, confidence_score)

        # Collect recommendations
        recommendations = confidence_score.recommendations.copy()

        return VerificationFinding(
            file_path=str(file_path),
            artifact_type=artifact_type,
            controls=controls,
            time_result=time_result,
            provenance_result=provenance_result,
            apt_result=apt_result,
            hardening_result=hardening_result,
            confidence_score=confidence_score,
            summary=summary,
            risk_flags=risk_flags,
            recommendations=recommendations,
            metadata={
                "file_size": file_path.stat().st_size,
                "last_modified": datetime.fromtimestamp(file_path.stat().st_mtime).isoformat()
            }
        )

    def analyze_artifact(
        self,
        artifact_path: Path,
        signature_path: Optional[Path] = None,
        maximum_age: Optional[timedelta] = None
    ) -> VerificationFinding:
        """
        Analyze an artifact with signature verification.

        Args:
            artifact_path: Path to artifact
            signature_path: Optional path to detached signature
            maximum_age: Maximum allowed age for artifact

        Returns:
            VerificationFinding with full analysis
        """
        controls = []

        # Check time integrity
        time_result = self.time_checker.check_time_integrity()

        # Check provenance
        provenance_result = self.provenance_checker.check_provenance(
            artifact_path,
            signature_path
        )

        # Validate freshness if signature has timestamp
        if provenance_result.signature_info and provenance_result.signature_info.timestamp:
            sig_time = datetime.fromtimestamp(int(provenance_result.signature_info.timestamp))
            max_age = maximum_age or timedelta(days=7)

            is_fresh, reason, _ = self.time_checker.validate_freshness(
                sig_time,
                max_age,
                require_trusted_source=True
            )

            controls.append(VerificationControl(
                control_name="freshness",
                implemented=is_fresh,
                line_number=None,
                details=reason,
                severity="critical" if not is_fresh else "info"
            ))

        # Check notation binding
        controls.append(VerificationControl(
            control_name="notation_binding",
            implemented=provenance_result.notation_binding_verified,
            line_number=None,
            details="Notation binding to artifact file/hash",
            severity="high" if not provenance_result.notation_binding_verified else "info"
        ))

        # Calculate confidence
        confidence_score = self.confidence_model.calculate_confidence(
            time_result=time_result,
            provenance_result=provenance_result
        )

        risk_flags = []
        if not provenance_result.signature_info or not provenance_result.signature_info.is_valid:
            risk_flags.append("invalid_signature")
        if not provenance_result.notation_binding_verified:
            risk_flags.append("substitution_risk")

        summary = f"Artifact verification: {confidence_score.overall_confidence} confidence"

        return VerificationFinding(
            file_path=str(artifact_path),
            artifact_type="artifact",
            controls=controls,
            time_result=time_result,
            provenance_result=provenance_result,
            apt_result=None,
            hardening_result=None,
            confidence_score=confidence_score,
            summary=summary,
            risk_flags=risk_flags,
            recommendations=confidence_score.recommendations,
            metadata={}
        )

    def _determine_artifact_type(self, file_path: Path, content: str) -> str:
        """Determine artifact type from file."""
        suffix = file_path.suffix.lower()

        if suffix in ['.sh', '.bash']:
            return "script"
        elif suffix in ['.conf', '.cfg', '.ini']:
            return "config"
        elif 'gpg' in content.lower() or 'signature' in content.lower():
            return "verification_script"
        else:
            return "unknown"

    def _is_verification_relevant(self, file_path: Path, content: str) -> bool:
        """
        Check if file is relevant to verification.

        Only flag files that are actual verification/installation/build scripts,
        not documentation, tests, or offensive security tools.

        Args:
            file_path: Path to file
            content: File content

        Returns:
            True if file is a verification script
        """
        content_lower = content.lower()
        filename = file_path.name.lower()

        # Strong indicators of verification scripts
        strong_indicators = [
            'gpg --verify',
            'gpg verify',
            'gpg2 --verify',
            'signature verification',
            'verify signature',
            'apt-get update',
            'apt update',
            'download and verify',
            'checksum verification',
        ]

        # Count strong indicators
        strong_count = sum(1 for indicator in strong_indicators if indicator in content_lower)

        # If multiple strong indicators, it's likely a verification script
        if strong_count >= 2:
            return True

        # Check for install/setup scripts with verification
        if any(name in filename for name in ['install', 'setup', 'deploy', 'build']):
            if any(keyword in content_lower for keyword in ['gpg', 'signature', 'verify', 'checksum']):
                return True

        # Shell scripts that do package management with verification
        if file_path.suffix in ['.sh', '.bash']:
            has_package_mgmt = any(word in content_lower for word in ['apt-get', 'apt ', 'dnf', 'yum', 'pacman'])
            has_verification = any(word in content_lower for word in ['gpg', 'signature', 'verify'])

            if has_package_mgmt and has_verification:
                return True

        # Default: not a verification script
        return False

    def _looks_like_signed_artifact(self, file_path: Path) -> bool:
        """Check if artifact appears to have a signature."""
        # Check for companion signature files
        for ext in ['.sig', '.asc', '.gpg']:
            sig_path = file_path.with_suffix(file_path.suffix + ext)
            if sig_path.exists():
                return True
        return False

    def _analyze_controls(self, content: str) -> List[VerificationControl]:
        """Analyze security controls in content."""
        controls = []

        # Control: Rollback protection (freshness checks)
        has_freshness = bool(re.search(
            r'(maximum_age|max_age|freshness|--max-days|signed.*time)',
            content,
            re.IGNORECASE
        ))

        freshness_line = None
        if has_freshness:
            match = re.search(r'.*(maximum_age|freshness).*', content, re.IGNORECASE | re.MULTILINE)
            if match:
                freshness_line = content[:match.start()].count('\n') + 1

        controls.append(VerificationControl(
            control_name="rollback",
            implemented=has_freshness,
            line_number=freshness_line,
            details="Freshness/maximum age checks for signatures",
            severity="critical" if not has_freshness else "info"
        ))

        # Control: Tampering protection (notation binding)
        has_notation = bool(re.search(
            r'(notation|file@|hash@|--set-notation)',
            content,
            re.IGNORECASE
        ))

        notation_line = None
        if has_notation:
            match = re.search(r'.*(notation|file@).*', content, re.IGNORECASE | re.MULTILINE)
            if match:
                notation_line = content[:match.start()].count('\n') + 1

        controls.append(VerificationControl(
            control_name="tampering",
            implemented=has_notation,
            line_number=notation_line,
            details="Notation binding to artifact file/hash",
            severity="high" if not has_notation else "info"
        ))

        # Control: Freeze protection (apt pinning)
        has_pinning = bool(re.search(
            r'(apt.*pin|preferences|hold|freeze)',
            content,
            re.IGNORECASE
        ))

        controls.append(VerificationControl(
            control_name="freeze",
            implemented=has_pinning,
            line_number=None,
            details="APT pinning or package freezing",
            severity="medium" if not has_pinning else "info"
        ))

        # Control: Endless data protection (timeouts)
        has_timeouts = bool(re.search(
            r'(timeout|--max-time|kill.*after|ulimit.*time)',
            content,
            re.IGNORECASE
        ))

        timeout_line = None
        if has_timeouts:
            match = re.search(r'.*(timeout|kill.*after).*', content, re.IGNORECASE | re.MULTILINE)
            if match:
                timeout_line = content[:match.start()].count('\n') + 1

        controls.append(VerificationControl(
            control_name="endless_data",
            implemented=has_timeouts,
            line_number=timeout_line,
            details="Timeouts for GPG verification",
            severity="medium" if not has_timeouts else "info"
        ))

        return controls

    def _generate_risk_flags(
        self,
        controls: List[VerificationControl],
        time_result: TimeIntegrityResult,
        provenance_result: Optional[ProvenanceResult],
        apt_usage: Dict[str, Any],
        hardening_assumptions: Dict[str, Any]
    ) -> List[str]:
        """Generate risk flags from analysis."""
        flags = []

        # Critical controls missing
        critical_controls = [c for c in controls if c.severity == "critical" and not c.implemented]
        if critical_controls:
            flags.append("critical_controls_missing")

        # Time source issues
        if time_result.confidence == "low":
            flags.append("untrusted_time_source")

        # Provenance issues
        if provenance_result:
            if not provenance_result.signature_info or not provenance_result.signature_info.is_valid:
                flags.append("invalid_signature")
            if not provenance_result.notation_binding_verified:
                flags.append("substitution_risk")

        # APT issues
        if apt_usage.get("uses_apt") and not apt_usage.get("uses_tor"):
            flags.append("apt_not_torified")

        # Hardening issues
        if hardening_assumptions.get("assumes_permissive"):
            flags.append("assumes_permissive_host")

        return flags

    def _generate_summary(
        self,
        file_path: Path,
        controls: List[VerificationControl],
        confidence: ConfidenceScore
    ) -> str:
        """Generate human-readable summary."""
        implemented = sum(1 for c in controls if c.implemented)
        total = len(controls)

        return (
            f"{file_path.name}: {implemented}/{total} controls implemented, "
            f"{confidence.overall_confidence} confidence"
        )
