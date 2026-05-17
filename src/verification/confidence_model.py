"""
Confidence Model - Multi-factor confidence scoring.

This module combines time integrity, provenance, APT security, and hardening
posture into a holistic confidence score for verification operations.
"""

from dataclasses import dataclass
from enum import Enum
from typing import Dict, Any, List, Optional

from .time_integrity import TimeIntegrityResult, TimeSource
from .provenance_checker import ProvenanceResult, ProvenanceLevel
from .apt_security import AptSecurityResult, AptTransportSecurity
from .hardening_detector import HardeningResult, HardeningLevel


class ConfidenceLevel(str, Enum):
    """Overall confidence levels."""
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    CRITICAL = "critical"  # Critical issues detected


@dataclass
class ConfidenceScore:
    """Multi-factor confidence score."""
    overall_confidence: ConfidenceLevel
    component_scores: Dict[str, str]
    weighted_score: float  # 0.0 to 1.0
    factors_met: List[str]
    factors_failed: List[str]
    critical_issues: List[str]
    recommendations: List[str]
    metadata: Dict[str, Any]


class ConfidenceModel:
    """
    Calculate multi-factor confidence scores.

    Combines:
    - Time integrity (20% weight)
    - Provenance/signatures (35% weight)
    - APT security (20% weight)
    - System hardening (25% weight)

    High confidence requires:
    - Trusted time source (sdwdate or verified NTP)
    - Valid signature with notation binding
    - Torified or HTTPS APT sources
    - Hardened system configuration
    """

    def __init__(self):
        """Initialize confidence model with default weights."""
        self.weights = {
            "time_integrity": 0.20,
            "provenance": 0.35,
            "apt_security": 0.20,
            "hardening": 0.25,
        }

    def calculate_confidence(
        self,
        time_result: Optional[TimeIntegrityResult] = None,
        provenance_result: Optional[ProvenanceResult] = None,
        apt_result: Optional[AptSecurityResult] = None,
        hardening_result: Optional[HardeningResult] = None
    ) -> ConfidenceScore:
        """
        Calculate overall confidence from component results.

        Args:
            time_result: Time integrity check result
            provenance_result: Provenance check result
            apt_result: APT security check result
            hardening_result: Hardening detection result

        Returns:
            ConfidenceScore with weighted multi-factor score
        """
        component_scores = {}
        scores = {}
        factors_met = []
        factors_failed = []
        critical_issues = []
        recommendations = []

        # Score time integrity
        # Note: Only treat time integrity as critical if we're actually doing verification
        has_verification = provenance_result is not None

        if time_result:
            time_score = self._score_time_integrity(time_result)
            component_scores["time_integrity"] = time_result.confidence
            scores["time_integrity"] = time_score

            if time_score >= 0.8:
                factors_met.append("Trusted time source detected")
            else:
                factors_failed.append("No trusted time source")
                # Only mark as critical if we're doing verification AND time source is low
                if time_result.confidence == "low" and has_verification:
                    critical_issues.append("Low confidence time source - freshness checks unreliable")
                elif time_result.confidence == "low":
                    # Warn but don't mark as critical if no verification happening
                    recommendations.append("Time source confidence is low (consider using sdwdate)")

            recommendations.extend(time_result.warnings)

        # Score provenance
        if provenance_result:
            prov_score = self._score_provenance(provenance_result)
            component_scores["provenance"] = provenance_result.confidence
            scores["provenance"] = prov_score

            if prov_score >= 0.8:
                factors_met.append("Strong provenance with notation binding")
            elif prov_score >= 0.5:
                factors_met.append("Valid signature detected")
                factors_failed.append("Missing notation binding")
            else:
                factors_failed.append("Weak or missing provenance")
                critical_issues.append("No valid signature found")

            recommendations.extend(provenance_result.recommendations)

        # Score APT security
        if apt_result:
            apt_score = self._score_apt_security(apt_result)
            component_scores["apt_security"] = apt_result.confidence
            scores["apt_security"] = apt_score

            if apt_score >= 0.8:
                factors_met.append("APT sources use secure transport")
            elif apt_score >= 0.5:
                factors_met.append("APT sources use HTTPS")
                factors_failed.append("APT not torified")
            else:
                factors_failed.append("Insecure APT sources detected")
                if apt_result.has_insecure_sources:
                    critical_issues.append("HTTP APT sources detected (vulnerable to MitM)")

            recommendations.extend(apt_result.recommendations)

        # Score hardening
        if hardening_result:
            hard_score = self._score_hardening(hardening_result)
            component_scores["hardening"] = hardening_result.confidence
            scores["hardening"] = hard_score

            if hard_score >= 0.8:
                factors_met.append("System hardening detected")
            elif hard_score >= 0.5:
                factors_met.append("Moderate system hardening")
                factors_failed.append("Some hardening features missing")
            else:
                factors_failed.append("Minimal system hardening")

            recommendations.extend(hardening_result.recommendations)

        # Calculate weighted score
        weighted_score = sum(
            scores[component] * self.weights[component]
            for component in scores
        )

        # Normalize if not all components present
        total_weight = sum(self.weights[c] for c in scores)
        if total_weight > 0:
            weighted_score = weighted_score / total_weight

        # Determine overall confidence
        if critical_issues:
            overall = ConfidenceLevel.CRITICAL
        elif weighted_score >= 0.8:
            overall = ConfidenceLevel.HIGH
        elif weighted_score >= 0.5:
            overall = ConfidenceLevel.MEDIUM
        else:
            overall = ConfidenceLevel.LOW

        # Add high-level recommendations
        if overall == ConfidenceLevel.HIGH:
            recommendations.insert(0, "All security controls in place - high confidence verification")
        elif overall == ConfidenceLevel.MEDIUM:
            recommendations.insert(0, "Some security controls missing - moderate risk")
        else:
            recommendations.insert(0, "Multiple security controls missing - high risk")

        return ConfidenceScore(
            overall_confidence=overall,
            component_scores=component_scores,
            weighted_score=weighted_score,
            factors_met=factors_met,
            factors_failed=factors_failed,
            critical_issues=critical_issues,
            recommendations=recommendations,
            metadata={
                "weights": self.weights,
                "component_weights": {c: scores.get(c, 0) * self.weights[c] for c in self.weights}
            }
        )

    def _score_time_integrity(self, result: TimeIntegrityResult) -> float:
        """Score time integrity result (0.0 to 1.0)."""
        if result.source == TimeSource.SDWDATE and result.is_synchronized:
            return 1.0
        elif result.source == TimeSource.SDWDATE:
            return 0.7
        elif result.source == TimeSource.NTP_VERIFIED and result.is_synchronized:
            return 0.6
        elif result.source == TimeSource.NTP_UNVERIFIED:
            return 0.3
        else:
            return 0.0

    def _score_provenance(self, result: ProvenanceResult) -> float:
        """Score provenance result (0.0 to 1.0)."""
        if result.level == ProvenanceLevel.HIGH and result.notation_binding_verified:
            return 1.0
        elif result.level == ProvenanceLevel.HIGH:
            return 0.8
        elif result.level == ProvenanceLevel.MEDIUM:
            return 0.5
        elif result.level == ProvenanceLevel.LOW:
            return 0.2
        else:
            return 0.0

    def _score_apt_security(self, result: AptSecurityResult) -> float:
        """Score APT security result (0.0 to 1.0)."""
        if result.has_torified_sources and not result.has_insecure_sources:
            return 1.0
        elif not result.has_insecure_sources:
            return 0.6
        elif result.has_torified_sources:
            return 0.4  # Mixed secure/insecure
        else:
            return 0.2

    def _score_hardening(self, result: HardeningResult) -> float:
        """Score hardening result (0.0 to 1.0)."""
        if result.level == HardeningLevel.HARDENED:
            return 1.0
        elif result.level == HardeningLevel.MODERATE:
            return 0.6
        elif result.level == HardeningLevel.MINIMAL:
            return 0.3
        else:
            return 0.0

    def requires_operator_review(self, score: ConfidenceScore) -> bool:
        """
        Determine if confidence score requires operator review.

        Args:
            score: Confidence score

        Returns:
            True if operator review is required
        """
        # Require review for critical issues or low confidence
        if score.overall_confidence in [ConfidenceLevel.CRITICAL, ConfidenceLevel.LOW]:
            return True

        # Require review if critical controls missing
        critical_failures = [
            "No trusted time source",
            "Weak or missing provenance",
            "Insecure APT sources detected"
        ]

        return any(failure in score.factors_failed for failure in critical_failures)
