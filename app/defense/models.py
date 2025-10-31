#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Defensive Evasion Matrix - Data Models

Immutable dataclasses for mapping attack techniques to defensive controls
and calculating residual risk.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, List
from datetime import datetime


class RiskLevel(str, Enum):
    """Risk severity levels."""
    CRITICAL = "critical"  # 9.0-10.0
    HIGH = "high"          # 7.0-8.9
    MEDIUM = "medium"      # 4.0-6.9
    LOW = "low"            # 1.0-3.9
    MINIMAL = "minimal"    # 0.0-0.9


class ControlEffectiveness(str, Enum):
    """Control effectiveness ratings."""
    COMPLETE = "complete"      # 90-100% effectiveness
    SUBSTANTIAL = "substantial"  # 70-89%
    MODERATE = "moderate"      # 40-69%
    LIMITED = "limited"        # 10-39%
    MINIMAL = "minimal"        # 0-9%


class TechniqueCategory(str, Enum):
    """MITRE ATT&CK tactic categories."""
    INITIAL_ACCESS = "initial-access"
    EXECUTION = "execution"
    PERSISTENCE = "persistence"
    PRIVILEGE_ESCALATION = "privilege-escalation"
    DEFENSE_EVASION = "defense-evasion"
    CREDENTIAL_ACCESS = "credential-access"
    DISCOVERY = "discovery"
    LATERAL_MOVEMENT = "lateral-movement"
    COLLECTION = "collection"
    COMMAND_AND_CONTROL = "command-and-control"
    EXFILTRATION = "exfiltration"
    IMPACT = "impact"


@dataclass(frozen=True)
class AttackTechnique:
    """MITRE ATT&CK technique representation."""

    technique_id: str  # e.g., "T1059.001"
    technique_name: str
    tactic: TechniqueCategory
    description: str
    platform: List[str] = field(default_factory=list)  # ["linux", "windows", "macos"]
    data_sources: List[str] = field(default_factory=list)
    detection_difficulty: RiskLevel = RiskLevel.MEDIUM

    def __post_init__(self):
        """Validate technique ID format."""
        if not self.technique_id.startswith("T"):
            raise ValueError(f"Invalid technique ID: {self.technique_id}")


@dataclass(frozen=True)
class DefensiveControl:
    """Security control to mitigate attack techniques."""

    control_id: str  # e.g., "CTRL-001"
    control_name: str
    control_type: str  # "preventive", "detective", "corrective"
    description: str
    implementation_cost: RiskLevel  # effort to implement
    effectiveness: ControlEffectiveness
    coverage: List[str] = field(default_factory=list)  # Technique IDs covered
    detection_methods: List[str] = field(default_factory=list)
    response_actions: List[str] = field(default_factory=list)

    def effectiveness_score(self) -> float:
        """Convert effectiveness enum to numeric score."""
        mapping = {
            ControlEffectiveness.COMPLETE: 0.95,
            ControlEffectiveness.SUBSTANTIAL: 0.80,
            ControlEffectiveness.MODERATE: 0.55,
            ControlEffectiveness.LIMITED: 0.25,
            ControlEffectiveness.MINIMAL: 0.05
        }
        return mapping.get(self.effectiveness, 0.5)


@dataclass(frozen=True)
class TechniqueControlMapping:
    """Maps an attack technique to defensive controls."""

    technique: AttackTechnique
    controls: tuple[DefensiveControl, ...] = field(default_factory=tuple)
    base_likelihood: float = 0.5  # 0.0-1.0
    base_impact: float = 0.5      # 0.0-1.0

    def calculate_residual_risk(self) -> float:
        """
        Calculate residual risk after applying controls.

        Formula: Residual = Inherent Risk × (1 - Control Effectiveness)
        Where: Inherent Risk = Likelihood × Impact
        """
        inherent_risk = self.base_likelihood * self.base_impact

        if not self.controls:
            return inherent_risk

        # Calculate combined control effectiveness
        combined_effectiveness = 1.0
        for control in self.controls:
            # Multiply reduction factors: (1 - eff1) × (1 - eff2) × ...
            combined_effectiveness *= (1.0 - control.effectiveness_score())

        residual_risk = inherent_risk * combined_effectiveness
        return round(residual_risk, 3)

    def risk_level(self) -> RiskLevel:
        """Convert residual risk score to severity level."""
        risk_score = self.calculate_residual_risk() * 10  # Scale to 0-10

        if risk_score >= 9.0:
            return RiskLevel.CRITICAL
        elif risk_score >= 7.0:
            return RiskLevel.HIGH
        elif risk_score >= 4.0:
            return RiskLevel.MEDIUM
        elif risk_score >= 1.0:
            return RiskLevel.LOW
        else:
            return RiskLevel.MINIMAL

    def control_gap_analysis(self) -> dict:
        """Identify gaps in defensive coverage."""
        return {
            "technique_id": self.technique.technique_id,
            "technique_name": self.technique.technique_name,
            "controls_count": len(self.controls),
            "residual_risk": self.calculate_residual_risk(),
            "risk_level": self.risk_level().value,
            "has_preventive": any(c.control_type == "preventive" for c in self.controls),
            "has_detective": any(c.control_type == "detective" for c in self.controls),
            "has_corrective": any(c.control_type == "corrective" for c in self.controls),
            "recommended_action": self._recommend_action()
        }

    def _recommend_action(self) -> str:
        """Recommend action based on residual risk."""
        risk = self.risk_level()
        control_count = len(self.controls)

        if risk in (RiskLevel.CRITICAL, RiskLevel.HIGH):
            if control_count == 0:
                return "URGENT: Implement preventive and detective controls immediately"
            else:
                return "PRIORITY: Strengthen existing controls or add compensating controls"
        elif risk == RiskLevel.MEDIUM:
            if control_count < 2:
                return "RECOMMENDED: Add additional detective controls"
            else:
                return "REVIEW: Verify control effectiveness through testing"
        elif risk == RiskLevel.LOW:
            return "MONITOR: Maintain current controls and monitor for changes"
        else:
            return "ACCEPTABLE: Current controls are sufficient"


@dataclass(frozen=True)
class EvasionMatrixReport:
    """Complete evasion matrix analysis report."""

    generated_at: datetime
    total_techniques: int
    total_controls: int
    mappings: tuple[TechniqueControlMapping, ...] = field(default_factory=tuple)
    overall_risk_score: float = 0.0

    def summary_statistics(self) -> dict:
        """Generate summary statistics for the matrix."""
        if not self.mappings:
            return {
                "total_techniques": 0,
                "total_controls": 0,
                "avg_residual_risk": 0.0,
                "critical_count": 0,
                "high_count": 0,
                "medium_count": 0,
                "low_count": 0,
                "coverage_percentage": 0.0
            }

        risk_counts = {
            RiskLevel.CRITICAL: 0,
            RiskLevel.HIGH: 0,
            RiskLevel.MEDIUM: 0,
            RiskLevel.LOW: 0,
            RiskLevel.MINIMAL: 0
        }

        total_residual = 0.0
        covered_techniques = 0

        for mapping in self.mappings:
            risk_level = mapping.risk_level()
            risk_counts[risk_level] += 1
            total_residual += mapping.calculate_residual_risk()
            if mapping.controls:
                covered_techniques += 1

        return {
            "total_techniques": len(self.mappings),
            "total_controls": self.total_controls,
            "avg_residual_risk": round(total_residual / len(self.mappings), 3),
            "critical_count": risk_counts[RiskLevel.CRITICAL],
            "high_count": risk_counts[RiskLevel.HIGH],
            "medium_count": risk_counts[RiskLevel.MEDIUM],
            "low_count": risk_counts[RiskLevel.LOW],
            "minimal_count": risk_counts[RiskLevel.MINIMAL],
            "coverage_percentage": round((covered_techniques / len(self.mappings)) * 100, 1)
        }

    def priority_gaps(self, top_n: int = 10) -> List[dict]:
        """Return top N highest-risk gaps requiring attention."""
        sorted_mappings = sorted(
            self.mappings,
            key=lambda m: m.calculate_residual_risk(),
            reverse=True
        )

        return [m.control_gap_analysis() for m in sorted_mappings[:top_n]]
