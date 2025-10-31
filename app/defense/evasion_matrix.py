#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Defensive Evasion Matrix Analyzer

Maps attack techniques to defensive controls and calculates residual risk.
"""
from __future__ import annotations

from datetime import datetime
from typing import Dict, List, Optional
from collections import defaultdict

from app.defense.models import (
    AttackTechnique,
    DefensiveControl,
    TechniqueControlMapping,
    EvasionMatrixReport,
    RiskLevel,
    TechniqueCategory
)
from app.defense.technique_database import (
    get_all_techniques,
    get_technique,
    get_techniques_by_tactic,
    get_techniques_by_platform
)
from app.defense.control_database import (
    get_all_controls,
    get_controls_for_technique,
    get_control
)


class EvasionMatrixAnalyzer:
    """
    Analyzes attack techniques and maps them to defensive controls.

    Provides risk assessment and gap analysis capabilities.
    """

    def __init__(self):
        """Initialize analyzer with technique and control databases."""
        self.techniques = get_all_techniques()
        self.controls = get_all_controls()

    def build_full_matrix(
        self,
        base_likelihood: float = 0.7,
        base_impact: float = 0.8
    ) -> EvasionMatrixReport:
        """
        Build complete evasion matrix for all techniques.

        Args:
            base_likelihood: Default likelihood score (0.0-1.0)
            base_impact: Default impact score (0.0-1.0)

        Returns:
            Complete matrix report with all mappings
        """
        mappings = []

        for technique_id, technique in self.techniques.items():
            controls = get_controls_for_technique(technique_id)

            # Adjust likelihood/impact based on detection difficulty
            adjusted_likelihood = self._adjust_likelihood(
                base_likelihood,
                technique.detection_difficulty
            )

            mapping = TechniqueControlMapping(
                technique=technique,
                controls=tuple(controls),
                base_likelihood=adjusted_likelihood,
                base_impact=base_impact
            )

            mappings.append(mapping)

        # Calculate overall risk score
        total_residual = sum(m.calculate_residual_risk() for m in mappings)
        avg_residual = total_residual / len(mappings) if mappings else 0.0

        return EvasionMatrixReport(
            generated_at=datetime.utcnow(),
            total_techniques=len(self.techniques),
            total_controls=len(self.controls),
            mappings=tuple(mappings),
            overall_risk_score=round(avg_residual, 3)
        )

    def analyze_technique(
        self,
        technique_id: str,
        base_likelihood: float = 0.7,
        base_impact: float = 0.8
    ) -> Optional[TechniqueControlMapping]:
        """
        Analyze a single technique and its controls.

        Args:
            technique_id: MITRE ATT&CK technique ID
            base_likelihood: Likelihood score (0.0-1.0)
            base_impact: Impact score (0.0-1.0)

        Returns:
            TechniqueControlMapping or None if technique not found
        """
        technique = get_technique(technique_id)
        if not technique:
            return None

        controls = get_controls_for_technique(technique_id)

        adjusted_likelihood = self._adjust_likelihood(
            base_likelihood,
            technique.detection_difficulty
        )

        return TechniqueControlMapping(
            technique=technique,
            controls=tuple(controls),
            base_likelihood=adjusted_likelihood,
            base_impact=base_impact
        )

    def analyze_by_tactic(
        self,
        tactic: TechniqueCategory,
        base_likelihood: float = 0.7,
        base_impact: float = 0.8
    ) -> List[TechniqueControlMapping]:
        """
        Analyze all techniques for a specific tactic.

        Args:
            tactic: MITRE ATT&CK tactic category
            base_likelihood: Likelihood score (0.0-1.0)
            base_impact: Impact score (0.0-1.0)

        Returns:
            List of technique-control mappings
        """
        techniques = get_techniques_by_tactic(tactic)
        mappings = []

        for technique in techniques:
            controls = get_controls_for_technique(technique.technique_id)

            adjusted_likelihood = self._adjust_likelihood(
                base_likelihood,
                technique.detection_difficulty
            )

            mapping = TechniqueControlMapping(
                technique=technique,
                controls=tuple(controls),
                base_likelihood=adjusted_likelihood,
                base_impact=base_impact
            )

            mappings.append(mapping)

        return mappings

    def analyze_by_platform(
        self,
        platform: str,
        base_likelihood: float = 0.7,
        base_impact: float = 0.8
    ) -> List[TechniqueControlMapping]:
        """
        Analyze all techniques applicable to a platform.

        Args:
            platform: Platform name (linux, windows, macos, web)
            base_likelihood: Likelihood score (0.0-1.0)
            base_impact: Impact score (0.0-1.0)

        Returns:
            List of technique-control mappings
        """
        techniques = get_techniques_by_platform(platform)
        mappings = []

        for technique in techniques:
            controls = get_controls_for_technique(technique.technique_id)

            adjusted_likelihood = self._adjust_likelihood(
                base_likelihood,
                technique.detection_difficulty
            )

            mapping = TechniqueControlMapping(
                technique=technique,
                controls=tuple(controls),
                base_likelihood=adjusted_likelihood,
                base_impact=base_impact
            )

            mappings.append(mapping)

        return mappings

    def coverage_analysis(self) -> Dict[str, any]:
        """
        Analyze overall defensive coverage.

        Returns:
            Coverage statistics and gaps
        """
        total_techniques = len(self.techniques)
        covered_techniques = 0
        control_distribution = defaultdict(int)

        for technique_id in self.techniques.keys():
            controls = get_controls_for_technique(technique_id)
            if controls:
                covered_techniques += 1
                control_distribution[len(controls)] += 1

        return {
            "total_techniques": total_techniques,
            "covered_techniques": covered_techniques,
            "uncovered_techniques": total_techniques - covered_techniques,
            "coverage_percentage": round((covered_techniques / total_techniques) * 100, 1),
            "control_distribution": dict(control_distribution),
            "avg_controls_per_technique": round(
                sum(k * v for k, v in control_distribution.items()) / total_techniques, 2
            ) if total_techniques > 0 else 0
        }

    def control_effectiveness_summary(self) -> Dict[str, any]:
        """
        Summarize effectiveness of all controls.

        Returns:
            Control effectiveness statistics
        """
        effectiveness_counts = defaultdict(int)
        type_counts = defaultdict(int)
        cost_counts = defaultdict(int)

        for control in self.controls.values():
            effectiveness_counts[control.effectiveness.value] += 1
            type_counts[control.control_type] += 1
            cost_counts[control.implementation_cost.value] += 1

        return {
            "total_controls": len(self.controls),
            "by_effectiveness": dict(effectiveness_counts),
            "by_type": dict(type_counts),
            "by_cost": dict(cost_counts)
        }

    def gap_prioritization(
        self,
        base_likelihood: float = 0.7,
        base_impact: float = 0.8,
        top_n: int = 10
    ) -> List[Dict]:
        """
        Identify and prioritize defensive gaps.

        Args:
            base_likelihood: Default likelihood score
            base_impact: Default impact score
            top_n: Number of top gaps to return

        Returns:
            List of highest-priority gaps
        """
        report = self.build_full_matrix(base_likelihood, base_impact)
        return report.priority_gaps(top_n)

    def generate_heatmap_data(
        self,
        base_likelihood: float = 0.7,
        base_impact: float = 0.8
    ) -> Dict[str, List[Dict]]:
        """
        Generate data for risk heatmap visualization.

        Returns:
            Heatmap data organized by tactic
        """
        heatmap = {}

        for tactic in TechniqueCategory:
            mappings = self.analyze_by_tactic(tactic, base_likelihood, base_impact)

            heatmap[tactic.value] = [
                {
                    "technique_id": m.technique.technique_id,
                    "technique_name": m.technique.technique_name,
                    "residual_risk": m.calculate_residual_risk(),
                    "risk_level": m.risk_level().value,
                    "control_count": len(m.controls)
                }
                for m in mappings
            ]

        return heatmap

    def _adjust_likelihood(
        self,
        base_likelihood: float,
        detection_difficulty: RiskLevel
    ) -> float:
        """
        Adjust likelihood based on detection difficulty.

        Harder-to-detect techniques have higher likelihood of success.
        """
        adjustments = {
            RiskLevel.CRITICAL: 1.2,  # Very hard to detect
            RiskLevel.HIGH: 1.1,
            RiskLevel.MEDIUM: 1.0,     # No adjustment
            RiskLevel.LOW: 0.8,        # Easy to detect
            RiskLevel.MINIMAL: 0.6
        }

        multiplier = adjustments.get(detection_difficulty, 1.0)
        adjusted = base_likelihood * multiplier

        # Clamp to 0.0-1.0 range
        return max(0.0, min(1.0, adjusted))

    def export_matrix_csv(self, report: EvasionMatrixReport) -> str:
        """
        Export matrix to CSV format.

        Returns:
            CSV-formatted string
        """
        lines = [
            "Technique ID,Technique Name,Tactic,Control Count,Residual Risk,Risk Level,Recommended Action"
        ]

        for mapping in report.mappings:
            gap = mapping.control_gap_analysis()
            lines.append(
                f"{gap['technique_id']},"
                f"\"{gap['technique_name']}\","
                f"{mapping.technique.tactic.value},"
                f"{gap['controls_count']},"
                f"{gap['residual_risk']},"
                f"{gap['risk_level']},"
                f"\"{gap['recommended_action']}\""
            )

        return "\n".join(lines)
