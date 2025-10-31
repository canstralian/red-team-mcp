#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Unit tests for Defensive Evasion Matrix.
"""
from __future__ import annotations

import pytest
from app.defense.models import (
    AttackTechnique,
    DefensiveControl,
    TechniqueControlMapping,
    RiskLevel,
    ControlEffectiveness,
    TechniqueCategory
)
from app.defense.evasion_matrix import EvasionMatrixAnalyzer
from app.defense.technique_database import get_technique
from app.defense.control_database import get_controls_for_technique


def test_technique_creation():
    """Test creating attack technique."""
    technique = AttackTechnique(
        technique_id="T1059.001",
        technique_name="PowerShell",
        tactic=TechniqueCategory.EXECUTION,
        description="PowerShell execution",
        platform=["windows"],
        detection_difficulty=RiskLevel.MEDIUM
    )

    assert technique.technique_id == "T1059.001"
    assert technique.tactic == TechniqueCategory.EXECUTION
    assert "windows" in technique.platform


def test_control_effectiveness_score():
    """Test control effectiveness conversion to score."""
    control = DefensiveControl(
        control_id="CTRL-TEST",
        control_name="Test Control",
        control_type="preventive",
        description="Test",
        implementation_cost=RiskLevel.LOW,
        effectiveness=ControlEffectiveness.SUBSTANTIAL,
        coverage=["T1059.001"]
    )

    assert control.effectiveness_score() == 0.80


def test_residual_risk_calculation():
    """Test residual risk calculation with controls."""
    technique = AttackTechnique(
        technique_id="T1059.001",
        technique_name="PowerShell",
        tactic=TechniqueCategory.EXECUTION,
        description="Test",
        platform=["windows"],
        detection_difficulty=RiskLevel.MEDIUM
    )

    # No controls - inherent risk = 0.5 * 0.5 = 0.25
    mapping_no_controls = TechniqueControlMapping(
        technique=technique,
        controls=tuple(),
        base_likelihood=0.5,
        base_impact=0.5
    )

    assert mapping_no_controls.calculate_residual_risk() == 0.25

    # With 80% effective control - residual = 0.25 * (1 - 0.8) = 0.05
    control = DefensiveControl(
        control_id="CTRL-001",
        control_name="Test Control",
        control_type="preventive",
        description="Test",
        implementation_cost=RiskLevel.LOW,
        effectiveness=ControlEffectiveness.SUBSTANTIAL,  # 0.80
        coverage=["T1059.001"]
    )

    mapping_with_control = TechniqueControlMapping(
        technique=technique,
        controls=(control,),
        base_likelihood=0.5,
        base_impact=0.5
    )

    assert mapping_with_control.calculate_residual_risk() == 0.05


def test_risk_level_classification():
    """Test risk level classification."""
    technique = AttackTechnique(
        technique_id="T1059.001",
        technique_name="PowerShell",
        tactic=TechniqueCategory.EXECUTION,
        description="Test",
        platform=["windows"],
        detection_difficulty=RiskLevel.MEDIUM
    )

    # High inherent risk, no controls = high residual risk
    high_risk_mapping = TechniqueControlMapping(
        technique=technique,
        controls=tuple(),
        base_likelihood=0.9,
        base_impact=0.9
    )

    # 0.9 * 0.9 = 0.81 * 10 = 8.1 -> HIGH
    assert high_risk_mapping.risk_level() == RiskLevel.HIGH

    # With effective control
    control = DefensiveControl(
        control_id="CTRL-001",
        control_name="Test Control",
        control_type="preventive",
        description="Test",
        implementation_cost=RiskLevel.LOW,
        effectiveness=ControlEffectiveness.COMPLETE,  # 0.95
        coverage=["T1059.001"]
    )

    low_risk_mapping = TechniqueControlMapping(
        technique=technique,
        controls=(control,),
        base_likelihood=0.9,
        base_impact=0.9
    )

    # 0.81 * (1 - 0.95) = 0.81 * 0.05 = 0.0405 * 10 = 0.405 -> MINIMAL
    assert low_risk_mapping.risk_level() == RiskLevel.MINIMAL


def test_control_gap_analysis():
    """Test control gap analysis."""
    technique = AttackTechnique(
        technique_id="T1059.001",
        technique_name="PowerShell",
        tactic=TechniqueCategory.EXECUTION,
        description="Test",
        platform=["windows"],
        detection_difficulty=RiskLevel.MEDIUM
    )

    preventive_control = DefensiveControl(
        control_id="CTRL-001",
        control_name="Preventive",
        control_type="preventive",
        description="Test",
        implementation_cost=RiskLevel.LOW,
        effectiveness=ControlEffectiveness.MODERATE,
        coverage=["T1059.001"]
    )

    detective_control = DefensiveControl(
        control_id="CTRL-002",
        control_name="Detective",
        control_type="detective",
        description="Test",
        implementation_cost=RiskLevel.LOW,
        effectiveness=ControlEffectiveness.SUBSTANTIAL,
        coverage=["T1059.001"]
    )

    mapping = TechniqueControlMapping(
        technique=technique,
        controls=(preventive_control, detective_control),
        base_likelihood=0.7,
        base_impact=0.8
    )

    gap = mapping.control_gap_analysis()

    assert gap["technique_id"] == "T1059.001"
    assert gap["controls_count"] == 2
    assert gap["has_preventive"] is True
    assert gap["has_detective"] is True
    assert gap["has_corrective"] is False


def test_matrix_analyzer_initialization():
    """Test matrix analyzer initialization."""
    analyzer = EvasionMatrixAnalyzer()

    assert len(analyzer.techniques) > 0
    assert len(analyzer.controls) > 0


def test_build_full_matrix():
    """Test building complete matrix."""
    analyzer = EvasionMatrixAnalyzer()
    report = analyzer.build_full_matrix()

    assert report.total_techniques > 0
    assert report.total_controls > 0
    assert len(report.mappings) == report.total_techniques
    assert report.overall_risk_score >= 0.0


def test_analyze_single_technique():
    """Test analyzing a single technique."""
    analyzer = EvasionMatrixAnalyzer()
    mapping = analyzer.analyze_technique("T1059.001")

    assert mapping is not None
    assert mapping.technique.technique_id == "T1059.001"
    assert isinstance(mapping.controls, tuple)


def test_analyze_nonexistent_technique():
    """Test analyzing technique that doesn't exist."""
    analyzer = EvasionMatrixAnalyzer()
    mapping = analyzer.analyze_technique("T9999.999")

    assert mapping is None


def test_coverage_analysis():
    """Test coverage analysis."""
    analyzer = EvasionMatrixAnalyzer()
    coverage = analyzer.coverage_analysis()

    assert "total_techniques" in coverage
    assert "covered_techniques" in coverage
    assert "coverage_percentage" in coverage
    assert coverage["coverage_percentage"] >= 0.0
    assert coverage["coverage_percentage"] <= 100.0


def test_gap_prioritization():
    """Test gap prioritization."""
    analyzer = EvasionMatrixAnalyzer()
    gaps = analyzer.gap_prioritization(top_n=5)

    assert len(gaps) <= 5
    assert all("technique_id" in gap for gap in gaps)
    assert all("residual_risk" in gap for gap in gaps)
    assert all("recommended_action" in gap for gap in gaps)


def test_heatmap_generation():
    """Test heatmap data generation."""
    analyzer = EvasionMatrixAnalyzer()
    heatmap = analyzer.generate_heatmap_data()

    assert isinstance(heatmap, dict)
    assert len(heatmap) > 0

    # Check structure
    for tactic, techniques in heatmap.items():
        assert isinstance(techniques, list)
        for tech in techniques:
            assert "technique_id" in tech
            assert "residual_risk" in tech
            assert "risk_level" in tech


def test_platform_filtering():
    """Test filtering techniques by platform."""
    analyzer = EvasionMatrixAnalyzer()
    windows_mappings = analyzer.analyze_by_platform("windows")
    linux_mappings = analyzer.analyze_by_platform("linux")

    assert len(windows_mappings) > 0
    assert len(linux_mappings) > 0

    # Verify all windows techniques include windows in platform
    for mapping in windows_mappings:
        assert "windows" in mapping.technique.platform


def test_tactic_filtering():
    """Test filtering techniques by tactic."""
    analyzer = EvasionMatrixAnalyzer()
    execution_mappings = analyzer.analyze_by_tactic(TechniqueCategory.EXECUTION)
    c2_mappings = analyzer.analyze_by_tactic(TechniqueCategory.COMMAND_AND_CONTROL)

    assert len(execution_mappings) > 0
    assert len(c2_mappings) > 0

    # Verify all execution techniques have correct tactic
    for mapping in execution_mappings:
        assert mapping.technique.tactic == TechniqueCategory.EXECUTION


def test_csv_export():
    """Test CSV export functionality."""
    analyzer = EvasionMatrixAnalyzer()
    report = analyzer.build_full_matrix()
    csv_content = analyzer.export_matrix_csv(report)

    assert isinstance(csv_content, str)
    assert "Technique ID" in csv_content
    assert "Residual Risk" in csv_content
    assert len(csv_content.split("\n")) > 1  # Header + data rows


def test_summary_statistics():
    """Test summary statistics generation."""
    analyzer = EvasionMatrixAnalyzer()
    report = analyzer.build_full_matrix()
    stats = report.summary_statistics()

    assert "total_techniques" in stats
    assert "total_controls" in stats
    assert "avg_residual_risk" in stats
    assert "critical_count" in stats
    assert "high_count" in stats
    assert "medium_count" in stats
    assert "low_count" in stats
    assert "coverage_percentage" in stats

    # Verify counts sum correctly
    total_risks = (
        stats["critical_count"] +
        stats["high_count"] +
        stats["medium_count"] +
        stats["low_count"] +
        stats["minimal_count"]
    )
    assert total_risks == stats["total_techniques"]


def test_control_effectiveness_summary():
    """Test control effectiveness summary."""
    analyzer = EvasionMatrixAnalyzer()
    summary = analyzer.control_effectiveness_summary()

    assert "total_controls" in summary
    assert "by_effectiveness" in summary
    assert "by_type" in summary
    assert "by_cost" in summary

    # Verify counts
    assert summary["total_controls"] > 0
    assert len(summary["by_type"]) > 0
