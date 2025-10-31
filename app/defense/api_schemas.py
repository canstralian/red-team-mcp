#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
API schemas for Evasion Matrix endpoints.
"""
from __future__ import annotations

from pydantic import BaseModel, Field
from typing import List, Dict, Optional
from datetime import datetime


class TechniqueOut(BaseModel):
    """Output schema for attack technique."""
    technique_id: str
    technique_name: str
    tactic: str
    description: str
    platform: List[str]
    detection_difficulty: str


class ControlOut(BaseModel):
    """Output schema for defensive control."""
    control_id: str
    control_name: str
    control_type: str
    description: str
    effectiveness: str
    implementation_cost: str


class MappingOut(BaseModel):
    """Output schema for technique-control mapping."""
    technique: TechniqueOut
    controls: List[ControlOut]
    residual_risk: float
    risk_level: str
    recommended_action: str


class MatrixReportOut(BaseModel):
    """Output schema for full matrix report."""
    generated_at: datetime
    total_techniques: int
    total_controls: int
    overall_risk_score: float
    summary_statistics: Dict
    mappings: List[MappingOut]


class GapAnalysisOut(BaseModel):
    """Output schema for gap analysis."""
    technique_id: str
    technique_name: str
    controls_count: int
    residual_risk: float
    risk_level: str
    has_preventive: bool
    has_detective: bool
    has_corrective: bool
    recommended_action: str


class CoverageStatsOut(BaseModel):
    """Output schema for coverage analysis."""
    total_techniques: int
    covered_techniques: int
    uncovered_techniques: int
    coverage_percentage: float
    control_distribution: Dict[str, int]
    avg_controls_per_technique: float


class HeatmapOut(BaseModel):
    """Output schema for heatmap data."""
    tactic: str
    techniques: List[Dict]


class AnalysisQueryIn(BaseModel):
    """Input schema for analysis queries."""
    base_likelihood: float = Field(
        default=0.7,
        ge=0.0,
        le=1.0,
        description="Base likelihood score (0.0-1.0)"
    )
    base_impact: float = Field(
        default=0.8,
        ge=0.0,
        le=1.0,
        description="Base impact score (0.0-1.0)"
    )


class TechniqueQueryIn(BaseModel):
    """Input schema for single technique query."""
    technique_id: str = Field(
        ...,
        description="MITRE ATT&CK technique ID (e.g., T1059.001)",
        pattern=r"^T\d{4}(\.\d{3})?$"
    )
    base_likelihood: float = Field(default=0.7, ge=0.0, le=1.0)
    base_impact: float = Field(default=0.8, ge=0.0, le=1.0)


class PlatformQueryIn(BaseModel):
    """Input schema for platform-specific query."""
    platform: str = Field(
        ...,
        description="Platform name (linux, windows, macos, web)"
    )
    base_likelihood: float = Field(default=0.7, ge=0.0, le=1.0)
    base_impact: float = Field(default=0.8, ge=0.0, le=1.0)


class TacticQueryIn(BaseModel):
    """Input schema for tactic-specific query."""
    tactic: str = Field(
        ...,
        description="MITRE ATT&CK tactic (e.g., execution, defense-evasion)"
    )
    base_likelihood: float = Field(default=0.7, ge=0.0, le=1.0)
    base_impact: float = Field(default=0.8, ge=0.0, le=1.0)
