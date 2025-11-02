#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
FastAPI app wiring the VerificationIntegrityAgent with async DB logging
and Defensive Evasion Matrix analysis.
"""
from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from pathlib import Path
from fastapi import FastAPI, Depends, HTTPException
from fastapi.responses import JSONResponse, PlainTextResponse
from sqlalchemy.ext.asyncio import AsyncSession
from app.api.schemas import ScriptAuditIn, FileAuditIn, FindingOut
from app.agents.verification_integrity import (
    VerificationIntegrityAgent,
    AUDITABLE_ROOT,
)
from app.db.session import engine, get_session
from app.db.models import Base
from app.repositories.findings import save_finding, list_findings
from app.defense.evasion_matrix import EvasionMatrixAnalyzer
from app.defense.api_schemas import (
    TechniqueQueryIn, PlatformQueryIn, TacticQueryIn,
    AnalysisQueryIn, GapAnalysisOut, CoverageStatsOut
)
from app.defense.models import TechniqueCategory

agent = VerificationIntegrityAgent()
matrix_analyzer = EvasionMatrixAnalyzer()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize database on startup."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield


app = FastAPI(title="Verification Integrity Service", lifespan=lifespan)


@app.post("/audit/verification-script", response_model=FindingOut)
async def audit_verification_script(
    payload: ScriptAuditIn, session: AsyncSession = Depends(get_session)
):
    finding = agent.analyze_text(payload.script_text, file_path=payload.source_path)
    finding_json = {
        "file_path": finding.file_path,
        "controls": [c.__dict__ for c in finding.controls],
        "summary": finding.summary,
        "risk_flags": finding.risk_flags,
    }
    await save_finding(session, finding_json)
    return JSONResponse(finding_json)


@app.post("/audit/verification-script/from-file", response_model=FindingOut)
async def audit_verification_script_from_file(
    payload: FileAuditIn, session: AsyncSession = Depends(get_session)
):
    requested_path = Path(payload.file_path)

    if requested_path.is_absolute():
        raise HTTPException(
            status_code=400, detail="absolute file paths are not allowed"
        )

    resolved_auditable_root = AUDITABLE_ROOT.resolve()
    sanitized_path = (resolved_auditable_root / requested_path).resolve()

    try:
        sanitized_path.relative_to(resolved_auditable_root)
    except ValueError:
        raise HTTPException(
            status_code=400, detail="file path outside allowed directory"
        )

    try:
        with open(sanitized_path, "r", encoding="utf-8") as file_obj:
            f = agent.analyze_file(file_obj, file_path=sanitized_path)
    except (OSError, IOError):
        raise HTTPException(status_code=400, detail="file unreadable or too large")
    if f is None:
        raise HTTPException(status_code=400, detail="file unreadable or too large")
    finding_json = {
        "file_path": f.file_path,
        "controls": [c.__dict__ for c in f.controls],
        "summary": f.summary,
        "risk_flags": f.risk_flags,
    }
    await save_finding(session, finding_json)
    return JSONResponse(finding_json)


@app.get("/findings")
async def get_recent_findings(session: AsyncSession = Depends(get_session)):
    rows = await list_findings(session, limit=50)
    out = []
    for r in rows:
        out.append(
            {
                "id": r.id,
                "file_path": r.file_path,
                "summary": r.summary,
                "risk_flags": r.risk_flags,
                "created_at": r.created_at.isoformat(),
            }
        )
    return out


# ═══════════════════════════════════════════════════════════════════════════
# DEFENSIVE EVASION MATRIX ENDPOINTS
# ═══════════════════════════════════════════════════════════════════════════

@app.get("/defense/matrix/full")
async def get_full_matrix(
    base_likelihood: float = 0.7,
    base_impact: float = 0.8
):
    """
    Generate complete defensive evasion matrix.

    Maps all attack techniques to defensive controls with residual risk analysis.
    """
    report = matrix_analyzer.build_full_matrix(base_likelihood, base_impact)

    mappings = []
    for mapping in report.mappings:
        gap = mapping.control_gap_analysis()

        mappings.append({
            "technique": {
                "technique_id": mapping.technique.technique_id,
                "technique_name": mapping.technique.technique_name,
                "tactic": mapping.technique.tactic.value,
                "description": mapping.technique.description,
                "platform": mapping.technique.platform,
                "detection_difficulty": mapping.technique.detection_difficulty.value
            },
            "controls": [
                {
                    "control_id": c.control_id,
                    "control_name": c.control_name,
                    "control_type": c.control_type,
                    "effectiveness": c.effectiveness.value
                }
                for c in mapping.controls
            ],
            "residual_risk": mapping.calculate_residual_risk(),
            "risk_level": gap["risk_level"],
            "recommended_action": gap["recommended_action"]
        })

    return {
        "generated_at": report.generated_at.isoformat(),
        "total_techniques": report.total_techniques,
        "total_controls": report.total_controls,
        "overall_risk_score": report.overall_risk_score,
        "summary_statistics": report.summary_statistics(),
        "mappings": mappings
    }


@app.post("/defense/matrix/technique")
async def analyze_technique(query: TechniqueQueryIn):
    """
    Analyze a specific MITRE ATT&CK technique.

    Returns defensive controls and residual risk for the technique.
    """
    mapping = matrix_analyzer.analyze_technique(
        query.technique_id,
        query.base_likelihood,
        query.base_impact
    )

    if not mapping:
        raise HTTPException(status_code=404, detail=f"Technique {query.technique_id} not found")

    gap = mapping.control_gap_analysis()

    return {
        "technique": {
            "technique_id": mapping.technique.technique_id,
            "technique_name": mapping.technique.technique_name,
            "tactic": mapping.technique.tactic.value,
            "description": mapping.technique.description,
            "platform": mapping.technique.platform,
            "detection_difficulty": mapping.technique.detection_difficulty.value
        },
        "controls": [
            {
                "control_id": c.control_id,
                "control_name": c.control_name,
                "control_type": c.control_type,
                "description": c.description,
                "effectiveness": c.effectiveness.value,
                "implementation_cost": c.implementation_cost.value,
                "detection_methods": c.detection_methods,
                "response_actions": c.response_actions
            }
            for c in mapping.controls
        ],
        "residual_risk": mapping.calculate_residual_risk(),
        "risk_level": gap["risk_level"],
        "control_gap_analysis": gap
    }


@app.get("/defense/matrix/coverage")
async def get_coverage_analysis():
    """
    Analyze overall defensive coverage across all techniques.

    Returns coverage statistics and control distribution.
    """
    return matrix_analyzer.coverage_analysis()


@app.get("/defense/matrix/gaps")
async def get_priority_gaps(
    base_likelihood: float = 0.7,
    base_impact: float = 0.8,
    top_n: int = 10
):
    """
    Identify highest-priority defensive gaps.

    Returns top N techniques with highest residual risk.
    """
    gaps = matrix_analyzer.gap_prioritization(base_likelihood, base_impact, top_n)
    return {"priority_gaps": gaps}


@app.get("/defense/matrix/heatmap")
async def get_heatmap_data(
    base_likelihood: float = 0.7,
    base_impact: float = 0.8
):
    """
    Generate risk heatmap data organized by MITRE ATT&CK tactics.

    Returns technique risk scores grouped by tactic for visualization.
    """
    heatmap = matrix_analyzer.generate_heatmap_data(base_likelihood, base_impact)

    return {
        "heatmap": [
            {
                "tactic": tactic,
                "techniques": techniques
            }
            for tactic, techniques in heatmap.items()
        ]
    }


@app.get("/defense/matrix/by-platform/{platform}")
async def get_platform_analysis(
    platform: str,
    base_likelihood: float = 0.7,
    base_impact: float = 0.8
):
    """
    Analyze techniques applicable to a specific platform.

    Platforms: linux, windows, macos, web
    """
    mappings = matrix_analyzer.analyze_by_platform(platform, base_likelihood, base_impact)

    if not mappings:
        raise HTTPException(status_code=404, detail=f"No techniques found for platform '{platform}'")

    return {
        "platform": platform,
        "total_techniques": len(mappings),
        "techniques": [
            {
                "technique_id": m.technique.technique_id,
                "technique_name": m.technique.technique_name,
                "tactic": m.technique.tactic.value,
                "control_count": len(m.controls),
                "residual_risk": m.calculate_residual_risk(),
                "risk_level": m.risk_level().value
            }
            for m in mappings
        ]
    }


@app.get("/defense/matrix/by-tactic/{tactic}")
async def get_tactic_analysis(
    tactic: str,
    base_likelihood: float = 0.7,
    base_impact: float = 0.8
):
    """
    Analyze techniques for a specific MITRE ATT&CK tactic.

    Tactics: execution, persistence, privilege-escalation, defense-evasion,
             credential-access, discovery, lateral-movement, collection,
             command-and-control, exfiltration, initial-access, impact
    """
    try:
        tactic_enum = TechniqueCategory(tactic)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid tactic '{tactic}'")

    mappings = matrix_analyzer.analyze_by_tactic(tactic_enum, base_likelihood, base_impact)

    return {
        "tactic": tactic,
        "total_techniques": len(mappings),
        "techniques": [
            {
                "technique_id": m.technique.technique_id,
                "technique_name": m.technique.technique_name,
                "control_count": len(m.controls),
                "residual_risk": m.calculate_residual_risk(),
                "risk_level": m.risk_level().value
            }
            for m in mappings
        ]
    }


@app.get("/defense/matrix/export/csv", response_class=PlainTextResponse)
async def export_matrix_csv(
    base_likelihood: float = 0.7,
    base_impact: float = 0.8
):
    """
    Export complete matrix to CSV format.

    Returns CSV file for spreadsheet analysis.
    """
    report = matrix_analyzer.build_full_matrix(base_likelihood, base_impact)
    csv_content = matrix_analyzer.export_matrix_csv(report)

    return PlainTextResponse(
        content=csv_content,
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=evasion_matrix.csv"}
    )


@app.get("/defense/controls/effectiveness")
async def get_control_effectiveness():
    """
    Summarize effectiveness of all defensive controls.

    Returns control statistics by effectiveness, type, and cost.
    """
    return matrix_analyzer.control_effectiveness_summary()
