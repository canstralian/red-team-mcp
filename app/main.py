#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
FastAPI app wiring the VerificationIntegrityAgent with async DB logging.
"""
from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from pathlib import Path
from fastapi import FastAPI, Depends, HTTPException
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession
from app.api.schemas import ScriptAuditIn, FileAuditIn, FindingOut
from app.agents.verification_integrity import VerificationIntegrityAgent
from app.db.session import engine, get_session
from app.db.models import Base
from app.repositories.findings import save_finding, list_findings

agent = VerificationIntegrityAgent()


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
    f = agent.analyze_file(Path(payload.file_path))
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
