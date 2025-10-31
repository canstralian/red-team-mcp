#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Persistence helpers for VerificationIntegrityAgent findings.
"""
from __future__ import annotations

from typing import Sequence
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.db.models import Finding, ControlEvidence


async def save_finding(session: AsyncSession, finding_json: dict) -> Finding:
    f = Finding(
        file_path=finding_json["file_path"],
        summary=finding_json["summary"],
        risk_flags=finding_json["risk_flags"],
    )
    session.add(f)
    await session.flush()

    controls: Sequence[dict] = finding_json["controls"]
    for c in controls:
        session.add(
            ControlEvidence(
                finding_id=f.id,
                control_name=c["control_name"],
                implemented=bool(c["implemented"]),
                line_number=c.get("line_number"),
                snippet=c.get("snippet", "")[:4000],
                confidence=float(c.get("confidence", 0.0)),
            )
        )

    await session.commit()
    await session.refresh(f)
    return f


async def list_findings(session: AsyncSession, limit: int = 50) -> list[Finding]:
    q = select(Finding).order_by(Finding.id.desc()).limit(limit)
    res = await session.execute(q)
    return list(res.scalars().all())
