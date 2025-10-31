#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SQLAlchemy models for VerificationIntegrityAgent findings.
"""
from __future__ import annotations

from datetime import datetime
from typing import Optional
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship
from sqlalchemy import String, Integer, DateTime, ForeignKey, JSON, Text


class Base(DeclarativeBase):
    pass


class Finding(Base):
    __tablename__ = "findings"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    file_path: Mapped[str] = mapped_column(String(512), index=True)
    summary: Mapped[str] = mapped_column(Text)
    risk_flags: Mapped[list[str]] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    controls: Mapped[list["ControlEvidence"]] = relationship(
        back_populates="finding", cascade="all, delete-orphan"
    )


class ControlEvidence(Base):
    __tablename__ = "control_evidences"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    finding_id: Mapped[int] = mapped_column(ForeignKey("findings.id", ondelete="CASCADE"))
    control_name: Mapped[str] = mapped_column(String(128), index=True)
    implemented: Mapped[bool]
    line_number: Mapped[Optional[int]]
    snippet: Mapped[str] = mapped_column(Text)
    confidence: Mapped[float]

    finding: Mapped[Finding] = relationship(back_populates="controls")
