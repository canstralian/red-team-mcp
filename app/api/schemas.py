#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Pydantic schemas for API I/O.
"""
from __future__ import annotations

from pydantic import BaseModel, Field, constr
from typing import Optional, List


class ScriptAuditIn(BaseModel):
    script_text: constr(min_length=1)
    source_path: Optional[str] = "<inline>"


class FileAuditIn(BaseModel):
    file_path: constr(min_length=1)


class ControlOut(BaseModel):
    control_name: str
    implemented: bool
    line_number: Optional[int] = None
    snippet: str
    confidence: float


class FindingOut(BaseModel):
    file_path: str
    controls: List[ControlOut]
    summary: str
    risk_flags: List[str]
