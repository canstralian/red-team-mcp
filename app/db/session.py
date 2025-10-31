#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DB session factory for async SQLAlchemy 2.x (SQLite/Postgres).
"""
from __future__ import annotations

from typing import AsyncGenerator
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.engine import URL

# Example: sqlite+aiosqlite:///./verifier.db
DATABASE_URL = "sqlite+aiosqlite:///./verifier.db"

engine = create_async_engine(DATABASE_URL, future=True, echo=False)
SessionLocal = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)


async def get_session() -> AsyncGenerator[AsyncSession, None]:
    async with SessionLocal() as session:
        yield session
