#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Integration tests for FastAPI endpoints with database.
"""
from __future__ import annotations

import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from app.main import app
from app.db.models import Base
from app.db.session import get_session

# Test database URL
TEST_DATABASE_URL = "sqlite+aiosqlite:///:memory:"


@pytest_asyncio.fixture
async def test_db():
    """Create test database and session."""
    engine = create_async_engine(TEST_DATABASE_URL, future=True, echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    SessionLocal = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)

    async def override_get_session():
        async with SessionLocal() as session:
            yield session

    app.dependency_overrides[get_session] = override_get_session

    yield engine

    app.dependency_overrides.clear()
    await engine.dispose()


@pytest.mark.asyncio
async def test_audit_verification_script_endpoint(test_db):
    """Test POST /audit/verification-script endpoint."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        payload = {
            "script_text": """
                gpg --status-fd 1 --verify sig.asc artifact
                gpg_bash_lib_output_signed_on_unixtime=1700000000
                gpg_bash_lib_input_maximum_age_in_seconds=604800
                gpg_bash_lib_input_verify_timeout_after=30
                gpg_bash_lib_input_kill_after=45
                notation["file@name"]="artifact.tar.gz"
            """,
            "source_path": "test_script.sh"
        }

        response = await client.post("/audit/verification-script", json=payload)

        assert response.status_code == 200
        data = response.json()

        assert data["file_path"] == "test_script.sh"
        assert len(data["controls"]) == 5
        assert data["summary"].startswith("GPG verification script analysis")
        assert len(data["risk_flags"]) == 0  # All controls implemented


@pytest.mark.asyncio
async def test_audit_detects_missing_controls(test_db):
    """Test that weak scripts are flagged appropriately."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        payload = {
            "script_text": "gpg --verify sig.asc artifact",
            "source_path": "weak.sh"
        }

        response = await client.post("/audit/verification-script", json=payload)

        assert response.status_code == 200
        data = response.json()

        assert "possible_endless_data_dos_no_timeouts" in data["risk_flags"]
        assert "possible_filename_tampering_risk" in data["risk_flags"]


@pytest.mark.asyncio
async def test_get_recent_findings_endpoint(test_db):
    """Test GET /findings endpoint."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        # First, create some findings
        payload = {
            "script_text": "gpg --verify sig.asc",
            "source_path": "test1.sh"
        }
        await client.post("/audit/verification-script", json=payload)

        # Fetch findings
        response = await client.get("/findings")

        assert response.status_code == 200
        findings = response.json()

        assert len(findings) >= 1
        assert findings[0]["file_path"] == "test1.sh"
        assert "created_at" in findings[0]
