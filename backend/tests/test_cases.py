"""
Tests for Case API routes: /test, /{case_id}, and health.
"""

import re
import pytest
from httpx import ASGITransport, AsyncClient

from app.main import app


@pytest.mark.asyncio
async def test_health_endpoint_remains_functional():
    """Verify GET /api/health still returns status ok."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        res = await client.get("/api/health")
    assert res.status_code == 200
    assert res.json() == {"status": "ok", "service": "MAILTRACE AI"}


@pytest.mark.asyncio
async def test_create_test_case():
    """Verify POST /api/cases/test creates a case with MT-2026-XXXXXX format."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        res = await client.post("/api/cases/test", json={})
    assert res.status_code == 201
    data = res.json()
    assert "case_id" in data
    assert "status" in data
    assert data["status"] == "UPLOADED"
    assert re.match(r"^MT-2026-\d{6}$", data["case_id"]), f"Invalid case format: {data['case_id']}"


@pytest.mark.asyncio
async def test_get_case_detail_contract():
    """Verify GET /api/cases/{case_id} returns the complete canonical contract structure."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # 1. Create a case
        create_res = await client.post("/api/cases/test", json={})
        assert create_res.status_code == 201
        case_id = create_res.json()["case_id"]

        # 2. Retrieve case
        get_res = await client.get(f"/api/cases/{case_id}")
        assert get_res.status_code == 200
        case_data = get_res.json()

        # 3. Verify all canonical contract fields exist
        assert case_data["case_id"] == case_id
        assert case_data["status"] == "UPLOADED"
        assert case_data["risk_score"] is None
        assert case_data["classification"] is None
        assert case_data["confidence"] is None
        assert isinstance(case_data["email"], dict)
        assert isinstance(case_data["authentication"], dict)
        assert isinstance(case_data["identity"], dict)
        assert isinstance(case_data["indicators"], list)
        assert isinstance(case_data["infrastructure"], dict)
        assert isinstance(case_data["risk_dimensions"], dict)
        assert isinstance(case_data["reasons"], list)
        assert isinstance(case_data["graph"], dict)
        assert isinstance(case_data["evidence"], dict)


@pytest.mark.asyncio
async def test_get_nonexistent_case_returns_404():
    """Verify GET /api/cases/{nonexistent} returns 404."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        res = await client.get("/api/cases/MT-2026-999999")
    assert res.status_code == 404
    assert "not found" in res.json()["detail"].lower()
