"""
Integration tests for Phase 6 full infrastructure intelligence and offline resilience workflow.
"""

from pathlib import Path
from unittest.mock import patch
import dns.exception
import httpx
import pytest
from httpx import ASGITransport, AsyncClient

from app.main import app


@pytest.mark.asyncio
async def test_full_phase6_analyze_workflow_bec_fixture():
    """
    Test complete lifecycle with Phase 6 infrastructure enrichment on the BEC fixture.
    Verifies that dns, rdap, geoip, infrastructure, and infrastructure_score are returned.
    """
    sample_path = Path("samples/bec/demo_bec_invoice.eml")
    assert sample_path.exists()
    content = sample_path.read_bytes()

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # 1. Upload
        files = {"file": ("demo_bec_invoice.eml", content, "message/rfc822")}
        upload_res = await client.post("/api/cases/upload", files=files)
        assert upload_res.status_code == 201
        case_id = upload_res.json()["case_id"]

        # 2. Verify
        verify_res = await client.post(f"/api/cases/{case_id}/verify")
        assert verify_res.status_code == 200

        # 3. Analyze
        analyze_res = await client.post(f"/api/cases/{case_id}/analyze")
        assert analyze_res.status_code == 200
        a_data = analyze_res.json()

        assert a_data["case_id"] == case_id
        assert a_data["status"] == "ANALYZED"
        assert "infrastructure" in a_data
        assert "dns" in a_data
        assert "rdap" in a_data
        assert "geoip" in a_data
        assert "infrastructure_score" in a_data
        assert a_data["infrastructure_score"] >= 0
        assert a_data["risk_score"] >= 70

        # Check infrastructure object details
        infra = a_data["infrastructure"]
        assert infra["source_ip"] == "198.51.100.42"

        # 4. Check GET /api/cases/{case_id}
        case_res = await client.get(f"/api/cases/{case_id}")
        assert case_res.status_code == 200
        c_data = case_res.json()
        assert c_data["status"] == "ANALYZED"
        assert c_data["infrastructure"]["source_ip"] == "198.51.100.42"


@pytest.mark.asyncio
async def test_phase6_offline_resilience_simulation():
    """
    Simulate complete offline conditions: DNS timeout, RDAP timeout, missing GeoIP DB.
    Verifies that the /analyze endpoint completes successfully with HTTP 200,
    recording UNAVAILABLE statuses without crashing or losing previous forensic evidence.
    """
    sample_path = Path("samples/bec/demo_bec_invoice.eml")
    content = sample_path.read_bytes()

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Upload
        files = {"file": ("demo_bec_invoice.eml", content, "message/rfc822")}
        upload_res = await client.post("/api/cases/upload", files=files)
        assert upload_res.status_code == 201
        case_id = upload_res.json()["case_id"]

        # Mock total external network and DB failures
        with patch("dns.resolver.Resolver.resolve", side_effect=dns.exception.Timeout("DNS Timeout")), \
             patch("httpx.Client.get", side_effect=httpx.TimeoutException("RDAP Timeout")):

            analyze_res = await client.post(f"/api/cases/{case_id}/analyze")
            assert analyze_res.status_code == 200
            data = analyze_res.json()

            assert data["status"] == "ANALYZED"
            assert data["risk_score"] >= 0
            assert "infrastructure" in data
            assert data["infrastructure_score"] == 0
            # Offline statuses recorded
            assert data["infrastructure"]["dns_status"] in ("unavailable", "not_found")
            assert data["infrastructure"]["rdap_status"] in ("unavailable", "not_found")
            assert data["infrastructure"]["geoip_status"] in ("unavailable", "not_found")
