"""
Integration tests for the /verify workflow, authentication endpoints, and offline resiliency.
"""

from pathlib import Path
from unittest.mock import patch
import pytest
import dns.exception
from httpx import ASGITransport, AsyncClient

from app.main import app


@pytest.mark.asyncio
async def test_full_verify_workflow_bec_fixture():
    """
    Test complete lifecycle from upload to verification using the authentic BEC fixture.
    Verifies that declared SPF/DKIM/DMARC are parsed and DMARC alignment failure is identified.
    """
    sample_path = Path("samples/bec/demo_bec_invoice.eml")
    assert sample_path.exists()
    content = sample_path.read_bytes()

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # 1. Upload .eml
        files = {"file": ("demo_bec_invoice.eml", content, "message/rfc822")}
        upload_res = await client.post("/api/cases/upload", files=files)
        assert upload_res.status_code == 201
        case_id = upload_res.json()["case_id"]
        assert upload_res.json()["status"] == "PARSED"

        # 2. Call /verify endpoint
        verify_res = await client.post(f"/api/cases/{case_id}/verify")
        assert verify_res.status_code == 200
        v_data = verify_res.json()
        assert v_data["case_id"] == case_id
        assert v_data["status"] == "VERIFIED"

        # Verify authentication structure
        auth = v_data["authentication"]
        assert auth["declared"]["spf"] == "PASS"
        assert auth["declared"]["dkim"] == "PASS"
        assert auth["declared"]["dmarc"] == "FAIL"

        # DMARC alignment should be false because notify-acme.co != acme-finance.com
        assert auth["alignment_details"]["overall"] is False
        assert auth["alignment"] == "FAIL"

        # Verify identity structure
        identity = v_data["identity"]
        assert identity["mismatch_detected"] is True
        assert identity["reply_to_mismatch"] is True
        assert identity["return_path_mismatch"] is True
        assert identity["from_domain"] == "acme-finance.com"
        assert identity["reply_to_domain"] == "gmail.com"
        assert identity["return_path_domain"] == "notify-acme.co"

        # 3. Query GET /api/cases/{case_id}/authentication
        auth_res = await client.get(f"/api/cases/{case_id}/authentication")
        assert auth_res.status_code == 200
        auth_query = auth_res.json()
        assert auth_query["declared"]["dmarc"] == "FAIL"

        # 4. Query GET /api/cases/{case_id}
        detail_res = await client.get(f"/api/cases/{case_id}")
        assert detail_res.status_code == 200
        detail = detail_res.json()
        assert detail["status"] == "VERIFIED"
        assert detail["authentication"]["declared"]["spf"] == "PASS"


@pytest.mark.asyncio
async def test_verify_nonexistent_case_returns_404():
    """Verify calling /verify on nonexistent case returns 404."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        res = await client.post("/api/cases/MT-2026-999999/verify")
        assert res.status_code == 404


@pytest.mark.asyncio
async def test_verify_unparsed_case_returns_400():
    """Verify calling /verify on a case that is only UPLOADED (not parsed) returns 400."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Create a test case (status: UPLOADED)
        test_case_res = await client.post("/api/cases/test", json={})
        assert test_case_res.status_code == 201
        case_id = test_case_res.json()["case_id"]

        # Attempt verification before uploading an email
        res = await client.post(f"/api/cases/{case_id}/verify")
        assert res.status_code == 400
        assert "must be parsed" in res.json()["detail"].lower()


@pytest.mark.asyncio
async def test_verify_offline_no_dns_mode():
    """
    Verify system handles offline / DNS failure gracefully without crashing,
    returning UNAVAILABLE/UNKNOWN active statuses while preserving declared headers.
    """
    sample_path = Path("samples/bec/demo_bec_invoice.eml")
    content = sample_path.read_bytes()

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        files = {"file": ("demo_bec_invoice.eml", content, "message/rfc822")}
        upload_res = await client.post("/api/cases/upload", files=files)
        assert upload_res.status_code == 201
        case_id = upload_res.json()["case_id"]

        # Simulate total network/DNS blackout
        with patch("dns.resolver.Resolver.resolve", side_effect=dns.exception.Timeout):
            verify_res = await client.post(f"/api/cases/{case_id}/verify")
            assert verify_res.status_code == 200
            v_data = verify_res.json()
            assert v_data["status"] == "VERIFIED"

            auth = v_data["authentication"]
            # Active verification should report UNAVAILABLE
            assert auth["verified"]["spf"] == "UNAVAILABLE"
            # Declared headers from the email must still be preserved
            assert auth["declared"]["spf"] == "PASS"
            assert auth["declared"]["dmarc"] == "FAIL"
