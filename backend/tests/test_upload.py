"""
Tests for POST /api/cases/upload and forensic extraction routes.
"""

from pathlib import Path
import pytest
from httpx import ASGITransport, AsyncClient

from app.main import app
from app.evidence.hasher import calculate_sha256


@pytest.mark.asyncio
async def test_upload_valid_bec_eml():
    """Verify uploading authentic demo_bec_invoice.eml succeeds and parses completely."""
    sample_path = Path("samples/bec/demo_bec_invoice.eml")
    assert sample_path.exists()
    content = sample_path.read_bytes()
    expected_sha256 = calculate_sha256(content)

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Upload .eml file
        files = {"file": ("demo_bec_invoice.eml", content, "message/rfc822")}
        response = await client.post("/api/cases/upload", files=files)

        assert response.status_code == 201
        data = response.json()
        assert "case_id" in data
        assert data["status"] == "PARSED"
        assert data["evidence"]["sha256"] == expected_sha256
        assert data["evidence"]["size_bytes"] == len(content)

        case_id = data["case_id"]

        # Verify full case detail contains parsed data
        case_res = await client.get(f"/api/cases/{case_id}")
        assert case_res.status_code == 200
        case_detail = case_res.json()
        assert case_detail["status"] == "PARSED"
        assert "cfo@acme-finance.com" in case_detail["email"]["from_address"].lower()
        assert "acme.invoice.alert@gmail.com" in case_detail["email"]["reply_to"].lower()
        assert case_detail["identity"]["mismatch_detected"] is True
        assert len(case_detail["indicators"]) > 0

        # Verify headers endpoint
        headers_res = await client.get(f"/api/cases/{case_id}/headers")
        assert headers_res.status_code == 200
        headers_data = headers_res.json()
        assert "From" in headers_data
        assert "Received" in headers_data

        # Verify indicators endpoint
        ind_res = await client.get(f"/api/cases/{case_id}/indicators")
        assert ind_res.status_code == 200
        indicators = ind_res.json()
        assert any(ind["type"] == "url" for ind in indicators)
        assert any(ind["type"] == "ip" for ind in indicators)

        # Verify evidence endpoint
        ev_res = await client.get(f"/api/cases/{case_id}/evidence")
        assert ev_res.status_code == 200
        ev_list = ev_res.json()
        assert len(ev_list) >= 1
        assert ev_list[0]["sha256"] == expected_sha256


@pytest.mark.asyncio
async def test_upload_phishing_fixture():
    """Verify uploading synthetic demo_credential_phishing.eml succeeds."""
    sample_path = Path("samples/phishing/demo_credential_phishing.eml")
    assert sample_path.exists()
    content = sample_path.read_bytes()

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        files = {"file": ("demo_credential_phishing.eml", content, "message/rfc822")}
        res = await client.post("/api/cases/upload", files=files)
        assert res.status_code == 201
        data = res.json()
        assert data["status"] == "PARSED"


@pytest.mark.asyncio
async def test_upload_legitimate_fixture():
    """Verify uploading synthetic demo_legitimate_report.eml succeeds."""
    sample_path = Path("samples/legitimate/demo_legitimate_report.eml")
    assert sample_path.exists()
    content = sample_path.read_bytes()

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        files = {"file": ("demo_legitimate_report.eml", content, "message/rfc822")}
        res = await client.post("/api/cases/upload", files=files)
        assert res.status_code == 201
        data = res.json()
        assert data["status"] == "PARSED"

        # Verify legitimate email has no identity mismatch
        case_res = await client.get(f"/api/cases/{data['case_id']}")
        assert case_res.status_code == 200
        case_detail = case_res.json()
        assert case_detail["identity"]["mismatch_detected"] is False


@pytest.mark.asyncio
async def test_upload_rejects_invalid_extension():
    """Verify upload rejects non-.eml files with HTTP 400."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        files = {"file": ("malicious.exe", b"binary content", "application/octet-stream")}
        res = await client.post("/api/cases/upload", files=files)
        assert res.status_code == 400
        assert "only .eml" in res.json()["detail"].lower()


@pytest.mark.asyncio
async def test_upload_rejects_empty_file():
    """Verify upload rejects 0-byte file with HTTP 400."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        files = {"file": ("empty.eml", b"", "message/rfc822")}
        res = await client.post("/api/cases/upload", files=files)
        assert res.status_code == 400
        assert "empty" in res.json()["detail"].lower()


@pytest.mark.asyncio
async def test_upload_rejects_oversized_file():
    """Verify upload rejects files exceeding 10MB."""
    oversized_content = b"A" * (10 * 1024 * 1024 + 1024)
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        files = {"file": ("large.eml", oversized_content, "message/rfc822")}
        res = await client.post("/api/cases/upload", files=files)
        assert res.status_code == 400
        assert "exceeds" in res.json()["detail"].lower()
