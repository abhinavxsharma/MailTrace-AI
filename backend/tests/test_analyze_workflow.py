"""
Integration tests for the /analyze workflow, AI threat detection, feature extraction, and risk fusion.
"""

from pathlib import Path
import pytest
from httpx import ASGITransport, AsyncClient

from app.main import app


@pytest.mark.asyncio
async def test_full_analyze_workflow_bec_fixture():
    """
    Test complete lifecycle from upload -> verify -> analyze using the authentic BEC fixture.
    Verifies that AI threat classification, feature extraction, and risk fusion execute properly,
    and that Phase 4 authentication evidence remains preserved.
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
        assert verify_res.json()["status"] == "VERIFIED"

        # 3. Call /analyze endpoint
        analyze_res = await client.post(f"/api/cases/{case_id}/analyze")
        assert analyze_res.status_code == 200
        a_data = analyze_res.json()

        assert a_data["case_id"] == case_id
        assert a_data["status"] == "ANALYZED"
        assert a_data["ai_prediction"]["label"] == "MALICIOUS"
        assert a_data["ai_confidence"] >= 0.85

        # Verify extracted features
        feats = a_data["extracted_features"]
        assert feats["urgency_detected"] is True
        assert feats["financial_detected"] is True
        assert feats["authority_detected"] is True
        assert feats["secrecy_detected"] is True
        assert feats["reply_to_mismatch"] is True
        assert feats["return_path_mismatch"] is True

        # Verify risk score & contributions
        assert a_data["risk_score"] >= 70
        assert a_data["risk_level"] in ("HIGH", "CRITICAL")
        contribs = a_data["risk_contributions"]
        assert contribs["ai_threat"] == 25
        assert contribs["identity"] == 20
        assert contribs["authentication"] == 10
        assert contribs["url_domain"] == 15
        assert contribs["infrastructure"] == 0
        assert contribs["campaign"] in (0, 10)

        # Verify explanations contain forensic statements
        exps = a_data["explanations"]
        assert any("MALICIOUS" in e for e in exps)
        assert any("Reply-To" in e for e in exps)
        assert any("DMARC" in e for e in exps)

        # 4. Verify Phase 4 authentication data remains intact
        auth_res = await client.get(f"/api/cases/{case_id}/authentication")
        assert auth_res.status_code == 200
        auth = auth_res.json()
        assert auth["declared"]["spf"] == "PASS"
        assert auth["declared"]["dkim"] == "PASS"
        assert auth["declared"]["dmarc"] == "FAIL"

        # 5. Verify GET /api/cases/{case_id} contains full analysis details
        case_res = await client.get(f"/api/cases/{case_id}")
        assert case_res.status_code == 200
        case_data = case_res.json()
        assert case_data["status"] == "ANALYZED"
        assert case_data["risk_score"] == a_data["risk_score"]
        assert case_data["classification"] == a_data["risk_level"]
        assert case_data["confidence"] is not None
        assert case_data["detection"] is not None
        assert case_data["detection"]["model"] == "dataset3_v1.0.0"
        assert len(case_data["reasons"]) > 0


@pytest.mark.asyncio
async def test_analyze_direct_from_parsed():
    """
    Verify that /analyze can be invoked directly on a PARSED case
    without prior manual /verify call, handling authentication safely.
    """
    sample_path = Path("samples/phishing/demo_credential_phishing.eml")
    assert sample_path.exists()
    content = sample_path.read_bytes()

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        files = {"file": ("demo_credential_phishing.eml", content, "message/rfc822")}
        upload_res = await client.post("/api/cases/upload", files=files)
        assert upload_res.status_code == 201
        case_id = upload_res.json()["case_id"]

        # Directly analyze
        analyze_res = await client.post(f"/api/cases/{case_id}/analyze")
        assert analyze_res.status_code == 200
        data = analyze_res.json()
        assert data["status"] == "ANALYZED"
        assert data["risk_score"] >= 0
        assert data["ai_prediction"] is not None


@pytest.mark.asyncio
async def test_analyze_nonexistent_case_returns_404():
    """Verify that analyzing a nonexistent case returns 404."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        res = await client.post("/api/cases/MT-2026-999999/analyze")
        assert res.status_code == 404


@pytest.mark.asyncio
async def test_analyze_unparsed_case_returns_400():
    """Verify that analyzing an unparsed test case (status UPLOADED) returns 400."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Create test case with status UPLOADED
        create_res = await client.post("/api/cases/test")
        assert create_res.status_code == 201
        case_id = create_res.json()["case_id"]

        # Attempt to analyze without parsing
        analyze_res = await client.post(f"/api/cases/{case_id}/analyze")
        assert analyze_res.status_code == 400
        assert "must be PARSED" in analyze_res.json()["detail"]
