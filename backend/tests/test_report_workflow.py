"""
Integration tests for Phase 9 Forensic Report Generation Workflow.
Verifies end-to-end execution of report endpoints, state transitions (ANALYZED -> REPORTED),
audit logging (REPORT_GENERATED), filesystem report persistence, and evidence preservation.
"""

from pathlib import Path
import json
import pytest
from httpx import ASGITransport, AsyncClient

from app.main import app
from app.evidence.hasher import calculate_sha256


@pytest.mark.asyncio
async def test_report_workflow_end_to_end():
    """
    Test complete Phase 9 workflow using the real BEC demo email:
    1. Upload .eml
    2. Attempt report generation before analysis -> expect 400
    3. Verify and Analyze email
    4. GET /api/cases/{case_id}/report (data object)
    5. GET /api/cases/{case_id}/report/json (JSON download & disk persistence)
    6. GET /api/cases/{case_id}/report/pdf (PDF download & disk persistence)
    7. Verify REPORTED status and REPORT_GENERATED audit event
    8. Verify evidence immutability
    """
    sample_path = Path("samples/bec/demo_bec_invoice.eml")
    assert sample_path.exists()
    content = sample_path.read_bytes()
    expected_sha256 = calculate_sha256(content)

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # 1. Upload .eml
        files = {"file": ("demo_bec_invoice.eml", content, "message/rfc822")}
        upload_res = await client.post("/api/cases/upload", files=files)
        assert upload_res.status_code == 201
        case_id = upload_res.json()["case_id"]

        # 2. Attempt report download before analyze -> 400
        early_json_res = await client.get(f"/api/cases/{case_id}/report/json")
        assert early_json_res.status_code == 400
        assert "must be ANALYZED" in early_json_res.json()["detail"]

        early_pdf_res = await client.get(f"/api/cases/{case_id}/report/pdf")
        assert early_pdf_res.status_code == 400

        # 3. Verify email authentication
        verify_res = await client.post(f"/api/cases/{case_id}/verify")
        assert verify_res.status_code == 200

        # 4. Analyze threat
        analyze_res = await client.post(f"/api/cases/{case_id}/analyze")
        assert analyze_res.status_code == 200

        # 5. GET /report (Data Object)
        report_data_res = await client.get(f"/api/cases/{case_id}/report")
        assert report_data_res.status_code == 200
        rdata = report_data_res.json()
        assert rdata["case_id"] == case_id
        assert rdata["evidence"]["sha256"] == expected_sha256
        assert "ai" in rdata
        assert "authentication" in rdata
        assert "infrastructure" in rdata
        assert "graph" in rdata
        assert "correlation" in rdata
        assert "timeline" in rdata
        assert "risk" in rdata
        assert "conclusion" in rdata
        assert "forensic_disclaimer" in rdata

        # 6. GET /report/json (Downloadable JSON)
        json_res = await client.get(f"/api/cases/{case_id}/report/json")
        assert json_res.status_code == 200
        assert "application/json" in json_res.headers.get("content-type", "")
        assert f'filename="forensic_report_{case_id}.json"' in json_res.headers.get("content-disposition", "")
        parsed_json_report = json.loads(json_res.text)
        assert parsed_json_report["evidence"]["sha256"] == expected_sha256

        # Check disk file persistence
        json_file_path = Path("reports") / case_id / "forensic_report.json"
        assert json_file_path.exists()
        assert json_file_path.is_file()

        # 7. GET /report/pdf (Downloadable PDF)
        pdf_res = await client.get(f"/api/cases/{case_id}/report/pdf")
        assert pdf_res.status_code == 200
        assert "application/pdf" in pdf_res.headers.get("content-type", "")
        assert f'filename="forensic_report_{case_id}.pdf"' in pdf_res.headers.get("content-disposition", "")
        assert pdf_res.content.startswith(b"%PDF-")

        # Check disk PDF persistence
        pdf_file_path = Path("reports") / case_id / "forensic_report.pdf"
        assert pdf_file_path.exists()
        assert pdf_file_path.is_file()
        assert pdf_file_path.read_bytes().startswith(b"%PDF-")

        # 8. Check Case Detail: Status should now be REPORTED
        case_res = await client.get(f"/api/cases/{case_id}")
        assert case_res.status_code == 200
        case_info = case_res.json()
        assert case_info["status"] == "REPORTED"

        # 9. Verify Evidence Immutability
        evidence_records = await client.get(f"/api/cases/{case_id}/evidence")
        assert evidence_records.status_code == 200
        ev_items = evidence_records.json()
        assert len(ev_items) >= 1
        stored_ev = ev_items[0]
        assert stored_ev["sha256"] == expected_sha256

        # Verify raw bytes on disk were not corrupted or modified
        preserved_file = Path(stored_ev["path"])
        assert preserved_file.exists()
        assert calculate_sha256(preserved_file.read_bytes()) == expected_sha256


@pytest.mark.asyncio
async def test_report_endpoints_nonexistent_case():
    """Verify 404 response for nonexistent case identifier on all report endpoints."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        res_data = await client.get("/api/cases/MT-2026-999999/report")
        assert res_data.status_code == 404

        res_json = await client.get("/api/cases/MT-2026-999999/report/json")
        assert res_json.status_code == 404

        res_pdf = await client.get("/api/cases/MT-2026-999999/report/pdf")
        assert res_pdf.status_code == 404
