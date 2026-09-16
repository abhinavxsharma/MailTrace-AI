"""
Evidence integrity and cryptographic chain-of-custody tests for MAILTRACE AI.
Verifies SHA-256 preservation, immutability, overwrite rejection, and complete audit logging.
"""

from pathlib import Path
import pytest
from httpx import ASGITransport, AsyncClient

from app.main import app
from app.evidence.preservation import preserve_evidence
from app.evidence.hasher import calculate_sha256


@pytest.mark.asyncio
async def test_evidence_sha256_immutable_across_workflow():
    """Verify evidence SHA-256 hash remains 100% constant from upload through reporting."""
    sample_path = Path("samples/bec/demo_bec_invoice.eml")
    assert sample_path.exists()
    content = sample_path.read_bytes()
    expected_sha256 = calculate_sha256(content)

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # 1. Upload
        files = {"file": ("demo_bec_invoice.eml", content, "message/rfc822")}
        res = await client.post("/api/cases/upload", files=files)
        assert res.status_code == 201
        case_id = res.json()["case_id"]
        assert res.json()["evidence"]["sha256"] == expected_sha256

        # 2. Verify
        v_res = await client.post(f"/api/cases/{case_id}/verify")
        assert v_res.status_code == 200

        # 3. Analyze
        a_res = await client.post(f"/api/cases/{case_id}/analyze")
        assert a_res.status_code == 200

        # 4. Check Case Detail
        d_res = await client.get(f"/api/cases/{case_id}")
        assert d_res.status_code == 200
        assert d_res.json()["evidence"]["sha256"] == expected_sha256

        # 5. Check Report JSON
        r_res = await client.get(f"/api/cases/{case_id}/report/json")
        assert r_res.status_code == 200
        report = r_res.json()
        assert report["evidence"]["sha256"] == expected_sha256

        # 6. Verify stored disk file has not been altered by even 1 bit
        vault_file = Path("evidence") / case_id / "raw.eml"
        assert vault_file.exists()
        assert calculate_sha256(vault_file.read_bytes()) == expected_sha256


def test_evidence_vault_overwrite_rejected(tmp_path):
    """Verify that preserve_evidence rejects silent overwrites of existing evidence."""
    case_id = "MT-TEST-INTEGRITY"
    content_a = b"Original email content"
    content_b = b"Tampered email content"

    # First preservation succeeds
    path, size, sha = preserve_evidence(case_id=case_id, raw_bytes=content_a, base_dir=tmp_path)
    assert path.exists()

    # Second preservation without overwrite flag raises FileExistsError
    with pytest.raises(FileExistsError):
        preserve_evidence(case_id=case_id, raw_bytes=content_b, base_dir=tmp_path, overwrite=False)

    # Content remains original
    assert path.read_bytes() == content_a


@pytest.mark.asyncio
async def test_audit_trail_tracks_all_milestones():
    """Verify that complete audit trail records all key case events."""
    sample_path = Path("samples/bec/demo_bec_invoice.eml")
    content = sample_path.read_bytes()

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Upload
        files = {"file": ("demo_bec_invoice.eml", content, "message/rfc822")}
        res = await client.post("/api/cases/upload", files=files)
        case_id = res.json()["case_id"]

        # Verify
        await client.post(f"/api/cases/{case_id}/verify")

        # Analyze
        await client.post(f"/api/cases/{case_id}/analyze")

        # Report
        await client.get(f"/api/cases/{case_id}/report/pdf")

        # Check audit trail in report
        rep_res = await client.get(f"/api/cases/{case_id}/report")
        assert rep_res.status_code == 200
        audit_events = rep_res.json()["audit"]
        event_types = [a["event_type"] for a in audit_events]

        assert "CASE_CREATED" in event_types
        assert "UPLOADED" in event_types
        assert "PARSED" in event_types
        assert "VERIFIED" in event_types
        assert "ANALYZED" in event_types
        assert "REPORT_GENERATED" in event_types
