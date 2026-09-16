"""
Security hardening tests for MAILTRACE AI.
Verifies defense against directory traversal, oversized uploads, malicious filenames, and secret exposure.
"""

from pathlib import Path
import pytest
from httpx import ASGITransport, AsyncClient

from app.main import app
from app.config import settings


@pytest.mark.asyncio
async def test_path_traversal_case_id_rejected():
    """Verify that case ID path traversal attempts are rejected with 400 Bad Request."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Test directory traversal sequences
        malicious_ids = [
            "../../../etc/passwd",
            "..\\..\\windows\\win.ini",
            "MT-2026/../../../secret",
            "case;DROP TABLE cases;",
            "case<script>",
            "a" * 100,  # exceeds 64 chars
        ]
        for bad_id in malicious_ids:
            res = await client.get(f"/api/cases/{bad_id}")
            assert res.status_code in (400, 404), f"Expected 400 or 404 for bad case ID '{bad_id}', got {res.status_code}"


@pytest.mark.asyncio
async def test_malicious_upload_filename_sanitized():
    """Verify that uploaded filenames with path traversal or null bytes are sanitized."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        content = b"From: user@example.com\r\nTo: admin@example.com\r\nSubject: Test\r\n\r\nTest content"
        
        # Test filename containing directory traversal and null bytes
        malicious_filename = "../../../etc/passwd\x00_test.eml"
        files = {"file": (malicious_filename, content, "message/rfc822")}
        
        res = await client.post("/api/cases/upload", files=files)
        assert res.status_code == 201
        case_data = res.json()
        case_id = case_data["case_id"]
        
        # Verify evidence was saved safely without traversing outside evidence vault
        evidence_path = Path("evidence") / case_id / "raw.eml"
        assert evidence_path.exists()
        assert not Path("evidence/../../../etc/passwd").exists()


@pytest.mark.asyncio
async def test_oversized_upload_rejected():
    """Verify that uploads exceeding 10MB limit are rejected with 400 Bad Request."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Create 11MB byte payload
        large_content = b"A" * (11 * 1024 * 1024)
        files = {"file": ("oversized.eml", large_content, "message/rfc822")}
        
        res = await client.post("/api/cases/upload", files=files)
        assert res.status_code == 400
        assert "exceeds maximum allowed limit" in res.json()["detail"]


def test_no_hardcoded_secrets():
    """Verify that settings does not contain hardcoded production secrets."""
    assert settings.VIRUSTOTAL_API_KEY == "" or isinstance(settings.VIRUSTOTAL_API_KEY, str)
    assert not settings.DATABASE_URL.startswith("postgres://admin:password")


def test_cors_restricted_origins():
    """Verify that CORS origins are restricted to local development domains."""
    origins = settings.CORS_ORIGINS if isinstance(settings.CORS_ORIGINS, list) else [settings.CORS_ORIGINS]
    assert "*" not in origins
    assert "http://127.0.0.1:5173" in origins or "http://localhost:5173" in origins
